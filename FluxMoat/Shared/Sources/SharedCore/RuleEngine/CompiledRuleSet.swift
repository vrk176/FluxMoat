import Foundation

/// The flow 5-tuple plus context that the tunnel builds for each flow.
public struct FlowDescriptor: Sendable {
    public var domain: String?
    public var ip: IPAddress?
    public var port: UInt16?
    public var protocolNumber: UInt8?
    public var profileID: UUID?
    public var timestamp: Date

    public init(
        domain: String? = nil,
        ip: IPAddress? = nil,
        port: UInt16? = nil,
        protocolNumber: UInt8? = nil,
        profileID: UUID? = nil,
        timestamp: Date = Date()
    ) {
        self.domain = domain
        self.ip = ip
        self.port = port
        self.protocolNumber = protocolNumber
        self.profileID = profileID
        self.timestamp = timestamp
    }
}

public struct Verdict: Sendable, Equatable {
    public enum Source: Equatable, Sendable {
        case userRule
        /// Ad/tracker blocklist (domain lists such as StevenBlack).
        case blocklist
        case modeDefault
        /// The upstream filtering DoH resolver blocked the name. Never produced by
        /// `CompiledRuleSet`; the SOCKS server sets it when `DoHResolver` returns
        /// `.blockedByResolver`.
        case filteringResolver
        /// Matched a local threat-intel feed (malware, C2 or botnet domain or IP).
        /// Counted separately from ad/tracker blocks.
        case threatFeed
    }

    public let action: RuleAction
    public let matchedRuleID: UUID?
    public let source: Source
}

/// Immutable, pre-indexed view of the active rules and blocklist domains.
/// Built once per snapshot change and swapped in atomically. Evaluation is
/// lock-free and read-only.
public struct CompiledRuleSet: Sendable {
    private let rules: [Rule]
    private var exactDomainRules: [String: [Int]] = [:]
    private var wildcardDomainRules: [String: [Int]] = [:]
    private var ipRulesV4: BitTrie<Int>
    private var ipRulesV6: BitTrie<Int>
    private var portRules: [(range: ClosedRange<UInt16>, index: Int)] = []
    private var networkRules: [(protocolNumber: UInt8, port: ClosedRange<UInt16>?, index: Int)] = []
    /// Ad/tracker blocklist domains. Matches the host and all subdomains.
    /// A hit reports `source: .blocklist`.
    private let blocklistDomains: Set<String>
    /// Threat-intel domains (URLhaus, OpenPhish and similar). Matched like
    /// `blocklistDomains`, but a hit reports `source: .threatFeed` and is
    /// counted separately.
    private let threatDomains: Set<String>
    /// Threat-intel IP/CIDR indicators (Feodo, Spamhaus and similar). There are
    /// no ad/tracker IP lists, so a hit always reports `.threatFeed`. Checked
    /// after user rules (so a user Allow wins) and before the mode default.
    /// A bare IP is stored as a /32 or /128.
    private var threatIPsV4 = BitTrie<Bool>()
    private var threatIPsV6 = BitTrie<Bool>()
    private let hasThreatIPs: Bool

    /// Number of rules actually compiled: user rules plus any added by
    /// `RuleSnapshot.compile()`, such as the encrypted-DNS deny set. Use this
    /// for logging instead of the snapshot's stored count.
    public var ruleCount: Int { rules.count }

    public init(
        rules: [Rule],
        blocklistDomains: some Sequence<String> = [],
        threatDomains: some Sequence<String> = [] as [String],
        threatIPs: some Sequence<String> = [] as [String]
    ) {
        self.rules = rules
        self.blocklistDomains = Set(blocklistDomains.map(DomainName.normalize(_:)))
        self.threatDomains = Set(threatDomains.map(DomainName.normalize(_:)))

        var blV4 = BitTrie<Bool>()
        var blV6 = BitTrie<Bool>()
        var ipCount = 0
        for entry in threatIPs {
            // A `network/prefix` entry, or a bare IP treated as a full-length prefix.
            // The parser already validated these; malformed entries are skipped.
            if let block = CIDRBlock(entry) {
                if block.address.isV4 {
                    blV4.insert(bytes: block.address.bytes, prefixLength: block.prefixLength, value: true)
                } else {
                    blV6.insert(bytes: block.address.bytes, prefixLength: block.prefixLength, value: true)
                }
                ipCount += 1
            } else if let ip = IPAddress.parse(entry) {
                if ip.isV4 {
                    blV4.insert(bytes: ip.bytes, prefixLength: 32, value: true)
                } else {
                    blV6.insert(bytes: ip.bytes, prefixLength: 128, value: true)
                }
                ipCount += 1
            }
        }
        self.threatIPsV4 = blV4
        self.threatIPsV6 = blV6
        self.hasThreatIPs = ipCount > 0

        var v4 = BitTrie<Int>()
        var v6 = BitTrie<Int>()

        for (index, rule) in rules.enumerated() {
            switch rule.target {
            case .domain(let raw):
                let normalized = DomainName.normalize(raw)
                if normalized.hasPrefix("*.") {
                    let suffix = String(normalized.dropFirst(2))
                    wildcardDomainRules[suffix, default: []].append(index)
                } else {
                    exactDomainRules[normalized, default: []].append(index)
                }
            case .ip(let raw):
                if let ip = IPAddress.parse(raw) {
                    let bytes = ip.bytes
                    if ip.isV4 {
                        v4.insert(bytes: bytes, prefixLength: 32, value: index)
                    } else {
                        v6.insert(bytes: bytes, prefixLength: 128, value: index)
                    }
                }
            case .cidr(let raw):
                if let block = CIDRBlock(raw) {
                    let bytes = block.address.bytes
                    if block.address.isV4 {
                        v4.insert(bytes: bytes, prefixLength: block.prefixLength, value: index)
                    } else {
                        v6.insert(bytes: bytes, prefixLength: block.prefixLength, value: index)
                    }
                }
            case .port(let range):
                portRules.append((range, index))
            case .network(let protocolNumber, let port):
                networkRules.append((protocolNumber, port, index))
            }
        }
        self.ipRulesV4 = v4
        self.ipRulesV6 = v6
    }

    /// Matching order: among matching user rules the highest priority wins and
    /// allow beats deny on a tie; then the blocklists; then the mode or profile
    /// default passed in by the caller.
    public func evaluate(_ flow: FlowDescriptor, mode: RunMode, profileDefault: RuleAction = .allow) -> Verdict {
        var candidates: [Int] = []

        if let rawDomain = flow.domain {
            let host = DomainName.normalize(rawDomain)
            candidates.append(contentsOf: exactDomainRules[host] ?? [])
            for parent in DomainName.parentDomains(of: host) {
                candidates.append(contentsOf: wildcardDomainRules[parent] ?? [])
            }
        }
        if let ip = flow.ip {
            let trie = ip.isV4 ? ipRulesV4 : ipRulesV6
            candidates.append(contentsOf: trie.coveringValues(bytes: ip.bytes))
        }
        if let port = flow.port {
            candidates.append(contentsOf: portRules.filter { $0.range.contains(port) }.map(\.index))
        }
        if let proto = flow.protocolNumber {
            for entry in networkRules where entry.protocolNumber == proto {
                if let required = entry.port {
                    guard let port = flow.port, required.contains(port) else { continue }
                }
                candidates.append(entry.index)
            }
        }

        var winner: Rule?
        for index in candidates {
            let rule = rules[index]
            guard rule.isActive(at: flow.timestamp, profileID: flow.profileID) else { continue }
            guard let current = winner else {
                winner = rule
                continue
            }
            if rule.priority > current.priority ||
                (rule.priority == current.priority && rule.action == .allow && current.action == .deny) {
                winner = rule
            }
        }
        if let winner {
            return Verdict(action: winner.action, matchedRuleID: winner.id, source: .userRule)
        }

        if mode != .pause, let rawDomain = flow.domain {
            let host = DomainName.normalize(rawDomain)
            let parents = DomainName.parentDomains(of: host)
            // A name on both an ad list and a threat feed is reported as a threat.
            if threatDomains.contains(host) || parents.contains(where: threatDomains.contains) {
                return Verdict(action: .deny, matchedRuleID: nil, source: .threatFeed)
            }
            if blocklistDomains.contains(host) || parents.contains(where: blocklistDomains.contains) {
                return Verdict(action: .deny, matchedRuleID: nil, source: .blocklist)
            }
        }

        if mode != .pause, hasThreatIPs, let ip = flow.ip {
            let trie = ip.isV4 ? threatIPsV4 : threatIPsV6
            if !trie.coveringValues(bytes: ip.bytes).isEmpty {
                return Verdict(action: .deny, matchedRuleID: nil, source: .threatFeed)
            }
        }

        return Verdict(
            action: mode.defaultAction(profileDefault: profileDefault),
            matchedRuleID: nil,
            source: .modeDefault
        )
    }
}
