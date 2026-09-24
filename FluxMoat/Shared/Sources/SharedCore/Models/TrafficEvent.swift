import Foundation

/// One observed flow, aggregated by the tunnel.
/// Never contains payload, HTTP bodies, user input, or credentials.
public struct TrafficEvent: Codable, Identifiable, Sendable, Hashable {
    public enum NetworkType: String, Codable, Sendable {
        case wifi
        case cellular
        case wired
        case other
    }

    /// What decided the verdict. Stored so history can separate threat blocks
    /// (filtering resolver, threat feeds) from ad/tracker blocks and user rules.
    public enum VerdictSource: String, Codable, Sendable {
        case userRule
        case blocklist
        case modeDefault
        /// The upstream filtering DoH resolver blocked the name.
        case filteringResolver
        /// Matched a local threat-intel feed.
        case threatFeed
        /// A resolver we can't vouch for blocked the name: a custom endpoint, or a
        /// preset that filters ads rather than threats. Counted as a plain block,
        /// never as a threat. Raw values are persisted, so new cases go at the end.
        case customResolver

        public init(_ source: Verdict.Source) {
            switch source {
            case .userRule: self = .userRule
            case .blocklist: self = .blocklist
            case .modeDefault: self = .modeDefault
            case .filteringResolver: self = .filteringResolver
            case .threatFeed: self = .threatFeed
            }
        }
    }

    public var id: UUID
    public var timestamp: Date
    public var remoteIP: String
    /// Only present when the tunnel correlated the IP via a recent DNS answer.
    public var domain: String?
    public var remotePort: UInt16?
    public var protocolNumber: UInt8
    public var bytesUp: UInt64
    public var bytesDown: UInt64
    public var verdict: RuleAction
    /// Nil on events persisted before the field existed.
    public var verdictSource: VerdictSource?
    public var matchedRuleID: UUID?
    public var profileID: UUID?
    public var countryCode: String?
    public var networkType: NetworkType
    /// Best-guess domain for a flow with no name: the domain our resolver
    /// recently resolved to this IP. It is inferred, so the UI shows it
    /// differently from `domain`, and it must never affect verdicts.
    /// nil on events persisted before the field existed.
    public var inferredDomain: String?

    public init(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        remoteIP: String,
        domain: String? = nil,
        remotePort: UInt16? = nil,
        protocolNumber: UInt8,
        bytesUp: UInt64 = 0,
        bytesDown: UInt64 = 0,
        verdict: RuleAction,
        verdictSource: VerdictSource? = nil,
        matchedRuleID: UUID? = nil,
        profileID: UUID? = nil,
        countryCode: String? = nil,
        networkType: NetworkType = .other,
        inferredDomain: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.remoteIP = remoteIP
        self.domain = domain
        self.remotePort = remotePort
        self.protocolNumber = protocolNumber
        self.bytesUp = bytesUp
        self.bytesDown = bytesDown
        self.verdict = verdict
        self.verdictSource = verdictSource
        self.matchedRuleID = matchedRuleID
        self.profileID = profileID
        self.countryCode = countryCode
        self.networkType = networkType
        self.inferredDomain = inferredDomain
    }
}
