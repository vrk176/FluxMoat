import CryptoKit
import Foundation

/// The immutable rule snapshot the app writes into the App Group and the
/// tunnel loads. The tunnel keeps the last valid snapshot if a new one fails
/// to decode or its checksum doesn't match.
///
/// New fields are optional with a nil default. Synthesized Codable omits nil
/// keys, so older snapshots decode unchanged, newer ones stay readable by
/// older builds, and `schemaVersion` stays 1.
public struct RuleSnapshot: Codable, Sendable {
    public static let currentSchemaVersion = 1

    public var schemaVersion: Int
    public var createdAt: Date
    public var rules: [Rule]
    /// Ad/tracker blocklist domains. Threat-intel domains go in `threatDomains`
    /// so their hits are counted separately.
    public var blocklistDomains: [String]
    /// Threat-intel domains (URLhaus, OpenPhish and similar). A hit reports
    /// `source: .threatFeed`.
    public var threatDomains: [String]?
    /// Threat-intel IP/CIDR indicators (Feodo, Spamhaus DROP and similar) as
    /// canonical strings (`93.184.216.34`, `192.0.2.0/24`).
    public var threatIPs: [String]?
    /// Run mode the tunnel enforces. nil means `.standard`.
    public var mode: RunMode?
    /// The active profile's action for flows no rule matches. nil means
    /// `.allow`.
    public var profileDefault: RuleAction?
    /// Kind of the profile `profileDefault` came from, so the app can restore
    /// the picker on the next launch. nil means Home. The tunnel doesn't use
    /// it; the snapshot also serves as the app's settings store.
    public var activeProfileKind: Profile.Kind?
    /// DoH upstream for hostname resolution in the tunnel. nil means off
    /// (system resolution).
    public var dohServerURL: String?
    /// Blocks public encrypted-DNS resolvers so clients fall back to plaintext
    /// DNS, which the domain rules can see. nil or false means off (the
    /// default). The deny rules aren't stored here; `compile()` adds them so
    /// they never end up in the user's rule list.
    public var blockEncryptedDNS: Bool?
    /// How long the extension keeps flow history. nil means
    /// `RetentionPeriod.default`.
    public var historyRetention: RetentionPeriod?
    /// Local-time window in which Ask notifications stay silent. nil means no
    /// quiet hours.
    public var askQuietHours: QuietHours?
    /// Wi-Fi to profile automation rules, enforced in the tunnel. nil means no
    /// automation.
    public var wifiAutoProfiles: [WiFiProfileAssignment]?
    /// Whether resolver blocks from `dohServerURL` count as threats. True only
    /// for the built-in threat-intel presets (Quad9, Cloudflare Security); a
    /// custom endpoint is often just an ad blocker. Set by the app, which knows
    /// which preset the URL came from. nil means false.
    public var resolverThreatIntel: Bool?

    public init(
        rules: [Rule],
        blocklistDomains: [String] = [],
        threatDomains: [String]? = nil,
        threatIPs: [String]? = nil,
        createdAt: Date = Date(),
        mode: RunMode? = nil,
        profileDefault: RuleAction? = nil,
        activeProfileKind: Profile.Kind? = nil,
        dohServerURL: String? = nil,
        blockEncryptedDNS: Bool? = nil,
        historyRetention: RetentionPeriod? = nil,
        askQuietHours: QuietHours? = nil,
        wifiAutoProfiles: [WiFiProfileAssignment]? = nil,
        resolverThreatIntel: Bool? = nil
    ) {
        self.schemaVersion = Self.currentSchemaVersion
        self.createdAt = createdAt
        self.rules = rules
        self.blocklistDomains = blocklistDomains
        self.threatDomains = threatDomains
        self.threatIPs = threatIPs
        self.mode = mode
        self.profileDefault = profileDefault
        self.activeProfileKind = activeProfileKind
        self.dohServerURL = dohServerURL
        self.blockEncryptedDNS = blockEncryptedDNS
        self.historyRetention = historyRetention
        self.askQuietHours = askQuietHours
        self.wifiAutoProfiles = wifiAutoProfiles
        self.resolverThreatIntel = resolverThreatIntel
    }

    /// User rules plus, when `blockEncryptedDNS` is on, the encrypted-DNS deny
    /// rules. Adding them here keeps the user's rule list clean and keeps the
    /// exemption for `dohServerURL` next to where it is decided.
    public func compile() -> CompiledRuleSet {
        var effective = rules
        if blockEncryptedDNS == true {
            let upstreamHost = dohServerURL.flatMap { URL(string: $0)?.host }
            effective += EncryptedDNSBlocklist.rules(exemptingUpstreamHost: upstreamHost)
        }
        return CompiledRuleSet(
            rules: effective,
            blocklistDomains: blocklistDomains,
            threatDomains: threatDomains ?? [],
            threatIPs: threatIPs ?? []
        )
    }

    // MARK: Serialization with integrity check

    public struct DecodeError: Error, Sendable {
        public let reason: String
    }

    /// JSON payload followed by a trailing SHA-256 line, so a truncated or
    /// corrupted file is rejected instead of loading bad data.
    public func serialize() throws -> Data {
        try serializedWithChecksum().data
    }

    /// Also returns the hex digest so callers can log which snapshot they
    /// wrote.
    public func serializedWithChecksum() throws -> (data: Data, sha256: String) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        var data = try encoder.encode(self)
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        data.append(Data("\n#sha256=\(digest)".utf8))
        return (data, digest)
    }

    public static func deserialize(_ data: Data) throws -> RuleSnapshot {
        guard let separator = data.lastIndex(of: UInt8(ascii: "\n")) else {
            throw DecodeError(reason: "missing checksum line")
        }
        let payload = data[data.startIndex..<separator]
        let trailer = String(decoding: data[data.index(after: separator)...], as: UTF8.self)
        guard trailer.hasPrefix("#sha256=") else {
            throw DecodeError(reason: "missing checksum prefix")
        }
        let expected = String(trailer.dropFirst("#sha256=".count))
        let actual = SHA256.hash(data: Data(payload)).map { String(format: "%02x", $0) }.joined()
        guard expected == actual else {
            throw DecodeError(reason: "checksum mismatch")
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let snapshot = try decoder.decode(RuleSnapshot.self, from: Data(payload))
        guard snapshot.schemaVersion == currentSchemaVersion else {
            throw DecodeError(reason: "unsupported schema version \(snapshot.schemaVersion)")
        }
        return snapshot
    }
}
