import Foundation

public enum RuleAction: String, Codable, Sendable, Hashable {
    case allow
    case deny
}

/// What a rule matches against. Domain wildcards use the `*.example.com`
/// convention: the wildcard form matches subdomains only, the bare form
/// matches the exact host only. Create both rules to cover a whole site.
public enum RuleTarget: Codable, Sendable, Hashable {
    case domain(String)
    case ip(String)
    case cidr(String)
    case port(ClosedRange<UInt16>)
    case network(protocolNumber: UInt8, port: ClosedRange<UInt16>?)
}

public struct Rule: Codable, Identifiable, Sendable, Hashable {
    public var id: UUID
    public var action: RuleAction
    public var target: RuleTarget
    /// nil means the rule applies in every profile.
    public var profileID: UUID?
    /// Higher wins. On a tie, allow wins over deny.
    public var priority: Int
    public var enabled: Bool
    public var expiresAt: Date?
    public var note: String?
    public var createdAt: Date

    public init(
        id: UUID = UUID(),
        action: RuleAction,
        target: RuleTarget,
        profileID: UUID? = nil,
        priority: Int = 0,
        enabled: Bool = true,
        expiresAt: Date? = nil,
        note: String? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.action = action
        self.target = target
        self.profileID = profileID
        self.priority = priority
        self.enabled = enabled
        self.expiresAt = expiresAt
        self.note = note
        self.createdAt = createdAt
    }

    public func isActive(at date: Date, profileID activeProfile: UUID?) -> Bool {
        guard enabled else { return false }
        if let expiresAt, expiresAt <= date { return false }
        if let profileID, profileID != activeProfile { return false }
        return true
    }
}

extension RuleTarget {
    /// Priority of a user rule, derived only from the shape of its target, so a
    /// more specific rule always outranks a broader one (a block on one host
    /// beats an allow on the whole site).
    ///
    ///   12  one host or one address
    ///   10  a whole site or network range
    ///    8  compiled from a country policy (app side, `CountryPolicy`)
    ///    5  a port or protocol, which matches every destination
    ///
    /// User rules never get 8; that level is reserved for rules compiled from
    /// country policies. The switch has no `default` so new target kinds must
    /// choose a level explicitly.
    public var derivedPriority: Int {
        switch self {
        case .domain(let raw):
            DomainName.normalize(raw).hasPrefix("*.") ? Self.siteWidePriority : Self.exactPriority
        case .ip:
            Self.exactPriority
        case .cidr:
            Self.siteWidePriority
        case .port, .network:
            Self.broadPriority
        }
    }

    /// One host or one address.
    public static let exactPriority = 12
    /// A whole site or network range.
    public static let siteWidePriority = 10
    /// A port or protocol. It matches every destination, so it ranks lowest.
    public static let broadPriority = 5
}

extension Rule {
    /// The same rule with its priority reset to `derivedPriority`.
    public var leveled: Rule {
        var copy = self
        copy.priority = target.derivedPriority
        return copy
    }

    /// Resets every rule's priority to `derivedPriority` and returns how many
    /// changed. Rules can arrive with other values (iCloud sync from an older
    /// build, `.lsrules` imports, restored backups), so this runs at launch.
    /// Idempotent: returns 0 when nothing needs changing.
    public static func relevelAll(_ rules: inout [Rule]) -> Int {
        var moved = 0
        for index in rules.indices {
            let wanted = rules[index].target.derivedPriority
            guard rules[index].priority != wanted else { continue }
            rules[index].priority = wanted
            moved += 1
        }
        return moved
    }
}
