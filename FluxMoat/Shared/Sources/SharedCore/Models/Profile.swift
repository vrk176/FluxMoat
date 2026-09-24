import Foundation

/// Tunnel run mode. Modes are global and independent of profiles.
public enum RunMode: String, Codable, Sendable, CaseIterable {
    /// Retired: no longer shown in the UI and decoded as `.standard`. It behaved
    /// exactly like Standard. The case stays for now so older devices syncing
    /// "learning" through iCloud still decode.
    case learning
    /// Allow unmatched connections; blocklists still deny.
    case standard
    /// Apply the profile's default action immediately and post a notification
    /// the user can answer later (an async take on Little Snitch's Alert Mode).
    case ask
    /// Deny unmatched connections.
    case strict
    /// Retired, same as `.learning`, and decoded as `.standard`. To stop
    /// filtering, use the protection switch.
    case pause

    /// Action for a connection no rule or blocklist matched.
    public func defaultAction(profileDefault: RuleAction) -> RuleAction {
        switch self {
        case .learning, .standard, .pause: .allow
        case .strict: .deny
        case .ask: profileDefault
        }
    }

    /// Maps a stored mode to a current one. Retired modes become `.standard`.
    public static func normalized(_ mode: RunMode) -> RunMode {
        switch mode {
        case .standard, .ask, .strict: mode
        case .learning, .pause: .standard
        }
    }

    /// Tolerant decode. `SyncedSettings.mode` is non-optional, so an unknown raw
    /// value would fail the whole settings section. Unknown or retired values
    /// (from older devices or snapshots) decode as `.standard`.
    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = RunMode(rawValue: raw).map(RunMode.normalized) ?? .standard
    }
}

public struct Profile: Codable, Identifiable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable, CaseIterable {
        case home
        case publicNetwork
        /// Retired: it behaved exactly like Home. Kept because stored Wi-Fi
        /// assignments and snapshots may still contain the raw value; read paths
        /// map it through `normalizedKind`.
        case lowData
        /// Reserved for user-made profiles. Nothing constructs one yet.
        case custom
    }

    public var id: UUID
    public var name: String
    public var kind: Kind
    /// Default action Ask mode falls back to for unmatched connections.
    public var unmatchedAction: RuleAction
    public var isBuiltIn: Bool

    public init(
        id: UUID = UUID(),
        name: String,
        kind: Kind,
        unmatchedAction: RuleAction = .allow,
        isBuiltIn: Bool = false
    ) {
        self.id = id
        self.name = name
        self.kind = kind
        self.unmatchedAction = unmatchedAction
        self.isBuiltIn = isBuiltIn
    }

    /// The built-in profiles, in display order.
    ///
    /// Their ids are fixed so the active profile and profile-scoped rules
    /// (`profileID`) still match across launches.
    public static let builtIns: [Profile] = [
        Profile(
            id: UUID(uuidString: "F10C0A70-0001-4000-8000-50524F464C01")!,
            name: "Home",
            kind: .home,
            isBuiltIn: true),
        Profile(
            id: UUID(uuidString: "F10C0A70-0002-4000-8000-50524F464C02")!,
            name: "Public",
            kind: .publicNetwork,
            unmatchedAction: .deny,
            isBuiltIn: true),
    ]

    /// The built-in profile of this kind, or nil when there isn't one
    /// (`.lowData` is retired, `.custom` isn't implemented yet).
    public static func builtIn(_ kind: Kind) -> Profile? {
        builtIns.first { $0.kind == kind }
    }

    /// Maps a stored profile kind to a current one. `.lowData` becomes Home
    /// (it behaved the same), and so does `.custom`, since nothing creates one
    /// yet and the picker must point at a profile in the list.
    public static func normalizedKind(_ kind: Kind) -> Kind {
        switch kind {
        case .home, .publicNetwork: kind
        case .lowData, .custom: .home
        }
    }
}
