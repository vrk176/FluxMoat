import Foundation

// iCloud config sync through the user's private CloudKit database, so rules
// and settings match across devices. Only user config syncs; traffic
// history and credentials (such as the abuse.ch key) never leave the device.
// Sync is opt-in and off by default.
//
// Merging: per-rule last-writer-wins on a sync-layer timestamp, deletions
// kept as tombstones so a stale device can't bring a rule back, and whole
// sections (settings, Wi-Fi, blocklists) merged by section timestamp.
// Timestamps live in this layer so `Rule` itself stays unchanged.

/// A rule plus its sync-layer last-modified time. The timestamp is set by
/// the device that noticed the change (by diffing against its last synced
/// state), not by the rule editor. See `CloudSyncService`.
public struct SyncedRule: Codable, Sendable, Equatable {
    public var rule: Rule
    public var updatedAt: Date

    public init(rule: Rule, updatedAt: Date) {
        self.rule = rule
        self.updatedAt = updatedAt
    }
}

/// Deletion marker: keeps a deleted rule dead when an offline device later
/// uploads a copy predating the deletion.
public struct RuleTombstone: Codable, Sendable, Equatable {
    public var id: UUID
    public var deletedAt: Date

    public init(id: UUID, deletedAt: Date) {
        self.id = id
        self.deletedAt = deletedAt
    }
}

/// Scalar settings, merged as a whole (newer section wins). These change
/// rarely, so per-field merging isn't worth it.
public struct SyncedSettings: Codable, Sendable, Equatable {
    public var mode: RunMode
    public var dohServerURL: String?
    public var blockEncryptedDNS: Bool
    public var historyRetention: RetentionPeriod
    public var askQuietHours: QuietHours?
    /// Active profile, by kind. Synced with the mode because the profile decides
    /// what Ask mode does with unmatched flows. Optional so documents written
    /// before this field still decode; nil means the other device didn't set it.
    public var activeProfileKind: Profile.Kind?
    public var updatedAt: Date

    public init(
        mode: RunMode,
        dohServerURL: String?,
        blockEncryptedDNS: Bool,
        historyRetention: RetentionPeriod,
        askQuietHours: QuietHours?,
        activeProfileKind: Profile.Kind? = nil,
        updatedAt: Date
    ) {
        self.mode = mode
        self.dohServerURL = dohServerURL
        self.blockEncryptedDNS = blockEncryptedDNS
        self.historyRetention = historyRetention
        self.askQuietHours = askQuietHours
        self.activeProfileKind = activeProfileKind
        self.updatedAt = updatedAt
    }
}

public struct SyncedWiFiProfiles: Codable, Sendable, Equatable {
    public var assignments: [WiFiProfileAssignment]
    public var updatedAt: Date

    public init(assignments: [WiFiProfileAssignment], updatedAt: Date) {
        self.assignments = assignments
        self.updatedAt = updatedAt
    }
}

/// Blocklist subscription metadata and manual domains. Downloaded list
/// content doesn't sync (it can be large and re-downloaded), and
/// device-local fields (etag, hit counts, errors) stay local.
public struct SyncedBlocklistSource: Codable, Sendable, Equatable {
    public var id: UUID
    public var name: String
    public var sourceURL: URL?
    public var format: BlocklistSource.Format
    public var category: BlocklistSource.Category?
    public var enabled: Bool

    public init(from source: BlocklistSource) {
        self.id = source.id
        self.name = source.name
        self.sourceURL = source.sourceURL
        self.format = source.format
        self.category = source.category
        self.enabled = source.enabled
    }
}

public struct SyncedBlocklist: Codable, Sendable, Equatable {
    public var manualDomains: [String]
    public var sources: [SyncedBlocklistSource]
    public var updatedAt: Date

    public init(manualDomains: [String], sources: [SyncedBlocklistSource], updatedAt: Date) {
        self.manualDomains = manualDomains
        self.sources = sources
        self.updatedAt = updatedAt
    }
}

/// The full synced document, stored as JSON in one CKRecord. Well under the
/// 1 MB record limit for realistic rule counts, since list content isn't
/// included.
public struct SyncedConfig: Codable, Sendable, Equatable {
    public static let currentSchemaVersion = 1

    public var schemaVersion: Int
    public var rules: [SyncedRule]
    public var tombstones: [RuleTombstone]
    public var settings: SyncedSettings
    public var wifi: SyncedWiFiProfiles
    public var blocklist: SyncedBlocklist

    public init(
        schemaVersion: Int = SyncedConfig.currentSchemaVersion,
        rules: [SyncedRule],
        tombstones: [RuleTombstone],
        settings: SyncedSettings,
        wifi: SyncedWiFiProfiles,
        blocklist: SyncedBlocklist
    ) {
        self.schemaVersion = schemaVersion
        self.rules = rules
        self.tombstones = tombstones
        self.settings = settings
        self.wifi = wifi
        self.blocklist = blocklist
    }

    public func serialized() throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    public static func deserialized(_ data: Data) throws -> SyncedConfig {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let config = try decoder.decode(SyncedConfig.self, from: data)
        guard config.schemaVersion <= currentSchemaVersion else {
            throw SyncError.newerSchema(config.schemaVersion)
        }
        return config
    }
}

public enum SyncError: Error, Equatable {
    /// The cloud copy was written by a newer app version. Merging is refused
    /// because rewriting it would drop fields this version doesn't know about.
    case newerSchema(Int)
}

public enum SyncMerge {
    /// How long a tombstone is kept after a deletion. A device offline for
    /// longer can bring a deleted rule back; the Settings footer explains this.
    public static let tombstoneLifetime: TimeInterval = 30 * 24 * 3600

    /// Deterministic, commutative, idempotent merge of two configs.
    ///
    /// - Rules: the newer `updatedAt` wins per id. A tombstone at least as new
    ///   as the rule deletes it (deletes win ties).
    /// - Tombstones: union by id keeping the newest time, dropped after
    ///   `tombstoneLifetime` relative to `now`.
    /// - Sections: the newer `updatedAt` wins as a whole. Ties are broken by
    ///   comparing encoded bytes so both devices end up identical.
    public static func merge(_ a: SyncedConfig, _ b: SyncedConfig, now: Date = Date()) -> SyncedConfig {
        // Tombstones: union keeping the newest time per id, minus expired ones.
        var tombstoneByID: [UUID: Date] = [:]
        for t in a.tombstones + b.tombstones {
            tombstoneByID[t.id] = max(tombstoneByID[t.id] ?? .distantPast, t.deletedAt)
        }
        tombstoneByID = tombstoneByID.filter { now.timeIntervalSince($0.value) < tombstoneLifetime }

        // Rules: newest per id, then tombstone check (delete wins ties).
        var ruleByID: [UUID: SyncedRule] = [:]
        for r in a.rules + b.rules {
            if let existing = ruleByID[r.rule.id] {
                if r.updatedAt > existing.updatedAt { ruleByID[r.rule.id] = r }
                else if r.updatedAt == existing.updatedAt, existing != r {
                    // Same time, different content (edited on two devices at once): pick by
                    // encoded bytes so both sides converge.
                    ruleByID[r.rule.id] = deterministicPick(existing, r)
                }
            } else {
                ruleByID[r.rule.id] = r
            }
        }
        for (id, deletedAt) in tombstoneByID {
            if let rule = ruleByID[id], rule.updatedAt <= deletedAt {
                ruleByID.removeValue(forKey: id)
            }
        }

        let mergedRules = ruleByID.values.sorted { $0.rule.id.uuidString < $1.rule.id.uuidString }
        let mergedTombstones = tombstoneByID
            .map { RuleTombstone(id: $0.key, deletedAt: $0.value) }
            .sorted { $0.id.uuidString < $1.id.uuidString }

        return SyncedConfig(
            rules: mergedRules,
            tombstones: mergedTombstones,
            settings: newerSection(a.settings, b.settings, stamp: \.updatedAt),
            wifi: newerSection(a.wifi, b.wifi, stamp: \.updatedAt),
            blocklist: newerSection(a.blocklist, b.blocklist, stamp: \.updatedAt)
        )
    }

    private static func newerSection<S: Codable & Equatable>(
        _ a: S, _ b: S, stamp: KeyPath<S, Date>
    ) -> S {
        if a[keyPath: stamp] != b[keyPath: stamp] {
            return a[keyPath: stamp] > b[keyPath: stamp] ? a : b
        }
        return a == b ? a : deterministicPick(a, b)
    }

    /// Turns the device's current local state into a timestamped config by
    /// diffing against the last synced state (`previous`):
    ///
    /// - unchanged rule or section: keeps the previous timestamp
    /// - changed: stamped `now`
    /// - in `previous` but gone locally: tombstone at `now`
    /// - `previous == nil` (first sync on this device): rules use their
    ///   `createdAt` and sections `.distantPast`, so existing cloud state wins
    ///   over a fresh install's defaults.
    public static func stampedLocal(
        rules: [Rule],
        settings: SyncedSettings,
        wifi: SyncedWiFiProfiles,
        blocklist: SyncedBlocklist,
        previous: SyncedConfig?,
        now: Date = Date()
    ) -> SyncedConfig {
        let previousRuleByID = Dictionary(
            uniqueKeysWithValues: (previous?.rules ?? []).map { ($0.rule.id, $0) })

        let stampedRules = rules.map { rule -> SyncedRule in
            if let prev = previousRuleByID[rule.id] {
                return prev.rule == rule ? prev : SyncedRule(rule: rule, updatedAt: now)
            }
            return SyncedRule(rule: rule, updatedAt: previous == nil ? rule.createdAt : now)
        }

        let currentIDs = Set(rules.map(\.id))
        var tombstones = previous?.tombstones ?? []
        for prev in previous?.rules ?? [] where !currentIDs.contains(prev.rule.id) {
            tombstones.append(RuleTombstone(id: prev.rule.id, deletedAt: now))
        }

        var stampedSettings = settings
        var stampedWiFi = wifi
        var stampedBlocklist = blocklist
        if let previous {
            stampedSettings.updatedAt = contentEqual(settings, previous.settings, neutralize: { $0.updatedAt = .distantPast })
                ? previous.settings.updatedAt : now
            stampedWiFi.updatedAt = contentEqual(wifi, previous.wifi, neutralize: { $0.updatedAt = .distantPast })
                ? previous.wifi.updatedAt : now
            stampedBlocklist.updatedAt = contentEqual(blocklist, previous.blocklist, neutralize: { $0.updatedAt = .distantPast })
                ? previous.blocklist.updatedAt : now
        } else {
            stampedSettings.updatedAt = .distantPast
            stampedWiFi.updatedAt = .distantPast
            stampedBlocklist.updatedAt = .distantPast
        }

        return SyncedConfig(
            rules: stampedRules,
            tombstones: tombstones,
            settings: stampedSettings,
            wifi: stampedWiFi,
            blocklist: stampedBlocklist
        )
    }

    private static func contentEqual<S: Equatable>(
        _ a: S, _ b: S, neutralize: (inout S) -> Void
    ) -> Bool {
        var a = a, b = b
        neutralize(&a)
        neutralize(&b)
        return a == b
    }

    /// Equal timestamps with different content. Comparing encoded bytes is
    /// arbitrary but symmetric, so both devices pick the same value.
    private static func deterministicPick<V: Codable>(_ a: V, _ b: V) -> V {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        let aData = (try? encoder.encode(a)) ?? Data()
        let bData = (try? encoder.encode(b)) ?? Data()
        return aData.base64EncodedString() <= bData.base64EncodedString() ? a : b
    }
}
