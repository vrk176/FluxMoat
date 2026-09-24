import Foundation
import SharedCore

/// A user's standing "block this country" choice, kept on the app side only.
///
/// The tunnel has no GeoIP database (no room in the extension's memory budget),
/// and `RuleTarget` is encoded directly into the rule snapshot, so adding a
/// country case would break existing snapshots. Instead the app compiles each
/// policy into ordinary domain and IP rules for destinations seen from that
/// country, and keeps adding new ones as they appear.
///
/// Policies only block; see `derivedAction`.
struct CountryPolicy: Codable, Identifiable, Hashable, Sendable {
    var id: UUID
    /// Uppercased ISO 3166-1 alpha-2, matching `TrafficEvent.countryCode`.
    var countryCode: String
    var enabled: Bool
    var createdAt: Date
    var note: String?
    /// Destinations seen from this country since the policy was created (exact
    /// domains for named flows, addresses otherwise). Persisted because the
    /// in-memory recent-flow buffer only holds 200 flows.
    var derivedTargets: [RuleTarget]

    init(
        id: UUID = UUID(),
        countryCode: String,
        enabled: Bool = true,
        createdAt: Date = Date(),
        note: String? = nil,
        derivedTargets: [RuleTarget] = []
    ) {
        self.id = id
        self.countryCode = countryCode.uppercased()
        self.enabled = enabled
        self.createdAt = createdAt
        self.note = note
        self.derivedTargets = derivedTargets
    }

    /// Country rules only deny. A user-rule allow bypasses the threat feed and
    /// blocklist for every target it matches, so a country-wide allow would
    /// silently exempt every new destination from that country. Users can still
    /// allow a single destination, and that exact rule outranks this one.
    static let derivedAction = RuleAction.deny

    /// Priority of compiled country rules:
    ///
    ///   12  one host or one address (RuleTarget.exactPriority)
    ///   10  a whole site or network range (RuleTarget.siteWidePriority)
    ///    8  compiled from a country policy
    ///    5  a port or a protocol (RuleTarget.broadPriority)
    ///    0  profile default
    ///
    /// User rule priorities come from the target's shape and none maps to 8, so
    /// `isDerived` can't match a user's rule. A user's rule on a specific
    /// destination always wins; the engine resolves this per connection, so
    /// derived rules are emitted even for targets the user has a rule on.
    static let derivedPriority = 8

    /// Note prefix that marks compiled rules. The snapshot stores rules as one flat
    /// array, so launch uses this (plus the priority) to separate derived rules
    /// from the user's. The gear glyph keeps a user-typed note from colliding.
    static let derivedNotePrefix = "⚙ Country policy: "

    /// Prefix used by the previous release. Without it, old derived rules would be
    /// promoted into the user's Rules list on launch.
    // TODO: Remove, with its `isDerived` clause, once no snapshot can still hold it.
    static let legacyDerivedNotePrefix = "Country policy: "

    func derivedNote(countryName: String) -> String {
        Self.derivedNotePrefix + countryName
    }

    /// True if the rule was compiled from a policy rather than written by the user.
    static func isDerived(_ rule: Rule) -> Bool {
        guard rule.priority == derivedPriority, let note = rule.note else { return false }
        return note.hasPrefix(derivedNotePrefix) || note.hasPrefix(legacyDerivedNotePrefix)
    }
}

/// App-side JSON store for country policies (temp file plus atomic replace,
/// with file protection).
///
/// Not part of SharedCore or the rule snapshot because the tunnel only needs the
/// compiled rules. Not synced to iCloud yet: devices see different traffic, so
/// merging `derivedTargets` needs more than last-writer-wins.
struct CountryPolicyStore: Sendable {
    struct StoreError: Error, Sendable {
        let reason: String
    }

    let directoryURL: URL

    var policiesURL: URL { directoryURL.appendingPathComponent("countries.json") }

    init(directoryURL: URL) {
        self.directoryURL = directoryURL
    }

    static func appGroup() -> CountryPolicyStore? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: RuleSnapshotStore.appGroupID)
            .map { CountryPolicyStore(directoryURL: $0.appendingPathComponent("Countries", isDirectory: true)) }
    }

    /// Loaded policies plus the count dropped during migration, for the caller to log.
    struct LoadResult: Sendable {
        var policies: [CountryPolicy] = []
        var droppedAllowPolicies = 0
    }

    /// The old on-disk fields needed to find policies that had a direction.
    private struct LegacyDirection: Decodable {
        let id: UUID
        let action: String?
    }

    /// A missing file means a fresh install, not an error.
    ///
    /// Old allow policies are dropped. `CountryPolicy` no longer has an `action`,
    /// so a plain decode would turn a persisted allow into a block.
    func load() throws -> LoadResult {
        guard FileManager.default.fileExists(atPath: policiesURL.path) else { return LoadResult() }
        let data = try Data(contentsOf: policiesURL)
        let decoder = JSONDecoder()
        let stored = try decoder.decode([CountryPolicy].self, from: data)
        let legacy = (try? decoder.decode([LegacyDirection].self, from: data)) ?? []
        let allowIDs = Set(legacy.filter { $0.action == RuleAction.allow.rawValue }.map(\.id))
        guard !allowIDs.isEmpty else { return LoadResult(policies: stored) }
        return LoadResult(
            policies: stored.filter { !allowIDs.contains($0.id) },
            droppedAllowPolicies: allowIDs.count
        )
    }

    func save(_ policies: [CountryPolicy]) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try atomicWrite(try encoder.encode(policies), to: policiesURL)
    }

    private func atomicWrite(_ data: Data, to url: URL) throws {
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        let temp = directoryURL.appendingPathComponent("\(UUID().uuidString).tmp")
        try data.write(to: temp, options: [.atomic, .completeFileProtectionUnlessOpen])
        _ = try FileManager.default.replaceItemAt(url, withItemAt: temp)
    }
}
