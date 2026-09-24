import Foundation
import Testing
@testable import SharedCore

@Suite struct SyncMergeTests {
    private let t0 = Date(timeIntervalSince1970: 1_700_000_000)
    private var t1: Date { t0.addingTimeInterval(60) }
    private var t2: Date { t0.addingTimeInterval(120) }
    private var now: Date { t0.addingTimeInterval(3600) }

    private func settings(updatedAt: Date) -> SyncedSettings {
        SyncedSettings(
            mode: .standard, dohServerURL: nil, blockEncryptedDNS: false,
            historyRetention: .default, askQuietHours: nil, updatedAt: updatedAt)
    }

    private func config(
        rules: [SyncedRule] = [],
        tombstones: [RuleTombstone] = [],
        settings: SyncedSettings? = nil,
        wifi: SyncedWiFiProfiles? = nil,
        blocklist: SyncedBlocklist? = nil
    ) -> SyncedConfig {
        SyncedConfig(
            rules: rules,
            tombstones: tombstones,
            settings: settings ?? self.settings(updatedAt: t0),
            wifi: wifi ?? SyncedWiFiProfiles(assignments: [], updatedAt: t0),
            blocklist: blocklist ?? SyncedBlocklist(manualDomains: [], sources: [], updatedAt: t0))
    }

    // MARK: rules

    @Test func newerRuleEditWins() {
        let id = UUID()
        let old = SyncedRule(rule: Rule(id: id, action: .allow, target: .domain("a.example")), updatedAt: t1)
        let new = SyncedRule(rule: Rule(id: id, action: .deny, target: .domain("a.example")), updatedAt: t2)
        let merged = SyncMerge.merge(config(rules: [old]), config(rules: [new]), now: now)
        #expect(merged.rules.count == 1)
        #expect(merged.rules[0].rule.action == .deny)
    }

    @Test func disjointRulesUnion() {
        let a = SyncedRule(rule: Rule(action: .deny, target: .domain("a.example")), updatedAt: t1)
        let b = SyncedRule(rule: Rule(action: .deny, target: .domain("b.example")), updatedAt: t1)
        let merged = SyncMerge.merge(config(rules: [a]), config(rules: [b]), now: now)
        #expect(merged.rules.count == 2)
    }

    /// Regression: a stale device uploading a copy that predates the
    /// deletion must not resurrect the rule.
    @Test func tombstoneBeatsStaleRule() {
        let id = UUID()
        let stale = SyncedRule(rule: Rule(id: id, action: .deny, target: .domain("x.example")), updatedAt: t1)
        let deleted = config(tombstones: [RuleTombstone(id: id, deletedAt: t2)])
        let merged = SyncMerge.merge(config(rules: [stale]), deleted, now: now)
        #expect(merged.rules.isEmpty)
        #expect(merged.tombstones.count == 1)
    }

    /// An edit NEWER than the deletion revives the rule (the user re-created
    /// or re-edited it after some device deleted it).
    @Test func newerEditBeatsTombstone() {
        let id = UUID()
        let edited = SyncedRule(rule: Rule(id: id, action: .allow, target: .domain("x.example")), updatedAt: t2)
        let deleted = config(tombstones: [RuleTombstone(id: id, deletedAt: t1)])
        let merged = SyncMerge.merge(config(rules: [edited]), deleted, now: now)
        #expect(merged.rules.count == 1)
    }

    /// Tie between edit and delete resolves to delete (resurrecting a
    /// deliberately deleted rule is the worse failure).
    @Test func deleteWinsTies() {
        let id = UUID()
        let edited = SyncedRule(rule: Rule(id: id, action: .allow, target: .domain("x.example")), updatedAt: t1)
        let deleted = config(tombstones: [RuleTombstone(id: id, deletedAt: t1)])
        let merged = SyncMerge.merge(config(rules: [edited]), deleted, now: now)
        #expect(merged.rules.isEmpty)
    }

    @Test func tombstonesExpireAfterLifetime() {
        let old = RuleTombstone(id: UUID(), deletedAt: t0)
        let merged = SyncMerge.merge(
            config(tombstones: [old]), config(),
            now: t0.addingTimeInterval(SyncMerge.tombstoneLifetime + 1))
        #expect(merged.tombstones.isEmpty)
    }

    // MARK: sections

    @Test func newerSettingsSectionWinsWholesale() {
        var newer = settings(updatedAt: t2)
        newer.mode = .strict
        newer.blockEncryptedDNS = true
        let merged = SyncMerge.merge(
            config(settings: settings(updatedAt: t1)), config(settings: newer), now: now)
        #expect(merged.settings.mode == .strict)
        #expect(merged.settings.blockEncryptedDNS == true)
    }

    @Test func newerWiFiSectionWins() {
        let newer = SyncedWiFiProfiles(
            assignments: [WiFiProfileAssignment(ssid: "Cafe", profileKind: .publicNetwork, unmatchedAction: .deny)],
            updatedAt: t2)
        let merged = SyncMerge.merge(
            config(wifi: SyncedWiFiProfiles(assignments: [], updatedAt: t1)),
            config(wifi: newer), now: now)
        #expect(merged.wifi.assignments.count == 1)
    }

    // MARK: algebraic properties (convergence requires them)

    @Test func mergeIsCommutative() {
        let id = UUID()
        let a = config(
            rules: [SyncedRule(rule: Rule(id: id, action: .allow, target: .domain("x.example")), updatedAt: t1)],
            settings: settings(updatedAt: t2))
        let b = config(
            rules: [SyncedRule(rule: Rule(action: .deny, target: .domain("y.example")), updatedAt: t1)],
            tombstones: [RuleTombstone(id: id, deletedAt: t2)])
        #expect(SyncMerge.merge(a, b, now: now) == SyncMerge.merge(b, a, now: now))
    }

    @Test func mergeIsIdempotent() {
        let a = config(
            rules: [SyncedRule(rule: Rule(action: .deny, target: .domain("x.example")), updatedAt: t1)],
            tombstones: [RuleTombstone(id: UUID(), deletedAt: t1)])
        let once = SyncMerge.merge(a, a, now: now)
        #expect(SyncMerge.merge(once, once, now: now) == once)
    }

    /// Same stamp, different content on both sides (simultaneous edit):
    /// both merge orders must converge on the same winner.
    @Test func simultaneousEditConvergesDeterministically() {
        let id = UUID()
        let a = config(rules: [SyncedRule(rule: Rule(id: id, action: .allow, target: .domain("x.example")), updatedAt: t1)])
        let b = config(rules: [SyncedRule(rule: Rule(id: id, action: .deny, target: .domain("x.example")), updatedAt: t1)])
        let ab = SyncMerge.merge(a, b, now: now)
        let ba = SyncMerge.merge(b, a, now: now)
        #expect(ab == ba)
        #expect(ab.rules.count == 1)
    }

    // MARK: stampedLocal (diff against last-synced state)

    @Test func unchangedRuleKeepsPreviousStamp() {
        let rule = Rule(action: .deny, target: .domain("x.example"))
        let previous = config(rules: [SyncedRule(rule: rule, updatedAt: t1)])
        let stamped = SyncMerge.stampedLocal(
            rules: [rule], settings: settings(updatedAt: t1),
            wifi: previous.wifi, blocklist: previous.blocklist,
            previous: previous, now: now)
        #expect(stamped.rules[0].updatedAt == t1)
    }

    @Test func editedRuleStampedNow() {
        var rule = Rule(action: .deny, target: .domain("x.example"))
        let previous = config(rules: [SyncedRule(rule: rule, updatedAt: t1)])
        rule.enabled = false
        let stamped = SyncMerge.stampedLocal(
            rules: [rule], settings: settings(updatedAt: t1),
            wifi: previous.wifi, blocklist: previous.blocklist,
            previous: previous, now: now)
        #expect(stamped.rules[0].updatedAt == now)
    }

    @Test func locallyDeletedRuleBecomesTombstone() {
        let rule = Rule(action: .deny, target: .domain("x.example"))
        let previous = config(rules: [SyncedRule(rule: rule, updatedAt: t1)])
        let stamped = SyncMerge.stampedLocal(
            rules: [], settings: settings(updatedAt: t1),
            wifi: previous.wifi, blocklist: previous.blocklist,
            previous: previous, now: now)
        #expect(stamped.rules.isEmpty)
        #expect(stamped.tombstones == [RuleTombstone(id: rule.id, deletedAt: now)])
    }

    /// First sync on a fresh install must not clobber existing cloud state:
    /// rules fall back to createdAt, sections to .distantPast.
    @Test func firstSyncYieldsConservativeStamps() {
        let rule = Rule(action: .deny, target: .domain("x.example"), createdAt: t0)
        let stamped = SyncMerge.stampedLocal(
            rules: [rule], settings: settings(updatedAt: now),
            wifi: SyncedWiFiProfiles(assignments: [], updatedAt: now),
            blocklist: SyncedBlocklist(manualDomains: [], sources: [], updatedAt: now),
            previous: nil, now: now)
        #expect(stamped.rules[0].updatedAt == t0)
        #expect(stamped.settings.updatedAt == .distantPast)

        // ...so cloud settings (any real stamp) win the merge.
        var cloudSettings = settings(updatedAt: t1)
        cloudSettings.mode = .ask
        let merged = SyncMerge.merge(stamped, config(settings: cloudSettings), now: now)
        #expect(merged.settings.mode == .ask)
    }

    @Test func changedSettingsSectionStampedNow() {
        let previous = config(settings: settings(updatedAt: t1))
        var changed = settings(updatedAt: t1)
        changed.mode = .strict
        let stamped = SyncMerge.stampedLocal(
            rules: [], settings: changed,
            wifi: previous.wifi, blocklist: previous.blocklist,
            previous: previous, now: now)
        #expect(stamped.settings.updatedAt == now)
        #expect(stamped.settings.mode == .strict)
    }

    // MARK: reset-all (AppModel.resetAllConfiguration's cloud half)

    /// An emptied device that still holds its last-synced baseline stamps a
    /// tombstone for every rule that went, so merging against the cloud's
    /// untouched copy comes back empty rather than restoring it.
    @Test func resetPushesTombstonesRatherThanLosingToTheCloud() {
        let kept = Rule(action: .deny, target: .domain("a.example"))
        let alsoKept = Rule(action: .allow, target: .domain("b.example"))
        var populated = settings(updatedAt: t1)
        populated.dohServerURL = "https://dns.quad9.net/dns-query"
        let baseline = config(
            rules: [SyncedRule(rule: kept, updatedAt: t1), SyncedRule(rule: alsoKept, updatedAt: t1)],
            settings: populated,
            wifi: SyncedWiFiProfiles(
                assignments: [WiFiProfileAssignment(ssid: "Cafe", profileKind: .publicNetwork, unmatchedAction: .deny)],
                updatedAt: t1),
            blocklist: SyncedBlocklist(
                manualDomains: ["imported.example"],
                sources: [SyncedBlocklistSource(from: BlocklistSource(name: "L", format: .hosts))],
                updatedAt: t1))

        // The device right after reset: every ledger empty, baseline untouched.
        let stamped = SyncMerge.stampedLocal(
            rules: [],
            settings: settings(updatedAt: t1),
            wifi: SyncedWiFiProfiles(assignments: [], updatedAt: t1),
            blocklist: SyncedBlocklist(manualDomains: [], sources: [], updatedAt: t1),
            previous: baseline, now: now)

        #expect(stamped.rules.isEmpty)
        #expect(Set(stamped.tombstones.map(\.id)) == [kept.id, alsoKept.id])
        #expect(stamped.tombstones.allSatisfy { $0.deletedAt == now })
        #expect(stamped.settings.updatedAt == now)
        #expect(stamped.wifi.updatedAt == now)
        #expect(stamped.blocklist.updatedAt == now)

        // The cloud still holds everything. The empty side has to win.
        let merged = SyncMerge.merge(stamped, baseline, now: now)
        #expect(merged.rules.isEmpty)
        #expect(merged.settings.dohServerURL == nil)
        #expect(merged.wifi.assignments.isEmpty)
        #expect(merged.blocklist.manualDomains.isEmpty)
        #expect(merged.blocklist.sources.isEmpty)
    }

    /// With `previous == nil` the stamping is conservative: no tombstone is
    /// minted, and the cloud's copy wins the merge.
    @Test func resetWithoutBaselineLosesToTheCloud() {
        let rule = Rule(action: .deny, target: .domain("a.example"), createdAt: t0)
        let cloud = config(
            rules: [SyncedRule(rule: rule, updatedAt: t1)], settings: settings(updatedAt: t1))
        let stamped = SyncMerge.stampedLocal(
            rules: [], settings: settings(updatedAt: now),
            wifi: SyncedWiFiProfiles(assignments: [], updatedAt: now),
            blocklist: SyncedBlocklist(manualDomains: [], sources: [], updatedAt: now),
            previous: nil, now: now)
        #expect(stamped.tombstones.isEmpty)
        #expect(SyncMerge.merge(stamped, cloud, now: now).rules.count == 1)
    }

    // MARK: wire format

    @Test func configRoundTrips() throws {
        let original = config(
            // Whole-second createdAt: ISO8601 drops sub-second fractions,
            // and this test asserts byte-exact round-trip equality.
            rules: [SyncedRule(rule: Rule(action: .deny, target: .domain("x.example"), createdAt: t0), updatedAt: t1)],
            tombstones: [RuleTombstone(id: UUID(), deletedAt: t1)],
            blocklist: SyncedBlocklist(
                manualDomains: ["ads.example"],
                sources: [SyncedBlocklistSource(from: BlocklistSource(name: "L", format: .hosts))],
                updatedAt: t1))
        let back = try SyncedConfig.deserialized(original.serialized())
        // ISO8601 rounds to whole seconds; our fixed stamps are whole seconds.
        #expect(back == original)
    }

    @Test func newerSchemaIsRejected() throws {
        var future = config()
        future.schemaVersion = SyncedConfig.currentSchemaVersion + 1
        let data = try future.serialized()
        #expect(throws: SyncError.newerSchema(SyncedConfig.currentSchemaVersion + 1)) {
            _ = try SyncedConfig.deserialized(data)
        }
    }
}
