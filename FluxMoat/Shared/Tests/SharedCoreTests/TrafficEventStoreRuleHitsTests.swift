import Foundation
import SQLite3
import Testing
@testable import SharedCore

/// Covers the two reads the Rules screen makes: the rollup that decides
/// whether a rule shows a hit count at all, and the sample of flows behind it.
@Suite struct TrafficEventStoreRuleHitsTests {
    private func makeStore() -> (TrafficEventStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fluxmoat-rulehits-\(UUID().uuidString)", isDirectory: true)
        return (TrafficEventStore(directoryURL: dir), dir)
    }

    private func event(_ domain: String, at ts: Date, rule: UUID?,
                       verdict: RuleAction = .allow,
                       up: UInt64 = 10, down: UInt64 = 20) -> TrafficEvent {
        TrafficEvent(timestamp: ts, remoteIP: "203.0.113.7", domain: domain,
                     remotePort: 443, protocolNumber: 6, bytesUp: up, bytesDown: down,
                     verdict: verdict, matchedRuleID: rule,
                     countryCode: "US", networkType: .wifi)
    }

    // MARK: - matchedRuleRollup

    @Test func rollupCountsHitsAndLastHitPerRule() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let ruleA = UUID(), ruleB = UUID()
        // Interleaved on purpose: each rule's MAX(ts) must come from its own
        // rows, not from whichever row happens to be last overall.
        try store.append([
            event("a1.example", at: base, rule: ruleA),
            event("b1.example", at: base.addingTimeInterval(1), rule: ruleB),
            event("a2.example", at: base.addingTimeInterval(2), rule: ruleA),
            event("b2.example", at: base.addingTimeInterval(3), rule: ruleB),
            event("a3.example", at: base.addingTimeInterval(4), rule: ruleA),
        ])

        let rollup = try store.matchedRuleRollup(for: [ruleA, ruleB])
        #expect(rollup.count == 2)
        #expect(rollup[ruleA]?.hits == 3)
        #expect(rollup[ruleB]?.hits == 2)
        #expect(abs(rollup[ruleA]!.lastHit.timeIntervalSince(base.addingTimeInterval(4))) < 0.001)
        #expect(abs(rollup[ruleB]!.lastHit.timeIntervalSince(base.addingTimeInterval(3))) < 0.001)
    }

    @Test func rollupOmitsRulesNotAskedAbout() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let wanted = UUID(), unwanted = UUID()
        try store.append([
            event("wanted.example", at: base, rule: wanted),
            event("unwanted.example", at: base.addingTimeInterval(1), rule: unwanted),
        ])

        // The query rolls up every rule; the filtering happens in Swift, so
        // this is the assertion that the filter is actually applied.
        let rollup = try store.matchedRuleRollup(for: [wanted])
        #expect(rollup.count == 1)
        #expect(rollup[wanted]?.hits == 1)
        #expect(rollup[unwanted] == nil)
    }

    @Test func rollupOmitsRuleWithNoEventsRatherThanZeroing() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let fired = UUID(), never = UUID()
        try store.append([event("fired.example", at: base, rule: fired)])

        let rollup = try store.matchedRuleRollup(for: [fired, never])
        #expect(rollup[fired]?.hits == 1)
        // Absent, not RuleMatchRollup(hits: 0, ...): callers read the missing
        // key as "never matched".
        #expect(rollup[never] == nil)
        #expect(rollup.keys.contains(never) == false)
    }

    @Test func rollupOfEmptySetIsEmpty() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([event("a.example", at: Date(), rule: UUID())])

        #expect(try store.matchedRuleRollup(for: []).isEmpty)
    }

    @Test func rollupIgnoresEventsWithNoMatchedRule() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let rule = UUID()
        try store.append([
            event("ruled.example", at: base, rule: rule),
            // Most rows in a real store look like this one: allowed by the
            // default, matched by nothing.
            event("unruled.example", at: base.addingTimeInterval(1), rule: nil),
            event("unruled2.example", at: base.addingTimeInterval(2), rule: nil),
        ])

        let rollup = try store.matchedRuleRollup(for: [rule])
        #expect(rollup.count == 1)
        #expect(rollup[rule]?.hits == 1)
        #expect(abs(rollup[rule]!.lastHit.timeIntervalSince(base)) < 0.001)
    }

    // MARK: - recentMatches

    @Test func recentMatchesAreNewestFirstAndRespectLimit() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let rule = UUID()
        try store.append((0..<6).map { i in
            event("d\(i).example", at: base.addingTimeInterval(Double(i)), rule: rule)
        })

        let rows = try store.recentMatches(ruleID: rule, limit: 3)
        #expect(rows.map(\.domain) == ["d5.example", "d4.example", "d3.example"])
    }

    @Test func recentMatchesFilterToOneRule() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        let mine = UUID(), theirs = UUID()
        try store.append([
            event("mine1.example", at: base, rule: mine),
            event("theirs1.example", at: base.addingTimeInterval(1), rule: theirs),
            event("mine2.example", at: base.addingTimeInterval(2), rule: mine),
            event("nobody.example", at: base.addingTimeInterval(3), rule: nil),
        ])

        let rows = try store.recentMatches(ruleID: mine)
        #expect(rows.map(\.domain) == ["mine2.example", "mine1.example"])
        #expect(rows.allSatisfy { $0.matchedRuleID == mine })
    }

    @Test func recentMatchesForNeverMatchedRuleIsEmpty() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        try store.append([
            event("other.example", at: base, rule: UUID()),
            event("nobody.example", at: base.addingTimeInterval(1), rule: nil),
        ])

        // The common case on the Rules screen, and the one NOT INDEXED exists
        // to keep cheap.
        #expect(try store.recentMatches(ruleID: UUID()).isEmpty)
    }

    @Test func recentMatchesWithZeroLimitIsEmpty() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let rule = UUID()
        try store.append([event("a.example", at: Date(), rule: rule)])

        #expect(try store.recentMatches(ruleID: rule, limit: 0).isEmpty)
    }

    @Test func recentMatchesRoundTripsEveryColumn() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let rule = UUID(), profile = UUID()
        var e = event("blocked.example", at: Date(timeIntervalSince1970: 1_700_000_000),
                      rule: rule, verdict: .deny, up: 1234, down: 5678)
        e.profileID = profile
        e.verdictSource = .userRule
        e.inferredDomain = "inferred.example"
        try store.append([e])

        // This read selects the same column list as `recent` and unpacks it
        // with the same mapper; asserting the whole struct is what would catch
        // the two drifting apart.
        let rows = try store.recentMatches(ruleID: rule)
        #expect(rows.count == 1)
        let back = try #require(rows.first)
        #expect(back.id == e.id)
        #expect(back.domain == "blocked.example")
        #expect(back.remoteIP == "203.0.113.7")
        #expect(back.remotePort == 443)
        #expect(back.protocolNumber == 6)
        #expect(back.bytesUp == 1234)
        #expect(back.bytesDown == 5678)
        #expect(back.verdict == .deny)
        #expect(back.verdictSource == .userRule)
        #expect(back.matchedRuleID == rule)
        #expect(back.profileID == profile)
        #expect(back.countryCode == "US")
        #expect(back.networkType == .wifi)
        #expect(back.inferredDomain == "inferred.example")
        #expect(abs(back.timestamp.timeIntervalSince(e.timestamp)) < 0.001)
        // Same row through the untouched read path, to pin the equivalence.
        #expect(try store.recent(limit: 10).first == back)
    }
}
