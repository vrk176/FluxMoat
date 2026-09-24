import Foundation
import Testing
@testable import SharedCore

/// What the Insights share cards read off the store, and the two sums they
/// derive from it.
///
/// The rankings and per-IP rollup must split "blocked" into rule and
/// threat the same way the time rollup does. The fixture includes one of
/// each verdict source that could be mistaken for a threat (a
/// custom-resolver sink, a blocklist deny, an allow carrying a threat
/// source) next to the two that actually are threats.
@Suite struct ShareCardDataTests {
    private func makeStore() -> (TrafficEventStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fluxmoat-sharecard-\(UUID().uuidString)", isDirectory: true)
        return (TrafficEventStore(directoryURL: dir), dir)
    }

    private func event(
        _ domain: String?, at ts: Date, verdict: RuleAction = .allow,
        source: TrafficEvent.VerdictSource? = nil, ip: String = "203.0.113.7"
    ) -> TrafficEvent {
        TrafficEvent(
            timestamp: ts, remoteIP: ip, domain: domain, remotePort: 443,
            protocolNumber: 6, bytesUp: 10, bytesDown: 20, verdict: verdict,
            verdictSource: source, countryCode: "US", networkType: .wifi
        )
    }

    // MARK: - threatFlows on the rankings

    /// Both threat sources count, nothing else does, and the number is a
    /// subset of `blockedFlows`: the card prints `blocked − threat` in red
    /// and `threat` in violet, and those two must add back up.
    @Test func rankingsCountThreatFlowsLikeTheTimeRollup() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        try store.append([
            event("beacon.example", at: base, verdict: .deny, source: .threatFeed),
            event("beacon.example", at: base, verdict: .deny, source: .filteringResolver),
            event("beacon.example", at: base, verdict: .deny, source: .customResolver),
            event("beacon.example", at: base, verdict: .deny, source: .blocklist),
            event("beacon.example", at: base, verdict: .allow, source: .threatFeed),
            event("clean.example", at: base),
        ])

        let top = try #require(try store.topTargets().first { $0.target == "beacon.example" })
        #expect(top.flows == 5)
        #expect(top.blockedFlows == 4)
        #expect(top.threatFlows == 2)
        #expect(top.threatFlows <= top.blockedFlows)

        let blocked = try #require(try store.topBlockedTargets().first)
        #expect(blocked.target == "beacon.example" && blocked.threatFlows == 2)

        let fresh = try #require(try store.newTargets(since: base.addingTimeInterval(-60))
            .first { $0.target == "beacon.example" })
        #expect(fresh.threatFlows == 2)

        // The same window through the time rollup agrees.
        let buckets = try store.bucketAggregates(bucketSeconds: 3600)
        #expect(buckets.reduce(0) { $0 + $1.threatFlows } == 2)
        #expect(try store.topTargets().reduce(0) { $0 + $1.threatFlows } == 2)

        let clean = try #require(try store.topTargets().first { $0.target == "clean.example" })
        #expect(clean.threatFlows == 0)
    }

    /// The per-IP rollup carries the same column, per address.
    @Test func ipAggregatesCountThreatFlows() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        try store.append([
            event("a.example", at: base, verdict: .deny, source: .threatFeed, ip: "198.51.100.1"),
            event("a.example", at: base, verdict: .deny, source: .customResolver, ip: "198.51.100.1"),
            event("b.example", at: base, verdict: .deny, source: .filteringResolver, ip: "198.51.100.2"),
            event("c.example", at: base, ip: "198.51.100.3"),
        ])
        let rows = try store.ipAggregates()
        let byIP = Dictionary(uniqueKeysWithValues: rows.map { ($0.remoteIP, $0) })
        #expect(byIP["198.51.100.1"]?.blockedFlows == 2)
        #expect(byIP["198.51.100.1"]?.threatFlows == 1)
        #expect(byIP["198.51.100.2"]?.threatFlows == 1)
        #expect(byIP["198.51.100.3"]?.threatFlows == 0)
    }

    // MARK: - distinctTargets

    /// Counts destinations the way the rankings key them: a domain is one
    /// target however many addresses answered for it, a nameless flow counts
    /// by address, an empty-string domain is nameless, and the window edges
    /// apply.
    @Test func distinctTargetsKeysLikeTheRankings() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        try store.append([
            event("api.example", at: base, ip: "198.51.100.1"),
            event("api.example", at: base, ip: "198.51.100.2"),
            event(nil, at: base, ip: "198.51.100.3"),
            event("", at: base, ip: "198.51.100.3"),
            event("old.example", at: base.addingTimeInterval(-7200)),
        ])
        #expect(try store.distinctTargets() == 3)
        #expect(try store.distinctTargets(since: base.addingTimeInterval(-60)) == 2)
        #expect(try store.distinctTargets(since: base.addingTimeInterval(60)) == 0)
        #expect(try store.distinctTargets(until: base) == 1)
    }

    @Test func distinctTargetsOnEmptyStoreIsZero() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(try store.distinctTargets() == 0)
    }

    // MARK: - ShareCardMath

    @Test func peakIndexIsFirstMaximumAndNilWhenNothingBlocked() {
        #expect(ShareCardMath.peakIndex(blockedPerBucket: [10, 9, 31, 12, 31, 8]) == 2)
        #expect(ShareCardMath.peakIndex(blockedPerBucket: [0, 0, 4]) == 2)
        #expect(ShareCardMath.peakIndex(blockedPerBucket: [0, 0, 0]) == nil)
        #expect(ShareCardMath.peakIndex(blockedPerBucket: []) == nil)
    }

    /// The sample summary from the spec: 1,284 over 7 days is "183 a day",
    /// and the rounding is to nearest, not down.
    @Test func perBucketAverageRoundsToNearest() {
        #expect(ShareCardMath.perBucketAverage(total: 1284, buckets: 7) == 183)
        #expect(ShareCardMath.perBucketAverage(total: 5412, buckets: 30) == 180)
        #expect(ShareCardMath.perBucketAverage(total: 1283, buckets: 24) == 53)
        #expect(ShareCardMath.perBucketAverage(total: 10, buckets: 4) == 3)
        #expect(ShareCardMath.perBucketAverage(total: 11, buckets: 4) == 3)
        #expect(ShareCardMath.perBucketAverage(total: 7, buckets: 0) == 0)
    }

    /// Truncation, never rounding: 24,963 is "24.9k", because an
    /// abbreviated count that rounds up would claim connections the
    /// device never saw.
    @Test func abbreviatedCutsTheTailAndNeverRoundsUp() {
        #expect(ShareCardMath.abbreviated(999) == "999")
        #expect(ShareCardMath.abbreviated(1_000) == "1k")
        #expect(ShareCardMath.abbreviated(1_050) == "1k")
        #expect(ShareCardMath.abbreviated(12_345) == "12.3k")
        #expect(ShareCardMath.abbreviated(24_963) == "24.9k")
        #expect(ShareCardMath.abbreviated(65_298) == "65.2k")
        #expect(ShareCardMath.abbreviated(372_371) == "372.3k")
        #expect(ShareCardMath.abbreviated(999_999) == "999.9k")
        #expect(ShareCardMath.abbreviated(1_000_000) == "1M")
        #expect(ShareCardMath.abbreviated(1_234_567) == "1.2M")
        #expect(ShareCardMath.abbreviated(999_999_999) == "999.9M")
        // Past the M unit the number goes out whole rather than in a "B" the
        // rest of the app has never printed.
        #expect(ShareCardMath.abbreviated(1_000_000_000) == 1_000_000_000.formatted())
        #expect(ShareCardMath.abbreviated(0) == "0")
    }

    /// The card's own threshold: four digits stay whole and grouped, five
    /// start abbreviating. The un-abbreviated side is compared against
    /// `formatted` rather than a literal "9,999" because the separator is the
    /// reader's locale's, and this suite runs in whatever locale it is run in.
    @Test func cardCountAbbreviatesFromTenThousand() {
        #expect(ShareCardMath.cardCount(9_999) == 9_999.formatted(.number.grouping(.automatic)))
        #expect(!ShareCardMath.cardCount(9_999).contains("k"))
        #expect(ShareCardMath.cardCount(0) == "0")
        #expect(ShareCardMath.cardCount(87) == "87")
        #expect(ShareCardMath.cardCount(1_284) == 1_284.formatted(.number.grouping(.automatic)))
        #expect(ShareCardMath.cardCount(10_000) == "10k")
        #expect(ShareCardMath.cardCount(12_345) == "12.3k")
        #expect(ShareCardMath.cardCount(1_000_000) == "1M")
    }
}
