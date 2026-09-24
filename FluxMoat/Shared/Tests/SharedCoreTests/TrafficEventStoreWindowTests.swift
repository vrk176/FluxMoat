import Foundation
import SQLite3
import Testing
@testable import SharedCore

/// Covers three additions to the rollup queries: an upper window edge, a
/// resolver-block count, and a rewritten `newTargets`.
///
/// Kept separate from `TrafficEventStoreTests`, which covers the store's
/// long-standing behavior.
@Suite struct TrafficEventStoreWindowTests {
    private func makeStore() -> (TrafficEventStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fluxmoat-window-\(UUID().uuidString)", isDirectory: true)
        return (TrafficEventStore(directoryURL: dir), dir)
    }

    private func event(
        _ domain: String?, at ts: Date, verdict: RuleAction = .allow,
        source: TrafficEvent.VerdictSource? = nil,
        up: UInt64 = 10, down: UInt64 = 20, ip: String = "203.0.113.7"
    ) -> TrafficEvent {
        TrafficEvent(
            timestamp: ts, remoteIP: ip, domain: domain, remotePort: 443,
            protocolNumber: 6, bytesUp: up, bytesDown: down, verdict: verdict,
            verdictSource: source, countryCode: "US", networkType: .wifi
        )
    }

    // MARK: - until: bounding

    /// `since` is inclusive and `until` is exclusive, so a row on the upper
    /// edge belongs to the next window, not this one.
    @Test func untilExcludesItsOwnEdgeAcrossEveryRollup() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        let early = base
        let middle = base.addingTimeInterval(3600)
        let late = base.addingTimeInterval(7200)
        try store.append([
            event("early.example", at: early, ip: "203.0.113.1"),
            event("middle.example", at: middle, ip: "203.0.113.2"),
            event("late.example", at: late, ip: "203.0.113.3"),
        ])

        // [middle, late): one row, both neighbors excluded.
        #expect(try store.topTargets(since: middle, until: late).map(\.target)
                == ["middle.example"])
        #expect(try store.ipAggregates(since: middle, until: late).map(\.remoteIP)
                == ["203.0.113.2"])
        let buckets = try store.bucketAggregates(
            bucketSeconds: 3600, since: middle, until: late)
        #expect(buckets.count == 1)
        #expect(buckets[0].flows == 1)

        // since is inclusive, so the row's own instant still matches.
        #expect(try store.topTargets(since: middle, until: middle).isEmpty)
        #expect(try store.topTargets(since: middle, until: middle.addingTimeInterval(1))
                .map(\.target) == ["middle.example"])
    }

    /// The blocked ranking has its own HAVING clause, so it needs the same check.
    @Test func untilBoundsTheBlockedRanking() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        try store.append([
            event("ads.example", at: base, verdict: .deny),
            event("ads.example", at: base.addingTimeInterval(60), verdict: .deny),
            // Outside the window below; an unbounded query includes it, a
            // bounded one must not.
            event("later.example", at: base.addingTimeInterval(7200), verdict: .deny),
        ])

        let bounded = try store.topBlockedTargets(
            since: base, until: base.addingTimeInterval(3600))
        #expect(bounded.map(\.target) == ["ads.example"])
        #expect(bounded[0].blockedFlows == 2)
        #expect(try store.topBlockedTargets(since: base).count == 2)
    }

    /// `until` on `newTargets` affects both what counts as a first appearance
    /// and which rows get counted.
    @Test func untilBoundsFirstAppearanceAndTheCountsWithIt() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        let edge = base.addingTimeInterval(3600)
        try store.append([
            event("fresh.example", at: base),
            event("fresh.example", at: base.addingTimeInterval(60)),
            event("fresh.example", at: edge.addingTimeInterval(60)),
            // First seen after the edge, so not part of this window.
            event("later.example", at: edge.addingTimeInterval(120)),
        ])

        let bounded = try store.newTargets(since: base, until: edge)
        #expect(bounded.map(\.target) == ["fresh.example"])
        #expect(bounded[0].flows == 2)

        // Unbounded, the same target picks up its third flow and the late
        // arrival joins the list.
        let open = try store.newTargets(since: base)
        #expect(Set(open.map(\.target)) == ["fresh.example", "later.example"])
        #expect(try #require(open.first { $0.target == "fresh.example" }).flows == 3)
    }

    /// Regression: passing `until: nil` explicitly must behave the same as
    /// omitting it.
    @Test func nilUntilIsTheOldUnboundedQuery() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        try store.append([
            event("a.example", at: base, verdict: .deny, ip: "203.0.113.1"),
            event("b.example", at: base.addingTimeInterval(3600), ip: "203.0.113.2"),
            event(nil, at: base.addingTimeInterval(7200), ip: "203.0.113.3"),
        ])

        #expect(try store.topTargets() == store.topTargets(until: nil))
        #expect(try store.topBlockedTargets() == store.topBlockedTargets(until: nil))
        #expect(try store.ipAggregates() == store.ipAggregates(until: nil))
        #expect(try store.bucketAggregates(bucketSeconds: 3600)
                == store.bucketAggregates(bucketSeconds: 3600, until: nil))
        #expect(try store.newTargets(since: base) == store.newTargets(since: base, until: nil))
    }

    // MARK: - resolverBlockedFlows

    /// Only resolver-sourced denies count as resolver blocks. Covers a
    /// resolver deny, a custom-resolver deny, a blocklist deny, and an
    /// allow that happens to carry a resolver source.
    @Test func resolverBlockedFlowsCountsBothResolverSourcesAndOnlyDenies() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        try store.append([
            event("mixed.example", at: base, verdict: .deny, source: .filteringResolver),
            event("mixed.example", at: base, verdict: .deny, source: .customResolver),
            event("mixed.example", at: base, verdict: .deny, source: .blocklist),
            event("mixed.example", at: base, verdict: .allow, source: .filteringResolver),
            // Every block on this target came from the resolver.
            event("sunk.example", at: base, verdict: .deny, source: .customResolver),
            event("sunk.example", at: base, verdict: .allow),
        ])

        let mixed = try #require(try store.topTargets().first { $0.target == "mixed.example" })
        #expect(mixed.flows == 4)
        #expect(mixed.blockedFlows == 3)
        #expect(mixed.resolverBlockedFlows == 2)
        // The check HistoryView relies on for these two numbers.
        #expect(!(mixed.blockedFlows > 0 && mixed.resolverBlockedFlows == mixed.blockedFlows))

        let sunk = try #require(try store.topBlockedTargets().first { $0.target == "sunk.example" })
        #expect(sunk.blockedFlows == 1 && sunk.resolverBlockedFlows == 1)
        #expect(sunk.blockedFlows > 0 && sunk.resolverBlockedFlows == sunk.blockedFlows)

        // newTargets carries the same resolver count.
        let clean = try #require(try store.newTargets(since: base.addingTimeInterval(-60))
            .first { $0.target == "sunk.example" })
        #expect(clean.resolverBlockedFlows == 1)
    }

    /// threatFeed blocks are decided locally, not by the resolver, so they
    /// must not count as resolver blocks.
    @Test func threatFeedBlocksAreNotResolverBlocks() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        try store.append([
            event("ioc.example", at: base, verdict: .deny, source: .threatFeed),
            event("ioc.example", at: base, verdict: .deny, source: .userRule),
        ])

        let row = try #require(try store.topBlockedTargets().first)
        #expect(row.blockedFlows == 2)
        #expect(row.resolverBlockedFlows == 0)
    }

    // MARK: - newTargets pre-filter equivalence

    /// Runs the old, unfiltered `newTargets` query verbatim on a second
    /// connection and compares full result sets against the new pre-filtered
    /// one, since the two use genuinely different query plans and should
    /// still agree row for row.
    @Test func newTargetsPreFilterMatchesReferenceQuery() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        let cutoff = base.addingTimeInterval(3600)

        var events: [TrafficEvent] = []
        // Seen before the cutoff and still active inside the window; the
        // pre-filter must exclude these.
        for i in 0..<6 {
            events.append(event("familiar\(i).example", at: base.addingTimeInterval(Double(i))))
            events.append(event("familiar\(i).example", at: cutoff.addingTimeInterval(Double(i))))
        }
        // Genuinely new names, some with several flows so the sums differ.
        for i in 0..<5 {
            let when = cutoff.addingTimeInterval(Double(60 + i * 7))
            events.append(event("fresh\(i).example", at: when, verdict: .deny,
                                source: i.isMultiple(of: 2) ? .customResolver : .blocklist,
                                up: UInt64(i + 1), down: UInt64(i * 3)))
            events.append(event("fresh\(i).example", at: when.addingTimeInterval(1)))
        }
        // Nameless flows exercise the COALESCE fallback: one old address,
        // one new one.
        events.append(event(nil, at: base, ip: "198.51.100.1"))
        events.append(event(nil, at: cutoff.addingTimeInterval(30), ip: "198.51.100.1"))
        events.append(event(nil, at: cutoff.addingTimeInterval(40), ip: "198.51.100.2"))
        // Empty-string domain, which NULLIF has to treat as nameless too.
        events.append(event("", at: cutoff.addingTimeInterval(50), ip: "198.51.100.3"))
        try store.append(events)

        // Covers a window with some rows, one with everything, and one with
        // none.
        for since in [cutoff, base.addingTimeInterval(-3600), cutoff.addingTimeInterval(86_400)] {
            for limit in [5, 50] {
                let new = try store.newTargets(since: since, limit: limit)
                let reference = try Self.legacyNewTargets(
                    databaseAt: dir, since: since, limit: limit)
                #expect(new == reference,
                        "pre-filter disagreed at since=\(since.timeIntervalSince1970) limit=\(limit)")
            }
        }
        // Sanity check the count isn't vacuously right: 5 fresh names plus
        // 2 nameless newcomers; 198.51.100.1 is old and excluded.
        #expect(try store.newTargets(since: cutoff, limit: 50).count == 7)
    }

    /// `newTargets` exactly as it was written before the pre-filter, selecting
    /// the same seven columns, executed on its own connection.
    private static func legacyNewTargets(
        databaseAt directory: URL, since: Date, limit: Int
    ) throws -> [TrafficEventStore.TargetAggregate] {
        let path = directory.appendingPathComponent("events.sqlite").path
        var db: OpaquePointer?
        guard sqlite3_open(path, &db) == SQLITE_OK, let db else {
            sqlite3_close_v2(db)
            throw TrafficEventStore.StoreError(reason: "reference open failed")
        }
        defer { sqlite3_close_v2(db) }
        let sql = """
        SELECT COALESCE(NULLIF(domain, ''), remote_ip),
               MAX(CASE WHEN domain IS NOT NULL AND domain != '' THEN 1 ELSE 0 END),
               COUNT(*),
               SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END),
               SUM(CASE WHEN verdict = 'deny'
                         AND verdict_source IN ('filteringResolver', 'customResolver')
                        THEN 1 ELSE 0 END),
               SUM(CASE WHEN verdict = 'deny'
                         AND verdict_source IN ('filteringResolver', 'threatFeed')
                        THEN 1 ELSE 0 END),
               SUM(bytes_up), SUM(bytes_down)
        FROM events
        GROUP BY 1
        HAVING MIN(ts) >= ?
        ORDER BY MIN(ts) DESC LIMIT ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw TrafficEventStore.StoreError(reason: "reference prepare failed")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, since.timeIntervalSince1970)
        sqlite3_bind_int(stmt, 2, Int32(max(0, limit)))

        var rows: [TrafficEventStore.TargetAggregate] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            rows.append(TrafficEventStore.TargetAggregate(
                target: sqlite3_column_text(stmt, 0).map { String(cString: $0) } ?? "",
                isDomain: sqlite3_column_int64(stmt, 1) == 1,
                flows: Int(sqlite3_column_int64(stmt, 2)),
                blockedFlows: Int(sqlite3_column_int64(stmt, 3)),
                resolverBlockedFlows: Int(sqlite3_column_int64(stmt, 4)),
                threatFlows: Int(sqlite3_column_int64(stmt, 5)),
                bytesUp: UInt64(bitPattern: sqlite3_column_int64(stmt, 6)),
                bytesDown: UInt64(bitPattern: sqlite3_column_int64(stmt, 7))
            ))
        }
        return rows
    }
}
