import Foundation
import SQLite3
import Testing
@testable import SharedCore

@Suite struct TrafficEventStoreTests {
    private func makeStore() -> (TrafficEventStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fluxmoat-eventstore-\(UUID().uuidString)", isDirectory: true)
        return (TrafficEventStore(directoryURL: dir), dir)
    }

    private func event(_ domain: String, at ts: Date = Date(), verdict: RuleAction = .allow,
                       up: UInt64 = 10, down: UInt64 = 20, ip: String = "203.0.113.7") -> TrafficEvent {
        TrafficEvent(timestamp: ts, remoteIP: ip, domain: domain, remotePort: 443,
                     protocolNumber: 6, bytesUp: up, bytesDown: down, verdict: verdict,
                     countryCode: "US", networkType: .wifi)
    }

    @Test func appendAndRecentRoundTripsAllFields() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let ruleID = UUID()
        var e = event("api.example")
        e.matchedRuleID = ruleID
        e.verdictSource = .filteringResolver
        e.inferredDomain = "inferred.example"
        try store.append([e])

        let back = try store.recent(limit: 10)
        #expect(back.count == 1)
        #expect(back[0].id == e.id)
        #expect(back[0].domain == "api.example")
        #expect(back[0].remoteIP == "203.0.113.7")
        #expect(back[0].remotePort == 443)
        #expect(back[0].protocolNumber == 6)
        #expect(back[0].bytesUp == 10)
        #expect(back[0].bytesDown == 20)
        #expect(back[0].verdict == .allow)
        #expect(back[0].verdictSource == .filteringResolver)
        #expect(back[0].matchedRuleID == ruleID)
        #expect(back[0].countryCode == "US")
        #expect(back[0].networkType == .wifi)
        #expect(back[0].inferredDomain == "inferred.example")
        #expect(abs(back[0].timestamp.timeIntervalSince(e.timestamp)) < 0.001)
    }

    @Test func recentIsNewestFirstAndPageable() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date()
        try store.append((0..<5).map { i in
            event("d\(i).example", at: base.addingTimeInterval(Double(i)))
        })

        let firstPage = try store.recent(limit: 2)
        #expect(firstPage.map(\.domain) == ["d4.example", "d3.example"])
        let nextPage = try store.recent(limit: 2, before: firstPage.last!.timestamp)
        #expect(nextPage.map(\.domain) == ["d2.example", "d1.example"])
    }

    @Test func pruneDropsOldAndCapsRows() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let now = Date()
        // 2 stale (10 days old) + 4 fresh.
        try store.append((0..<2).map { i in event("old\(i).example", at: now.addingTimeInterval(-10 * 24 * 3600 + Double(i))) })
        try store.append((0..<4).map { i in event("new\(i).example", at: now.addingTimeInterval(Double(i))) })

        // Age prune removes the stale two; row cap 3 then drops the oldest fresh.
        let deleted = try store.prune(maxAge: 7 * 24 * 3600, maxRows: 3)
        #expect(deleted == 3)
        let left = try store.recent(limit: 10)
        #expect(left.map(\.domain) == ["new3.example", "new2.example", "new1.example"])
    }

    @Test func wipeEmptiesAndSurvivesReopen() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([event("a.example"), event("b.example")])
        try store.wipe()
        #expect(try store.count() == 0)
        // A fresh connection over the same files must also see nothing.
        let reopened = TrafficEventStore(directoryURL: dir)
        #expect(try reopened.count() == 0)
    }

    @Test func persistsAcrossConnectionsLikeExtensionWriterAppReader() throws {
        let (writer, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try writer.append([event("seen-by-app.example")])

        // Second connection on the same directory = the app process reading
        // what the extension wrote (WAL: single writer + readers).
        let reader = TrafficEventStore(directoryURL: dir)
        let back = try reader.recent(limit: 10)
        #expect(back.map(\.domain) == ["seen-by-app.example"])
    }

    /// The raw value is the exact string the SQL rollups match on, so this
    /// pins the spelling as much as the round-trip.
    @Test func customResolverSourceRoundTrips() throws {
        #expect(TrafficEvent.VerdictSource.customResolver.rawValue == "customResolver")
        #expect(TrafficEvent.VerdictSource(rawValue: "customResolver") == .customResolver)

        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        var e = event("ads.example", verdict: .deny)
        e.verdictSource = .customResolver
        try store.append([e])
        #expect(try store.recent(limit: 1)[0].verdictSource == .customResolver)
    }

    @Test func deniedEventKeepsVerdict() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([event("ads.example", verdict: .deny, up: 0, down: 0)])
        #expect(try store.recent(limit: 1)[0].verdict == .deny)
    }

    /// A database created before the verdict_source column existed must be
    /// migrated in place: old rows read back with nil, new writes persist it.
    @Test func migratesPreVerdictSourceDatabase() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fluxmoat-eventstore-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)

        // Build the pre-migration schema and one legacy row by hand.
        var db: OpaquePointer?
        let path = dir.appendingPathComponent("events.sqlite").path
        #expect(sqlite3_open(path, &db) == SQLITE_OK)
        let legacySchema = """
        CREATE TABLE events (
          id TEXT PRIMARY KEY, ts REAL NOT NULL, remote_ip TEXT NOT NULL,
          domain TEXT, remote_port INTEGER, proto INTEGER NOT NULL,
          bytes_up INTEGER NOT NULL, bytes_down INTEGER NOT NULL,
          verdict TEXT NOT NULL, matched_rule_id TEXT, profile_id TEXT,
          country TEXT, network TEXT
        )
        """
        #expect(sqlite3_exec(db, legacySchema, nil, nil, nil) == SQLITE_OK)
        let insert = """
        INSERT INTO events (id, ts, remote_ip, domain, proto, bytes_up, bytes_down, verdict, network)
        VALUES ('\(UUID().uuidString)', 1000, '', 'legacy.example', 6, 1, 2, 'allow', 'wifi')
        """
        #expect(sqlite3_exec(db, insert, nil, nil, nil) == SQLITE_OK)
        sqlite3_close_v2(db)

        let store = TrafficEventStore(directoryURL: dir)
        var e = event("new.example", verdict: .deny)
        e.verdictSource = .filteringResolver
        try store.append([e])

        let back = try store.recent(limit: 10)
        #expect(back.map(\.domain) == ["new.example", "legacy.example"])
        #expect(back[0].verdictSource == .filteringResolver)
        #expect(back[1].verdictSource == nil)
        // inferred_domain rides the same migration: legacy rows read nil.
        #expect(back[1].inferredDomain == nil)
    }

    // MARK: - ipAggregates + country merge

    /// Groups by `remote_ip`, not `country` (NULL until GeoIP runs app-side).
    /// Regression: grouping on `country` collapsed everything into Unknown.
    @Test func ipAggregatesGroupsCountsAndSums() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([
            event("a.example", up: 10, down: 20, ip: "203.0.113.7"),
            event("b.example", verdict: .deny, up: 1, down: 2, ip: "203.0.113.7"),
            event("c.example", up: 100, down: 200, ip: "198.51.100.9"),
        ])

        let rows = try store.ipAggregates()
        #expect(rows.count == 2)
        // Most flows first.
        #expect(rows[0].remoteIP == "203.0.113.7")
        #expect(rows[0].flows == 2)
        #expect(rows[0].blockedFlows == 1)
        #expect(rows[0].bytesUp == 11)
        #expect(rows[0].bytesDown == 22)
        #expect(rows[1].remoteIP == "198.51.100.9")
        #expect(rows[1].flows == 1 && rows[1].blockedFlows == 0)
    }

    /// `since` excludes older rows from the rollup.
    @Test func ipAggregatesRespectsSince() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([
            event("old.example", at: Date(timeIntervalSinceNow: -3600)),
            event("new.example"),
        ])
        let rows = try store.ipAggregates(since: Date(timeIntervalSinceNow: -60))
        #expect(rows.count == 1)
        #expect(rows[0].flows == 1)
    }

    /// Empty store aggregates to an empty list, not an error.
    @Test func ipAggregatesOnEmptyStoreIsEmpty() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(try store.ipAggregates().isEmpty)
    }

    /// Country merge: distinct IPs collapse into their country, unplaceable
    /// IPs (private ranges, absent from GeoIP) into the nil bucket, sorted
    /// most flows first. Totals still add up to the IP-level totals.
    @Test func countryMergeCollapsesIPsAndKeepsUnknownBucket() {
        let ips = [
            TrafficEventStore.IPAggregate(remoteIP: "1.2.3.4", flows: 3, blockedFlows: 1, threatFlows: 0, bytesUp: 30, bytesDown: 60),
            TrafficEventStore.IPAggregate(remoteIP: "1.2.3.5", flows: 2, blockedFlows: 0, threatFlows: 0, bytesUp: 20, bytesDown: 40),
            TrafficEventStore.IPAggregate(remoteIP: "9.9.9.9", flows: 4, blockedFlows: 4, threatFlows: 2, bytesUp: 1, bytesDown: 1),
            TrafficEventStore.IPAggregate(remoteIP: "192.168.1.1", flows: 1, blockedFlows: 0, threatFlows: 0, bytesUp: 5, bytesDown: 5),
        ]
        let lookup = ["1.2.3.4": "US", "1.2.3.5": "US", "9.9.9.9": "CH"]
        let rows = TrafficEventStore.CountryAggregate.aggregate(ips) { lookup[$0] }

        #expect(rows.count == 3)
        #expect(rows[0].countryCode == "US")
        #expect(rows[0].flows == 5)
        #expect(rows[0].blockedFlows == 1)
        #expect(rows[0].bytesUp == 50 && rows[0].bytesDown == 100)
        #expect(rows[1].countryCode == "CH" && rows[1].flows == 4 && rows[1].blockedFlows == 4)
        #expect(rows[2].countryCode == nil && rows[2].flows == 1)
        #expect(rows.map(\.flows).reduce(0, +) == ips.map(\.flows).reduce(0, +))
    }

    // MARK: - bucketAggregates

    /// Hourly bucketing: rows land in their hour, bucket starts are aligned
    /// to the granularity, and per-bucket counts distinguish blocked and
    /// threat (filteringResolver/threatFeed) flows.
    @Test func bucketAggregatesGroupsByHourWithExactStarts() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        // 999_997_200 is exactly divisible by 3600.
        let hour1 = Date(timeIntervalSince1970: 999_997_200)
        var threat = event("c2.example", at: hour1.addingTimeInterval(300), verdict: .deny)
        threat.verdictSource = .threatFeed
        var plainDeny = event("ads.example", at: hour1.addingTimeInterval(3900), verdict: .deny)
        plainDeny.verdictSource = .userRule
        try store.append([
            event("a.example", at: hour1.addingTimeInterval(200)),
            threat,
            plainDeny,
        ])

        let rows = try store.bucketAggregates(bucketSeconds: 3600)
        #expect(rows.count == 2)
        #expect(rows[0].bucketStart == hour1)
        #expect(rows[0].flows == 2)
        #expect(rows[0].blockedFlows == 1)
        #expect(rows[0].threatFlows == 1)
        #expect(rows[0].bytesUp == 20 && rows[0].bytesDown == 40)
        #expect(rows[1].bucketStart == hour1.addingTimeInterval(3600))
        // A user-rule deny is blocked but NOT a threat.
        #expect(rows[1].blockedFlows == 1 && rows[1].threatFlows == 0)
    }

    /// Regression: a custom resolver's sink is a block like any other, but
    /// must never reach the threat column (what Dashboard, History, and the
    /// Widget call "threats").
    @Test func bucketAggregatesExcludeCustomResolverFromThreats() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let hour = Date(timeIntervalSince1970: 999_997_200)
        var adSink = event("ads.example", at: hour.addingTimeInterval(60), verdict: .deny)
        adSink.verdictSource = .customResolver
        var malwareSink = event("evil.example", at: hour.addingTimeInterval(120), verdict: .deny)
        malwareSink.verdictSource = .filteringResolver
        try store.append([adSink, malwareSink])

        let rows = try store.bucketAggregates(bucketSeconds: 3600)
        #expect(rows.count == 1)
        #expect(rows[0].blockedFlows == 2)
        #expect(rows[0].threatFlows == 1)
    }

    /// `offsetSeconds` realigns day buckets to local midnight: an event at
    /// local 00:30 (+8 h zone) belongs to the local day, which UTC bucketing
    /// would place a day earlier.
    @Test func bucketAggregatesOffsetAlignsDaysToLocalMidnight() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let offset = 8 * 3600
        let day = 20_000 // days since epoch
        let localMidnight = TimeInterval(day * 86_400 - offset)
        try store.append([event("late.example", at: Date(timeIntervalSince1970: localMidnight + 1800))])

        let local = try store.bucketAggregates(bucketSeconds: 86_400, offsetSeconds: offset)
        #expect(local.map(\.bucketStart) == [Date(timeIntervalSince1970: localMidnight)])
        let utc = try store.bucketAggregates(bucketSeconds: 86_400)
        #expect(utc.map(\.bucketStart) == [Date(timeIntervalSince1970: TimeInterval((day - 1) * 86_400))])
    }

    /// `since` filters, empty stores aggregate empty, and a non-positive
    /// bucket size is a caller error, not silent garbage.
    @Test func bucketAggregatesSinceEmptyAndInvalidBucket() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        #expect(try store.bucketAggregates(bucketSeconds: 3600).isEmpty)
        try store.append([
            event("old.example", at: Date(timeIntervalSinceNow: -7200)),
            event("new.example"),
        ])
        let recent = try store.bucketAggregates(bucketSeconds: 3600, since: Date(timeIntervalSinceNow: -60))
        #expect(recent.reduce(0) { $0 + $1.flows } == 1)
        #expect(throws: TrafficEventStore.StoreError.self) {
            _ = try store.bucketAggregates(bucketSeconds: 0)
        }
    }

    // MARK: - topTargets

    /// Ranking groups by domain (falling back to IP for nameless flows),
    /// most flows first, honoring `limit` and `since`.
    @Test func topTargetsRanksDomainsAndFallsBackToIP() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        var nameless = event("ignored", ip: "198.51.100.9")
        nameless.domain = nil
        try store.append([
            event("api.example"), event("api.example"),
            event("api.example", verdict: .deny),
            event("cdn.example"),
            nameless,
        ])

        let rows = try store.topTargets(limit: 2)
        #expect(rows.count == 2)
        #expect(rows[0].target == "api.example")
        #expect(rows[0].isDomain && rows[0].flows == 3 && rows[0].blockedFlows == 1)
        #expect(rows[1].flows == 1)

        let all = try store.topTargets()
        let ip = try #require(all.first { $0.target == "198.51.100.9" })
        #expect(!ip.isDomain)

        let none = try store.topTargets(since: Date(timeIntervalSinceNow: 60))
        #expect(none.isEmpty)
    }

    // MARK: - topBlockedTargets / newTargets

    /// Blocked ranking orders by deny count and excludes never-blocked
    /// targets entirely.
    @Test func topBlockedTargetsOrdersByDenyAndExcludesClean() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([
            event("ads.example", verdict: .deny), event("ads.example", verdict: .deny),
            event("tracker.example", verdict: .deny),
            event("tracker.example"),
            event("clean.example"), event("clean.example"), event("clean.example"),
        ])

        let rows = try store.topBlockedTargets()
        #expect(rows.map(\.target) == ["ads.example", "tracker.example"])
        #expect(rows[0].blockedFlows == 2)
        #expect(rows[1].flows == 2 && rows[1].blockedFlows == 1)
    }

    /// "New" = first-ever appearance inside the window; a familiar target
    /// re-appearing in the window doesn't qualify.
    @Test func newTargetsJudgesFirstAppearanceAgainstAllHistory() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let old = Date(timeIntervalSinceNow: -3600)
        let cutoff = Date(timeIntervalSinceNow: -60)
        try store.append([
            event("familiar.example", at: old),
            event("familiar.example", at: Date()),
            event("fresh.example", at: Date()),
        ])

        let rows = try store.newTargets(since: cutoff)
        #expect(rows.map(\.target) == ["fresh.example"])

        let everything = try store.newTargets(since: Date(timeIntervalSinceNow: -7200))
        #expect(everything.count == 2)
    }

    // MARK: - exportCSV

    /// Export writes a header + one RFC 4180 row per event, oldest first,
    /// with the exact on-disk field set and ISO 8601 UTC timestamps.
    @Test func exportCSVWritesHeaderAndRowsOldestFirst() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let t0 = Date(timeIntervalSince1970: 1_700_000_000)
        var threat = event("bad.example", at: t0.addingTimeInterval(60), verdict: .deny)
        threat.verdictSource = .threatFeed
        try store.append([event("a.example", at: t0), threat])

        let out = dir.appendingPathComponent("export.csv")
        let rows = try store.exportCSV(to: out)
        #expect(rows == 2)

        let lines = try String(contentsOf: out, encoding: .utf8)
            .split(separator: "\n").map(String.init)
        #expect(lines.count == 3)
        #expect(lines[0] == "timestamp,domain,remote_ip,remote_port,protocol,bytes_up,bytes_down,verdict,verdict_source,country,network,inferred_domain")
        #expect(lines[1] == "2023-11-14T22:13:20Z,a.example,203.0.113.7,443,6,10,20,allow,,US,wifi,")
        #expect(lines[2] == "2023-11-14T22:14:20Z,bad.example,203.0.113.7,443,6,10,20,deny,threatFeed,US,wifi,")
    }

    /// Fields containing CSV metacharacters are quoted and embedded quotes
    /// doubled, so one malformed value can't shear the file's columns.
    @Test func exportCSVEscapesMetacharacters() {
        #expect(TrafficEventStore.csvEscaped("plain.example") == "plain.example")
        #expect(TrafficEventStore.csvEscaped("a,b") == "\"a,b\"")
        #expect(TrafficEventStore.csvEscaped("say \"hi\"") == "\"say \"\"hi\"\"\"")
        #expect(TrafficEventStore.csvEscaped("line\nbreak") == "\"line\nbreak\"")
    }

    /// An empty store exports a header-only file (0 rows), not an error.
    @Test func exportCSVOnEmptyStoreIsHeaderOnly() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let out = dir.appendingPathComponent("empty.csv")
        #expect(try store.exportCSV(to: out) == 0)
        let content = try String(contentsOf: out, encoding: .utf8)
        #expect(content.split(separator: "\n").count == 1)
    }

    // MARK: - Retention + compaction

    /// The periods scale monotonically in both dimensions, and `.default`
    /// matches prune's historical defaults (7 d / 20k) so a nil snapshot
    /// field means exactly the pre-setting behavior.
    @Test func retentionPeriodsScaleMonotonically() {
        #expect(RetentionPeriod.default.maxAge == 30 * 24 * 3600)
        #expect(RetentionPeriod.default.maxRows == 50_000)
        let ordered = RetentionPeriod.allCases
        #expect(zip(ordered, ordered.dropFirst()).allSatisfy { $0.maxAge < $1.maxAge })
        #expect(zip(ordered, ordered.dropFirst()).allSatisfy { $0.maxRows < $1.maxRows })
        #expect(RetentionPeriod.months12.days == 365)
    }

    /// Shrinking retention must return disk, not just rows: after a prune
    /// that deletes most of the database, compaction (VACUUM) shrinks the
    /// file itself instead of leaving it at its high-water size.
    @Test func pruneCompactsFileAfterMassDeletion() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let filler = String(repeating: "x", count: 120)
        // Old enough that a 1-hour maxAge deletes every row.
        let old = Date(timeIntervalSinceNow: -24 * 3600)
        for batch in 0..<5 {
            try store.append((0..<1000).map { i in
                event("\(filler)-\(batch)-\(i).example", at: old)
            })
        }
        // WAL mode: fresh writes live in the -wal file until checkpoint, so
        // footprint is main + WAL, which VACUUM + wal_checkpoint(TRUNCATE)
        // should shrink.
        let footprint = {
            ["events.sqlite", "events.sqlite-wal"].reduce(0) { total, name in
                let path = dir.appendingPathComponent(name).path
                let size = (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? 0
                return total + (size ?? 0)
            }
        }
        let sizeBefore = footprint()

        let deleted = try store.prune(maxAge: 3600, maxRows: 20_000)
        #expect(deleted == 5000)
        let sizeAfter = footprint()
        #expect(sizeAfter < sizeBefore / 2, "expected compaction: \(sizeBefore) → \(sizeAfter)")
        // And the store still works after VACUUM.
        try store.append([event("post-compact.example")])
        #expect(try store.count() == 1)
    }
}

@Suite struct WidgetStateStoreTests {
    /// Round-trips through the App Group file; unwritten reads nil.
    @Test func roundTripsAndMissingReadsNil() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fluxmoat-widgetstate-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let store = WidgetStateStore(directoryURL: dir)

        #expect(store.read() == nil)
        let state = WidgetState(protectionOn: true, updatedAt: Date(timeIntervalSince1970: 1_700_000_000))
        try store.write(state)
        #expect(store.read() == state)
        // Overwrite is replace, not merge.
        try store.write(WidgetState(protectionOn: false, updatedAt: Date(timeIntervalSince1970: 1_700_000_100)))
        #expect(store.read()?.protectionOn == false)
    }
}
