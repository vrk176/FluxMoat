import Foundation
import SQLite3

/// SQLite history of observed flows in the App Group container. The tunnel
/// batch-appends every closed flow so history is complete even if the app
/// never opens; the app reads it and can wipe it. WAL mode allows one writer
/// and concurrent readers across processes.
///
/// Privacy: rows hold only connection metadata (domain, IP, port, protocol,
/// bytes, verdict, rule id), never payload. `wipe()` deletes rows, vacuums
/// and truncates the WAL so nothing is left in free pages or the log.
///
/// Concurrency: each process opens its own store. Call instance methods from
/// one queue at a time. A busy timeout handles cross-process contention.
public final class TrafficEventStore {
    public static let appGroupID = AppIdentifiers.appGroup

    public struct StoreError: Error, CustomStringConvertible {
        public let reason: String
        public var description: String { "TrafficEventStore: \(reason)" }
    }

    /// Store inside the App Group container, or nil when the entitlement is
    /// missing (for example unsigned simulator builds).
    public static func appGroup() -> TrafficEventStore? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
            .map { TrafficEventStore(directoryURL: $0.appendingPathComponent("Events", isDirectory: true)) }
    }

    private let directoryURL: URL
    private var db: OpaquePointer?

    public init(directoryURL: URL) {
        self.directoryURL = directoryURL
    }

    deinit {
        if let db { sqlite3_close_v2(db) }
    }

    // MARK: - Public API

    /// Appends closed flows in a single transaction.
    public func append(_ events: [TrafficEvent]) throws {
        guard !events.isEmpty else { return }
        let db = try handle()
        try exec(db, "BEGIN IMMEDIATE")
        do {
            let sql = """
            INSERT OR REPLACE INTO events
              (id, ts, remote_ip, domain, remote_port, proto, bytes_up, bytes_down,
               verdict, matched_rule_id, profile_id, country, network, verdict_source,
               inferred_domain)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """
            var stmt: OpaquePointer?
            guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
                throw StoreError(reason: "prepare insert: \(message(db))")
            }
            defer { sqlite3_finalize(stmt) }
            for event in events {
                sqlite3_reset(stmt)
                sqlite3_clear_bindings(stmt)
                bindText(stmt, 1, event.id.uuidString)
                sqlite3_bind_double(stmt, 2, event.timestamp.timeIntervalSince1970)
                bindText(stmt, 3, event.remoteIP)
                bindText(stmt, 4, event.domain)
                if let port = event.remotePort {
                    sqlite3_bind_int(stmt, 5, Int32(port))
                } else {
                    sqlite3_bind_null(stmt, 5)
                }
                sqlite3_bind_int(stmt, 6, Int32(event.protocolNumber))
                sqlite3_bind_int64(stmt, 7, Int64(bitPattern: event.bytesUp))
                sqlite3_bind_int64(stmt, 8, Int64(bitPattern: event.bytesDown))
                bindText(stmt, 9, event.verdict.rawValue)
                bindText(stmt, 10, event.matchedRuleID?.uuidString)
                bindText(stmt, 11, event.profileID?.uuidString)
                bindText(stmt, 12, event.countryCode)
                bindText(stmt, 13, event.networkType.rawValue)
                bindText(stmt, 14, event.verdictSource?.rawValue)
                bindText(stmt, 15, event.inferredDomain)
                guard sqlite3_step(stmt) == SQLITE_DONE else {
                    throw StoreError(reason: "insert step: \(message(db))")
                }
            }
            try exec(db, "COMMIT")
        } catch {
            try? exec(db, "ROLLBACK")
            throw error
        }
    }

    /// The fifteen columns every full-row read selects, in the order
    /// `trafficEvent(_:)` reads them. The order differs from the struct's field
    /// order (`verdict_source` and `inferred_domain` were added later), so keep
    /// both in sync through this one list.
    private static let eventColumns = """
    id, ts, remote_ip, domain, remote_port, proto, bytes_up, bytes_down, verdict, \
    matched_rule_id, profile_id, country, network, verdict_source, inferred_domain
    """

    /// Newest-first page of history; pass `before` to page further back.
    public func recent(limit: Int, before: Date? = nil) throws -> [TrafficEvent] {
        let db = try handle()
        let sql = "SELECT \(Self.eventColumns) FROM events"
            + (before != nil ? " WHERE ts < ?" : "")
            + " ORDER BY ts DESC LIMIT ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare select: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        var index: Int32 = 1
        if let before {
            sqlite3_bind_double(stmt, index, before.timeIntervalSince1970)
            index += 1
        }
        sqlite3_bind_int(stmt, index, Int32(max(0, limit)))

        var events: [TrafficEvent] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            events.append(trafficEvent(stmt))
        }
        return events
    }

    /// Builds an event from a `Self.eventColumns` row. A row missing its id or
    /// verdict (only possible through corruption) gets a new UUID and `.allow`
    /// instead of being dropped.
    private func trafficEvent(_ stmt: OpaquePointer?) -> TrafficEvent {
        TrafficEvent(
            id: text(stmt, 0).flatMap(UUID.init(uuidString:)) ?? UUID(),
            timestamp: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 1)),
            remoteIP: text(stmt, 2) ?? "",
            domain: text(stmt, 3),
            remotePort: sqlite3_column_type(stmt, 4) == SQLITE_NULL ? nil : UInt16(truncatingIfNeeded: sqlite3_column_int(stmt, 4)),
            protocolNumber: UInt8(truncatingIfNeeded: sqlite3_column_int(stmt, 5)),
            bytesUp: UInt64(bitPattern: sqlite3_column_int64(stmt, 6)),
            bytesDown: UInt64(bitPattern: sqlite3_column_int64(stmt, 7)),
            verdict: text(stmt, 8).flatMap(RuleAction.init(rawValue:)) ?? .allow,
            verdictSource: text(stmt, 13).flatMap(TrafficEvent.VerdictSource.init(rawValue:)),
            matchedRuleID: text(stmt, 9).flatMap(UUID.init(uuidString:)),
            profileID: text(stmt, 10).flatMap(UUID.init(uuidString:)),
            countryCode: text(stmt, 11),
            networkType: text(stmt, 12).flatMap(TrafficEvent.NetworkType.init(rawValue:)) ?? .other,
            inferredDomain: text(stmt, 14)
        )
    }

    /// One rule's footprint in history: how many flows it decided, and when it
    /// last decided one.
    public struct RuleMatchRollup: Sendable, Equatable {
        public let hits: Int
        public let lastHit: Date
    }

    /// Hit count and last hit time for each id in `ruleIDs` that has matched.
    /// Ids that never matched are absent from the result, not zero.
    ///
    /// The ids aren't bound into the SQL: `matched_rule_id` has no index, so an
    /// IN list doesn't make the scan cheaper, and it could exceed
    /// SQLITE_MAX_VARIABLE_NUMBER (999) with a large rule list. The query rolls
    /// up every rule and filters in Swift; the result size is bounded by the
    /// number of distinct rule ids. An empty set returns without querying.
    public func matchedRuleRollup(for ruleIDs: Set<UUID>) throws -> [UUID: RuleMatchRollup] {
        guard !ruleIDs.isEmpty else { return [:] }
        let db = try handle()
        let sql = """
        SELECT matched_rule_id, COUNT(*), MAX(ts)
        FROM events WHERE matched_rule_id IS NOT NULL GROUP BY matched_rule_id
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare rule rollup: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }

        var rollups: [UUID: RuleMatchRollup] = [:]
        while sqlite3_step(stmt) == SQLITE_ROW {
            // Skip rules the caller didn't ask for, and ids that aren't valid UUIDs.
            guard let id = text(stmt, 0).flatMap(UUID.init(uuidString:)),
                  ruleIDs.contains(id) else { continue }
            rollups[id] = RuleMatchRollup(
                hits: Int(sqlite3_column_int64(stmt, 1)),
                lastHit: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 2))
            )
        }
        return rollups
    }

    /// The `limit` most recent flows this rule decided, newest first.
    ///
    /// Uses `NOT INDEXED` deliberately. With `idx_events_ts`, SQLite walks the
    /// whole index when the rule has no hits (about 0.9 s on 841k rows), which
    /// is the common case. A full scan with a temp B-tree takes a steady
    /// 0.03-0.04 s whether or not the rule matched, and only sorts this rule's
    /// matching rows.
    ///
    /// Callers should still check `matchedRuleRollup(for:)` first and skip this
    /// for rules with no hits.
    public func recentMatches(ruleID: UUID, limit: Int = 20) throws -> [TrafficEvent] {
        let db = try handle()
        let sql = "SELECT \(Self.eventColumns) FROM events NOT INDEXED"
            + " WHERE matched_rule_id = ? ORDER BY ts DESC LIMIT ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare rule matches: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        // Uppercase both sides: the column is written from `uuidString`.
        bindText(stmt, 1, ruleID.uuidString)
        sqlite3_bind_int(stmt, 2, Int32(max(0, limit)))

        var events: [TrafficEvent] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            events.append(trafficEvent(stmt))
        }
        return events
    }

    /// Writes the full history as RFC 4180 CSV to `url`, oldest first, and
    /// returns the row count. Streams rows so large exports don't load into
    /// memory. Columns are the stored metadata fields; timestamps are ISO 8601
    /// UTC.
    @discardableResult
    public func exportCSV(to url: URL) throws -> Int {
        let db = try handle()
        let sql = """
        SELECT ts, domain, remote_ip, remote_port, proto, bytes_up, bytes_down,
               verdict, verdict_source, country, network, inferred_domain
        FROM events ORDER BY ts ASC
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare export: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }

        FileManager.default.createFile(atPath: url.path, contents: nil)
        guard let handle = try? FileHandle(forWritingTo: url) else {
            throw StoreError(reason: "cannot open export file")
        }
        defer { try? handle.close() }

        let formatter = ISO8601DateFormatter()
        var rows = 0
        var chunk = "timestamp,domain,remote_ip,remote_port,protocol,bytes_up,bytes_down,verdict,verdict_source,country,network,inferred_domain\n"
        while sqlite3_step(stmt) == SQLITE_ROW {
            let fields: [String] = [
                formatter.string(from: Date(timeIntervalSince1970: sqlite3_column_double(stmt, 0))),
                text(stmt, 1) ?? "",
                text(stmt, 2) ?? "",
                sqlite3_column_type(stmt, 3) == SQLITE_NULL ? "" : String(sqlite3_column_int64(stmt, 3)),
                String(sqlite3_column_int64(stmt, 4)),
                String(UInt64(bitPattern: sqlite3_column_int64(stmt, 5))),
                String(UInt64(bitPattern: sqlite3_column_int64(stmt, 6))),
                text(stmt, 7) ?? "",
                text(stmt, 8) ?? "",
                text(stmt, 9) ?? "",
                text(stmt, 10) ?? "",
                text(stmt, 11) ?? "",
            ]
            chunk += fields.map(Self.csvEscaped).joined(separator: ",") + "\n"
            rows += 1
            // Flush in bounded chunks so memory stays flat on large stores.
            if chunk.utf8.count > 64 * 1024 {
                try handle.write(contentsOf: Data(chunk.utf8))
                chunk = ""
            }
        }
        if !chunk.isEmpty {
            try handle.write(contentsOf: Data(chunk.utf8))
        }
        return rows
    }

    /// RFC 4180: quote a field containing a comma, quote or newline, and double
    /// embedded quotes. Stored fields rarely need it, but a bad row must not
    /// break the file.
    static func csvEscaped(_ field: String) -> String {
        guard field.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" || $0 == "\r" }) else {
            return field
        }
        return "\"\(field.replacingOccurrences(of: "\"", with: "\"\""))\""
    }

    /// One time bucket of history, used by the History charts. Aggregated in
    /// SQL; charts never load raw rows.
    public struct TimeBucketAggregate: Sendable, Equatable {
        /// Inclusive start of the bucket, aligned to `bucketSeconds` after the
        /// caller's offset (see `bucketAggregates(bucketSeconds:...)`).
        public let bucketStart: Date
        public let flows: Int
        public let blockedFlows: Int
        /// Part of `blockedFlows` from threat intel: filtering-resolver blocks plus
        /// threat feed hits.
        public let threatFlows: Int
        public let bytesUp: UInt64
        public let bytesDown: UInt64
    }

    /// Groups history into fixed buckets of `bucketSeconds` (3600 for hourly,
    /// 86400 for daily). `offsetSeconds` shifts bucket boundaries so days align
    /// to local midnight (pass `TimeZone.current.secondsFromGMT()`). Empty
    /// buckets are omitted; the chart decides whether to fill zeros.
    ///
    /// `until` is the upper edge (nil for none). The range is half-open; see
    /// `timeBounds`.
    public func bucketAggregates(
        bucketSeconds: Int, offsetSeconds: Int = 0, since: Date? = nil, until: Date? = nil
    ) throws -> [TimeBucketAggregate] {
        try bucketRollup(
            bucketSeconds: bucketSeconds, offsetSeconds: offsetSeconds,
            since: since, until: until, target: nil
        )
    }

    /// Same rollup as `bucketAggregates`, limited to one destination, for
    /// per-target sparklines.
    ///
    /// `target` is matched exactly against the same expression the ranking
    /// queries group by (`COALESCE(NULLIF(domain, ''), remote_ip)`), so pass the
    /// string from `TargetAggregate` unchanged. Empty buckets are omitted. No
    /// index covers the expression, but the time bounds use `idx_events_ts` and
    /// retention keeps the table small.
    public func targetBucketAggregates(
        target: String, bucketSeconds: Int, offsetSeconds: Int = 0,
        since: Date? = nil, until: Date? = nil
    ) throws -> [TimeBucketAggregate] {
        try bucketRollup(
            bucketSeconds: bucketSeconds, offsetSeconds: offsetSeconds,
            since: since, until: until, target: target
        )
    }

    /// Shared query for both rollups so "blocked" and "threat" mean the same
    /// thing in each.
    private func bucketRollup(
        bucketSeconds: Int, offsetSeconds: Int, since: Date?, until: Date?, target: String?
    ) throws -> [TimeBucketAggregate] {
        guard bucketSeconds > 0 else {
            throw StoreError(reason: "bucketSeconds must be positive")
        }
        let db = try handle()
        let bounds = Self.timeBounds(since: since, until: until)
        // Added after the time bounds, matching the bind order.
        let filter = target == nil
            ? ""
            : (bounds.clause.isEmpty ? " WHERE " : " AND ")
                + "COALESCE(NULLIF(domain, ''), remote_ip) = ?"
        let sql = """
        SELECT CAST((ts + ?) / ? AS INTEGER),
               COUNT(*),
               SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END),
               \(Self.threatBlockedSum),
               SUM(bytes_up), SUM(bytes_down)
        FROM events
        """
            + bounds.clause
            + filter
            + " GROUP BY 1 ORDER BY 1"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare bucket aggregate: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        sqlite3_bind_double(stmt, 1, Double(offsetSeconds))
        sqlite3_bind_double(stmt, 2, Double(bucketSeconds))
        let next = bind(bounds.values, to: stmt, from: 3)
        if let target { bindText(stmt, next, target) }

        var rows: [TimeBucketAggregate] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let bucket = sqlite3_column_int64(stmt, 0)
            rows.append(TimeBucketAggregate(
                bucketStart: Date(timeIntervalSince1970:
                    Double(bucket) * Double(bucketSeconds) - Double(offsetSeconds)),
                flows: Int(sqlite3_column_int64(stmt, 1)),
                blockedFlows: Int(sqlite3_column_int64(stmt, 2)),
                threatFlows: Int(sqlite3_column_int64(stmt, 3)),
                bytesUp: UInt64(bitPattern: sqlite3_column_int64(stmt, 4)),
                bytesDown: UInt64(bitPattern: sqlite3_column_int64(stmt, 5))
            ))
        }
        return rows
    }

    /// One destination's rollup for the History ranking. `target` is the domain
    /// when the flow had one, otherwise the IP (leaf's fake-DNS names most
    /// flows; IP-literal traffic ranks by address).
    public struct TargetAggregate: Sendable, Equatable {
        public let target: String
        public let isDomain: Bool
        public let flows: Int
        public let blockedFlows: Int
        /// Part of `blockedFlows` blocked by a DoH resolver (both filtering and
        /// custom) rather than the rule engine.
        ///
        /// Lets a rollup-based UI tell whether an Allow rule would do anything:
        /// if every block came from the resolver (`blockedFlows > 0 &&
        /// resolverBlockedFlows == blockedFlows`), an Allow rule can't help,
        /// because the resolver never returned an address.
        public let resolverBlockedFlows: Int
        /// Part of `blockedFlows` from threat intel, counted the same way as
        /// `TimeBucketAggregate.threatFlows`. Overlaps `resolverBlockedFlows`
        /// (both include `filteringResolver`); neither can be derived from the
        /// other.
        public let threatFlows: Int
        public let bytesUp: UInt64
        public let bytesDown: UInt64
    }

    /// The resolver-block sum used by every ranking query, defined once so they
    /// all agree. Values are `TrafficEvent.VerdictSource` raw values.
    private static let resolverBlockedSum = """
    SUM(CASE WHEN verdict = 'deny'
              AND verdict_source IN ('filteringResolver', 'customResolver')
             THEN 1 ELSE 0 END)
    """

    /// The threat sum, defined once and shared by the time rollup, the rankings
    /// and the per-IP rollup.
    private static let threatBlockedSum = """
    SUM(CASE WHEN verdict = 'deny'
              AND verdict_source IN ('filteringResolver', 'threatFeed')
             THEN 1 ELSE 0 END)
    """

    /// Number of distinct destinations inside `since..<until`, grouped the same
    /// way as the rankings. The rankings are limited, so this supplies the
    /// "and N more" count.
    public func distinctTargets(since: Date? = nil, until: Date? = nil) throws -> Int {
        let db = try handle()
        let bounds = Self.timeBounds(since: since, until: until)
        let sql = "SELECT COUNT(DISTINCT COALESCE(NULLIF(domain, ''), remote_ip)) FROM events"
            + bounds.clause
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare distinct targets: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        bind(bounds.values, to: stmt, from: 1)
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw StoreError(reason: "distinct targets step: \(message(db))")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Most-contacted destinations inside `since..<until`, most flows first.
    public func topTargets(
        since: Date? = nil, until: Date? = nil, limit: Int = 10
    ) throws -> [TargetAggregate] {
        let db = try handle()
        let bounds = Self.timeBounds(since: since, until: until)
        let sql = """
        SELECT COALESCE(NULLIF(domain, ''), remote_ip),
               MAX(CASE WHEN domain IS NOT NULL AND domain != '' THEN 1 ELSE 0 END),
               COUNT(*),
               SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END),
               \(Self.resolverBlockedSum),
               \(Self.threatBlockedSum),
               SUM(bytes_up), SUM(bytes_down)
        FROM events
        """
            + bounds.clause
            + " GROUP BY 1 ORDER BY COUNT(*) DESC LIMIT ?"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare top targets: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        let index = bind(bounds.values, to: stmt, from: 1)
        sqlite3_bind_int(stmt, index, Int32(max(0, limit)))

        var rows: [TargetAggregate] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            rows.append(targetAggregate(stmt))
        }
        return rows
    }

    /// Most-blocked destinations inside `since..<until`: only targets with at
    /// least one deny, most denies first.
    public func topBlockedTargets(
        since: Date? = nil, until: Date? = nil, limit: Int = 10
    ) throws -> [TargetAggregate] {
        let db = try handle()
        let bounds = Self.timeBounds(since: since, until: until)
        let sql = """
        SELECT COALESCE(NULLIF(domain, ''), remote_ip),
               MAX(CASE WHEN domain IS NOT NULL AND domain != '' THEN 1 ELSE 0 END),
               COUNT(*),
               SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END),
               \(Self.resolverBlockedSum),
               \(Self.threatBlockedSum),
               SUM(bytes_up), SUM(bytes_down)
        FROM events
        """
            + bounds.clause
            + """
         GROUP BY 1
        HAVING SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END) > 0
        ORDER BY 4 DESC LIMIT ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare top blocked: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        let index = bind(bounds.values, to: stmt, from: 1)
        sqlite3_bind_int(stmt, index, Int32(max(0, limit)))

        var rows: [TargetAggregate] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            rows.append(targetAggregate(stmt))
        }
        return rows
    }

    /// Destinations first seen inside `since..<until`, newest first. "First
    /// seen" is judged against all retained history, so a familiar site that
    /// reappears in the window doesn't count.
    ///
    /// Counts cover the target's rows up to `until`. Since a new target has no
    /// rows before `since`, that equals the count inside the window.
    ///
    /// The outer query scans only the window (through `idx_events_ts`), and a
    /// `NOT IN` subquery excludes targets seen before `since`. This is 2-3x
    /// faster than grouping the whole table on a 200k-row store. `NOT IN` is
    /// safe here because `remote_ip` is NOT NULL, so the subquery never yields
    /// NULL. `newTargetsPreFilterMatchesReferenceQuery` checks the results
    /// against the simpler whole-table query.
    public func newTargets(
        since: Date, until: Date? = nil, limit: Int = 10
    ) throws -> [TargetAggregate] {
        let db = try handle()
        let sql = """
        SELECT COALESCE(NULLIF(domain, ''), remote_ip) AS target,
               MAX(CASE WHEN domain IS NOT NULL AND domain != '' THEN 1 ELSE 0 END),
               COUNT(*),
               SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END),
               \(Self.resolverBlockedSum),
               \(Self.threatBlockedSum),
               SUM(bytes_up), SUM(bytes_down)
        FROM events
        WHERE ts >= ?\(until != nil ? " AND ts < ?" : "")
        GROUP BY 1
        HAVING target NOT IN (
                 SELECT COALESCE(NULLIF(domain, ''), remote_ip)
                 FROM events WHERE ts < ?
               )
        ORDER BY MIN(ts) DESC LIMIT ?
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare new targets: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        var index: Int32 = 1
        sqlite3_bind_double(stmt, index, since.timeIntervalSince1970)
        index += 1
        if let until {
            sqlite3_bind_double(stmt, index, until.timeIntervalSince1970)
            index += 1
        }
        // `since` again, for the subquery.
        sqlite3_bind_double(stmt, index, since.timeIntervalSince1970)
        index += 1
        sqlite3_bind_int(stmt, index, Int32(max(0, limit)))

        var rows: [TargetAggregate] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            rows.append(targetAggregate(stmt))
        }
        return rows
    }

    /// The most recent non-empty remote IP for each of `targets` inside
    /// `since..<until`, so ranking rows can show a flag. Returns addresses only;
    /// the app does the GeoIP lookup (the tunnel never does).
    ///
    /// Newest, so a name that moved CDNs shows where it is now. Non-empty,
    /// because older domain rows have an empty `remote_ip`; a target with only
    /// such rows is missing from the result, which means "no flag".
    ///
    /// One query for the whole list (callers pass up to about 15 targets), and
    /// the time bounds go in the WHERE clause so the scan uses `idx_events_ts`.
    ///
    /// The bare `remote_ip` next to `MAX(ts)` relies on SQLite's documented
    /// behavior: with `max()`, bare columns come from the row holding the
    /// maximum. That isn't portable SQL, but a correlated `ORDER BY ts DESC
    /// LIMIT 1` per target was about 2.6x slower.
    public func latestRemoteIPs(
        for targets: [String], since: Date? = nil, until: Date? = nil
    ) throws -> [String: String] {
        // Deduplicate, since the ranking sections overlap.
        var seen = Set<String>()
        let wanted = targets.filter { seen.insert($0).inserted }
        guard !wanted.isEmpty else { return [:] }
        let db = try handle()
        let bounds = Self.timeBounds(since: since, until: until)
        let placeholders = Array(repeating: "?", count: wanted.count).joined(separator: ", ")
        let sql = """
        SELECT COALESCE(NULLIF(domain, ''), remote_ip), remote_ip, MAX(ts)
        FROM events
        """
            + (bounds.clause.isEmpty ? " WHERE " : bounds.clause + " AND ")
            + """
        remote_ip != ''
          AND COALESCE(NULLIF(domain, ''), remote_ip) IN (\(placeholders))
        GROUP BY 1
        """
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare latest remote IPs: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        // Bounds first, then the list, matching the clause order.
        var index = bind(bounds.values, to: stmt, from: 1)
        for target in wanted {
            bindText(stmt, index, target)
            index += 1
        }

        var latest: [String: String] = [:]
        while sqlite3_step(stmt) == SQLITE_ROW {
            guard let target = text(stmt, 0), let ip = text(stmt, 1), !ip.isEmpty else { continue }
            latest[target] = ip
        }
        return latest
    }

    /// Reads the eight columns every ranking query selects, in order.
    private func targetAggregate(_ stmt: OpaquePointer?) -> TargetAggregate {
        TargetAggregate(
            target: text(stmt, 0) ?? "",
            isDomain: sqlite3_column_int64(stmt, 1) == 1,
            flows: Int(sqlite3_column_int64(stmt, 2)),
            blockedFlows: Int(sqlite3_column_int64(stmt, 3)),
            resolverBlockedFlows: Int(sqlite3_column_int64(stmt, 4)),
            threatFlows: Int(sqlite3_column_int64(stmt, 5)),
            bytesUp: UInt64(bitPattern: sqlite3_column_int64(stmt, 6)),
            bytesDown: UInt64(bitPattern: sqlite3_column_int64(stmt, 7))
        )
    }

    /// Per-IP rollup used by the world map. Groups by `remote_ip` rather than
    /// the `country` column, which is always NULL on device: the tunnel doesn't
    /// do GeoIP (it would cost extension memory), so only the app maps IPs to
    /// countries. Distinct IPs are bounded by retention.
    public struct IPAggregate: Sendable, Equatable {
        public let remoteIP: String
        public let flows: Int
        public let blockedFlows: Int
        /// Part of `blockedFlows` from threat intel, same expression as
        /// `TargetAggregate.threatFlows`. `CountryAggregate` sums it per country.
        public let threatFlows: Int
        public let bytesUp: UInt64
        public let bytesDown: UInt64
    }

    /// One country's merged rollup for the world map. Built by
    /// `CountryAggregate.aggregate(_:countryFor:)` rather than SQL (see
    /// `IPAggregate`). IPs the lookup can't place (private ranges, missing from
    /// the database) go into a single `countryCode == nil` bucket so totals add
    /// up.
    public struct CountryAggregate: Sendable, Equatable {
        public let countryCode: String?
        public let flows: Int
        public let blockedFlows: Int
        /// Part of `blockedFlows` from threat intel: the sum of the per-IP values.
        public let threatFlows: Int
        public let bytesUp: UInt64
        public let bytesDown: UInt64

        /// Merges per-IP rollups into per-country rollups using `countryFor`
        /// (injected so SharedCore doesn't depend on GeoIP), most flows first.
        public static func aggregate(
            _ ips: [IPAggregate], countryFor: (String) -> String?
        ) -> [CountryAggregate] {
            var flows: [String?: (Int, Int, Int, UInt64, UInt64)] = [:]
            for ip in ips {
                let key = countryFor(ip.remoteIP)
                let old = flows[key] ?? (0, 0, 0, 0, 0)
                flows[key] = (old.0 + ip.flows, old.1 + ip.blockedFlows, old.2 + ip.threatFlows,
                              old.3 &+ ip.bytesUp, old.4 &+ ip.bytesDown)
            }
            return flows.map { key, sums in
                CountryAggregate(countryCode: key, flows: sums.0, blockedFlows: sums.1,
                                 threatFlows: sums.2, bytesUp: sums.3, bytesDown: sums.4)
            }
            .sorted { $0.flows > $1.flows }
        }
    }

    /// Aggregates events inside `since..<until` (both nil = all history), most
    /// flows first.
    public func ipAggregates(since: Date? = nil, until: Date? = nil) throws -> [IPAggregate] {
        let db = try handle()
        let bounds = Self.timeBounds(since: since, until: until)
        let sql = """
        SELECT remote_ip, COUNT(*),
               SUM(CASE WHEN verdict = 'deny' THEN 1 ELSE 0 END),
               \(Self.threatBlockedSum),
               SUM(bytes_up), SUM(bytes_down)
        FROM events
        """
            + bounds.clause
            + " GROUP BY remote_ip ORDER BY COUNT(*) DESC"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare aggregate: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        bind(bounds.values, to: stmt, from: 1)

        var rows: [IPAggregate] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            rows.append(IPAggregate(
                remoteIP: text(stmt, 0) ?? "",
                flows: Int(sqlite3_column_int64(stmt, 1)),
                blockedFlows: Int(sqlite3_column_int64(stmt, 2)),
                threatFlows: Int(sqlite3_column_int64(stmt, 3)),
                bytesUp: UInt64(bitPattern: sqlite3_column_int64(stmt, 4)),
                bytesDown: UInt64(bitPattern: sqlite3_column_int64(stmt, 5))
            ))
        }
        return rows
    }

    public func count() throws -> Int {
        let db = try handle()
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM events", -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "prepare count: \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw StoreError(reason: "count step: \(message(db))")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Drops rows older than `maxAge`, then the oldest rows beyond `maxRows`.
    /// Returns the number of rows deleted.
    ///
    /// SQLite doesn't return freed pages to the filesystem, so after shrinking
    /// retention the file would stay at its peak size. When enough pages are
    /// free, the prune ends with VACUUM and a WAL truncate; the threshold keeps
    /// no-op prunes cheap.
    @discardableResult
    public func prune(maxAge: TimeInterval = 7 * 24 * 3600, maxRows: Int = 20_000) throws -> Int {
        let db = try handle()
        let cutoff = Date().timeIntervalSince1970 - maxAge
        try exec(db, "DELETE FROM events WHERE ts < \(cutoff)")
        var deleted = Int(sqlite3_changes(db))
        try exec(db, "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY ts DESC LIMIT -1 OFFSET \(max(0, maxRows)))")
        deleted += Int(sqlite3_changes(db))

        if deleted > 0,
           let free = try? pragmaInt(db, "freelist_count"),
           let total = try? pragmaInt(db, "page_count"),
           free > 50, free * 4 > total {
            try exec(db, "VACUUM")
            try exec(db, "PRAGMA wal_checkpoint(TRUNCATE)")
        }
        return deleted
    }

    private func pragmaInt(_ db: OpaquePointer, _ name: String) throws -> Int {
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, "PRAGMA \(name)", -1, &stmt, nil) == SQLITE_OK else {
            throw StoreError(reason: "pragma \(name): \(message(db))")
        }
        defer { sqlite3_finalize(stmt) }
        guard sqlite3_step(stmt) == SQLITE_ROW else {
            throw StoreError(reason: "pragma \(name) step: \(message(db))")
        }
        return Int(sqlite3_column_int64(stmt, 0))
    }

    /// Erases all history: deletes rows, vacuums (rewriting without freed pages)
    /// and truncates the WAL so no event data remains on disk.
    public func wipe() throws {
        let db = try handle()
        try exec(db, "DELETE FROM events")
        try exec(db, "VACUUM")
        try exec(db, "PRAGMA wal_checkpoint(TRUNCATE)")
    }

    // MARK: - Connection

    private func handle() throws -> OpaquePointer {
        if let db { return db }
        let fm = FileManager.default
        try fm.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        let path = directoryURL.appendingPathComponent("events.sqlite").path
        var handle: OpaquePointer?
        guard sqlite3_open(path, &handle) == SQLITE_OK, let handle else {
            let reason = handle.map { message($0) } ?? "open failed"
            sqlite3_close_v2(handle)
            throw StoreError(reason: "open \(path): \(reason)")
        }
        db = handle
        // WAL for one writer plus readers across processes; the busy timeout covers
        // overlapping access.
        try exec(handle, "PRAGMA journal_mode=WAL")
        sqlite3_busy_timeout(handle, 2000)
        try exec(handle, """
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY,
          ts REAL NOT NULL,
          remote_ip TEXT NOT NULL,
          domain TEXT,
          remote_port INTEGER,
          proto INTEGER NOT NULL,
          bytes_up INTEGER NOT NULL,
          bytes_down INTEGER NOT NULL,
          verdict TEXT NOT NULL,
          matched_rule_id TEXT,
          profile_id TEXT,
          country TEXT,
          network TEXT,
          verdict_source TEXT
        )
        """)
        // Migration for databases created before verdict_source existed. Once
        // migrated it fails with "duplicate column", so the error is ignored.
        try? exec(handle, "ALTER TABLE events ADD COLUMN verdict_source TEXT")
        // Same migration pattern for inferred_domain.
        try? exec(handle, "ALTER TABLE events ADD COLUMN inferred_domain TEXT")
        try exec(handle, "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
        // Same protection class as the rule snapshot (until first unlock), so the
        // extension can read and write while the device is locked after first
        // unlock.
        applyProtection(to: path)
        return handle
    }

    private func applyProtection(to path: String) {
        let attrs: [FileAttributeKey: Any] = [
            .protectionKey: FileProtectionType.completeUntilFirstUserAuthentication,
        ]
        for suffix in ["", "-wal", "-shm"] {
            try? FileManager.default.setAttributes(attrs, ofItemAtPath: path + suffix)
        }
    }

    // MARK: - SQLite helpers

    /// `since..<until` as a WHERE clause plus the values to bind, in order.
    /// Either edge may be nil; both nil means no clause.
    ///
    /// The range is half-open (`>= since`, `< until`) so adjacent windows don't
    /// both count rows at the shared instant.
    private static func timeBounds(
        since: Date?, until: Date?
    ) -> (clause: String, values: [Double]) {
        var conditions: [String] = []
        var values: [Double] = []
        if let since {
            conditions.append("ts >= ?")
            values.append(since.timeIntervalSince1970)
        }
        if let until {
            conditions.append("ts < ?")
            values.append(until.timeIntervalSince1970)
        }
        guard !conditions.isEmpty else { return ("", []) }
        return (" WHERE " + conditions.joined(separator: " AND "), values)
    }

    /// Binds `values` starting at `start` and returns the next free index.
    @discardableResult
    private func bind(
        _ values: [Double], to stmt: OpaquePointer?, from start: Int32
    ) -> Int32 {
        var index = start
        for value in values {
            sqlite3_bind_double(stmt, index, value)
            index += 1
        }
        return index
    }

    private func exec(_ db: OpaquePointer, _ sql: String) throws {
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw StoreError(reason: "exec \(sql.prefix(32)): \(message(db))")
        }
    }

    private func message(_ db: OpaquePointer) -> String {
        String(cString: sqlite3_errmsg(db))
    }

    private let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    private func bindText(_ stmt: OpaquePointer?, _ index: Int32, _ value: String?) {
        if let value {
            sqlite3_bind_text(stmt, index, value, -1, transient)
        } else {
            sqlite3_bind_null(stmt, index)
        }
    }

    private func text(_ stmt: OpaquePointer?, _ column: Int32) -> String? {
        sqlite3_column_text(stmt, column).map { String(cString: $0) }
    }
}
