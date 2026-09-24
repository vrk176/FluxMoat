import Foundation
import Testing
@testable import SharedCore

/// `targetBucketAggregates` is the per-target time rollup the Insights
/// target sheet draws its sparkline from.
///
/// Covers three things: it respects the same window edges as the other
/// rollups, it actually filters to the named target, and it agrees with
/// the unfiltered rollup when only one target exists.
@Suite struct TrafficEventStoreTargetBucketsTests {
    private func makeStore() -> (TrafficEventStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fluxmoat-targetbuckets-\(UUID().uuidString)", isDirectory: true)
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

    // MARK: - Filtering

    /// Two destinations share every bucket. Counts, blocked share, and bytes
    /// must all come back scoped to the requested target.
    @Test func filtersToTheNamedTargetOnly() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        try store.append([
            event("ads.example", at: base, verdict: .deny, up: 1, down: 2),
            event("ads.example", at: base.addingTimeInterval(60), up: 3, down: 4),
            event("cdn.example", at: base.addingTimeInterval(120), up: 100, down: 200),
            event("cdn.example", at: base.addingTimeInterval(3700), up: 5, down: 6),
        ])

        let ads = try store.targetBucketAggregates(target: "ads.example", bucketSeconds: 3600)
        #expect(ads.count == 1)
        #expect(ads[0].flows == 2)
        #expect(ads[0].blockedFlows == 1)
        #expect(ads[0].bytesUp == 4 && ads[0].bytesDown == 6)

        // The neighbour spans two hours and has no denies at all.
        let cdn = try store.targetBucketAggregates(target: "cdn.example", bucketSeconds: 3600)
        #expect(cdn.map(\.flows) == [1, 1])
        #expect(cdn.allSatisfy { $0.blockedFlows == 0 })

        // A name nobody talked to returns empty, not everything.
        #expect(try store.targetBucketAggregates(
            target: "never.example", bucketSeconds: 3600).isEmpty)
    }

    /// Nameless flows rank by address via
    /// `COALESCE(NULLIF(domain, ''), remote_ip)`; an empty-string domain
    /// must fall through to the address the same way.
    @Test func matchesTheAddressWhenAFlowHasNoName() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        try store.append([
            event(nil, at: base, ip: "198.51.100.4"),
            event("", at: base.addingTimeInterval(30), ip: "198.51.100.4"),
            event("named.example", at: base.addingTimeInterval(60), ip: "198.51.100.4"),
        ])

        let byAddress = try store.targetBucketAggregates(
            target: "198.51.100.4", bucketSeconds: 3600)
        #expect(byAddress.count == 1)
        // The named flow shares the address but ranks under its own name.
        #expect(byAddress[0].flows == 2)
        #expect(try store.targetBucketAggregates(
            target: "named.example", bucketSeconds: 3600).first?.flows == 1)
    }

    // MARK: - Window edges

    /// Same half-open contract as the other rollups: `since` inclusive,
    /// `until` exclusive. This query binds its own predicate after the edge
    /// params, so it needs its own check.
    @Test func honorsTheHalfOpenWindow() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        let middle = base.addingTimeInterval(3600)
        let late = base.addingTimeInterval(7200)
        try store.append([
            event("one.example", at: base),
            event("one.example", at: middle),
            event("one.example", at: late),
        ])

        let bounded = try store.targetBucketAggregates(
            target: "one.example", bucketSeconds: 3600, since: middle, until: late)
        #expect(bounded.count == 1)
        #expect(bounded[0].flows == 1)
        // Read bucketStart off the unfiltered rollup rather than recomputing
        // the bucket grid math here.
        #expect(bounded[0].bucketStart == (try store.bucketAggregates(
            bucketSeconds: 3600, since: middle, until: late)).first?.bucketStart)

        // The lower edge keeps its own instant, the upper edge gives it away.
        #expect(try store.targetBucketAggregates(
            target: "one.example", bucketSeconds: 3600, since: middle, until: middle).isEmpty)
        #expect(try store.targetBucketAggregates(
            target: "one.example", bucketSeconds: 3600, since: base).count == 3)

        // No bounds at all exercises the branch where the filter has to
        // introduce the WHERE clause itself.
        #expect(try store.targetBucketAggregates(target: "one.example", bucketSeconds: 3600)
                == store.targetBucketAggregates(
                    target: "one.example", bucketSeconds: 3600, since: nil, until: nil))
    }

    // MARK: - Parity with the page chart

    /// A fixture with exactly one destination, so the filter can't change
    /// the answer: the per-target and unfiltered rollups must then agree
    /// bucket for bucket, field for field.
    @Test func matchesTheUnfilteredRollupWhenOnlyOneTargetExists() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let base = Date(timeIntervalSince1970: 1_780_000_000)
        var events: [TrafficEvent] = []
        for hour in 0..<6 {
            // Uneven counts with two empty hours, so this checks a real
            // shape rather than a flat line.
            for i in 0..<(hour == 2 || hour == 4 ? 0 : hour + 1) {
                events.append(event(
                    "solo.example",
                    at: base.addingTimeInterval(Double(hour * 3600 + i * 30)),
                    verdict: i.isMultiple(of: 3) ? .deny : .allow,
                    source: i.isMultiple(of: 3) ? .threatFeed : nil,
                    up: UInt64(i + 1), down: UInt64(hour + 1)
                ))
            }
        }
        try store.append(events)

        // Every offset the app actually passes: UTC and a local-midnight
        // shift either side of it.
        for offset in [0, 8 * 3600, -5 * 3600] {
            let all = try store.bucketAggregates(bucketSeconds: 3600, offsetSeconds: offset)
            let solo = try store.targetBucketAggregates(
                target: "solo.example", bucketSeconds: 3600, offsetSeconds: offset)
            #expect(solo == all, "per-target rollup diverged at offset \(offset)")
        }
        // Not vacuous: four non-empty hours and a nonzero threat count.
        let buckets = try store.targetBucketAggregates(
            target: "solo.example", bucketSeconds: 3600)
        #expect(buckets.count == 4)
        #expect(buckets.reduce(0) { $0 + $1.threatFlows } > 0)

        // The bounded pair agrees too, since the filter shares the same
        // WHERE clause as the edges.
        let edge = base.addingTimeInterval(3 * 3600)
        #expect(try store.targetBucketAggregates(
            target: "solo.example", bucketSeconds: 3600, since: base, until: edge)
                == store.bucketAggregates(bucketSeconds: 3600, since: base, until: edge))
    }
}
