import Foundation
import Testing
@testable import SharedCore

/// `latestRemoteIPs` is the lookup that lets a historical ranking row draw
/// a flag.
///
/// Covers four things: it picks the newest address, skips empty ones (old
/// rows have no address at all), respects the window edges, and reports a
/// target it has nothing for as absent rather than empty.
@Suite struct TrafficEventStoreLatestIPTests {
    private func makeStore() -> (TrafficEventStore, URL) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("fluxmoat-latestip-\(UUID().uuidString)", isDirectory: true)
        return (TrafficEventStore(directoryURL: dir), dir)
    }

    private func event(_ domain: String?, ip: String, at ts: Date) -> TrafficEvent {
        TrafficEvent(
            timestamp: ts, remoteIP: ip, domain: domain, remotePort: 443,
            protocolNumber: 6, bytesUp: 1, bytesDown: 2, verdict: .allow,
            networkType: .wifi
        )
    }

    private let base = Date(timeIntervalSince1970: 1_780_000_000)

    // MARK: - Which address wins

    /// A name that answered from two hosts, plus a third, newest row with
    /// no address at all. Picking recency alone would return that empty
    /// string, and CountryFlag would draw a globe for a target whose
    /// country is known one row down.
    @Test func picksTheNewestNonEmptyAddress() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([
            event("cdn.example", ip: "198.51.100.4", at: base),
            event("cdn.example", ip: "203.0.113.9", at: base.addingTimeInterval(60)),
            event("cdn.example", ip: "", at: base.addingTimeInterval(120)),
        ])

        #expect(try store.latestRemoteIPs(for: ["cdn.example"]) == ["cdn.example": "203.0.113.9"])
    }

    /// Regression: old rows have no address on disk at all. The target
    /// should come back missing rather than empty, the caller's cue to
    /// draw the globe.
    @Test func targetWithOnlyPreFixRowsIsAbsent() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([
            event("old.example", ip: "", at: base),
            event("old.example", ip: "", at: base.addingTimeInterval(60)),
            event("new.example", ip: "203.0.113.9", at: base.addingTimeInterval(90)),
        ])

        let found = try store.latestRemoteIPs(for: ["old.example", "new.example"])
        #expect(found["old.example"] == nil)
        #expect(found["new.example"] == "203.0.113.9")
    }

    /// A nameless flow ranks by its address via
    /// `COALESCE(NULLIF(domain, ''), remote_ip)`, so asking about one must
    /// hand the address straight back.
    @Test func addressTargetsAnswerWithThemselves() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([
            event(nil, ip: "198.51.100.4", at: base),
            event("", ip: "198.51.100.4", at: base.addingTimeInterval(30)),
            // Shares the address but ranks under its own name.
            event("named.example", ip: "198.51.100.4", at: base.addingTimeInterval(60)),
        ])

        #expect(try store.latestRemoteIPs(for: ["198.51.100.4"])
            == ["198.51.100.4": "198.51.100.4"])
    }

    // MARK: - Window edges

    /// Half-open like the other rollups: `since` inclusive, `until`
    /// exclusive. The flag must come from the newest row inside the
    /// window, not after it.
    @Test func respectsWindowBounds() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        let middle = base.addingTimeInterval(3600)
        let late = base.addingTimeInterval(7200)
        try store.append([
            event("cdn.example", ip: "198.51.100.4", at: base),
            event("cdn.example", ip: "203.0.113.9", at: middle),
            event("cdn.example", ip: "192.0.2.77", at: late),
        ])

        // Unbounded: the last one wins.
        #expect(try store.latestRemoteIPs(for: ["cdn.example"])["cdn.example"] == "192.0.2.77")
        // Closed at the top: the late row is outside, so the middle one wins.
        #expect(try store.latestRemoteIPs(for: ["cdn.example"], until: late)["cdn.example"]
            == "203.0.113.9")
        // `since` is inclusive, so the row sitting exactly on the edge counts.
        #expect(try store.latestRemoteIPs(for: ["cdn.example"], since: middle, until: late)["cdn.example"]
            == "203.0.113.9")
        // An empty half-open window holds nothing at all.
        #expect(try store.latestRemoteIPs(for: ["cdn.example"], since: middle, until: middle).isEmpty)
    }

    // MARK: - What it does with a list

    /// The mixed ask the Trends page makes: several names, one contacted
    /// only outside the window. Unknown targets are absent, and an empty
    /// ask is a no-op rather than an `IN ()` the parser would reject.
    @Test func unknownTargetsAreAbsentAndAnEmptyAskIsFree() throws {
        let (store, dir) = makeStore()
        defer { try? FileManager.default.removeItem(at: dir) }
        try store.append([
            event("a.example", ip: "198.51.100.4", at: base),
            event("b.example", ip: "203.0.113.9", at: base.addingTimeInterval(60)),
            event("gone.example", ip: "192.0.2.77", at: base.addingTimeInterval(-7200)),
        ])

        let found = try store.latestRemoteIPs(
            for: ["a.example", "b.example", "gone.example", "never.example"],
            since: base
        )
        #expect(found == ["a.example": "198.51.100.4", "b.example": "203.0.113.9"])
        #expect(try store.latestRemoteIPs(for: []).isEmpty)
        // Duplicates collapse rather than lengthening the IN list.
        #expect(try store.latestRemoteIPs(for: ["a.example", "a.example"])
            == ["a.example": "198.51.100.4"])
    }
}
