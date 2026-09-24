import Foundation
import Testing
@testable import SharedCore

@Suite struct TrafficEventBufferTests {
    private func event(_ domain: String, up: UInt64 = 0, down: UInt64 = 0) -> TrafficEvent {
        TrafficEvent(remoteIP: "", domain: domain, remotePort: 443, protocolNumber: 6,
                     bytesUp: up, bytesDown: down, verdict: .allow)
    }

    @Test func appendAndDrainReturnsInOrderThenClears() {
        var buffer = TrafficEventBuffer(capacity: 8)
        buffer.append(event("a.example"))
        buffer.append(event("b.example"))
        let drained = buffer.drain()
        #expect(drained.map(\.domain) == ["a.example", "b.example"])
        // Drain clears, so a second drain is empty (each event delivered once).
        #expect(buffer.drain().isEmpty)
    }

    @Test func overflowDropsOldest() {
        var buffer = TrafficEventBuffer(capacity: 3)
        for name in ["a", "b", "c", "d", "e"] { buffer.append(event("\(name).example")) }
        // Only the newest 3 survive.
        #expect(buffer.drain().map(\.domain) == ["c.example", "d.example", "e.example"])
    }

    @Test func capacityIsAtLeastOne() {
        var buffer = TrafficEventBuffer(capacity: 0)
        buffer.append(event("a.example"))
        buffer.append(event("b.example"))
        #expect(buffer.drain().map(\.domain) == ["b.example"])
    }
}

@Suite struct ProviderRecentEventsTests {
    @Test func recentEventsRequestRoundTrips() throws {
        let decoded = try ProviderRequest.decoded(from: ProviderRequest.recentEvents.encoded())
        if case .recentEvents = decoded {} else { Issue.record("wrong case") }
    }

    @Test func recentEventsResponseRoundTripsPreservingFields() throws {
        let events = [
            TrafficEvent(remoteIP: "1.1.1.1", domain: "dns.example", remotePort: 443,
                         protocolNumber: 6, bytesUp: 100, bytesDown: 2000, verdict: .allow,
                         countryCode: "US", networkType: .wifi),
            TrafficEvent(remoteIP: "", domain: "ads.tracker.example", remotePort: 443,
                         protocolNumber: 17, bytesUp: 5, bytesDown: 0, verdict: .deny),
        ]
        let response = ProviderResponse.recentEvents(events)
        let decoded = try ProviderResponse.decoded(from: response.encoded())
        guard case .recentEvents(let back) = decoded else {
            Issue.record("wrong case"); return
        }
        #expect(back.count == 2)
        #expect(back[0].domain == "dns.example")
        #expect(back[0].bytesDown == 2000)
        #expect(back[0].verdict == .allow)
        #expect(back[1].verdict == .deny)
        #expect(back[1].protocolNumber == 17)
    }

    /// Old-format responses (no recentEvents case) must still decode: the
    /// new case is appended, so existing cases are unaffected.
    @Test func existingCasesUnaffected() throws {
        let counters = ProviderResponse.liveCounters(
            .init(bytesUpPerSecond: 1, bytesDownPerSecond: 2, activeFlows: 3, blockedToday: 4))
        if case .liveCounters(let c) = try ProviderResponse.decoded(from: counters.encoded()) {
            #expect(c.activeFlows == 3)
        } else {
            Issue.record("wrong case")
        }
    }

    /// Both appended-optional fields must decode as nil from payloads written
    /// before they existed (older tunnel process answering a newer app).
    @Test func legacyPayloadsWithoutAppendedFieldsDecodeAsNil() throws {
        let legacyCounters = Data("""
        {"bytesUpPerSecond":1,"bytesDownPerSecond":2,"activeFlows":3,"blockedToday":4}
        """.utf8)
        let counters = try JSONDecoder().decode(ProviderResponse.LiveCounters.self, from: legacyCounters)
        #expect(counters.blockedToday == 4)
        #expect(counters.threatBlockedToday == nil)

        let legacyEvent = Data("""
        {"id":"\(UUID().uuidString)","timestamp":700000000,"remoteIP":"","domain":"a.example",
         "protocolNumber":6,"bytesUp":0,"bytesDown":0,"verdict":"deny","networkType":"wifi"}
        """.utf8)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        let event = try decoder.decode(TrafficEvent.self, from: legacyEvent)
        #expect(event.verdict == .deny)
        #expect(event.verdictSource == nil)
    }

    @Test func verdictSourceRoundTripsThroughProviderMessaging() throws {
        let response = ProviderResponse.recentEvents([
            TrafficEvent(remoteIP: "", domain: "sunk.example", protocolNumber: 6,
                         verdict: .deny, verdictSource: .filteringResolver),
        ])
        guard case .recentEvents(let back) = try ProviderResponse.decoded(from: response.encoded()) else {
            Issue.record("wrong case"); return
        }
        #expect(back[0].verdictSource == .filteringResolver)

        let withThreats = ProviderResponse.liveCounters(
            .init(bytesUpPerSecond: 0, bytesDownPerSecond: 0, activeFlows: 0,
                  blockedToday: 7, threatBlockedToday: 2))
        if case .liveCounters(let c) = try ProviderResponse.decoded(from: withThreats.encoded()) {
            #expect(c.threatBlockedToday == 2)
        } else {
            Issue.record("wrong case")
        }
    }
}
