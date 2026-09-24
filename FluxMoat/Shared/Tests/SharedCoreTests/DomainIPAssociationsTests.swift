import Foundation
import Testing
@testable import SharedCore

@Suite struct DomainIPAssociationsTests {
    private let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    /// Fresh answers look up by any of their addresses; expiry ends it.
    @Test func recordsLookupAndExpires() {
        var assoc = DomainIPAssociations()
        assoc.record(domain: "api.example", addresses: ["93.184.216.34", "2606:2800:220:1::1"], now: t0)
        #expect(assoc.lookup(ip: "93.184.216.34", now: t0.addingTimeInterval(60)) == "api.example")
        #expect(assoc.lookup(ip: "93.184.216.34", now: t0.addingTimeInterval(DomainIPAssociations.ttl + 1)) == nil)
        #expect(assoc.lookup(ip: "198.51.100.1", now: t0) == nil)
    }

    /// v6 spelling differences normalize to the same key.
    @Test func normalizesIPv6Spellings() {
        var assoc = DomainIPAssociations()
        assoc.record(domain: "v6.example", addresses: ["2606:2800:0220:0001::1"], now: t0)
        #expect(assoc.lookup(ip: "2606:2800:220:1:0:0:0:1", now: t0) == "v6.example")
    }

    /// The most recent answer wins attribution for a shared IP: a CDN
    /// address re-resolved from another name re-attributes, which is why
    /// associations are display-only.
    @Test func newestAnswerOverwritesSharedIP() {
        var assoc = DomainIPAssociations()
        assoc.record(domain: "first.example", addresses: ["203.0.113.7"], now: t0)
        assoc.record(domain: "second.example", addresses: ["203.0.113.7"], now: t0.addingTimeInterval(10))
        #expect(assoc.lookup(ip: "203.0.113.7", now: t0.addingTimeInterval(20)) == "second.example")
    }

    /// Bounded: over capacity, the soonest-to-expire entries are evicted;
    /// invalid address strings never enter the table.
    @Test func capacityEvictsOldestAndSkipsInvalid() {
        var assoc = DomainIPAssociations(capacity: 4)
        for i in 0..<6 {
            assoc.record(domain: "d\(i).example", addresses: ["10.0.0.\(i)"],
                         now: t0.addingTimeInterval(Double(i)))
        }
        #expect(assoc.count <= 4)
        #expect(assoc.lookup(ip: "10.0.0.0", now: t0.addingTimeInterval(10)) == nil)
        #expect(assoc.lookup(ip: "10.0.0.5", now: t0.addingTimeInterval(10)) == "d5.example")

        assoc.record(domain: "junk.example", addresses: ["not-an-ip"], now: t0)
        #expect(assoc.lookup(ip: "not-an-ip", now: t0) == nil)
    }
}