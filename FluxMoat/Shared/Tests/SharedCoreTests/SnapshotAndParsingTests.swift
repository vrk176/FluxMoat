import Foundation
import Testing
@testable import SharedCore

@Suite struct IPParsingTests {
    @Test func parsesAndFormats() {
        #expect(IPAddress.parse("192.168.1.1")?.isV4 == true)
        #expect(IPAddress.parse("::1")?.isV4 == false)
        #expect(IPAddress.parse("not an ip") == nil)
        #expect(IPAddress.parse("300.1.1.1") == nil)
        #expect(IPAddress.parse("192.168.1.1")?.description == "192.168.1.1")
    }

    @Test func cidrValidation() {
        #expect(CIDRBlock("10.0.0.0/8") != nil)
        #expect(CIDRBlock("10.0.0.0/33") == nil)
        #expect(CIDRBlock("2001:db8::/129") == nil)
        #expect(CIDRBlock("10.0.0.0") == nil)
        #expect(CIDRBlock("garbage/8") == nil)
    }

    @Test func cidrNormalizesHostBits() {
        let a = CIDRBlock("10.1.2.3/8")
        let b = CIDRBlock("10.0.0.0/8")
        #expect(a == b)
    }
}

@Suite struct RuleSnapshotTests {
    private var sampleRules: [Rule] {
        [
            Rule(action: .deny, target: .domain("*.ads.example"), priority: 1, note: "test"),
            Rule(action: .allow, target: .cidr("10.0.0.0/8")),
            Rule(action: .deny, target: .network(protocolNumber: 17, port: 53...53)),
        ]
    }

    @Test func roundTripPreservesRulesAndVerdicts() throws {
        let snapshot = RuleSnapshot(rules: sampleRules, blocklistDomains: ["tracker.example"])
        let data = try snapshot.serialize()
        let restored = try RuleSnapshot.deserialize(data)
        // ISO8601 dates round to whole seconds, so compare semantic fields.
        #expect(restored.rules.map(\.id) == snapshot.rules.map(\.id))
        #expect(restored.rules.map(\.target) == snapshot.rules.map(\.target))
        #expect(restored.rules.map(\.action) == snapshot.rules.map(\.action))
        #expect(restored.blocklistDomains == snapshot.blocklistDomains)

        let set = restored.compile()
        let verdict = set.evaluate(
            FlowDescriptor(domain: "x.ads.example"),
            mode: .standard
        )
        #expect(verdict.action == .deny)
    }

    @Test func threatIPsRoundTripAndMatchAfterCompile() throws {
        let snapshot = RuleSnapshot(rules: [], threatIPs: ["192.0.2.0/24", "2001:db8::1"])
        let restored = try RuleSnapshot.deserialize(try snapshot.serialize())
        #expect(restored.threatIPs == ["192.0.2.0/24", "2001:db8::1"])
        let set = restored.compile()
        #expect(set.evaluate(FlowDescriptor(ip: IPAddress.parse("192.0.2.9")), mode: .standard).source == .threatFeed)
        #expect(set.evaluate(FlowDescriptor(ip: IPAddress.parse("2001:db8::1")), mode: .standard).action == .deny)
    }

    @Test func threatDomainsRoundTripAndReportThreatFeed() throws {
        let snapshot = RuleSnapshot(rules: [], threatDomains: ["malware.example"])
        let restored = try RuleSnapshot.deserialize(try snapshot.serialize())
        #expect(restored.threatDomains == ["malware.example"])
        #expect(restored.compile().evaluate(FlowDescriptor(domain: "malware.example"), mode: .standard).source == .threatFeed)
    }

    /// nil threat fields must stay out of the wire format so older builds keep
    /// decoding new snapshots (same optional-omitting contract as mode/DoH).
    @Test func nilThreatFieldsOmittedFromWireFormat() throws {
        let (data, _) = try RuleSnapshot(rules: []).serializedWithChecksum()
        let json = String(decoding: data, as: UTF8.self)
        #expect(!json.contains("threatIPs"))
        #expect(!json.contains("threatDomains"))
    }

    /// historyRetention rides the snapshot: a set value round-trips, and
    /// nil stays out of the wire format so older builds keep decoding new
    /// snapshots.
    @Test func historyRetentionRoundTripsAndNilIsOmitted() throws {
        let set = try RuleSnapshot.deserialize(
            try RuleSnapshot(rules: [], historyRetention: .months6).serialize())
        #expect(set.historyRetention == .months6)

        let (data, _) = try RuleSnapshot(rules: []).serializedWithChecksum()
        #expect(!String(decoding: data, as: UTF8.self).contains("historyRetention"))
    }

    /// askQuietHours rides the snapshot: a set value round-trips, and nil
    /// stays out of the wire format (same optional-omitting contract).
    @Test func askQuietHoursRoundTripsAndNilIsOmitted() throws {
        let set = try RuleSnapshot.deserialize(
            try RuleSnapshot(rules: [], askQuietHours: QuietHours(startMinute: 1320, endMinute: 420)).serialize())
        #expect(set.askQuietHours == QuietHours(startMinute: 1320, endMinute: 420))

        let (data, _) = try RuleSnapshot(rules: []).serializedWithChecksum()
        #expect(!String(decoding: data, as: UTF8.self).contains("askQuietHours"))
    }

    /// Tells the tunnel whether the configured resolver's sinks may be
    /// called threats. true/false both round-trip; nil stays out of the
    /// wire format and reads back as nil, which the tunnel treats as
    /// "don't claim threat".
    @Test func resolverThreatIntelRoundTripsAndNilIsOmitted() throws {
        let yes = try RuleSnapshot.deserialize(
            try RuleSnapshot(rules: [], resolverThreatIntel: true).serialize())
        #expect(yes.resolverThreatIntel == true)

        let no = try RuleSnapshot.deserialize(
            try RuleSnapshot(rules: [], resolverThreatIntel: false).serialize())
        #expect(no.resolverThreatIntel == false)

        let (data, _) = try RuleSnapshot(rules: []).serializedWithChecksum()
        #expect(!String(decoding: data, as: UTF8.self).contains("resolverThreatIntel"))
        let old = try RuleSnapshot.deserialize(data)
        #expect(old.resolverThreatIntel == nil)
        #expect(old.schemaVersion == RuleSnapshot.currentSchemaVersion)
    }

    @Test func truncatedSnapshotIsRejected() throws {
        let data = try RuleSnapshot(rules: sampleRules).serialize()
        let truncated = data.prefix(data.count - 10)
        #expect(throws: (any Error).self) {
            _ = try RuleSnapshot.deserialize(Data(truncated))
        }
    }

    @Test func corruptedSnapshotIsRejected() throws {
        var data = try RuleSnapshot(rules: sampleRules).serialize()
        data[data.count / 2] ^= 0xFF
        #expect(throws: (any Error).self) {
            _ = try RuleSnapshot.deserialize(data)
        }
    }
}

@Suite struct ProviderMessageTests {
    @Test func requestAndResponseRoundTrip() throws {
        let profileID = UUID()
        let request = ProviderRequest.switchProfile(profileID)
        let decodedRequest = try ProviderRequest.decoded(from: request.encoded())
        if case .switchProfile(let id) = decodedRequest {
            #expect(id == profileID)
        } else {
            Issue.record("wrong case")
        }

        let response = ProviderResponse.liveCounters(
            .init(bytesUpPerSecond: 1, bytesDownPerSecond: 2, activeFlows: 3, blockedToday: 4)
        )
        let decodedResponse = try ProviderResponse.decoded(from: response.encoded())
        if case .liveCounters(let counters) = decodedResponse {
            #expect(counters.blockedToday == 4)
        } else {
            Issue.record("wrong case")
        }
    }
}

@Suite struct LargeListPerformanceTests {
    /// Lookups must stay fast with a 100k-entry blocklist. Bound is
    /// generous to avoid CI flakiness.
    @Test func hundredThousandDomainBlocklistLookups() {
        let domains = (0..<100_000).map { "host\($0).ads.example" }
        let set = CompiledRuleSet(rules: [], blocklistDomains: domains)

        let start = ContinuousClock.now
        var denied = 0
        for i in stride(from: 0, to: 100_000, by: 10) {
            let verdict = set.evaluate(
                FlowDescriptor(domain: "sub.host\(i).ads.example"),
                mode: .standard
            )
            if verdict.action == .deny { denied += 1 }
        }
        let elapsed = ContinuousClock.now - start
        #expect(denied == 10_000)
        #expect(elapsed < .seconds(2), "10k lookups against 100k-entry list took \(elapsed)")
    }
}

@Suite struct WiFiProfileAssignmentTests {
    /// Assignments ride the snapshot: round-trip with values, and nil
    /// stays out of the wire format.
    @Test func snapshotRoundTripsAndNilIsOmitted() throws {
        let rules = [WiFiProfileAssignment(ssid: "HomeNet-5G", profileKind: .home, unmatchedAction: .allow)]
        let back = try RuleSnapshot.deserialize(
            try RuleSnapshot(rules: [], wifiAutoProfiles: rules).serialize())
        #expect(back.wifiAutoProfiles == rules)

        let (data, _) = try RuleSnapshot(rules: []).serializedWithChecksum()
        #expect(!String(decoding: data, as: UTF8.self).contains("wifiAutoProfiles"))
    }

    /// Exact byte match only: SSIDs are identifiers, not patterns.
    @Test func matchIsExactOnly() {
        let rules = [
            WiFiProfileAssignment(ssid: "Cafe", profileKind: .publicNetwork, unmatchedAction: .deny),
            WiFiProfileAssignment(ssid: "Home", profileKind: .home, unmatchedAction: .allow),
        ]
        #expect(WiFiProfileAssignment.match("Cafe", in: rules)?.profileKind == .publicNetwork)
        #expect(WiFiProfileAssignment.match("cafe", in: rules) == nil)
        #expect(WiFiProfileAssignment.match("Cafe ", in: rules) == nil)
        #expect(WiFiProfileAssignment.match("Home", in: rules)?.unmatchedAction == .allow)
    }
}
