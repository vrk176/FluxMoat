import Foundation
import Testing
@testable import SharedCore

@Suite struct AskCenterTests {
    @Test func newDestinationReturnsQuestionAndCoalescesRepeats() {
        var center = AskCenter()
        let first = center.record(domain: "new.example", remoteIP: "", port: 443, appliedAction: .allow)
        #expect(first != nil)
        #expect(first?.targetKey == "new.example")
        // Same destination again (different port): absorbed, no new question.
        let repeated = center.record(domain: "new.example", remoteIP: "", port: 8443, appliedAction: .allow)
        #expect(repeated == nil)
        #expect(center.pending.count == 1)
        #expect(center.pending[0].flowCount == 2)
        #expect(center.pending[0].firstPort == 443) // first flow's port kept
    }

    @Test func ipOnlyDestinationsCoalesceByIP() {
        var center = AskCenter()
        #expect(center.record(domain: nil, remoteIP: "203.0.113.7", port: 443, appliedAction: .deny) != nil)
        #expect(center.record(domain: nil, remoteIP: "203.0.113.7", port: 443, appliedAction: .deny) == nil)
        #expect(center.record(domain: nil, remoteIP: "203.0.113.8", port: 443, appliedAction: .deny) != nil)
        #expect(center.pending.count == 2)
    }

    @Test func capacityDropsNewDestinationsNotOldQuestions() {
        var center = AskCenter(capacity: 2)
        center.record(domain: "a.example", remoteIP: "", port: 443, appliedAction: .allow)
        center.record(domain: "b.example", remoteIP: "", port: 443, appliedAction: .allow)
        // Full: new destination dropped, existing questions keep their slot.
        #expect(center.record(domain: "c.example", remoteIP: "", port: 443, appliedAction: .allow) == nil)
        #expect(center.pending.map(\.targetKey) == ["a.example", "b.example"])
        // Resolving frees a slot.
        center.resolve(id: center.pending[0].id)
        #expect(center.record(domain: "c.example", remoteIP: "", port: 443, appliedAction: .allow) != nil)
    }

    @Test func resolveRemovesAndReturnsQuestion() {
        var center = AskCenter()
        let ask = center.record(domain: "x.example", remoteIP: "", port: 443, appliedAction: .allow)!
        let resolved = center.resolve(id: ask.id)
        #expect(resolved?.targetKey == "x.example")
        #expect(center.pending.isEmpty)
        #expect(center.resolve(id: ask.id) == nil) // second resolve is a no-op
    }

    @Test func expiryDropsOldQuestions() {
        var center = AskCenter(maxAge: 60)
        let past = Date().addingTimeInterval(-3600)
        center.record(domain: "old.example", remoteIP: "", port: 443, appliedAction: .allow, at: past)
        // Recording anything later expires the stale question first.
        center.record(domain: "fresh.example", remoteIP: "", port: 443, appliedAction: .allow)
        #expect(center.pending.map(\.targetKey) == ["fresh.example"])
    }
}

@Suite struct AskModeGatekeeperTests {
    private func request(domain: String) -> SOCKS5Request {
        SOCKS5Request(command: .connect, destination: .domain(domain), port: 443)
    }

    @Test func unmatchedFlowInAskModeAsksAndAppliesProfileDefault() {
        // Allow-default profile: flow runs, question raised.
        let allowGate = FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: .ask, profileDefault: .allow)
        let allowed = allowGate.decide(request(domain: "new.example"))
        #expect(allowed.allowed && allowed.asksUser)

        // Deny-default profile (e.g. Public): flow refused, question raised.
        let denyGate = FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: .ask, profileDefault: .deny)
        let denied = denyGate.decide(request(domain: "new.example"))
        #expect(!denied.allowed && denied.asksUser)
        #expect(denied.reply == .notAllowed)
    }

    @Test func matchedRuleNeverAsks() {
        let rules = CompiledRuleSet(rules: [Rule(action: .deny, target: .domain("ads.example"))])
        let gate = FlowGatekeeper(rules: rules, mode: .ask)
        let decision = gate.decide(request(domain: "ads.example"))
        #expect(!decision.allowed && !decision.asksUser) // rule answered it
    }

    @Test func blocklistHitNeverAsks() {
        let rules = CompiledRuleSet(rules: [], blocklistDomains: ["tracker.example"])
        let gate = FlowGatekeeper(rules: rules, mode: .ask)
        #expect(gate.decide(request(domain: "sub.tracker.example")).asksUser == false)
    }

    @Test func otherModesNeverAsk() {
        for mode in [RunMode.learning, .standard, .strict, .pause] {
            let gate = FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: mode)
            #expect(gate.decide(request(domain: "new.example")).asksUser == false)
        }
    }
}

@Suite struct SnapshotModeFieldTests {
    @Test func modeAndDefaultRoundTrip() throws {
        let snapshot = RuleSnapshot(rules: [], mode: .ask, profileDefault: .deny)
        let back = try RuleSnapshot.deserialize(try snapshot.serialize())
        #expect(back.mode == .ask)
        #expect(back.profileDefault == .deny)
    }

    /// nil mode serializes with the keys absent, byte-compatible with the
    /// pre-mode snapshot format, so old snapshots decode and old builds
    /// can read new nil-mode snapshots (schemaVersion stays 1).
    @Test func nilModeMatchesLegacyFormatAndDecodes() throws {
        let (data, _) = try RuleSnapshot(rules: []).serializedWithChecksum()
        let json = String(decoding: data, as: UTF8.self)
        #expect(!json.contains("\"mode\""))
        #expect(!json.contains("\"profileDefault\""))
        let back = try RuleSnapshot.deserialize(data)
        #expect(back.mode == nil) // caller defaults to .standard
    }
}

@Suite struct AskProviderMessageTests {
    @Test func pendingAsksRoundTrips() throws {
        let asks = [PendingAsk(domain: "q.example", remoteIP: "", firstPort: 443, appliedAction: .allow, flowCount: 3)]
        let decoded = try ProviderResponse.decoded(from: ProviderResponse.pendingAsks(asks).encoded())
        guard case .pendingAsks(let back) = decoded else { Issue.record("wrong case"); return }
        #expect(back.count == 1)
        #expect(back[0].domain == "q.example")
        #expect(back[0].flowCount == 3)
        #expect(back[0].appliedAction == .allow)
    }

    @Test func resolveAskRoundTripsID() throws {
        let id = UUID()
        let decoded = try ProviderRequest.decoded(from: ProviderRequest.resolveAsk(id).encoded())
        guard case .resolveAsk(let back) = decoded else { Issue.record("wrong case"); return }
        #expect(back == id)
    }
}
