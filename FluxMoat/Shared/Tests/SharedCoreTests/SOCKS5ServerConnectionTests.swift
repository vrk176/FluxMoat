import Foundation
import Testing
@testable import SharedCore

@Suite struct SOCKS5ServerConnectionTests {
    private func gate(_ rules: [Rule], mode: RunMode = .standard, blocklist: [String] = []) -> FlowGatekeeper {
        FlowGatekeeper(rules: CompiledRuleSet(rules: rules, blocklistDomains: blocklist), mode: mode)
    }

    private func greeting() -> Data { Data([0x05, 0x01, 0x00]) }

    private func connectRequest(domain: String, port: UInt16 = 443) -> Data {
        var bytes: [UInt8] = [0x05, 0x01, 0x00, 0x03, UInt8(domain.count)]
        bytes.append(contentsOf: Array(domain.utf8))
        bytes.append(UInt8(port >> 8)); bytes.append(UInt8(port & 0xFF))
        return Data(bytes)
    }

    @Test func allowedFlowCompletesHandshakeAndRelays() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([Rule(action: .allow, target: .domain("api.example"))]))

        // Greeting → method selection.
        #expect(conn.handle(.clientBytes(greeting())) == [.sendToClient(Data([0x05, 0x00]))])

        // Request (allow) → openOutbound, no reply yet.
        #expect(conn.handle(.clientBytes(connectRequest(domain: "api.example"))) ==
            [.openOutbound(host: "api.example", port: 443)])

        // Outbound connects → succeeded reply.
        let onConnect = conn.handle(.outboundConnected)
        #expect(onConnect == [.sendToClient(SOCKS5Reply.encode(.succeeded))])

        // Relay both directions with byte accounting.
        #expect(conn.handle(.clientBytes(Data([1, 2, 3]))) == [.forwardToOutbound(Data([1, 2, 3]))])
        #expect(conn.handle(.outboundBytes(Data([9, 9]))) == [.sendToClient(Data([9, 9]))])
        #expect(conn.bytesUp == 3)
        #expect(conn.bytesDown == 2)
        #expect(conn.verdict?.action == .allow)
    }

    // Regression: the connection's gatekeeper copy pins the whole compiled
    // set's COW storage, so it must go once its one decide() call is done.
    // Long-lived flows holding onto it drove the extension into the jetsam limit.
    @Test func ruleSetDroppedOnceVerdictIsOut() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([Rule(action: .allow, target: .domain("x.example"))]))
        #expect(conn.holdsRuleSet)
        _ = conn.handle(.clientBytes(greeting()))
        #expect(conn.holdsRuleSet) // still pre-verdict
        _ = conn.handle(.clientBytes(connectRequest(domain: "x.example")))
        #expect(!conn.holdsRuleSet) // verdict out → copy gone
        _ = conn.handle(.outboundConnected)
        #expect(conn.handle(.clientBytes(Data([1]))) == [.forwardToOutbound(Data([1]))])
        #expect(!conn.holdsRuleSet) // relaying never brings it back
    }

    @Test func ruleSetDroppedOnDeniedVerdict() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([], blocklist: ["ads.example"]))
        _ = conn.handle(.clientBytes(greeting()))
        _ = conn.handle(.clientBytes(connectRequest(domain: "ads.example")))
        #expect(!conn.holdsRuleSet)
    }

    @Test func ruleSetDroppedOnUDPAssociate() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([]))
        _ = conn.handle(.clientBytes(greeting()))
        // ASSOCIATE with the usual 0.0.0.0:0 destination leaf sends.
        let associate = Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        #expect(conn.handle(.clientBytes(associate)) == [.beginUDPAssociate])
        #expect(!conn.holdsRuleSet) // relay owns judging from here on
    }

    @Test func deniedFlowRepliesNotAllowedAndCloses() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([], blocklist: ["ads.example"]))
        _ = conn.handle(.clientBytes(greeting()))
        let actions = conn.handle(.clientBytes(connectRequest(domain: "ads.example")))
        #expect(actions == [.sendToClient(SOCKS5Reply.encode(.notAllowed)), .closeAll])
        #expect(conn.verdict?.source == .blocklist)
    }

    @Test func fragmentedGreetingAndRequestReassemble() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([Rule(action: .allow, target: .domain("x.example"))]))
        // Greeting split across two reads.
        #expect(conn.handle(.clientBytes(Data([0x05]))) == [])
        #expect(conn.handle(.clientBytes(Data([0x01, 0x00]))) == [.sendToClient(Data([0x05, 0x00]))])

        // Request split mid-domain.
        let req = connectRequest(domain: "x.example")
        #expect(conn.handle(.clientBytes(req.prefix(6))) == [])
        #expect(conn.handle(.clientBytes(req.suffix(from: req.index(req.startIndex, offsetBy: 6)))) ==
            [.openOutbound(host: "x.example", port: 443)])
    }

    @Test func pipelinedGreetingAndRequestInOneRead() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([Rule(action: .allow, target: .domain("x.example"))]))
        var combined = greeting()
        combined.append(connectRequest(domain: "x.example"))
        let actions = conn.handle(.clientBytes(combined))
        #expect(actions == [
            .sendToClient(Data([0x05, 0x00])),
            .openOutbound(host: "x.example", port: 443),
        ])
    }

    @Test func earlyClientDataBufferedUntilConnected() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([Rule(action: .allow, target: .domain("x.example"))]))
        _ = conn.handle(.clientBytes(greeting()))
        _ = conn.handle(.clientBytes(connectRequest(domain: "x.example")))
        // Client sends payload before outbound is up → buffered, no action.
        #expect(conn.handle(.clientBytes(Data([7, 7, 7]))) == [])
        // On connect: succeeded reply THEN the buffered payload flushes.
        let actions = conn.handle(.outboundConnected)
        #expect(actions == [
            .sendToClient(SOCKS5Reply.encode(.succeeded)),
            .forwardToOutbound(Data([7, 7, 7])),
        ])
        #expect(conn.bytesUp == 3)
    }

    @Test func outboundFailureRepliesHostUnreachable() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([Rule(action: .allow, target: .domain("x.example"))]))
        _ = conn.handle(.clientBytes(greeting()))
        _ = conn.handle(.clientBytes(connectRequest(domain: "x.example")))
        let actions = conn.handle(.outboundFailed)
        #expect(actions == [.sendToClient(SOCKS5Reply.encode(.hostUnreachable)), .closeAll])
    }

    @Test func noAcceptableAuthMethodRejects() {
        let conn = SOCKS5ServerConnection(gatekeeper: gate([]))
        // Greeting offering only GSSAPI (0x01), no no-auth.
        let actions = conn.handle(.clientBytes(Data([0x05, 0x01, 0x01])))
        #expect(actions == [.sendToClient(Data([0x05, 0xFF])), .closeAll])
    }
}
