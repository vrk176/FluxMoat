import Foundation
import Testing
@testable import SharedCore

@Suite struct SOCKS5GreetingTests {
    @Test func parsesNoAuthGreeting() {
        let bytes: [UInt8] = [0x05, 0x01, 0x00]
        guard case .parsed(let greeting, let consumed) = SOCKS5Greeting.parse(bytes) else {
            Issue.record("expected parsed"); return
        }
        #expect(greeting.methods == [0x00])
        #expect(consumed == 3)
    }

    @Test func needsMoreWhenTruncated() {
        if case .needMore = SOCKS5Greeting.parse([0x05, 0x02, 0x00]) {} else {
            Issue.record("expected needMore")
        }
    }

    @Test func rejectsWrongVersion() {
        if case .invalid = SOCKS5Greeting.parse([0x04, 0x01, 0x00]) {} else {
            Issue.record("expected invalid")
        }
    }

    @Test func methodSelectionBytes() {
        #expect(Array(SOCKS5Greeting.methodSelection(SOCKS5Greeting.noAuth)) == [0x05, 0x00])
    }
}

@Suite struct SOCKS5RequestTests {
    @Test func parsesIPv4Connect() {
        // CONNECT 203.0.113.7:443
        let bytes: [UInt8] = [0x05, 0x01, 0x00, 0x01, 203, 0, 113, 7, 0x01, 0xBB]
        guard case .parsed(let req, let consumed) = SOCKS5Request.parse(bytes) else {
            Issue.record("expected parsed"); return
        }
        #expect(req.command == .connect)
        #expect(req.destination == .ipv4(IPAddress.parse("203.0.113.7")!))
        #expect(req.port == 443)
        #expect(consumed == 10)
    }

    @Test func parsesDomainConnectNormalized() {
        let host = "Example.COM"
        var bytes: [UInt8] = [0x05, 0x01, 0x00, 0x03, UInt8(host.count)]
        bytes.append(contentsOf: Array(host.utf8))
        bytes.append(contentsOf: [0x01, 0xBB])
        guard case .parsed(let req, _) = SOCKS5Request.parse(bytes) else {
            Issue.record("expected parsed"); return
        }
        #expect(req.destination == .domain("example.com"))
        #expect(req.port == 443)
    }

    @Test func parsesIPv6UDPAssociate() {
        var bytes: [UInt8] = [0x05, 0x03, 0x00, 0x04]
        bytes.append(contentsOf: IPAddress.parse("2001:db8::1")!.bytes)
        bytes.append(contentsOf: [0x00, 0x35]) // port 53
        guard case .parsed(let req, _) = SOCKS5Request.parse(bytes) else {
            Issue.record("expected parsed"); return
        }
        #expect(req.command == .udpAssociate)
        #expect(req.destination == .ipv6(IPAddress.parse("2001:db8::1")!))
        #expect(req.port == 53)
    }

    @Test func needsMoreForSplitDomainRequest() {
        // Header says 11-byte domain but only 5 bytes present.
        let bytes: [UInt8] = [0x05, 0x01, 0x00, 0x03, 11, 0x65, 0x78]
        if case .needMore = SOCKS5Request.parse(bytes) {} else {
            Issue.record("expected needMore")
        }
    }

    @Test func rejectsBadAddressType() {
        if case .invalid = SOCKS5Request.parse([0x05, 0x01, 0x00, 0x09, 0, 0]) {} else {
            Issue.record("expected invalid")
        }
    }

    @Test func flowDescriptorMapsProtocolAndTarget() {
        let tcp: [UInt8] = [0x05, 0x01, 0x00, 0x01, 8, 8, 8, 8, 0x01, 0xBB]
        guard case .parsed(let req, _) = SOCKS5Request.parse(tcp) else {
            Issue.record("parse"); return
        }
        let flow = req.flowDescriptor()
        #expect(flow.protocolNumber == 6)
        #expect(flow.port == 443)
        #expect(flow.ip == IPAddress.parse("8.8.8.8"))
    }
}

@Suite struct SOCKS5ReplyTests {
    @Test func encodesSucceeded() {
        #expect(Array(SOCKS5Reply.encode(.succeeded)) ==
            [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
    }

    @Test func encodesNotAllowed() {
        #expect(Array(SOCKS5Reply.encode(.notAllowed))[1] == 0x02)
    }
}

@Suite struct FlowGatekeeperTests {
    private func request(domain: String, port: UInt16 = 443, command: SOCKS5.Command = .connect) -> SOCKS5Request {
        SOCKS5Request(command: command, destination: .domain(domain), port: port)
    }

    @Test func denyRuleYieldsNotAllowedReply() {
        let rules = CompiledRuleSet(rules: [Rule(action: .deny, target: .domain("ads.example"))])
        let gate = FlowGatekeeper(rules: rules, mode: .standard)
        let decision = gate.decide(request(domain: "ads.example"))
        #expect(decision.allowed == false)
        #expect(decision.reply == .notAllowed)
        #expect(decision.verdict.source == .userRule)
    }

    @Test func allowRuleYieldsSucceeded() {
        let rules = CompiledRuleSet(rules: [Rule(action: .allow, target: .domain("api.example"))])
        let gate = FlowGatekeeper(rules: rules, mode: .strict)
        let decision = gate.decide(request(domain: "api.example"))
        #expect(decision.allowed)
        #expect(decision.reply == .succeeded)
    }

    @Test func blocklistDenies() {
        let rules = CompiledRuleSet(rules: [], blocklistDomains: ["tracker.example"])
        let gate = FlowGatekeeper(rules: rules, mode: .standard)
        #expect(gate.decide(request(domain: "sub.tracker.example")).reply == .notAllowed)
    }

    @Test func strictModeDefaultDenies() {
        let gate = FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: .strict)
        #expect(gate.decide(request(domain: "unknown.example")).allowed == false)
    }

    @Test func bindCommandUnsupported() {
        let gate = FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: .standard)
        let decision = gate.decide(request(domain: "x.example", command: .bind))
        #expect(decision.reply == .commandNotSupported)
        #expect(decision.allowed == false)
    }

    // UDP ASSOCIATE has no relay yet, so it must be rejected rather than
    // allowed through to a TCP openOutbound (which self-loops to the listener).
    @Test func udpAssociateUnsupported() {
        let gate = FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: .standard)
        // Even an explicitly allowed target must not open a UDP-associate flow.
        let allowRule = Rule(action: .allow, target: .domain("x.example"))
        let gate2 = FlowGatekeeper(rules: CompiledRuleSet(rules: [allowRule]), mode: .standard)
        for g in [gate, gate2] {
            let decision = g.decide(request(domain: "x.example", command: .udpAssociate))
            #expect(decision.reply == .commandNotSupported)
            #expect(decision.allowed == false)
        }
    }
}
