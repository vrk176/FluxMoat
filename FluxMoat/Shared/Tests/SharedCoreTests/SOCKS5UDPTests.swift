import Foundation
import Testing
@testable import SharedCore

@Suite struct SOCKS5UDPDatagramTests {
    /// Builds a wrapped datagram: RSV(2)+FRAG(1)+ATYP+ADDR+PORT(2)+DATA.
    private func ipv4Frame(frag: UInt8 = 0, addr: [UInt8] = [1, 1, 1, 1], port: UInt16 = 53, payload: [UInt8]) -> [UInt8] {
        var b: [UInt8] = [0x00, 0x00, frag, 0x01]
        b.append(contentsOf: addr)
        b.append(contentsOf: [UInt8(port >> 8), UInt8(port & 0xFF)])
        b.append(contentsOf: payload)
        return b
    }

    @Test func parsesIPv4Datagram() {
        let frame = ipv4Frame(addr: [1, 1, 1, 1], port: 53, payload: [0xDE, 0xAD])
        guard case .parsed(let dg, let consumed) = SOCKS5UDPDatagram.parse(frame) else {
            Issue.record("expected parsed"); return
        }
        #expect(dg.destination == .ipv4(IPAddress.parse("1.1.1.1")!))
        #expect(dg.port == 53)
        #expect(Array(dg.payload) == [0xDE, 0xAD])
        #expect(consumed == frame.count)
    }

    @Test func parsesIPv6Datagram() {
        var frame: [UInt8] = [0x00, 0x00, 0x00, 0x04]
        frame.append(contentsOf: IPAddress.parse("2001:db8::1")!.bytes)
        frame.append(contentsOf: [0x01, 0xBB]) // 443
        frame.append(contentsOf: [0x11, 0x22])
        guard case .parsed(let dg, _) = SOCKS5UDPDatagram.parse(frame) else {
            Issue.record("expected parsed"); return
        }
        #expect(dg.destination == .ipv6(IPAddress.parse("2001:db8::1")!))
        #expect(dg.port == 443)
        #expect(Array(dg.payload) == [0x11, 0x22])
    }

    @Test func parsesDomainDatagramNormalized() {
        let host = "Example.COM"
        var frame: [UInt8] = [0x00, 0x00, 0x00, 0x03, UInt8(host.count)]
        frame.append(contentsOf: Array(host.utf8))
        frame.append(contentsOf: [0x01, 0xBB])
        frame.append(0x42)
        guard case .parsed(let dg, _) = SOCKS5UDPDatagram.parse(frame) else {
            Issue.record("expected parsed"); return
        }
        #expect(dg.destination == .domain("example.com"))
        #expect(dg.port == 443)
        #expect(Array(dg.payload) == [0x42])
    }

    @Test func emptyPayloadIsValid() {
        let frame = ipv4Frame(payload: [])
        guard case .parsed(let dg, _) = SOCKS5UDPDatagram.parse(frame) else {
            Issue.record("expected parsed"); return
        }
        #expect(dg.payload.isEmpty)
    }

    @Test func rejectsFragmentation() {
        let frame = ipv4Frame(frag: 0x01, payload: [0x00])
        if case .invalid = SOCKS5UDPDatagram.parse(frame) {} else {
            Issue.record("expected invalid for FRAG != 0")
        }
    }

    @Test func rejectsTruncatedDatagram() {
        // ATYP ipv4 but only 2 address bytes present.
        let frame: [UInt8] = [0x00, 0x00, 0x00, 0x01, 1, 1]
        if case .invalid = SOCKS5UDPDatagram.parse(frame) {} else {
            Issue.record("expected invalid for truncation")
        }
    }

    @Test func rejectsBadAddressType() {
        let frame: [UInt8] = [0x00, 0x00, 0x00, 0x09, 0, 0]
        if case .invalid = SOCKS5UDPDatagram.parse(frame) {} else {
            Issue.record("expected invalid for bad ATYP")
        }
    }

    @Test func encodeRoundTripsIPv4() {
        let dg = SOCKS5UDPDatagram(
            destination: .ipv4(IPAddress.parse("8.8.4.4")!),
            port: 443,
            payload: Data([0x01, 0x02, 0x03])
        )
        guard case .parsed(let back, _) = SOCKS5UDPDatagram.parse(Array(dg.encoded())) else {
            Issue.record("expected parsed"); return
        }
        #expect(back == dg)
    }

    @Test func encodeRoundTripsDomain() {
        let dg = SOCKS5UDPDatagram(
            destination: .domain("dns.example"),
            port: 53,
            payload: Data([0xAB])
        )
        guard case .parsed(let back, _) = SOCKS5UDPDatagram.parse(Array(dg.encoded())) else {
            Issue.record("expected parsed"); return
        }
        #expect(back == dg)
    }

    @Test func encodedHeaderLayoutIPv4() {
        let dg = SOCKS5UDPDatagram(
            destination: .ipv4(IPAddress.parse("1.2.3.4")!),
            port: 53,
            payload: Data([0xFF])
        )
        #expect(Array(dg.encoded()) == [0x00, 0x00, 0x00, 0x01, 1, 2, 3, 4, 0x00, 0x35, 0xFF])
    }
}

@Suite struct SOCKS5UDPAssociateStateTests {
    private func machine() -> SOCKS5ServerConnection {
        SOCKS5ServerConnection(gatekeeper: FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: .standard))
    }

    /// Greeting then UDP ASSOCIATE (dst 0.0.0.0:0, as leaf sends).
    private func associate(_ m: SOCKS5ServerConnection) -> [SOCKS5ServerConnection.Action] {
        _ = m.handle(.clientBytes(Data([0x05, 0x01, 0x00])))
        return m.handle(.clientBytes(Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])))
    }

    @Test func udpAssociateBeginsRelayNotOutbound() {
        let m = machine()
        let actions = associate(m)
        #expect(actions.contains(.beginUDPAssociate))
        #expect(!actions.contains { if case .openOutbound = $0 { return true }; return false })
        #expect(m.request?.command == .udpAssociate)
        #expect(m.verdict?.action == .allow)
    }

    @Test func controlBytesIgnoredAfterAssociate() {
        let m = machine()
        _ = associate(m)
        // Stray data on the TCP control channel must not be forwarded anywhere.
        let actions = m.handle(.clientBytes(Data([0xFF, 0xFF])))
        #expect(actions.isEmpty)
    }

    @Test func udpAssociateAllowedEvenInStrictMode() {
        // The association is always establishable; per-datagram filtering is
        // where strict mode bites (covered in FlowGatekeeperDatagramTests).
        let m = SOCKS5ServerConnection(gatekeeper: FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: .strict))
        #expect(associate(m).contains(.beginUDPAssociate))
    }
}

@Suite struct SOCKS5ReplyBoundTests {
    @Test func encodeReplyWithBoundLoopbackEndpoint() {
        let data = SOCKS5Reply.encode(.succeeded, bound: (ip: IPAddress.parse("127.0.0.1")!, port: 0x1234))
        #expect(Array(data) == [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34])
    }

    @Test func encodeReplyDefaultUnchanged() {
        #expect(Array(SOCKS5Reply.encode(.succeeded)) == [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
    }
}

@Suite struct FlowGatekeeperDatagramTests {
    @Test func denyRuleDeniesDatagram() {
        let rules = CompiledRuleSet(rules: [Rule(action: .deny, target: .domain("ads.example"))])
        let gate = FlowGatekeeper(rules: rules, mode: .standard)
        let verdict = gate.decideDatagram(destination: .domain("ads.example"), port: 443)
        #expect(verdict.action == .deny)
    }

    @Test func defaultAllowsDatagramInStandardMode() {
        let gate = FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: .standard)
        let verdict = gate.decideDatagram(destination: .ipv4(IPAddress.parse("8.8.8.8")!), port: 443)
        #expect(verdict.action == .allow)
    }

    @Test func strictModeDefaultDeniesDatagram() {
        let gate = FlowGatekeeper(rules: CompiledRuleSet(rules: []), mode: .strict)
        let verdict = gate.decideDatagram(destination: .domain("unknown.example"), port: 443)
        #expect(verdict.action == .deny)
    }

    @Test func blocklistDeniesDatagram() {
        let rules = CompiledRuleSet(rules: [], blocklistDomains: ["tracker.example"])
        let gate = FlowGatekeeper(rules: rules, mode: .standard)
        let verdict = gate.decideDatagram(destination: .domain("sub.tracker.example"), port: 443)
        #expect(verdict.action == .deny)
    }
}
