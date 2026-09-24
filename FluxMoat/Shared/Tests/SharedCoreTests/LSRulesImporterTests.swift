import Foundation
import Testing
@testable import SharedCore

@Suite struct LSRulesImporterTests {
    @Test func simplifiedBlocklistFormat() throws {
        let json = """
        {
          "name": "Ad Servers",
          "description": "test list",
          "denied-remote-domains": ["ads.example", "Track.Example."],
          "denied-remote-hosts": ["exact.host.example"],
          "denied-remote-addresses": ["203.0.113.7", "10.0.0.0/8", "1.2.3.4-1.2.3.9"]
        }
        """
        let report = try LSRulesImporter.parse(Data(json.utf8))

        #expect(report.groupName == "Ad Servers")
        #expect(report.blocklistDomains == ["ads.example", "track.example"])
        // exact host + ip + cidr = 3 rules; the address range is skipped
        #expect(report.rules.count == 3)
        #expect(report.skipped.count == 1)
        #expect(report.rules.allSatisfy { $0.action == .deny })

        // Blocklist domains block subdomains; the host rule stays exact.
        let set = CompiledRuleSet(
            rules: report.rules,
            blocklistDomains: report.blocklistDomains
        )
        #expect(set.evaluate(FlowDescriptor(domain: "cdn.ads.example"), mode: .standard).action == .deny)
        #expect(set.evaluate(FlowDescriptor(domain: "exact.host.example"), mode: .standard).action == .deny)
        #expect(set.evaluate(FlowDescriptor(domain: "sub.exact.host.example"), mode: .standard).action == .allow)
        #expect(set.evaluate(FlowDescriptor(ip: IPAddress.parse("10.9.8.7")), mode: .standard).action == .deny)
    }

    @Test func fullRulesArray() throws {
        let json = """
        {
          "name": "Mixed",
          "rules": [
            {"action": "deny", "remote-domains": "evil.example", "notes": "bad actor"},
            {"action": "allow", "remote-hosts": ["api.good.example"], "priority": "high"},
            {"action": "deny", "process": "/Applications/Foo.app/Contents/MacOS/Foo",
             "remote-hosts": "telemetry.foo.example"},
            {"action": "deny", "remote-domains": "porty.example", "ports": "443", "protocol": "tcp"},
            {"action": "deny", "protocol": "udp", "ports": "53"},
            {"action": "deny", "ports": "6881-6889"},
            {"action": "ask", "remote-domains": "ask.example"},
            {"action": "deny", "direction": "incoming", "remote-hosts": "in.example"},
            {"action": "deny", "process": "/usr/bin/thing"},
            {"action": "deny", "remote-hosts": "off.example", "disabled": true}
          ]
        }
        """
        let report = try LSRulesImporter.parse(Data(json.utf8))

        // ask + incoming + app-scope-only are skipped.
        #expect(report.skipped.count == 3)
        // process on rule 3 and 9 → two app-scope drops.
        #expect(report.appScopeDropped == 2)
        // domain+port conjunction on rule 4 → one constraint drop.
        #expect(report.constraintsDropped == 1)

        let set = CompiledRuleSet(rules: report.rules)
        // remote-domains covers apex and subdomains via the rule pair.
        #expect(set.evaluate(FlowDescriptor(domain: "evil.example"), mode: .standard).action == .deny)
        #expect(set.evaluate(FlowDescriptor(domain: "x.evil.example"), mode: .standard).action == .deny)
        // high-priority allow present and enabled.
        #expect(set.evaluate(FlowDescriptor(domain: "api.good.example"), mode: .standard).action == .allow)
        // pure protocol+port and port-range rules survive.
        #expect(set.evaluate(FlowDescriptor(port: 53, protocolNumber: 17), mode: .strict).action == .deny)
        #expect(set.evaluate(FlowDescriptor(port: 6885), mode: .standard).action == .deny)
        // disabled rule imported but inert.
        #expect(report.rules.contains { $0.enabled == false })
        #expect(set.evaluate(FlowDescriptor(domain: "off.example"), mode: .standard).action == .allow)
        // notes carried through.
        #expect(report.rules.contains { $0.note == "bad actor" })
    }

    @Test func rejectsNonLsrulesJSON() {
        #expect(throws: (any Error).self) {
            _ = try LSRulesImporter.parse(Data("[1,2,3]".utf8))
        }
        #expect(throws: (any Error).self) {
            _ = try LSRulesImporter.parse(Data("{\"foo\": 1}".utf8))
        }
    }
}
