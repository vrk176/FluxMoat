import Foundation
import Testing
@testable import SharedCore

/// Guards the constraints the encrypted-DNS blocklist must uphold; each
/// case names the constraint it checks.
@Suite struct EncryptedDNSBlocklistTests {
    private func targets(_ rules: [Rule]) -> (ports: [ClosedRange<UInt16>], ips: Set<String>) {
        var ports: [ClosedRange<UInt16>] = []
        var ips: Set<String> = []
        for rule in rules {
            switch rule.target {
            case .port(let range): ports.append(range)
            case .ip(let address): ips.insert(address)
            default: break
            }
        }
        return (ports, ips)
    }

    /// Port and IP rules must ship together: blocking :853 alone lets a
    /// client fail over to DoH on :443.
    @Test func portAndAddressRulesShipTogether() {
        let (ports, ips) = targets(EncryptedDNSBlocklist.rules(exemptingUpstreamHost: nil))
        #expect(ports == [853...853])
        #expect(ips.contains("1.1.1.1"))
        #expect(ips.contains("8.8.8.8"))
        #expect(ips.contains("9.9.9.9"))
        #expect(ips.contains("94.140.14.14"))
        // v6 endpoints too, since the tunnel claims both default routes.
        #expect(ips.contains("2606:4700:4700::1111"))
        #expect(ips.contains("2001:4860:4860::8888"))
    }

    /// The configured DoH upstream must be exempt from the injected
    /// blocklist. Exemption is whole-operator: picking Quad9 must not
    /// leave its secondary or variant addresses blocked.
    @Test func configuredUpstreamOperatorIsFullyExempt() {
        let (_, ips) = targets(
            EncryptedDNSBlocklist.rules(exemptingUpstreamHost: "dns.quad9.net")
        )
        for quad9 in ["9.9.9.9", "149.112.112.112", "9.9.9.11", "2620:fe::fe"] {
            #expect(!ips.contains(quad9), "Quad9 endpoint \(quad9) must be exempt")
        }
        // Other operators stay blocked.
        #expect(ips.contains("1.1.1.1"))
        #expect(ips.contains("8.8.8.8"))
    }

    /// A Cloudflare *variant* host (the 1.1.1.2 filtering endpoint) must
    /// exempt the whole Cloudflare operator, not just that one address.
    @Test func variantHostExemptsWholeOperator() {
        let (_, ips) = targets(
            EncryptedDNSBlocklist.rules(exemptingUpstreamHost: "security.cloudflare-dns.com")
        )
        for cf in ["1.1.1.1", "1.1.1.2", "1.0.0.3", "2606:4700:4700::1112"] {
            #expect(!ips.contains(cf), "Cloudflare endpoint \(cf) must be exempt")
        }
        #expect(ips.contains("9.9.9.9"))
    }

    /// An unknown or custom upstream exempts nothing, but must not crash
    /// or drop the rule set.
    @Test func unknownUpstreamExemptsNothing() {
        let all = targets(EncryptedDNSBlocklist.rules(exemptingUpstreamHost: nil)).ips
        let custom = targets(
            EncryptedDNSBlocklist.rules(exemptingUpstreamHost: "dns.example.invalid")
        ).ips
        #expect(custom == all)
    }

    /// Deliberate exclusions (see the doc comment): Cloudflare's CDN
    /// addresses are shared with much of the web, NextDNS is geo-steered.
    /// Blocking either would be wrong.
    @Test func sharedCDNAndSteeredAddressesAreNotListed() {
        let ips = targets(EncryptedDNSBlocklist.rules(exemptingUpstreamHost: nil)).ips
        for excluded in ["104.16.248.249", "104.16.249.249", "149.28.148.222"] {
            #expect(!ips.contains(excluded), "\(excluded) must never be blocked")
        }
    }

    /// Synthetic ids must be stable across calls, or past events'
    /// `matchedRuleID` would go dangling on every recompile.
    @Test func syntheticIDsAreStableAcrossCalls() {
        let first = EncryptedDNSBlocklist.rules(exemptingUpstreamHost: nil).map(\.id)
        let second = EncryptedDNSBlocklist.rules(exemptingUpstreamHost: nil).map(\.id)
        #expect(first == second)
        #expect(Set(first).count == first.count, "ids must be unique")
    }
}

@Suite struct EncryptedDNSSnapshotCompositionTests {
    private let dotFlow = FlowDescriptor(
        domain: "one.one.one.one", port: 853, protocolNumber: 6
    )

    /// Must not be enabled by default. A snapshot that never mentions the
    /// switch must behave exactly as before the field existed.
    @Test func defaultOffLeavesTrafficUntouched() throws {
        let snapshot = RuleSnapshot(rules: [])
        #expect(snapshot.blockEncryptedDNS == nil)
        let verdict = snapshot.compile().evaluate(dotFlow, mode: .standard)
        #expect(verdict.action == .allow)

        // nil must also stay out of the wire format (old builds keep reading).
        let (data, _) = try snapshot.serializedWithChecksum()
        #expect(!String(decoding: data, as: UTF8.self).contains("blockEncryptedDNS"))
    }

    @Test func switchOnDeniesDoTAndResolverAddresses() {
        let compiled = RuleSnapshot(rules: [], blockEncryptedDNS: true).compile()
        #expect(compiled.evaluate(dotFlow, mode: .standard).action == .deny)
        let byAddress = FlowDescriptor(
            ip: IPAddress.parse("8.8.8.8"), port: 443, protocolNumber: 6
        )
        #expect(compiled.evaluate(byAddress, mode: .standard).action == .deny)
    }

    /// The exemption must survive the snapshot round trip: the upstream is
    /// stored as a full URL, the blocklist matches on host.
    @Test func compileDerivesExemptionFromDoHURL() {
        let snapshot = RuleSnapshot(
            rules: [],
            dohServerURL: "https://dns.quad9.net/dns-query",
            blockEncryptedDNS: true
        )
        let compiled = snapshot.compile()
        let quad9 = FlowDescriptor(
            ip: IPAddress.parse("9.9.9.9"), port: 443, protocolNumber: 6
        )
        #expect(compiled.evaluate(quad9, mode: .standard).action == .allow)
        let google = FlowDescriptor(
            ip: IPAddress.parse("8.8.8.8"), port: 443, protocolNumber: 6
        )
        #expect(compiled.evaluate(google, mode: .standard).action == .deny)
    }

    /// Composed rules must never leak into the stored rule list, or
    /// they'd pollute the user's Rules screen on reload.
    @Test func composedRulesStayOutOfStoredSnapshot() throws {
        let snapshot = RuleSnapshot(rules: [], blockEncryptedDNS: true)
        let back = try RuleSnapshot.deserialize(try snapshot.serialize())
        #expect(back.rules.isEmpty)
        #expect(back.blockEncryptedDNS == true)
    }

    /// A user Allow rule can override the synthetic deny; ties resolve
    /// allow-over-deny, the documented escape hatch.
    @Test func userAllowRuleOverridesSyntheticDeny() {
        let allow = Rule(action: .allow, target: .ip("8.8.8.8"))
        let compiled = RuleSnapshot(rules: [allow], blockEncryptedDNS: true).compile()
        let google = FlowDescriptor(
            ip: IPAddress.parse("8.8.8.8"), port: 443, protocolNumber: 6
        )
        #expect(compiled.evaluate(google, mode: .standard).action == .allow)
    }

    // MARK: - classify

    /// Any :853 destination is DoT, regardless of host form (bootstrap
    /// lookups arrive as a domain CONNECT).
    @Test func classifyPort853IsDoTForAnyHost() {
        #expect(EncryptedDNSBlocklist.classify(host: "1.1.1.1", port: 853) == .dot)
        #expect(EncryptedDNSBlocklist.classify(host: "one.one.one.one", port: 853) == .dot)
        #expect(EncryptedDNSBlocklist.classify(host: "203.0.113.9", port: 853) == .dot)
    }

    /// A resolver's dedicated IP on :443 is DoH-by-IP, v4 and v6, matched
    /// through IP normalization so v6 spelling differences still hit.
    @Test func classifyResolverIPOn443IsDoHIP() {
        #expect(EncryptedDNSBlocklist.classify(host: "9.9.9.9", port: 443) == .dohIP)
        #expect(EncryptedDNSBlocklist.classify(host: "94.140.14.14", port: 443) == .dohIP)
        #expect(EncryptedDNSBlocklist.classify(host: "2606:4700:4700:0:0:0:0:1111", port: 443) == .dohIP)
    }

    /// Ordinary destinations and non-resolver IPs on :443 are not encrypted
    /// DNS, so there's no false positive on normal HTTPS.
    @Test func classifyIgnoresOrdinaryTraffic() {
        #expect(EncryptedDNSBlocklist.classify(host: "example.com", port: 443) == nil)
        #expect(EncryptedDNSBlocklist.classify(host: "93.184.216.34", port: 443) == nil)
        #expect(EncryptedDNSBlocklist.classify(host: "1.1.1.1", port: 80) == nil)
    }
}
