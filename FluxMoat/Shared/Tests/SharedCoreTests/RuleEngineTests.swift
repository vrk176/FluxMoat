import Foundation
import Testing
@testable import SharedCore

private func flow(
    domain: String? = nil,
    ip: String? = nil,
    port: UInt16? = nil,
    proto: UInt8? = nil,
    profileID: UUID? = nil,
    at date: Date = Date()
) -> FlowDescriptor {
    FlowDescriptor(
        domain: domain,
        ip: ip.flatMap(IPAddress.parse(_:)),
        port: port,
        protocolNumber: proto,
        profileID: profileID,
        timestamp: date
    )
}

@Suite struct DomainMatchingTests {
    @Test func exactDomainIsCaseAndTrailingDotInsensitive() {
        let rule = Rule(action: .deny, target: .domain("Example.COM."))
        let set = CompiledRuleSet(rules: [rule])
        #expect(set.evaluate(flow(domain: "EXAMPLE.com"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(domain: "example.com."), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(domain: "www.example.com"), mode: .standard).action == .allow)
    }

    @Test func wildcardMatchesSubdomainsOnly() {
        let rule = Rule(action: .deny, target: .domain("*.example.com"))
        let set = CompiledRuleSet(rules: [rule])
        #expect(set.evaluate(flow(domain: "a.example.com"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(domain: "a.b.example.com"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(domain: "example.com"), mode: .standard).action == .allow)
        #expect(set.evaluate(flow(domain: "notexample.com"), mode: .standard).action == .allow)
    }

    @Test func punycodeDomainsMatchAsEncoded() {
        let rule = Rule(action: .deny, target: .domain("xn--fsq.example"))
        let set = CompiledRuleSet(rules: [rule])
        #expect(set.evaluate(flow(domain: "XN--FSQ.example"), mode: .standard).action == .deny)
    }
}

@Suite struct IPMatchingTests {
    @Test func exactIPv4AndIPv6() {
        let rules = [
            Rule(action: .deny, target: .ip("203.0.113.7")),
            Rule(action: .deny, target: .ip("2001:db8::7")),
        ]
        let set = CompiledRuleSet(rules: rules)
        #expect(set.evaluate(flow(ip: "203.0.113.7"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(ip: "203.0.113.8"), mode: .standard).action == .allow)
        #expect(set.evaluate(flow(ip: "2001:db8:0::7"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(ip: "2001:db8::8"), mode: .standard).action == .allow)
    }

    @Test func cidrMatching() {
        let rules = [
            Rule(action: .deny, target: .cidr("10.0.0.0/8")),
            Rule(action: .deny, target: .cidr("2001:db8::/32")),
        ]
        let set = CompiledRuleSet(rules: rules)
        #expect(set.evaluate(flow(ip: "10.255.1.2"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(ip: "11.0.0.1"), mode: .standard).action == .allow)
        #expect(set.evaluate(flow(ip: "2001:db8:ffff::1"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(ip: "2001:db9::1"), mode: .standard).action == .allow)
    }

    @Test func nat64PrefixMatchesEmbeddedIPv4() {
        let rule = Rule(action: .deny, target: .cidr("64:ff9b::/96"))
        let set = CompiledRuleSet(rules: [rule])
        #expect(set.evaluate(flow(ip: "64:ff9b::203.0.113.7"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(ip: "2001:db8::1"), mode: .standard).action == .allow)
    }

    @Test func overlappingCIDRsResolveByPriority() {
        let broad = Rule(action: .deny, target: .cidr("10.0.0.0/8"), priority: 0)
        let narrow = Rule(action: .allow, target: .cidr("10.1.0.0/16"), priority: 10)
        let set = CompiledRuleSet(rules: [broad, narrow])
        let verdict = set.evaluate(flow(ip: "10.1.2.3"), mode: .standard)
        #expect(verdict.action == .allow)
        #expect(verdict.matchedRuleID == narrow.id)
        #expect(set.evaluate(flow(ip: "10.2.0.1"), mode: .standard).action == .deny)
    }
}

@Suite struct PortAndProtocolTests {
    @Test func overlappingPortRangesResolveByPriorityThenAllow() {
        let denyWide = Rule(action: .deny, target: .port(1000...2000), priority: 0)
        let allowSame = Rule(action: .allow, target: .port(1500...1600), priority: 0)
        let set = CompiledRuleSet(rules: [denyWide, allowSame])
        // Equal priority: allow wins the tie.
        #expect(set.evaluate(flow(port: 1550), mode: .standard).action == .allow)
        #expect(set.evaluate(flow(port: 1200), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(port: 3000), mode: .standard).action == .allow)
    }

    @Test func protocolRuleWithOptionalPort() {
        let udp = UInt8(17)
        let denyUDP53 = Rule(action: .deny, target: .network(protocolNumber: udp, port: 53...53))
        let set = CompiledRuleSet(rules: [denyUDP53])
        #expect(set.evaluate(flow(port: 53, proto: udp), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(port: 443, proto: udp), mode: .standard).action == .allow)
        #expect(set.evaluate(flow(port: 53, proto: 6), mode: .standard).action == .allow)
    }
}

/// Why a target may never end up holding an allow and a deny at once.
///
/// Regression: allow-then-block on the same target used to leave a
/// permanent, never-firing deny rule because writers appended rules
/// instead of replacing them. The tie-break itself (allow wins) is
/// correct and is not what changed.
@Suite struct EqualPriorityTieTests {
    @Test func allowBeatsDenyOnTheSameTargetAtEqualPriority() {
        let allow = Rule(action: .allow, target: .domain("tracker.example"), priority: 10)
        let deny = Rule(action: .deny, target: .domain("tracker.example"), priority: 10)
        // Both orderings: the winner is the action, never the arrival order.
        for rules in [[allow, deny], [deny, allow]] {
            let verdict = CompiledRuleSet(rules: rules).evaluate(flow(domain: "tracker.example"), mode: .standard)
            #expect(verdict.action == .allow)
            #expect(verdict.matchedRuleID == allow.id)
        }
    }

    @Test func denyWinsOnceItOutranksTheAllow() {
        // What the app writes now instead of a pair, and what a
        // hand-authored priority can still do.
        let allow = Rule(action: .allow, target: .ip("203.0.113.7"), priority: 10)
        let deny = Rule(action: .deny, target: .ip("203.0.113.7"), priority: 11)
        let set = CompiledRuleSet(rules: [allow, deny])
        let verdict = set.evaluate(flow(ip: "203.0.113.7"), mode: .standard)
        #expect(verdict.action == .deny)
        #expect(verdict.matchedRuleID == deny.id)
    }

    @Test func aLoneDenySurvivesTheReplacement() {
        // The state the fixed writer leaves behind: one rule, and it decides.
        let deny = Rule(action: .deny, target: .domain("tracker.example"), priority: 12)
        let verdict = CompiledRuleSet(rules: [deny]).evaluate(flow(domain: "tracker.example"), mode: .standard)
        #expect(verdict.action == .deny)
        #expect(verdict.matchedRuleID == deny.id)
    }
}

@Suite struct PrecedenceTests {
    @Test func userAllowOverridesBlocklist() {
        let allow = Rule(action: .allow, target: .domain("tracker.example"))
        let set = CompiledRuleSet(rules: [allow], blocklistDomains: ["tracker.example"])
        let verdict = set.evaluate(flow(domain: "tracker.example"), mode: .standard)
        #expect(verdict.action == .allow)
        #expect(verdict.source == .userRule)
    }

    @Test func blocklistBlocksHostAndSubdomains() {
        let set = CompiledRuleSet(rules: [], blocklistDomains: ["ads.example"])
        #expect(set.evaluate(flow(domain: "ads.example"), mode: .standard).source == .blocklist)
        #expect(set.evaluate(flow(domain: "cdn.ads.example"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(domain: "example"), mode: .standard).action == .allow)
    }

    // MARK: - Threat-intel layer 2: IP/CIDR feeds + threat domains

    @Test func threatIPBlocksExactAddressAsThreatFeed() {
        let set = CompiledRuleSet(rules: [], threatIPs: ["93.184.216.34"])
        let verdict = set.evaluate(flow(ip: "93.184.216.34"), mode: .standard)
        #expect(verdict.action == .deny)
        #expect(verdict.source == .threatFeed)
        #expect(set.evaluate(flow(ip: "93.184.216.35"), mode: .standard).action == .allow)
    }

    @Test func threatCIDRBlocksNetworkRange() {
        let set = CompiledRuleSet(rules: [], threatIPs: ["192.0.2.0/24"])
        #expect(set.evaluate(flow(ip: "192.0.2.5"), mode: .standard).source == .threatFeed)
        #expect(set.evaluate(flow(ip: "192.0.2.255"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(ip: "192.0.3.1"), mode: .standard).action == .allow)
    }

    @Test func threatIPMatchesV6() {
        let set = CompiledRuleSet(rules: [], threatIPs: ["2001:db8::/32"])
        #expect(set.evaluate(flow(ip: "2001:db8::1"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(ip: "2001:db9::1"), mode: .standard).action == .allow)
    }

    /// Threat domains report `.threatFeed`, distinct from the ad/tracker
    /// blocklist's `.blocklist`.
    @Test func threatDomainReportsThreatFeed() {
        let set = CompiledRuleSet(rules: [], threatDomains: ["malware.example"])
        let verdict = set.evaluate(flow(domain: "c2.malware.example"), mode: .standard)
        #expect(verdict.action == .deny)
        #expect(verdict.source == .threatFeed)
    }

    /// A name on both an ad list and a threat feed reports the more serious
    /// classification.
    @Test func threatDomainTakesPrecedenceOverAdBlocklist() {
        let set = CompiledRuleSet(
            rules: [], blocklistDomains: ["dual.example"], threatDomains: ["dual.example"]
        )
        #expect(set.evaluate(flow(domain: "dual.example"), mode: .standard).source == .threatFeed)
    }

    /// A user Allow rule must override a threat block, same escape hatch
    /// as the ad blocklist.
    @Test func userAllowOverridesThreatFeed() {
        let allow = Rule(action: .allow, target: .ip("93.184.216.34"))
        let set = CompiledRuleSet(rules: [allow], threatIPs: ["93.184.216.34"])
        let verdict = set.evaluate(flow(ip: "93.184.216.34"), mode: .standard)
        #expect(verdict.action == .allow)
        #expect(verdict.source == .userRule)
    }

    /// Pause never blocks, including threat hits.
    @Test func pauseModeIgnoresThreatFeed() {
        let set = CompiledRuleSet(rules: [], threatIPs: ["93.184.216.34"])
        #expect(set.evaluate(flow(ip: "93.184.216.34"), mode: .pause).action == .allow)
    }

    /// Ad blocklist and threat feeds coexist and report distinct sources.
    @Test func adBlocklistAndThreatFeedsCoexist() {
        let set = CompiledRuleSet(
            rules: [], blocklistDomains: ["ads.example"], threatIPs: ["10.20.30.40"]
        )
        #expect(set.evaluate(flow(domain: "ads.example"), mode: .standard).source == .blocklist)
        #expect(set.evaluate(flow(ip: "10.20.30.40"), mode: .standard).source == .threatFeed)
        #expect(set.evaluate(flow(ip: "10.20.30.41"), mode: .standard).action == .allow)
    }

    @Test func expiredTemporaryRuleIsIgnored() {
        let now = Date()
        let temp = Rule(action: .deny, target: .domain("example.com"), expiresAt: now.addingTimeInterval(60))
        let set = CompiledRuleSet(rules: [temp])
        #expect(set.evaluate(flow(domain: "example.com", at: now), mode: .standard).action == .deny)
        let later = now.addingTimeInterval(120)
        #expect(set.evaluate(flow(domain: "example.com", at: later), mode: .standard).action == .allow)
    }

    @Test func profileScopedRuleOnlyAppliesInItsProfile() {
        let profile = UUID()
        let other = UUID()
        let rule = Rule(action: .deny, target: .domain("example.com"), profileID: profile)
        let set = CompiledRuleSet(rules: [rule])
        #expect(set.evaluate(flow(domain: "example.com", profileID: profile), mode: .standard).action == .deny)
        #expect(set.evaluate(flow(domain: "example.com", profileID: other), mode: .standard).action == .allow)
        #expect(set.evaluate(flow(domain: "example.com"), mode: .standard).action == .allow)
    }

    @Test func modeDefaultsForUnmatchedFlows() {
        let set = CompiledRuleSet(rules: [], blocklistDomains: ["ads.example"])
        #expect(set.evaluate(flow(domain: "new.example"), mode: .learning).action == .allow)
        #expect(set.evaluate(flow(domain: "new.example"), mode: .strict).action == .deny)
        #expect(set.evaluate(flow(domain: "new.example"), mode: .ask, profileDefault: .deny).action == .deny)
        // Pause keeps counting but never blocks, including blocklist hits.
        #expect(set.evaluate(flow(domain: "ads.example"), mode: .pause).action == .allow)
    }

    @Test func disabledRuleIsIgnored() {
        let rule = Rule(action: .deny, target: .domain("example.com"), enabled: false)
        let set = CompiledRuleSet(rules: [rule])
        #expect(set.evaluate(flow(domain: "example.com"), mode: .standard).action == .allow)
    }
}
