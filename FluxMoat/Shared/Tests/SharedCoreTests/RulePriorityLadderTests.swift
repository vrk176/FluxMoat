import Foundation
import Testing
@testable import SharedCore

/// The shape ladder: every `RuleTarget` case, and the rung it lands on.
@Suite struct RuleTargetPriorityTests {
    @Test func exactDomainIsTheNarrowestRung() {
        #expect(RuleTarget.domain("example.com").derivedPriority == 12)
    }

    @Test func wildcardDomainIsSiteWide() {
        #expect(RuleTarget.domain("*.example.com").derivedPriority == 10)
    }

    /// The wildcard test above with the input a person actually types. Rank is
    /// read off the canonical form, or `*.Example.COM.` would be filed as an
    /// exact host and quietly outrank the leaf rules underneath it.
    @Test func wildcardIsRecognizedThroughNormalization() {
        #expect(RuleTarget.domain(" *.Example.COM. ").derivedPriority == 10)
        #expect(RuleTarget.domain("Example.COM.").derivedPriority == 12)
    }

    @Test func addressesAreExact() {
        #expect(RuleTarget.ip("203.0.113.7").derivedPriority == 12)
        #expect(RuleTarget.ip("2001:db8::1").derivedPriority == 12)
    }

    @Test func rangesSitWithSites() {
        #expect(RuleTarget.cidr("10.0.0.0/8").derivedPriority == 10)
        #expect(RuleTarget.cidr("2001:db8::/32").derivedPriority == 10)
    }

    @Test func portsAndProtocolsAreTheBroadestClaim() {
        #expect(RuleTarget.port(443...443).derivedPriority == 5)
        #expect(RuleTarget.port(1...1024).derivedPriority == 5)
        #expect(RuleTarget.network(protocolNumber: 6, port: nil).derivedPriority == 5)
        #expect(RuleTarget.network(protocolNumber: 17, port: 53...53).derivedPriority == 5)
    }

    /// The country layer compiles at 8 and strips its own rules back out at
    /// launch by that number plus a note prefix. A user rule landing on 8 would
    /// be read as ours and deleted, so no shape may reach it.
    @Test func noShapeLandsOnTheCountryRung() {
        let everyShape: [RuleTarget] = [
            .domain("example.com"),
            .domain("*.example.com"),
            .ip("203.0.113.7"),
            .cidr("10.0.0.0/8"),
            .port(443...443),
            .network(protocolNumber: 6, port: nil),
        ]
        #expect(everyShape.allSatisfy { $0.derivedPriority != 8 })
    }

    /// An exact host has to beat the site above it, or the decision made
    /// on the narrower row does nothing.
    @Test func narrowOutranksWide() {
        #expect(RuleTarget.domain("a.example.com").derivedPriority
            > RuleTarget.domain("*.example.com").derivedPriority)
        #expect(RuleTarget.domain("*.example.com").derivedPriority
            > RuleTarget.port(443...443).derivedPriority)
    }
}

@Suite struct RulePriorityNormalizationTests {
    /// Whatever numbers a file or an old device brought, one pass puts
    /// them on the ladder, and a second pass has nothing left to do.
    @Test func arbitraryNumbersConvergeInOnePass() {
        var rules = [
            Rule(action: .deny, target: .domain("ads.example.com"), priority: 0),
            Rule(action: .allow, target: .domain("*.example.com"), priority: 97),
            Rule(action: .deny, target: .ip("203.0.113.7"), priority: 3),
            Rule(action: .deny, target: .cidr("10.0.0.0/8"), priority: 41),
            Rule(action: .deny, target: .port(443...443), priority: 12),
        ]

        #expect(Rule.relevelAll(&rules) == 5)
        #expect(rules.map(\.priority) == [12, 10, 12, 10, 5])
        #expect(Rule.relevelAll(&rules) == 0)
        #expect(rules.map(\.priority) == [12, 10, 12, 10, 5])
    }

    @Test func aLedgerAlreadyOnTheLadderIsNotTouched() {
        var rules = [
            Rule(action: .deny, target: .domain("ads.example.com"), priority: 12),
            Rule(action: .allow, target: .domain("*.example.com"), priority: 10),
        ]
        #expect(Rule.relevelAll(&rules) == 0)
    }

    /// Only the priority moves. iCloud merges per id, so a launch that
    /// reissued ids would turn a normalization into a delete-plus-insert
    /// on every other device.
    @Test func nothingElseAboutTheRuleMoves() {
        let original = Rule(
            action: .allow,
            target: .domain("api.example.com"),
            profileID: UUID(),
            priority: 0,
            expiresAt: Date(timeIntervalSince1970: 1_800_000_000),
            note: "keep me",
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        var rules = [original]
        #expect(Rule.relevelAll(&rules) == 1)

        let leveled = rules[0]
        #expect(leveled.priority == 12)
        #expect(leveled.id == original.id)
        #expect(leveled.action == original.action)
        #expect(leveled.target == original.target)
        #expect(leveled.profileID == original.profileID)
        #expect(leveled.enabled == original.enabled)
        #expect(leveled.expiresAt == original.expiresAt)
        #expect(leveled.note == original.note)
        #expect(leveled.createdAt == original.createdAt)
    }

    @Test func emptyLedgerAnswersZero() {
        var rules: [Rule] = []
        #expect(Rule.relevelAll(&rules) == 0)
    }
}

/// The ladder as the engine actually reads it. These go through
/// `CompiledRuleSet` rather than comparing integers, since "an exact
/// target beats a site-wide rule" is a claim about verdicts, not numbers.
@Suite struct LeveledRuleResolutionTests {
    private func flow(_ domain: String) -> FlowDescriptor {
        FlowDescriptor(domain: domain, ip: nil, port: nil, protocolNumber: nil, profileID: nil, timestamp: Date())
    }

    @Test func exactBlockSurvivesUnderASiteWideAllow() {
        let set = CompiledRuleSet(rules: [
            Rule(action: .allow, target: .domain("*.example.com")).leveled,
            Rule(action: .deny, target: .domain("ads.example.com")).leveled,
        ])
        #expect(set.evaluate(flow("ads.example.com"), mode: .standard).action == .deny)
        #expect(set.evaluate(flow("cdn.example.com"), mode: .standard).action == .allow)
    }

    @Test func exactAllowSurvivesUnderASiteWideBlock() {
        let set = CompiledRuleSet(rules: [
            Rule(action: .deny, target: .domain("*.example.com")).leveled,
            Rule(action: .allow, target: .domain("api.example.com")).leveled,
        ])
        #expect(set.evaluate(flow("api.example.com"), mode: .standard).action == .allow)
        #expect(set.evaluate(flow("ads.example.com"), mode: .standard).action == .deny)
    }

    /// The import case, and the reason `applyImport` re-levels: the same two
    /// rules with the numbers a file might carry resolve the wrong way round.
    @Test func importedNumbersWouldInvertWithoutReleveling() {
        let raw = [
            Rule(action: .allow, target: .domain("*.example.com"), priority: 10),
            Rule(action: .deny, target: .domain("ads.example.com"), priority: 0),
        ]
        #expect(CompiledRuleSet(rules: raw).evaluate(flow("ads.example.com"), mode: .standard).action == .allow)

        var leveled = raw
        _ = Rule.relevelAll(&leveled)
        #expect(CompiledRuleSet(rules: leveled).evaluate(flow("ads.example.com"), mode: .standard).action == .deny)
    }
}
