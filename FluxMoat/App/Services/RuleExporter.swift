import Foundation
import SharedCore

/// Serializes the user's rules into a file for the share sheet.
///
/// The JSON envelope is the complete, app-native format. The `.lsrules` form is
/// for Little Snitch interchange; `LSRulesLoss` reports what it can't carry so
/// the UI can say so before sharing.
///
/// Nothing here logs: the file contains the user's domains, and they must not
/// end up in the device log. `AppModel` owns the temp directory, the share sheet
/// and count-only logging.
enum RuleExporter {

    // MARK: - JSON envelope (primary)

    /// The full rule set in the app's own format. Export only; nothing reads it
    /// back yet. `format` and `version` let a future importer reject foreign or
    /// incompatible files, and rule ids let it merge instead of duplicating.
    ///
    /// Encodes `Rule` and `CountryPolicy` directly (no DTOs) so new fields are
    /// exported automatically. `.iso8601` truncates timestamps to whole seconds.
    struct RuleExportEnvelope: Codable {
        /// Constant marker so a reader can reject files that are not ours.
        var format: String = RuleExporter.envelopeFormat
        /// Schema version. Bump when a field changes meaning; added keys are
        /// skipped by readers that ignore unknown keys.
        var version: Int = RuleExporter.envelopeVersion
        /// Whole-second resolution.
        var exportedAt: Date
        var rules: [Rule]
        /// Includes `derivedTargets` so a restore keeps the accumulated targets.
        var countryPolicies: [CountryPolicy]
        /// Manually added or imported domains only. Subscribed lists are omitted
        /// because the app can re-fetch them from their URL.
        var blocklistDomains: [String]
    }

    static let envelopeFormat = "fluxmoat.rules"
    static let envelopeVersion = 1

    /// What a preview sheet needs to describe the file before sharing it.
    struct JSONExport {
        let url: URL
        let rules: Int
        let countryPolicies: Int
        let blocklistDomains: Int
    }

    static func makeEnvelope(
        rules: [Rule],
        countryPolicies: [CountryPolicy],
        blocklistDomains: [String],
        exportedAt: Date = Date()
    ) -> RuleExportEnvelope {
        RuleExportEnvelope(
            exportedAt: exportedAt,
            rules: rules,
            countryPolicies: countryPolicies,
            blocklistDomains: blocklistDomains
        )
    }

    static func jsonData(
        rules: [Rule],
        countryPolicies: [CountryPolicy],
        blocklistDomains: [String],
        exportedAt: Date = Date()
    ) throws -> Data {
        try encoder().encode(
            makeEnvelope(
                rules: rules,
                countryPolicies: countryPolicies,
                blocklistDomains: blocklistDomains,
                exportedAt: exportedAt
            )
        )
    }

    /// Writes into `directory`, which the caller creates and cleans up.
    static func writeJSON(
        rules: [Rule],
        countryPolicies: [CountryPolicy],
        blocklistDomains: [String],
        into directory: URL,
        now: Date = Date()
    ) throws -> JSONExport {
        let url = directory.appendingPathComponent("FluxMoat-rules-\(stamp(now)).json")
        try write(
            try jsonData(
                rules: rules,
                countryPolicies: countryPolicies,
                blocklistDomains: blocklistDomains,
                exportedAt: now
            ),
            to: url
        )
        return JSONExport(
            url: url,
            rules: rules.count,
            countryPolicies: countryPolicies.count,
            blocklistDomains: blocklistDomains.count
        )
    }

    // MARK: - .lsrules (secondary, lossy by design)

    /// What this export loses in .lsrules form, beyond what the format always
    /// drops: rule ids, creation dates, and `profileID` (the importer creates
    /// fresh rules that apply in every profile). `lossCaption` names both.
    struct LSRulesLoss {
        /// No .lsrules equivalent, so temporary rules come back permanent.
        var rulesWithExpiry: Int
        /// Not written at all; see `writeLSRules`.
        var countryPolicies: Int

        /// Nothing lost beyond the fixed fields above.
        var isLossless: Bool {
            rulesWithExpiry == 0 && countryPolicies == 0
        }
    }

    // Priority is not counted as a loss: it is derived from the target's shape,
    // which .lsrules carries, and `AppModel.applyImport` re-derives it.

    struct LSRulesExport {
        let url: URL
        let rules: Int
        let blocklistDomains: Int
        let loss: LSRulesLoss
    }

    /// Inverse of the importer's threshold for `priority: high`.
    private static let lsHighPriority = 10

    static func loss(rules: [Rule], countryPolicies: [CountryPolicy]) -> LSRulesLoss {
        LSRulesLoss(
            rulesWithExpiry: rules.count { $0.expiresAt != nil },
            countryPolicies: countryPolicies.count
        )
    }

    /// One sentence for the share sheet, shown before exporting. Lists only real
    /// losses (notes do survive the round trip).
    static func lossCaption(_ loss: LSRulesLoss) -> String {
        // Always lost, regardless of content.
        var missing = ["rule ids", "creation dates"]
        if loss.rulesWithExpiry > 0 { missing.append("expiry dates") }
        if loss.countryPolicies > 0 {
            missing.append(loss.countryPolicies == 1 ? "1 country policy" : "\(loss.countryPolicies) country policies")
        }
        return "Little Snitch format keeps targets, actions, notes and on/off state — "
            + sentenceList(missing) + " are not part of it."
    }

    static func lsRulesData(
        rules: [Rule],
        blocklistDomains: [String],
        now: Date = Date()
    ) throws -> Data {
        let stamp = stamp(now)
        let group = LSRuleGroup(
            name: "FluxMoat rules \(stamp)",
            // Counts only: other tools display the description, so it must not
            // contain user domains.
            groupDescription: "Exported from FluxMoat on \(stamp) — "
                + "\(rules.count) rule\(rules.count == 1 ? "" : "s"), "
                + "\(blocklistDomains.count) blocked domain\(blocklistDomains.count == 1 ? "" : "s").",
            // Omitted when empty; the importer treats a missing key as empty.
            deniedRemoteDomains: blocklistDomains.isEmpty ? nil : blocklistDomains,
            rules: rules.map(lsRule)
        )
        return try encoder().encode(group)
    }

    /// Writes the .lsrules file. Country policies are left out: they are app-side
    /// state that keeps updating, and exporting their current compiled rules
    /// would freeze them. The JSON envelope carries the policies themselves.
    /// Caller owns `directory`, as with `writeJSON`.
    static func writeLSRules(
        rules: [Rule],
        countryPolicies: [CountryPolicy],
        blocklistDomains: [String],
        into directory: URL,
        now: Date = Date()
    ) throws -> LSRulesExport {
        let url = directory.appendingPathComponent("FluxMoat-rules-\(stamp(now)).lsrules")
        try write(try lsRulesData(rules: rules, blocklistDomains: blocklistDomains, now: now), to: url)
        return LSRulesExport(
            url: url,
            rules: rules.count,
            blocklistDomains: blocklistDomains.count,
            loss: loss(rules: rules, countryPolicies: countryPolicies)
        )
    }

    // MARK: - Rule → LS entry

    /// Maps one rule to one entry, as the exact inverse of
    /// `LSRulesImporter.translate`, so export then import returns the same rules.
    /// Each entry has a single target dimension, which keeps the importer off its
    /// lossy host-plus-port path and leaves `notes` unchanged.
    private static func lsRule(for rule: Rule) -> LSRule {
        var entry = LSRule(action: rule.action.rawValue)
        // A missing `disabled` key means enabled.
        if !rule.enabled { entry.disabled = true }
        entry.notes = rule.note
        if rule.priority >= lsHighPriority { entry.priority = "high" }

        switch rule.target {
        case .domain(let host):
            // `remote-hosts` with the wildcard written literally: normalization
            // keeps a leading `*.`, so it round-trips unchanged. The importer
            // expands `remote-domains` into an apex plus wildcard pair, which
            // would widen the rule on re-import.
            entry.remoteHosts = [host]
        case .ip(let address), .cidr(let address):
            // The importer tells IP from CIDR by the slash.
            entry.remoteAddresses = [address]
        case .port(let range):
            // No host: with one, the importer builds a host rule and drops the ports.
            entry.ports = lsPorts(range)
        case .network(let protocolNumber, let port):
            // Protocol without a host is the only input that imports as `.network`.
            entry.networkProtocol = lsProtocol(protocolNumber)
            if let port { entry.ports = lsPorts(port) }
        }
        return entry
    }

    /// A single port as a number, a range as "low-high", the two forms the importer accepts.
    private static func lsPorts(_ range: ClosedRange<UInt16>) -> LSScalar {
        range.lowerBound == range.upperBound
            ? .number(Int(range.lowerBound))
            : .text("\(range.lowerBound)-\(range.upperBound)")
    }

    /// Names for the protocols Little Snitch spells out, numbers for the rest.
    /// The importer accepts both.
    private static func lsProtocol(_ number: UInt8) -> LSScalar {
        switch number {
        case 6: .text("tcp")
        case 17: .text("udp")
        case 1: .text("icmp")
        default: .number(Int(number))
        }
    }

    // MARK: - Wire shapes

    private struct LSRuleGroup: Encodable {
        var name: String
        var groupDescription: String
        var deniedRemoteDomains: [String]?
        var rules: [LSRule]

        enum CodingKeys: String, CodingKey {
            case name
            case groupDescription = "description"
            case deniedRemoteDomains = "denied-remote-domains"
            case rules
        }
    }

    private struct LSRule: Encodable {
        var action: String
        var disabled: Bool?
        var notes: String?
        var priority: String?
        var remoteHosts: [String]?
        var remoteAddresses: [String]?
        var ports: LSScalar?
        var networkProtocol: LSScalar?

        enum CodingKeys: String, CodingKey {
            case action, disabled, notes, priority, ports
            case remoteHosts = "remote-hosts"
            case remoteAddresses = "remote-addresses"
            case networkProtocol = "protocol"
        }
    }

    /// `ports` and `protocol` can each be a number or a string.
    private enum LSScalar: Encodable {
        case number(Int)
        case text(String)

        func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .number(let value): try container.encode(value)
            case .text(let value): try container.encode(value)
            }
        }
    }

    // MARK: - Plumbing

    /// `.sortedKeys` makes exports of unchanged rules byte-identical (useful for
    /// backups kept in git). `.withoutEscapingSlashes` keeps CIDRs as `10.0.0.0/8`.
    private static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }

    /// Same date stamp as `AppModel.exportHistory`, so exports sort together.
    private static func stamp(_ date: Date) -> String {
        date.formatted(.iso8601.year().month().day())
    }

    /// The temp file holds the user's full rule set, so it gets file protection.
    /// `UnlessOpen` lets the share sheet finish a copy started while unlocked.
    private static func write(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: [.atomic, .completeFileProtectionUnlessOpen])
    }

    private static func sentenceList(_ items: [String]) -> String {
        switch items.count {
        case 0: ""
        case 1: items[0]
        case 2: "\(items[0]) and \(items[1])"
        default: items.dropLast().joined(separator: ", ") + " and " + (items.last ?? "")
        }
    }
}
