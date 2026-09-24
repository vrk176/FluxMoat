import Foundation

/// Importer for Little Snitch rule group files (`.lsrules`, JSON).
///
/// iOS has no per-app network identity, so app-scoped fields (`process`,
/// `via`, `owner`, `helper`) are ignored; the network targets are still
/// imported and the skipped fields are counted for the UI. Little Snitch
/// combines fields with AND (domain and port), but our rules carry a single
/// target, so port/protocol limits on host rules are dropped and counted in
/// `constraintsDropped`.
public enum LSRulesImporter {
    public struct Report: Sendable {
        public var groupName: String?
        public var groupDescription: String?
        /// User rules translated from the `rules` array and the
        /// `denied-remote-hosts`/`denied-remote-addresses` shorthands.
        public var rules: [Rule] = []
        /// From the `denied-remote-domains` shorthand. Matches the host and all
        /// subdomains, same as a blocklist entry.
        public var blocklistDomains: [String] = []
        /// Rules whose process/via/owner/helper fields were ignored.
        public var appScopeDropped = 0
        /// Rules whose port/protocol conjunction could not be represented.
        public var constraintsDropped = 0
        public var skipped: [Skipped] = []

        public struct Skipped: Sendable {
            public let index: Int
            public let reason: String
        }

        public var importedCount: Int { rules.count }
    }

    public struct ParseError: Error, Sendable {
        public let reason: String
    }

    public static func parse(_ data: Data) throws -> Report {
        guard let root = try? JSONSerialization.jsonObject(with: data),
              let dict = root as? [String: Any]
        else {
            throw ParseError(reason: "not a JSON object")
        }

        var report = Report()
        report.groupName = dict["name"] as? String
        report.groupDescription = dict["description"] as? String

        // Shorthand lists (common for subscription blocklists).
        for domain in stringList(dict["denied-remote-domains"]) {
            report.blocklistDomains.append(DomainName.normalize(domain))
        }
        for host in stringList(dict["denied-remote-hosts"]) {
            report.rules.append(Rule(action: .deny, target: .domain(DomainName.normalize(host))))
        }
        for (index, address) in stringList(dict["denied-remote-addresses"]).enumerated() {
            if let target = addressTarget(address) {
                report.rules.append(Rule(action: .deny, target: target))
            } else {
                report.skipped.append(.init(index: index, reason: "unsupported address form: \(address)"))
            }
        }

        if let rules = dict["rules"] as? [[String: Any]] {
            for (index, entry) in rules.enumerated() {
                translate(entry, index: index, into: &report)
            }
        }

        if report.rules.isEmpty && report.blocklistDomains.isEmpty && report.skipped.isEmpty {
            throw ParseError(reason: "no rules found — is this a .lsrules file?")
        }
        return report
    }

    // MARK: - Single rule translation

    private static func translate(_ entry: [String: Any], index: Int, into report: inout Report) {
        let action: RuleAction
        switch (entry["action"] as? String)?.lowercased() ?? "deny" {
        case "allow": action = .allow
        case "deny": action = .deny
        case "ask":
            report.skipped.append(.init(index: index, reason: "ask action not supported on iOS"))
            return
        case let other:
            report.skipped.append(.init(index: index, reason: "unknown action: \(other)"))
            return
        }

        if let direction = (entry["direction"] as? String)?.lowercased(), direction == "incoming" {
            report.skipped.append(.init(index: index, reason: "incoming rules not supported"))
            return
        }

        if entry["process"] != nil || entry["via"] != nil
            || entry["owner"] != nil || entry["helper"] != nil {
            report.appScopeDropped += 1
        }

        let enabled = !((entry["disabled"] as? Bool) ?? false)
        let priority = (entry["priority"] as? String)?.lowercased() == "high" ? 10 : 0
        var note = entry["notes"] as? String

        let ports = portRange(entry["ports"])
        let protocolNumber = protocolNumber(entry["protocol"])

        var targets: [RuleTarget] = []
        for host in stringList(entry["remote-hosts"]) {
            targets.append(.domain(DomainName.normalize(host)))
        }
        for domain in stringList(entry["remote-domains"]) {
            // LS domain rules match the host and all subdomains.
            let normalized = DomainName.normalize(domain)
            targets.append(.domain(normalized))
            targets.append(.domain("*." + normalized))
        }
        for address in stringList(entry["remote-addresses"]) {
            if let target = addressTarget(address) {
                targets.append(target)
            } else {
                report.skipped.append(.init(index: index, reason: "unsupported address form: \(address)"))
            }
        }

        if targets.isEmpty {
            // No host dimension: a pure port/protocol rule is representable.
            if let protocolNumber {
                targets.append(.network(protocolNumber: protocolNumber, port: ports))
            } else if let ports {
                targets.append(.port(ports))
            } else {
                report.skipped.append(.init(index: index, reason: "no network-level target (app-scoped or alias-only rule)"))
                return
            }
        } else if ports != nil || protocolNumber != nil {
            // A host plus port/protocol combination can't be represented. Import the
            // host and count what was dropped.
            report.constraintsDropped += 1
            let dropped = "imported from .lsrules; port/protocol constraint dropped"
            note = note.map { "\($0) — \(dropped)" } ?? dropped
        }

        for target in targets {
            report.rules.append(Rule(
                action: action,
                target: target,
                priority: priority,
                enabled: enabled,
                note: note
            ))
        }
    }

    // MARK: - Field parsing

    private static func stringList(_ value: Any?) -> [String] {
        if let single = value as? String { return [single] }
        return (value as? [String]) ?? []
    }

    private static func addressTarget(_ raw: String) -> RuleTarget? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        if trimmed.contains("/") {
            return CIDRBlock(trimmed) != nil ? .cidr(trimmed) : nil
        }
        // "a.b.c.d-a.b.c.e" ranges are not supported in v1.
        if IPAddress.parse(trimmed) != nil { return .ip(trimmed) }
        return nil
    }

    private static func portRange(_ value: Any?) -> ClosedRange<UInt16>? {
        if let number = value as? Int, let port = UInt16(exactly: number) {
            return port...port
        }
        guard let string = (value as? String)?.trimmingCharacters(in: .whitespaces).lowercased(),
              !string.isEmpty, string != "any"
        else { return nil }
        let parts = string.split(separator: "-", maxSplits: 1)
        if parts.count == 2, let low = UInt16(parts[0]), let high = UInt16(parts[1]), low <= high {
            return low...high
        }
        if let port = UInt16(string) { return port...port }
        return nil
    }

    private static func protocolNumber(_ value: Any?) -> UInt8? {
        if let number = value as? Int { return UInt8(exactly: number) }
        switch (value as? String)?.lowercased() {
        case "tcp": return 6
        case "udp": return 17
        case "icmp": return 1
        default: return nil
        }
    }
}
