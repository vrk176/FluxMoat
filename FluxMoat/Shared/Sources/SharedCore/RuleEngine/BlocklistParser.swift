import Foundation

/// Parses downloaded blocklists into normalized entries. Domain formats
/// (`hosts`, plain domain lists) feed the ad/tracker lists; `ipList` and
/// `cidrList` feed threat-intel IP indicators matched per connection.
///
/// Entries are checked for length and characters and the total is capped.
/// Lines that aren't a plausible entry are skipped and counted instead of
/// failing the whole list.
public enum BlocklistParser {
    /// The parsed entries of one feed. A feed has one kind: domain lists fill
    /// `domains`, IP/CIDR feeds fill `ipEntries`, and the other stays empty
    /// (JSON feeds can fill both). `ipEntries` are canonical strings (single IP
    /// or `network/prefix`) so they can be stored the same way as domains.
    public struct Report: Sendable, Equatable {
        /// Normalized (lowercased, no trailing dot, `*.` and leading-dot wildcards
        /// reduced to the base domain, since matching already covers subdomains),
        /// deduplicated, in first-seen order.
        public let domains: [String]
        /// Canonical IP/CIDR strings, deduplicated, in first-seen order. A bare IP
        /// is kept as is (`93.184.216.34`); a CIDR has its host bits cleared
        /// (`192.0.2.5/24` becomes `192.0.2.0/24`).
        public let ipEntries: [String]
        /// Non-empty, non-comment lines that did not yield an entry.
        public let skippedCount: Int

        public init(domains: [String] = [], ipEntries: [String] = [], skippedCount: Int = 0) {
            self.domains = domains
            self.ipEntries = ipEntries
            self.skippedCount = skippedCount
        }
    }

    public struct ParseError: Error, Sendable {
        public let reason: String
    }

    /// Maximum accepted entries. Large enough for StevenBlack-sized lists
    /// (about 130k) while keeping the snapshot and the tunnel's trie within
    /// the extension's memory limit. Re-test memory on device before raising.
    public static let maxEntries = 200_000
    /// Longest legal DNS name.
    static let maxDomainLength = 253

    /// Host names that appear in every hosts file but are never targets.
    private static let hostsBoilerplate: Set<String> = [
        "localhost", "localhost.localdomain", "local", "broadcasthost",
        "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
        "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
    ]

    public static func parse(
        _ data: Data,
        format: BlocklistSource.Format,
        maxEntries: Int = BlocklistParser.maxEntries
    ) throws -> Report {
        guard let text = String(data: data, encoding: .utf8) else {
            throw ParseError(reason: "payload is not valid UTF-8")
        }
        switch format {
        case .hosts, .domainList:
            return try parseDomains(text, format: format, maxEntries: maxEntries)
        case .ipList, .cidrList:
            return try parseIPs(text, format: format, maxEntries: maxEntries)
        case .jsonManifest:
            return try parseJSON(data, maxEntries: maxEntries)
        default:
            throw ParseError(reason: "unsupported format \(format.rawValue)")
        }
    }

    // MARK: - Domain formats (ad/tracker)

    private static func parseDomains(
        _ text: String, format: BlocklistSource.Format, maxEntries: Int
    ) throws -> Report {
        var seen = Set<String>()
        var domains: [String] = []
        var skipped = 0

        for var line in text.split(omittingEmptySubsequences: true, whereSeparator: \.isNewline) {
            if let hash = line.firstIndex(of: "#") { line = line[..<hash] }
            let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard !tokens.isEmpty else { continue }

            let candidates: ArraySlice<Substring>
            switch format {
            case .hosts:
                // `0.0.0.0 ads.example tracker.example`: a sink address followed by one
                // or more host names.
                guard tokens.count >= 2, looksLikeIPAddress(tokens[0]) else {
                    skipped += 1
                    continue
                }
                candidates = tokens.dropFirst()
            default:
                guard tokens.count == 1 else {
                    skipped += 1
                    continue
                }
                candidates = tokens[...]
            }

            for candidate in candidates {
                guard let domain = normalizedDomain(candidate) else {
                    skipped += 1
                    continue
                }
                guard seen.insert(domain).inserted else { continue }
                if domains.count >= maxEntries {
                    throw ParseError(reason: "list exceeds \(maxEntries) entries")
                }
                domains.append(domain)
            }
        }

        return Report(domains: domains, skippedCount: skipped)
    }

    // MARK: - IP / CIDR formats (threat intel)

    /// Parses an IP list (one address per line, like Feodo) or a CIDR list
    /// (`network/prefix ; comment`, like Spamhaus DROP). Both `#` and `;` start
    /// comments. Feeds mix bare IPs and CIDRs, so both formats accept both; a
    /// bare IP becomes a /32 or /128.
    private static func parseIPs(
        _ text: String, format: BlocklistSource.Format, maxEntries: Int
    ) throws -> Report {
        var seen = Set<String>()
        var entries: [String] = []
        var skipped = 0

        for var line in text.split(omittingEmptySubsequences: true, whereSeparator: \.isNewline) {
            if let hash = line.firstIndex(where: { $0 == "#" || $0 == ";" }) {
                line = line[..<hash]
            }
            // First token only: DROP lines look like `192.0.2.0/24 ; SBL123` and some
            // feeds add extra columns.
            guard let token = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).first else {
                continue
            }
            guard let canonical = normalizedIPEntry(token, format: format) else {
                skipped += 1
                continue
            }
            guard seen.insert(canonical).inserted else { continue }
            if entries.count >= maxEntries {
                throw ParseError(reason: "list exceeds \(maxEntries) entries")
            }
            entries.append(canonical)
        }
        return Report(ipEntries: entries, skippedCount: skipped)
    }

    // MARK: - JSON (ThreatFox)

    /// One indicator from a JSON IOC record, or `.skip` when the IOC can't be
    /// enforced on device (file hashes) or can't be parsed.
    private enum MappedIOC { case domain(String), ip(String), skip }

    /// Parses a ThreatFox-style JSON IOC feed into domain and IP indicators.
    /// One feed can contain both kinds.
    ///
    /// Accepts three shapes, flattened to a list of IOC objects:
    ///  - `export/json/recent/`: `{ "<id>": [ {ioc...} ], ... }`
    ///  - `api/v1` query result: `{ "query_status": ..., "data": [ {ioc...} ] }`
    ///  - a top-level array: `[ {ioc...}, ... ]`
    ///
    /// Only `ip:port`, `domain` and `url` IOCs produce indicators; file hashes
    /// are counted as skipped. Malformed JSON throws so a broken download never
    /// looks empty, but individual bad records are just skipped.
    private static func parseJSON(_ data: Data, maxEntries: Int) throws -> Report {
        let root: Any
        do {
            root = try JSONSerialization.jsonObject(with: data)
        } catch {
            throw ParseError(reason: "payload is not valid JSON")
        }

        var seenDomains = Set<String>()
        var seenIPs = Set<String>()
        var domains: [String] = []
        var ips: [String] = []
        var skipped = 0

        for record in flattenIOCRecords(root) {
            guard let value = record["ioc_value"] as? String,
                  let type = record["ioc_type"] as? String else {
                skipped += 1
                continue
            }
            switch mapIOC(value: value, type: type) {
            case .domain(let domain):
                guard seenDomains.insert(domain).inserted else { continue }
                if domains.count + ips.count >= maxEntries {
                    throw ParseError(reason: "list exceeds \(maxEntries) entries")
                }
                domains.append(domain)
            case .ip(let ip):
                guard seenIPs.insert(ip).inserted else { continue }
                if domains.count + ips.count >= maxEntries {
                    throw ParseError(reason: "list exceeds \(maxEntries) entries")
                }
                ips.append(ip)
            case .skip:
                skipped += 1
            }
        }
        return Report(domains: domains, ipEntries: ips, skippedCount: skipped)
    }

    /// Flattens the three accepted ThreatFox container shapes into a single
    /// list of IOC record dictionaries.
    private static func flattenIOCRecords(_ root: Any) -> [[String: Any]] {
        if let array = root as? [[String: Any]] { return array }
        guard let dict = root as? [String: Any] else { return [] }
        // api/v1 query result.
        if let data = dict["data"] as? [[String: Any]] { return data }
        // export/json/recent/: each value is an array of IOC records.
        var records: [[String: Any]] = []
        for value in dict.values {
            if let array = value as? [[String: Any]] { records.append(contentsOf: array) }
        }
        return records
    }

    /// Maps one `(ioc_value, ioc_type)` pair to a matchable indicator.
    private static func mapIOC(value: String, type: String) -> MappedIOC {
        switch type {
        case "ip:port":
            // Try the raw value first (bare IPv6 has many colons), then with
            // the port stripped (`1.2.3.4:443`, `[2001:db8::1]:443`).
            for candidate in [value, strippingPort(value)] {
                if let ip = IPAddress.parse(candidate) { return .ip(ip.description) }
            }
            return .skip
        case "domain":
            if let domain = normalizedDomain(Substring(value)) { return .domain(domain) }
            return .skip
        case "url":
            if let host = URL(string: value)?.host,
               let domain = normalizedDomain(Substring(host)) { return .domain(domain) }
            return .skip
        default:
            // File hashes and anything else can't be matched against a network flow.
            return .skip
        }
    }

    /// Strips a trailing `:port` from a `host:port` string, handling the
    /// bracketed IPv6 form `[2001:db8::1]:443`.
    private static func strippingPort(_ value: String) -> String {
        if value.hasPrefix("["), let close = value.firstIndex(of: "]") {
            return String(value[value.index(after: value.startIndex)..<close])
        }
        if let colon = value.lastIndex(of: ":") { return String(value[..<colon]) }
        return value
    }

    /// Canonical string for an IP/CIDR indicator, or nil when the token is
    /// neither. CIDRs are network-masked so `192.0.2.5/24` and
    /// `192.0.2.0/24` dedupe to one entry.
    static func normalizedIPEntry(_ raw: Substring, format: BlocklistSource.Format) -> String? {
        if raw.contains("/") {
            guard let block = CIDRBlock(String(raw)) else { return nil }
            return "\(block.address.description)/\(block.prefixLength)"
        }
        guard let ip = IPAddress.parse(String(raw)) else { return nil }
        // Bare addresses in a cidrList are exact-host indicators; keep them as
        // plain IPs.
        return ip.description
    }

    /// Canonical base domain for blocklist membership, or nil when the
    /// token is not a plausible public DNS name.
    static func normalizedDomain(_ raw: Substring) -> String? {
        var s = DomainName.normalize(String(raw))
        // Matching already covers subdomains, so wildcard prefixes reduce to the
        // base domain.
        if s.hasPrefix("*.") { s.removeFirst(2) }
        while s.hasPrefix(".") { s.removeFirst() }

        guard !s.isEmpty, s.count <= maxDomainLength, !hostsBoilerplate.contains(s) else { return nil }

        let labels = s.split(separator: ".", omittingEmptySubsequences: false)
        // Single-label names and empty labels (`a..b`) are junk. A bare IPv4
        // address belongs in an IP feed, not a domain list.
        guard labels.count >= 2, !labels.contains(where: \.isEmpty) else { return nil }
        var allNumeric = true
        for label in labels {
            guard label.count <= 63,
                  label.first != "-", label.last != "-",
                  label.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
            else { return nil }
            if !label.allSatisfy(\.isNumber) { allNumeric = false }
        }
        guard !allNumeric else { return nil }
        return s
    }

    /// Loose shape check for the address column of a hosts file (`0.0.0.0`,
    /// `127.0.0.1`, `::`, `::1`, and so on).
    private static func looksLikeIPAddress(_ token: Substring) -> Bool {
        !token.isEmpty && token.allSatisfy {
            $0.isHexDigit || $0 == "." || $0 == ":" || $0 == "%"
        } && token.contains(where: { $0 == "." || $0 == ":" })
    }
}
