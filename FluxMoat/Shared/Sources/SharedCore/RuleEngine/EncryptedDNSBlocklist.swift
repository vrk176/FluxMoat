import Foundation

/// Endpoints of well-known public encrypted-DNS resolvers, and the deny rules
/// that push clients off them and back to plaintext DNS, where leaf's
/// fake-DNS sees the names and domain rules apply.
///
/// An app or OS-level DoT/DoH client resolves outside the tunnel, so its
/// apps connect by IP and domain-based rules, blocklists and tunnel DoH
/// can't see the names. Blocking the resolvers' endpoints (not just the DoT
/// port) makes clients fall back to plaintext without breaking connectivity.
///
/// The port rule and the address rules must be used together: blocking :853
/// alone makes clients switch to DoH on :443, and the address list alone
/// leaves unlisted DoT endpoints open. `rules(exemptingUpstreamHost:)` must
/// keep exempting the user's own DoH upstream, or every lookup falls back to
/// system DNS after a timeout.
public enum EncryptedDNSBlocklist {
    /// One resolver operator: the hostnames it answers on (used to match the
    /// user's configured upstream for exemption) and its dedicated endpoints.
    public struct Resolver: Sendable, Equatable {
        public let name: String
        /// Hostnames that identify this operator in a DoH URL.
        public let hosts: [String]
        /// Dedicated resolver addresses. Anycast addresses only; see the exclusions
        /// on `resolvers`.
        public let addresses: [String]

        public init(name: String, hosts: [String], addresses: [String]) {
            self.name = name
            self.hosts = hosts
            self.addresses = addresses
        }
    }

    /// DoT's dedicated port (RFC 7858). DoH shares :443 with all HTTPS, so it
    /// can only be matched by address.
    public static let dotPort: ClosedRange<UInt16> = 853...853

    /// Deliberately excluded (re-verify before adding):
    ///  - `cloudflare-dns.com` resolves to Cloudflare CDN addresses (104.16.x)
    ///    shared with much of the web. The resolver is already covered by its
    ///    dedicated 1.1.1.x / 2606:4700:4700:: endpoints.
    ///  - `dns.nextdns.io` is geo-steered, so its addresses aren't stable or
    ///    global.
    public static let resolvers: [Resolver] = [
        Resolver(
            name: "Cloudflare",
            hosts: ["one.one.one.one", "cloudflare-dns.com",
                    "security.cloudflare-dns.com", "family.cloudflare-dns.com"],
            addresses: [
                "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
                "2606:4700:4700::1111", "2606:4700:4700::1001",
                "2606:4700:4700::1112", "2606:4700:4700::1002",
                "2606:4700:4700::1113", "2606:4700:4700::1003",
            ]
        ),
        Resolver(
            name: "Google",
            hosts: ["dns.google"],
            addresses: [
                "8.8.8.8", "8.8.4.4",
                "2001:4860:4860::8888", "2001:4860:4860::8844",
            ]
        ),
        Resolver(
            name: "Quad9",
            hosts: ["dns.quad9.net", "dns9.quad9.net",
                    "dns10.quad9.net", "dns11.quad9.net"],
            addresses: [
                "9.9.9.9", "149.112.112.112",
                "9.9.9.10", "149.112.112.10",
                "9.9.9.11", "149.112.112.11",
                "2620:fe::fe", "2620:fe::9",
            ]
        ),
        Resolver(
            name: "AdGuard",
            hosts: ["dns.adguard-dns.com", "unfiltered.adguard-dns.com",
                    "family.adguard-dns.com"],
            addresses: [
                "94.140.14.14", "94.140.15.15",
                "94.140.14.140", "94.140.14.141",
                "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff",
            ]
        ),
    ]

    /// Deny rules that push clients off encrypted DNS: one port rule for DoT
    /// plus one address rule per endpoint. The operator of `upstreamHost` (the
    /// user's own DoH upstream) is exempt, so choosing Quad9 never blocks Quad9.
    ///
    /// Priority is 0, so any user Allow rule wins (ties go to allow).
    public static func rules(exemptingUpstreamHost upstreamHost: String?) -> [Rule] {
        let exemptHost = upstreamHost?.lowercased()
        let exempt = exemptHost.flatMap { host in
            resolvers.first { $0.hosts.contains(host) }
        }
        var rules: [Rule] = [
            Rule(
                id: syntheticID(0),
                action: .deny,
                target: .port(dotPort),
                note: "Encrypted DNS blocking: DoT (RFC 7858)"
            )
        ]
        for resolver in resolvers where resolver != exempt {
            for address in resolver.addresses {
                rules.append(
                    Rule(
                        id: syntheticID(rules.count),
                        action: .deny,
                        target: .ip(address),
                        note: "Encrypted DNS blocking: \(resolver.name)"
                    )
                )
            }
        }
        return rules
    }

    /// A destination classified as a known encrypted-DNS endpoint.
    public enum Endpoint: String, Sendable {
        /// DoT on :853 (RFC 7858), any host, since the port is dedicated.
        case dot = "dot853"
        /// DoH reaching a public resolver by its dedicated IP on :443.
        case dohIP = "dohip"
    }

    /// Classifies an outbound destination as a known encrypted-DNS endpoint, or
    /// returns nil. Uses the same constants as the deny rules (`dotPort` and
    /// `resolvers[].addresses`) so detection and blocking always agree. IPs are
    /// normalized so IPv6 spellings match.
    public static func classify(host: String, port: UInt16) -> Endpoint? {
        if dotPort.contains(port) { return .dot }
        // DoH is HTTPS, so a resolver IP only counts on :443. The same IP on :80
        // (1.1.1.1 also serves a website) is ordinary traffic.
        if port == 443, let ip = IPAddress.parse(host)?.description,
           resolvers.contains(where: { $0.addresses.contains { IPAddress.parse($0)?.description == ip } }) {
            return .dohIP
        }
        return nil
    }

    /// Deterministic ids so recompiling doesn't break the `matchedRuleID` stored
    /// on past events. The `4009` marker makes these ids easy to spot in logs.
    /// They never appear in the user's rule list, so they can't collide with
    /// user-created ids.
    static func syntheticID(_ index: Int) -> UUID {
        UUID(uuidString: String(format: "00000000-0000-4009-8000-%012d", index))
            ?? UUID()
    }
}
