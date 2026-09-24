import Foundation

/// Builds the leaf JSON config for the tunnel.
///
/// Packets flow utun fd -> leaf `tun` inbound (netstack + fake-DNS) -> leaf
/// `socks` outbound -> the in-process SOCKS5 server on 127.0.0.1, which applies
/// rules, counts bytes and does the real egress. Leaf never connects out itself.
///
/// Fake-DNS answers plaintext DNS with 198.18.x.x placeholders and puts the real
/// hostname into the SOCKS CONNECT, so domain rules see names. It is the only
/// source of domain visibility: clients using DoT, DoH or their own resolvers
/// are invisible to domain rules.
///
/// Schema follows leaf v0.14.2 `config/common.rs`. Leaf only enables fake-DNS
/// when `fakeDnsExclude` or `fakeDnsInclude` is non-empty, so an empty list
/// silently turns it off.
public struct LeafConfig: Sendable {
    /// The utun fd leaf's tun inbound reads and writes packets on.
    public var tunFD: Int32
    /// tun MTU. Must match `NEPacketTunnelNetworkSettings.mtu`.
    public var mtu: Int
    /// Loopback port of the in-process SOCKS5 server.
    public var socksPort: UInt16
    /// Leaf log level ("trace", "debug", "info", "warn", "error", "none").
    /// Keep it at "warn" or above so leaf never logs per-connection destinations.
    public var logLevel: String
    /// Upstream servers for leaf's own resolver. Leaf requires the key, but with
    /// this config its only outbound is the loopback SOCKS server, so leaf does
    /// not send traffic to these directly.
    public var dnsServers: [String]

    public init(
        tunFD: Int32,
        mtu: Int = 1500,
        socksPort: UInt16,
        logLevel: String = "warn",
        dnsServers: [String] = ["1.1.1.1", "8.8.8.8"]
    ) {
        self.tunFD = tunFD
        self.mtu = mtu
        self.socksPort = socksPort
        self.logLevel = logLevel
        self.dnsServers = dnsServers
    }

    /// Serializes to the JSON string leaf's FFI expects.
    public func json() throws -> String {
        let root = Root(
            log: Root.Log(level: logLevel),
            dns: Root.Dns(servers: dnsServers),
            inbounds: [
                Inbound(tag: "tun", protocol: "tun",
                        settings: Inbound.Settings(fd: tunFD, mtu: mtu,
                                                   fakeDnsExclude: [Self.fakeDnsActivator])),
            ],
            outbounds: [
                Outbound(tag: "socks_out", protocol: "socks",
                         settings: Outbound.Settings(address: "127.0.0.1", port: socksPort)),
            ]
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        let data = try encoder.encode(root)
        guard let string = String(data: data, encoding: .utf8) else {
            throw ConfigError.encodingFailed
        }
        return string
    }

    public enum ConfigError: Error { case encodingFailed }

    /// Keeps `fakeDnsExclude` non-empty so leaf enables fake-DNS. The `.invalid`
    /// TLD (RFC 2606) never matches real traffic, so every real domain is faked.
    private static let fakeDnsActivator = "never-match.fluxmoat.invalid"

    // MARK: - Encodable schema (leaf JSON, per config/common.rs)

    private struct Root: Encodable {
        struct Log: Encodable { let level: String }
        struct Dns: Encodable { let servers: [String] }
        let log: Log
        let dns: Dns
        let inbounds: [Inbound]
        let outbounds: [Outbound]
    }

    private struct Inbound: Encodable {
        struct Settings: Encodable {
            let fd: Int32
            let mtu: Int
            /// Must be non-empty or leaf disables fake-DNS. Name matches leaf's
            /// serde rename.
            let fakeDnsExclude: [String]
        }
        let tag: String
        let `protocol`: String
        let settings: Settings
    }

    private struct Outbound: Encodable {
        struct Settings: Encodable {
            let address: String
            let port: UInt16
        }
        let tag: String
        let `protocol`: String
        let settings: Settings
    }
}
