import Foundation

/// SOCKS5 (RFC 1928) wire codec for the in-process proxy server.
///
/// The tun2socks library connects to this server over loopback as a SOCKS5
/// client. The server parses the destination, runs the rule engine to
/// accept or reject, and on allow opens a direct `NWConnection` while
/// counting bytes. This file is the pure codec; the networking code lives
/// in the tunnel extension.
public enum SOCKS5 {
    public static let version: UInt8 = 0x05

    public enum Command: UInt8, Sendable {
        case connect = 0x01
        case bind = 0x02
        case udpAssociate = 0x03
    }

    public enum AddressType: UInt8, Sendable {
        case ipv4 = 0x01
        case domain = 0x03
        case ipv6 = 0x04
    }

    /// Destination address as it arrived on the wire.
    public enum Destination: Sendable, Equatable {
        case ipv4(IPAddress)   // always .v4
        case ipv6(IPAddress)   // always .v6
        case domain(String)

        /// Host string for logging and the NWConnection endpoint.
        public var host: String {
            switch self {
            case .ipv4(let ip), .ipv6(let ip): ip.description
            case .domain(let name): name
            }
        }
    }

    /// RFC 1928 reply codes. `notAllowed` is returned when the rule engine
    /// blocks a flow.
    public enum Reply: UInt8, Sendable {
        case succeeded = 0x00
        case generalFailure = 0x01
        case notAllowed = 0x02
        case networkUnreachable = 0x03
        case hostUnreachable = 0x04
        case connectionRefused = 0x05
        case ttlExpired = 0x06
        case commandNotSupported = 0x07
        case addressNotSupported = 0x08
    }
}

/// Incremental parse result for a byte stream. SOCKS runs over TCP, so a
/// message may be split across reads.
public enum SOCKS5ParseResult<Value: Sendable>: Sendable {
    case parsed(Value, bytesConsumed: Int)
    case needMore
    case invalid(String)
}

// MARK: - Method-selection handshake

public struct SOCKS5Greeting: Sendable, Equatable {
    public let methods: [UInt8]

    /// `[VER, NMETHODS, METHODS...]`.
    public static func parse(_ data: some Collection<UInt8>) -> SOCKS5ParseResult<SOCKS5Greeting> {
        let bytes = Array(data)
        guard bytes.count >= 2 else { return .needMore }
        guard bytes[0] == SOCKS5.version else { return .invalid("bad version \(bytes[0])") }
        let count = Int(bytes[1])
        guard count > 0 else { return .invalid("zero methods") }
        guard bytes.count >= 2 + count else { return .needMore }
        return .parsed(SOCKS5Greeting(methods: Array(bytes[2..<(2 + count)])), bytesConsumed: 2 + count)
    }

    public static let noAuth: UInt8 = 0x00
    public static let noAcceptable: UInt8 = 0xFF

    /// `[VER, METHOD]`. Pass `noAcceptable` to reject.
    public static func methodSelection(_ method: UInt8) -> Data {
        Data([SOCKS5.version, method])
    }
}

// MARK: - Request

public struct SOCKS5Request: Sendable, Equatable {
    public let command: SOCKS5.Command
    public let destination: SOCKS5.Destination
    public let port: UInt16

    /// `[VER, CMD, RSV, ATYP, ADDR..., PORT(2)]`.
    public static func parse(_ data: some Collection<UInt8>) -> SOCKS5ParseResult<SOCKS5Request> {
        let bytes = Array(data)
        guard bytes.count >= 4 else { return .needMore }
        guard bytes[0] == SOCKS5.version else { return .invalid("bad version \(bytes[0])") }
        guard let command = SOCKS5.Command(rawValue: bytes[1]) else {
            return .invalid("bad command \(bytes[1])")
        }
        // bytes[2] is RSV, ignored.
        guard let atyp = SOCKS5.AddressType(rawValue: bytes[3]) else {
            return .invalid("bad address type \(bytes[3])")
        }

        let addressStart = 4
        let destination: SOCKS5.Destination
        let portStart: Int

        switch atyp {
        case .ipv4:
            let end = addressStart + 4
            guard bytes.count >= end + 2 else { return .needMore }
            let value = bytes[addressStart..<end].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            destination = .ipv4(.v4(value))
            portStart = end
        case .ipv6:
            let end = addressStart + 16
            guard bytes.count >= end + 2 else { return .needMore }
            destination = .ipv6(.v6(Array(bytes[addressStart..<end])))
            portStart = end
        case .domain:
            guard bytes.count >= addressStart + 1 else { return .needMore }
            let length = Int(bytes[addressStart])
            guard length > 0 else { return .invalid("zero-length domain") }
            let nameStart = addressStart + 1
            let end = nameStart + length
            guard bytes.count >= end + 2 else { return .needMore }
            let name = String(decoding: bytes[nameStart..<end], as: UTF8.self)
            destination = .domain(DomainName.normalize(name))
            portStart = end
        }

        let port = (UInt16(bytes[portStart]) << 8) | UInt16(bytes[portStart + 1])
        return .parsed(
            SOCKS5Request(command: command, destination: destination, port: port),
            bytesConsumed: portStart + 2
        )
    }

    /// The flow this request represents, for `CompiledRuleSet.evaluate`.
    /// TCP CONNECT is protocol 6; UDP ASSOCIATE is 17.
    public func flowDescriptor(profileID: UUID? = nil, timestamp: Date = Date()) -> FlowDescriptor {
        let proto: UInt8 = command == .udpAssociate ? 17 : 6
        switch destination {
        case .ipv4(let ip), .ipv6(let ip):
            return FlowDescriptor(ip: ip, port: port, protocolNumber: proto, profileID: profileID, timestamp: timestamp)
        case .domain(let name):
            return FlowDescriptor(domain: name, port: port, protocolNumber: proto, profileID: profileID, timestamp: timestamp)
        }
    }
}

// MARK: - Reply

public enum SOCKS5Reply {
    /// `[VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]`.
    ///
    /// For TCP CONNECT the bound address doesn't matter, so the default
    /// `0.0.0.0:0` is returned. For a successful UDP ASSOCIATE, pass the real
    /// loopback endpoint in `bound`: the client (leaf) sends its datagrams to
    /// BND.ADDR:BND.PORT.
    public static func encode(_ reply: SOCKS5.Reply, bound: (ip: IPAddress, port: UInt16)? = nil) -> Data {
        var out = Data([SOCKS5.version, reply.rawValue, 0x00]) // VER, REP, RSV
        if let bound {
            out.append(bound.ip.isV4 ? SOCKS5.AddressType.ipv4.rawValue
                                     : SOCKS5.AddressType.ipv6.rawValue)
            out.append(contentsOf: bound.ip.bytes)
            out.append(UInt8(bound.port >> 8))
            out.append(UInt8(bound.port & 0xFF))
        } else {
            out.append(contentsOf: [
                SOCKS5.AddressType.ipv4.rawValue,
                0x00, 0x00, 0x00, 0x00, // BND.ADDR 0.0.0.0
                0x00, 0x00,             // BND.PORT 0
            ])
        }
        return out
    }
}
