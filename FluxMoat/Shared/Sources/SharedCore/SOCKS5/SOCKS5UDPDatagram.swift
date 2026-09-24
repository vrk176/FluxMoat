import Foundation

/// RFC 1928 section 7 UDP request header that wraps every datagram relayed
/// through a SOCKS5 UDP ASSOCIATE. leaf sends these to the relay endpoint
/// from our ASSOCIATE reply. We unwrap each one, check the real destination
/// per datagram (the ASSOCIATE request's DST is usually `0.0.0.0:0`), relay
/// the payload, and wrap responses the same way.
///
/// Wire layout:
///
///   +----+------+------+----------+----------+----------+
///   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
///   +----+------+------+----------+----------+----------+
///   | 2  |  1   |  1   | Variable |    2     | Variable |
///
/// A datagram always arrives whole, so a short buffer is `.invalid`, never
/// `.needMore`. Fragmentation (FRAG != 0) is not supported, same as leaf.
public struct SOCKS5UDPDatagram: Sendable, Equatable {
    public let destination: SOCKS5.Destination
    public let port: UInt16
    public let payload: Data

    public init(destination: SOCKS5.Destination, port: UInt16, payload: Data) {
        self.destination = destination
        self.port = port
        self.payload = payload
    }

    /// Parses one wrapped datagram. Truncation returns `.invalid`;
    /// `bytesConsumed` covers the whole datagram (header and payload).
    public static func parse(_ data: some Collection<UInt8>) -> SOCKS5ParseResult<SOCKS5UDPDatagram> {
        let bytes = Array(data)
        // RSV(2) + FRAG(1) + ATYP(1), then the address and port.
        guard bytes.count >= 4 else { return .invalid("short udp header") }
        // bytes[0], bytes[1] are RSV, ignored.
        guard bytes[2] == 0x00 else { return .invalid("fragmentation unsupported frag=\(bytes[2])") }
        guard let atyp = SOCKS5.AddressType(rawValue: bytes[3]) else {
            return .invalid("bad address type \(bytes[3])")
        }

        let addressStart = 4
        let destination: SOCKS5.Destination
        let portStart: Int

        switch atyp {
        case .ipv4:
            let end = addressStart + 4
            guard bytes.count >= end + 2 else { return .invalid("truncated ipv4 udp datagram") }
            let value = bytes[addressStart..<end].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            destination = .ipv4(.v4(value))
            portStart = end
        case .ipv6:
            let end = addressStart + 16
            guard bytes.count >= end + 2 else { return .invalid("truncated ipv6 udp datagram") }
            destination = .ipv6(.v6(Array(bytes[addressStart..<end])))
            portStart = end
        case .domain:
            let length = Int(bytes[addressStart])
            guard length > 0 else { return .invalid("zero-length domain") }
            let nameStart = addressStart + 1
            let end = nameStart + length
            guard bytes.count >= end + 2 else { return .invalid("truncated domain udp datagram") }
            let name = String(decoding: bytes[nameStart..<end], as: UTF8.self)
            destination = .domain(DomainName.normalize(name))
            portStart = end
        }

        let port = (UInt16(bytes[portStart]) << 8) | UInt16(bytes[portStart + 1])
        let payloadStart = portStart + 2
        let payload = Data(bytes[payloadStart...])
        return .parsed(
            SOCKS5UDPDatagram(destination: destination, port: port, payload: payload),
            bytesConsumed: bytes.count
        )
    }

    /// Serializes the header and payload for a datagram sent back to the
    /// client. FRAG is always 0.
    public func encoded() -> Data {
        var out = Data([0x00, 0x00, 0x00]) // RSV(2) + FRAG(0)
        switch destination {
        case .ipv4(let ip):
            out.append(SOCKS5.AddressType.ipv4.rawValue)
            out.append(contentsOf: ip.bytes)
        case .ipv6(let ip):
            out.append(SOCKS5.AddressType.ipv6.rawValue)
            out.append(contentsOf: ip.bytes)
        case .domain(let name):
            let nameBytes = Array(name.utf8)
            out.append(SOCKS5.AddressType.domain.rawValue)
            out.append(UInt8(min(nameBytes.count, 255)))
            out.append(contentsOf: nameBytes.prefix(255))
        }
        out.append(UInt8(port >> 8))
        out.append(UInt8(port & 0xFF))
        out.append(payload)
        return out
    }
}
