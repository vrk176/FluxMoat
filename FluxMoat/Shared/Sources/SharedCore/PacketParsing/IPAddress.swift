import Foundation

/// A parsed IPv4 or IPv6 address, comparable at the bit level.
public enum IPAddress: Hashable, Sendable {
    case v4(UInt32)
    /// Exactly 16 bytes, network order.
    case v6([UInt8])

    public static func parse(_ string: String) -> IPAddress? {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.contains(":") {
            var buf = [UInt8](repeating: 0, count: 16)
            guard inet_pton(AF_INET6, trimmed, &buf) == 1 else { return nil }
            return .v6(buf)
        }
        var addr = in_addr()
        guard inet_pton(AF_INET, trimmed, &addr) == 1 else { return nil }
        return .v4(UInt32(bigEndian: addr.s_addr))
    }

    public var isV4: Bool {
        if case .v4 = self { return true }
        return false
    }

    /// Address bits as bytes, network order (4 for v4, 16 for v6).
    public var bytes: [UInt8] {
        switch self {
        case .v4(let value):
            return [
                UInt8((value >> 24) & 0xFF),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8(value & 0xFF),
            ]
        case .v6(let bytes):
            return bytes
        }
    }

    public var description: String {
        switch self {
        case .v4(let value):
            var addr = in_addr(s_addr: value.bigEndian)
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
            return Self.string(fromNulTerminated: buf)
        case .v6(let bytes):
            var raw = bytes
            var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            inet_ntop(AF_INET6, &raw, &buf, socklen_t(INET6_ADDRSTRLEN))
            return Self.string(fromNulTerminated: buf)
        }
    }

    private static func string(fromNulTerminated buf: [CChar]) -> String {
        String(
            decoding: buf.prefix(while: { $0 != 0 }).map(UInt8.init(bitPattern:)),
            as: UTF8.self
        )
    }
}

/// A parsed CIDR block with host bits zeroed.
public struct CIDRBlock: Hashable, Sendable {
    public let address: IPAddress
    public let prefixLength: Int

    public init?(_ string: String) {
        let parts = string.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              let parsed = IPAddress.parse(String(parts[0]))
        else { return nil }
        let maxPrefix = parsed.isV4 ? 32 : 128
        guard (0...maxPrefix).contains(prefix) else { return nil }
        self.prefixLength = prefix
        self.address = Self.maskHostBits(of: parsed, prefixLength: prefix)
    }

    public func contains(_ ip: IPAddress) -> Bool {
        guard ip.isV4 == address.isV4 else { return false }
        return Self.matchesPrefix(ip.bytes, address.bytes, prefixLength)
    }

    static func maskHostBits(of ip: IPAddress, prefixLength: Int) -> IPAddress {
        var bytes = ip.bytes
        for i in 0..<bytes.count {
            let bitsBefore = i * 8
            if bitsBefore >= prefixLength {
                bytes[i] = 0
            } else if bitsBefore + 8 > prefixLength {
                let keep = prefixLength - bitsBefore
                bytes[i] &= UInt8(0xFF << (8 - keep) & 0xFF)
            }
        }
        if ip.isV4 {
            let v = bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            return .v4(v)
        }
        return .v6(bytes)
    }

    static func matchesPrefix(_ candidate: [UInt8], _ network: [UInt8], _ prefixLength: Int) -> Bool {
        var remaining = prefixLength
        var i = 0
        while remaining >= 8 {
            if candidate[i] != network[i] { return false }
            i += 1
            remaining -= 8
        }
        if remaining > 0 {
            let mask = UInt8(0xFF << (8 - remaining) & 0xFF)
            if candidate[i] & mask != network[i] & mask { return false }
        }
        return true
    }
}
