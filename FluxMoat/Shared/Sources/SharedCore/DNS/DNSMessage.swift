import Foundation

/// Minimal RFC 1035 wire codec for the DoH resolver: builds one A/AAAA
/// query and parses the answer section (including name compression) into
/// addresses and a TTL. Not a general DNS library.
public enum DNSMessage {
    public enum RecordType: UInt16, Sendable {
        case a = 1
        case aaaa = 28
    }

    public struct ParseError: Error, Sendable {
        public let reason: String
    }

    // MARK: Query

    /// One-question query with RD set. `id` defaults to 0 because DoH matches
    /// responses by HTTP request, and RFC 8484 recommends 0 for caching.
    public static func query(host: String, type: RecordType, id: UInt16 = 0) throws -> Data {
        var out = Data(capacity: 32 + host.count)
        out.appendUInt16(id)
        out.appendUInt16(0x0100) // flags: RD
        out.appendUInt16(1)      // QDCOUNT
        out.appendUInt16(0)      // ANCOUNT
        out.appendUInt16(0)      // NSCOUNT
        out.appendUInt16(0)      // ARCOUNT
        for label in host.split(separator: ".", omittingEmptySubsequences: false) {
            guard !label.isEmpty, label.utf8.count <= 63 else {
                throw ParseError(reason: "invalid label in query name")
            }
            out.append(UInt8(label.utf8.count))
            out.append(contentsOf: label.utf8)
        }
        out.append(0) // root
        out.appendUInt16(type.rawValue)
        out.appendUInt16(1) // IN
        return out
    }

    // MARK: Response

    public struct Response: Sendable {
        /// RCODE from the header (0 = NOERROR, 3 = NXDOMAIN, and so on).
        public let rcode: UInt8
        /// A/AAAA rdata from the answer section in answer order, as address
        /// strings. CNAMEs are skipped; resolvers include the final A/AAAA records
        /// in the same answer.
        public let addresses: [String]
        /// Smallest TTL across the extracted address records; nil when
        /// there were none.
        public let minTTL: UInt32?
    }

    public static func parseResponse(_ data: Data) throws -> Response {
        // Data slices keep their indices; rebase so offsets are 0-based.
        let bytes = [UInt8](data)
        guard bytes.count >= 12 else { throw ParseError(reason: "short header") }
        let rcode = bytes[3] & 0x0F
        let qdcount = Int(bytes[4]) << 8 | Int(bytes[5])
        let ancount = Int(bytes[6]) << 8 | Int(bytes[7])

        var offset = 12
        for _ in 0..<qdcount {
            try skipName(bytes, &offset)
            try advance(&offset, by: 4, in: bytes) // QTYPE + QCLASS
        }

        var addresses: [String] = []
        var minTTL: UInt32?
        for _ in 0..<ancount {
            try skipName(bytes, &offset)
            guard offset + 10 <= bytes.count else { throw ParseError(reason: "truncated answer") }
            let type = UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
            let ttl = UInt32(bytes[offset + 4]) << 24 | UInt32(bytes[offset + 5]) << 16
                | UInt32(bytes[offset + 6]) << 8 | UInt32(bytes[offset + 7])
            let rdlength = Int(bytes[offset + 8]) << 8 | Int(bytes[offset + 9])
            offset += 10
            guard offset + rdlength <= bytes.count else { throw ParseError(reason: "truncated rdata") }

            switch (type, rdlength) {
            case (RecordType.a.rawValue, 4):
                addresses.append(bytes[offset..<offset + 4].map(String.init).joined(separator: "."))
                minTTL = min(minTTL ?? ttl, ttl)
            case (RecordType.aaaa.rawValue, 16):
                var groups: [String] = []
                for i in stride(from: offset, to: offset + 16, by: 2) {
                    groups.append(String(format: "%x", UInt16(bytes[i]) << 8 | UInt16(bytes[i + 1])))
                }
                addresses.append(groups.joined(separator: ":"))
                minTTL = min(minTTL ?? ttl, ttl)
            default:
                break // CNAME and others: skip
            }
            offset += rdlength
        }
        return Response(rcode: rcode, addresses: addresses, minTTL: minTTL)
    }

    /// Advances past a possibly compressed name. A pointer ends the name
    /// (RFC 1035 section 4.1.4), so on the first pointer we skip its 2 bytes
    /// and stop.
    private static func skipName(_ bytes: [UInt8], _ offset: inout Int) throws {
        var hops = 0
        while true {
            guard offset < bytes.count else { throw ParseError(reason: "truncated name") }
            let len = bytes[offset]
            if len == 0 {
                offset += 1
                return
            }
            if len & 0xC0 == 0xC0 {
                try advance(&offset, by: 2, in: bytes)
                return
            }
            guard len & 0xC0 == 0 else { throw ParseError(reason: "bad label type") }
            try advance(&offset, by: Int(len) + 1, in: bytes)
            hops += 1
            guard hops <= 128 else { throw ParseError(reason: "name too long") }
        }
    }

    private static func advance(_ offset: inout Int, by count: Int, in bytes: [UInt8]) throws {
        guard offset + count <= bytes.count else { throw ParseError(reason: "truncated message") }
        offset += count
    }
}

private extension Data {
    mutating func appendUInt16(_ value: UInt16) {
        append(UInt8(value >> 8))
        append(UInt8(value & 0xFF))
    }
}
