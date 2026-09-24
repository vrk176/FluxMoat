import Foundation

/// Minimal MaxMind DB (MMDB) reader, enough for country-level lookups in
/// DB-IP Lite or GeoLite2-style databases. Pure Swift; the file is
/// memory-mapped so loading is cheap.
/// Spec: https://maxmind.github.io/MaxMind-DB/
public final class GeoIPDatabase: Sendable {
    public struct FormatError: Error, Sendable {
        public let reason: String
    }

    private let data: Data
    private let nodeCount: Int
    private let recordSizeBits: Int
    private let nodeSizeBytes: Int
    private let ipVersion: Int
    /// Absolute offset where the data section begins (tree + 16-byte gap).
    private let dataSectionStart: Int

    /// Build date from the metadata's `build_epoch`, shown in Settings so users
    /// can see how old the country data is. nil when the file doesn't include
    /// it (the field is optional in the spec).
    public let buildDate: Date?

    public convenience init(contentsOf url: URL) throws {
        try self.init(data: Data(contentsOf: url, options: .mappedIfSafe))
    }

    public init(data: Data) throws {
        // Metadata lives after the last occurrence of the marker
        // "\xAB\xCD\xEFMaxMind.com" near the end of the file.
        let marker = Data([0xAB, 0xCD, 0xEF]) + Data("MaxMind.com".utf8)
        guard let markerRange = data.range(of: marker, options: .backwards) else {
            throw FormatError(reason: "metadata marker not found")
        }
        let metadataStart = markerRange.upperBound
        var offset = metadataStart
        let metadata = try MMDBDecoder(data: data, sectionStart: metadataStart)
            .decode(at: &offset)
        guard case .map(let fields) = metadata,
              case .uint(let nodeCount)? = fields["node_count"],
              case .uint(let recordSize)? = fields["record_size"],
              case .uint(let ipVersion)? = fields["ip_version"]
        else {
            throw FormatError(reason: "missing metadata fields")
        }
        guard recordSize == 24 || recordSize == 28 || recordSize == 32 else {
            throw FormatError(reason: "unsupported record size \(recordSize)")
        }

        // Optional: a missing or oddly typed build_epoch doesn't fail the load.
        if case .uint(let epoch)? = fields["build_epoch"] {
            self.buildDate = Date(timeIntervalSince1970: TimeInterval(epoch))
        } else {
            self.buildDate = nil
        }

        self.data = data
        self.nodeCount = Int(nodeCount)
        self.recordSizeBits = Int(recordSize)
        self.nodeSizeBytes = Int(recordSize) * 2 / 8
        self.ipVersion = Int(ipVersion)
        self.dataSectionStart = self.nodeCount * self.nodeSizeBytes + 16
        guard dataSectionStart < data.count else {
            throw FormatError(reason: "tree extends past end of file")
        }
    }

    /// ISO 3166-1 alpha-2 code for the network containing `ip`, or nil if
    /// the address is not in the database (reserved/private ranges).
    public func countryCode(for ip: IPAddress) -> String? {
        guard case .map(let record)? = lookup(ip) else { return nil }
        guard case .map(let country)? = record["country"],
              case .string(let code)? = country["iso_code"]
        else { return nil }
        return code
    }

    func lookup(_ ip: IPAddress) -> MMDBDecoder.Value? {
        if ipVersion == 4 && !ip.isV4 { return nil }

        var node = 0
        // In an IPv6 tree, IPv4 lives under the all-zero /96 prefix.
        if ipVersion == 6 && ip.isV4 {
            for _ in 0..<96 {
                guard let next = step(node: node, bit: 0) else { return nil }
                node = next
            }
        }
        for byte in ip.bytes {
            for shift in stride(from: 7, through: 0, by: -1) {
                let record = readRecord(node: node, side: (byte >> UInt8(shift)) & 1)
                if record == nodeCount { return nil }
                if record > nodeCount {
                    var offset = dataSectionStart + (record - nodeCount - 16)
                    guard offset < data.count else { return nil }
                    return try? MMDBDecoder(data: data, sectionStart: dataSectionStart)
                        .decode(at: &offset)
                }
                node = record
            }
        }
        return nil
    }

    private func step(node: Int, bit: UInt8) -> Int? {
        let record = readRecord(node: node, side: bit)
        return record < nodeCount ? record : nil
    }

    private func readRecord(node: Int, side: UInt8) -> Int {
        let base = node * nodeSizeBytes
        func byte(_ i: Int) -> Int { Int(data[base + i]) }
        switch recordSizeBits {
        case 24:
            let o = side == 0 ? 0 : 3
            return byte(o) << 16 | byte(o + 1) << 8 | byte(o + 2)
        case 28:
            if side == 0 {
                return (byte(3) >> 4) << 24 | byte(0) << 16 | byte(1) << 8 | byte(2)
            }
            return (byte(3) & 0x0F) << 24 | byte(4) << 16 | byte(5) << 8 | byte(6)
        default: // 32
            let o = side == 0 ? 0 : 4
            return byte(o) << 24 | byte(o + 1) << 16 | byte(o + 2) << 8 | byte(o + 3)
        }
    }
}

/// Decoder for the MMDB data section type system (the subset needed for
/// country databases: strings, integers, maps, arrays, bools, pointers).
struct MMDBDecoder {
    indirect enum Value {
        case string(String)
        case uint(UInt64)
        case int(Int64)
        case double(Double)
        case bytes(Data)
        case bool(Bool)
        case map([String: Value])
        case array([Value])
    }

    struct DecodeError: Error {
        let reason: String
    }

    let data: Data
    /// Pointers are relative to the start of the enclosing section.
    let sectionStart: Int

    func decode(at offset: inout Int) throws -> Value {
        guard offset < data.count else {
            throw DecodeError(reason: "offset past end")
        }
        let control = Int(data[offset])
        offset += 1
        var type = control >> 5

        if type == 1 { // pointer
            let pointerSize = (control >> 3) & 0x3
            let low = control & 0x7
            var pointer = 0
            switch pointerSize {
            case 0:
                pointer = low << 8 | next(&offset)
            case 1:
                pointer = (low << 16 | next(&offset) << 8 | next(&offset)) + 2048
            case 2:
                pointer = (low << 24 | next(&offset) << 16 | next(&offset) << 8 | next(&offset)) + 526_336
            default:
                pointer = next(&offset) << 24 | next(&offset) << 16 | next(&offset) << 8 | next(&offset)
            }
            var target = sectionStart + pointer
            return try decode(at: &target)
        }

        if type == 0 { // extended type
            type = Int(data[offset]) + 7
            offset += 1
        }

        var size = control & 0x1F
        switch size {
        case 29: size = 29 + next(&offset)
        case 30: size = 285 + (next(&offset) << 8 | next(&offset))
        case 31: size = 65_821 + (next(&offset) << 16 | next(&offset) << 8 | next(&offset))
        default: break
        }

        switch type {
        case 2: // UTF-8 string
            let value = String(decoding: slice(&offset, size), as: UTF8.self)
            return .string(value)
        case 3: // double
            let raw = slice(&offset, 8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
            return .double(Double(bitPattern: raw))
        case 4: // bytes
            return .bytes(slice(&offset, size))
        case 5, 6, 9: // uint16 / uint32 / uint64
            return .uint(slice(&offset, size).reduce(UInt64(0)) { $0 << 8 | UInt64($1) })
        case 8: // int32 (big-endian, stored in `size` bytes)
            let raw = slice(&offset, size).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            return .int(Int64(Int32(bitPattern: raw)))
        case 10: // uint128, truncated to 64 bits; country DBs don't use it
            return .uint(slice(&offset, size).suffix(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) })
        case 7: // map
            var entries: [String: Value] = [:]
            entries.reserveCapacity(size)
            for _ in 0..<size {
                guard case .string(let key) = try decode(at: &offset) else {
                    throw DecodeError(reason: "non-string map key")
                }
                entries[key] = try decode(at: &offset)
            }
            return .map(entries)
        case 11: // array
            var items: [Value] = []
            items.reserveCapacity(size)
            for _ in 0..<size {
                items.append(try decode(at: &offset))
            }
            return .array(items)
        case 14: // boolean, value encoded in size
            return .bool(size != 0)
        case 15: // float
            let raw = slice(&offset, 4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
            return .double(Double(Float(bitPattern: raw)))
        default:
            throw DecodeError(reason: "unsupported type \(type)")
        }
    }

    private func next(_ offset: inout Int) -> Int {
        defer { offset += 1 }
        return Int(data[offset])
    }

    private func slice(_ offset: inout Int, _ count: Int) -> Data {
        defer { offset += count }
        return data.subdata(in: offset..<min(offset + count, data.count))
    }
}
