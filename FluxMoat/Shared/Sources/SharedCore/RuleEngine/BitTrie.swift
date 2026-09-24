/// Binary trie over address bits for CIDR lookup. Returns the payloads of
/// every prefix that covers the address, so the caller's priority rules pick
/// the winner rather than prefix length.
/// Nodes are only mutated during construction; once the owning
/// `CompiledRuleSet` is built the trie is read-only.
struct BitTrie<Value: Sendable>: @unchecked Sendable {
    private final class Node {
        var zero: Node?
        var one: Node?
        var values: [Value] = []
    }

    private let root = Node()

    mutating func insert(bytes: [UInt8], prefixLength: Int, value: Value) {
        var node = root
        for bitIndex in 0..<prefixLength {
            let byte = bytes[bitIndex / 8]
            let bit = (byte >> (7 - UInt8(bitIndex % 8))) & 1
            if bit == 0 {
                if node.zero == nil { node.zero = Node() }
                node = node.zero!
            } else {
                if node.one == nil { node.one = Node() }
                node = node.one!
            }
        }
        node.values.append(value)
    }

    /// All values whose prefix covers `bytes`.
    func coveringValues(bytes: [UInt8]) -> [Value] {
        var result: [Value] = []
        var node = root
        result.append(contentsOf: node.values)
        for bitIndex in 0..<(bytes.count * 8) {
            let byte = bytes[bitIndex / 8]
            let bit = (byte >> (7 - UInt8(bitIndex % 8))) & 1
            guard let next = bit == 0 ? node.zero : node.one else { return result }
            node = next
            result.append(contentsOf: node.values)
        }
        return result
    }
}
