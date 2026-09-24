import Foundation

public enum DomainName {
    /// Canonical form used for all matching: lowercased, trailing dot stripped.
    /// IDN labels are expected in punycode (`xn--`) form; the UI converts user
    /// input before rules reach the engine.
    public static func normalize(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespaces).lowercased()
        while s.hasSuffix(".") { s.removeLast() }
        return s
    }

    /// Parent domains of `host`, nearest first: for `a.b.example.com`
    /// returns `b.example.com`, `example.com`, `com`.
    public static func parentDomains(of host: String) -> [String] {
        var parents: [String] = []
        var rest = Substring(host)
        while let dot = rest.firstIndex(of: ".") {
            rest = rest[rest.index(after: dot)...]
            if !rest.isEmpty { parents.append(String(rest)) }
        }
        return parents
    }
}
