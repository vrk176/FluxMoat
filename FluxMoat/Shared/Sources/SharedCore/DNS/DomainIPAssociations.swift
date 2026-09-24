import Foundation

/// Short-term domain to IP association: remembers which domain our own
/// resolver recently resolved to which addresses, so flows without a name
/// (IP-literal TCP, UDP targets) can be labeled "recently resolved as X" in
/// Live Traffic and history.
///
/// This is for display only and must never be used for verdicts. CDNs
/// share addresses, so a name mapped back from an IP isn't reliable enough
/// to enforce rules on.
///
/// Entries expire after a fixed 5 minutes rather than the DNS TTL: the
/// association means "this IP was in an answer moments ago", not that the
/// record is still valid. Bounded, and the clock is injected for tests.
public struct DomainIPAssociations: Sendable {
    public static let ttl: TimeInterval = 5 * 60
    public let capacity: Int

    private struct Entry {
        var domain: String
        var expiresAt: Date
    }

    private var entries: [String: Entry] = [:]

    public init(capacity: Int = 512) {
        self.capacity = capacity
    }

    public var count: Int { entries.count }

    /// Records `domain -> addresses` at `now`. Recording again refreshes the
    /// expiry; a different domain resolving to the same IP replaces it, since
    /// the latest answer is the most likely one. Over capacity, expired entries
    /// go first, then the ones closest to expiring.
    public mutating func record(domain: String, addresses: [String], now: Date) {
        let expiry = now.addingTimeInterval(Self.ttl)
        for address in addresses {
            guard let canonical = IPAddress.parse(address)?.description else { continue }
            entries[canonical] = Entry(domain: domain, expiresAt: expiry)
        }
        guard entries.count > capacity else { return }
        entries = entries.filter { $0.value.expiresAt > now }
        while entries.count > capacity,
              let oldest = entries.min(by: { $0.value.expiresAt < $1.value.expiresAt }) {
            entries.removeValue(forKey: oldest.key)
        }
    }

    /// The domain most recently resolved to `ip`, if that answer is still
    /// fresh. Normalizes the IP so v6 spelling differences still match.
    public func lookup(ip: String, now: Date) -> String? {
        guard let canonical = IPAddress.parse(ip)?.description,
              let entry = entries[canonical], entry.expiresAt > now else {
            return nil
        }
        return entry.domain
    }
}
