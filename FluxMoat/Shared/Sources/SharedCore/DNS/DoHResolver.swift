import Foundation

/// DNS-over-HTTPS stub resolver (RFC 8484 POST) with a TTL cache. Pointed
/// at a filtering resolver (Quad9, 1.1.1.2, NextDNS), every lookup gets
/// checked for threats without a separate cloud query per connection.
///
/// The caller decides what to do with `.blockedByResolver` and whether to
/// fall back to system DNS on failure. The SOCKS server fails open so a DoH
/// outage doesn't break browsing, and logs the fallback.
public actor DoHResolver {
    public enum Resolution: Sendable, Equatable {
        /// Connectable addresses in answer order (IPv4 first, since A is queried
        /// before AAAA).
        case addresses([String])
        /// The resolver answered with sink addresses only (0.0.0.0 or ::), meaning
        /// its filter blocked the name. Kept separate from NXDOMAIN so it can be
        /// counted as a threat block. Resolvers that filter by returning NXDOMAIN
        /// (like Quad9) can't be told apart from a missing name.
        case blockedByResolver
        /// NXDOMAIN, or NOERROR with no A/AAAA records.
        case noSuchDomain
    }

    public struct ResolveError: Error, Sendable {
        public let reason: String
    }

    /// TTL clamp and negative-cache TTL, seconds.
    static let ttlRange: ClosedRange<UInt32> = 30...3600
    static let negativeTTL: TimeInterval = 30
    static let cacheCapacity = 1024
    static let maxResponseBytes = 4096

    private struct CacheEntry {
        let resolution: Resolution
        let expiry: Date
    }

    /// Upstream host for logs. Host only: a NextDNS profile id lives in the URL
    /// path and must stay out of logs.
    public nonisolated var serverHost: String { serverURL.host ?? "?" }

    private nonisolated let serverURL: URL
    private let session: URLSession
    private let now: @Sendable () -> Date
    private var cache: [String: CacheEntry] = [:]

    public init(
        serverURL: URL,
        session: URLSession = .shared,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.serverURL = serverURL
        self.session = session
        self.now = now
    }

    /// `fromCache` tells the caller whether the answer came from the cache or
    /// the network.
    public func resolve(_ host: String) async throws -> (resolution: Resolution, fromCache: Bool) {
        let key = DomainName.normalize(host)
        if let entry = cache[key], entry.expiry > now() {
            return (entry.resolution, true)
        }

        var response = try DNSMessage.parseResponse(await exchange(query: DNSMessage.query(host: key, type: .a)))
        if response.rcode == 0, response.addresses.isEmpty {
            response = try DNSMessage.parseResponse(await exchange(query: DNSMessage.query(host: key, type: .aaaa)))
        }

        let resolution: Resolution
        let ttl: TimeInterval
        switch response.rcode {
        case 0 where !response.addresses.isEmpty:
            let sinks: Set<String> = ["0.0.0.0", "0:0:0:0:0:0:0:0"]
            let real = response.addresses.filter { !sinks.contains($0) }
            if real.isEmpty {
                resolution = .blockedByResolver
                ttl = Self.negativeTTL
            } else {
                resolution = .addresses(real)
                ttl = TimeInterval(min(max(response.minTTL ?? Self.ttlRange.lowerBound,
                                           Self.ttlRange.lowerBound), Self.ttlRange.upperBound))
            }
        case 0, 3:
            resolution = .noSuchDomain
            ttl = Self.negativeTTL
        default:
            throw ResolveError(reason: "resolver rcode \(response.rcode)")
        }

        if cache.count >= Self.cacheCapacity {
            evict()
        }
        cache[key] = CacheEntry(resolution: resolution, expiry: now().addingTimeInterval(ttl))
        return (resolution, false)
    }

    private func exchange(query: Data) async throws -> Data {
        var request = URLRequest(url: serverURL)
        request.httpMethod = "POST"
        request.httpBody = query
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 5

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw ResolveError(reason: "DoH HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1)")
        }
        guard data.count <= Self.maxResponseBytes else {
            throw ResolveError(reason: "DoH response too large")
        }
        return data
    }

    /// Drops expired entries; if still full, drops the half closest to
    /// expiring.
    private func evict() {
        let cutoff = now()
        cache = cache.filter { $0.value.expiry > cutoff }
        if cache.count >= Self.cacheCapacity {
            for (key, _) in cache.sorted(by: { $0.value.expiry < $1.value.expiry })
                .prefix(Self.cacheCapacity / 2) {
                cache.removeValue(forKey: key)
            }
        }
    }
}
