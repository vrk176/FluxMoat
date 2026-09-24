import Foundation

/// Downloads one blocklist subscription: HTTPS only, ETag conditional GET,
/// a size limit enforced while streaming, and parsing before anything is
/// returned. It doesn't persist anything, so a failure never affects the
/// active list.
public struct BlocklistUpdater: Sendable {
    /// Download size limit. The largest supported lists (hosts files with about
    /// 130k entries) are around 5 MB; anything bigger is treated as broken.
    public static let maxDownloadBytes = 10 * 1024 * 1024

    public enum Outcome: Sendable {
        /// Parsed successfully. Only one of `domains` or `ipEntries` is filled,
        /// depending on the source format; the other is empty.
        case updated(domains: [String], ipEntries: [String], skippedLines: Int, etag: String?)
        /// Server says our stored copy is current (ETag matched).
        case notModified
    }

    public struct UpdateError: Error, Sendable {
        public let reason: String
    }

    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    /// - Parameter authKey: abuse.ch key sent as the `Auth-Key` header. Callers
    ///   must only pass it for the hosts it belongs to so it never goes to an
    ///   arbitrary blocklist URL.
    public func fetch(_ source: BlocklistSource, authKey: String? = nil) async throws -> Outcome {
        guard let url = source.sourceURL else {
            throw UpdateError(reason: "source has no URL")
        }
        guard url.scheme?.lowercased() == "https" else {
            throw UpdateError(reason: "only HTTPS sources are allowed")
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 30
        if let etag = source.etag {
            request.setValue(etag, forHTTPHeaderField: "If-None-Match")
        }
        if let authKey, !authKey.isEmpty {
            request.setValue(authKey, forHTTPHeaderField: "Auth-Key")
        }

        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw UpdateError(reason: "non-HTTP response")
        }
        switch http.statusCode {
        case 304:
            return .notModified
        case 200:
            break
        case 401:
            // The only credential we ever send is the abuse.ch key, so a 401 means
            // that key is missing or wrong. Other status codes have no single cause,
            // so they keep their number.
            throw UpdateError(reason: "Key rejected — check it in Settings \u{2192} Threat intelligence.")
        default:
            throw UpdateError(reason: "HTTP \(http.statusCode)")
        }
        if http.expectedContentLength > Int64(Self.maxDownloadBytes) {
            throw UpdateError(reason: "list larger than \(Self.maxDownloadBytes / 1_048_576) MB")
        }

        var data = Data()
        data.reserveCapacity(min(Int(max(http.expectedContentLength, 0)), Self.maxDownloadBytes))
        for try await byte in bytes {
            data.append(byte)
            if data.count > Self.maxDownloadBytes {
                throw UpdateError(reason: "list larger than \(Self.maxDownloadBytes / 1_048_576) MB")
            }
        }

        do {
            let report = try BlocklistParser.parse(data, format: source.format)
            return .updated(
                domains: report.domains,
                ipEntries: report.ipEntries,
                skippedLines: report.skippedCount,
                etag: http.value(forHTTPHeaderField: "ETag")
            )
        } catch let error as BlocklistParser.ParseError {
            throw UpdateError(reason: error.reason)
        }
    }
}
