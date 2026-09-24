import Foundation

/// App to tunnel control messages sent with `sendProviderMessage`.
/// High-frequency data doesn't use this channel; the tunnel writes events
/// to the shared database instead.
/// New cases go at the end so older builds keep decoding.
public enum ProviderRequest: Codable, Sendable {
    case status
    case liveCounters
    case reloadRules
    case switchProfile(UUID)
    case healthCheck
    /// Drains the tunnel's recently closed flows for the Live Traffic view.
    /// Polled about once a second, like `liveCounters`.
    case recentEvents
    /// Ask mode: returns unanswered questions. Not drained; a question stays
    /// until it is answered or expires.
    case pendingAsks
    /// Ask mode: the user answered. The app has already written the rule and
    /// reloaded the snapshot, so this only clears the question in the tunnel.
    case resolveAsk(UUID)
}

public enum ProviderResponse: Codable, Sendable {
    public struct Status: Codable, Sendable {
        public var mode: RunMode
        public var activeProfileID: UUID?
        public var snapshotCreatedAt: Date?
        public var lastError: String?

        public init(mode: RunMode, activeProfileID: UUID?, snapshotCreatedAt: Date?, lastError: String?) {
            self.mode = mode
            self.activeProfileID = activeProfileID
            self.snapshotCreatedAt = snapshotCreatedAt
            self.lastError = lastError
        }
    }

    public struct LiveCounters: Codable, Sendable {
        public var bytesUpPerSecond: UInt64
        public var bytesDownPerSecond: UInt64
        public var activeFlows: Int
        public var blockedToday: Int
        /// Part of `blockedToday` blocked by the filtering DoH resolver.
        /// Optional because a tunnel from an older build omits it.
        public var threatBlockedToday: Int?
        /// Allowed flows to known encrypted-DNS endpoints while `blockEncryptedDNS`
        /// was off. The app shows a one-time warning when this is non-zero.
        /// Optional because an older tunnel omits it.
        public var encryptedDNSBypassToday: Int?
        /// Profile kind the tunnel switched to after a Wi-Fi change, so the app's
        /// picker matches what is enforced. nil means no automatic switch is active
        /// (or an older tunnel).
        public var autoProfileKind: String?

        public init(
            bytesUpPerSecond: UInt64,
            bytesDownPerSecond: UInt64,
            activeFlows: Int,
            blockedToday: Int,
            threatBlockedToday: Int? = nil,
            encryptedDNSBypassToday: Int? = nil,
            autoProfileKind: String? = nil
        ) {
            self.bytesUpPerSecond = bytesUpPerSecond
            self.bytesDownPerSecond = bytesDownPerSecond
            self.activeFlows = activeFlows
            self.blockedToday = blockedToday
            self.threatBlockedToday = threatBlockedToday
            self.encryptedDNSBypassToday = encryptedDNSBypassToday
            self.autoProfileKind = autoProfileKind
        }
    }

    case status(Status)
    case liveCounters(LiveCounters)
    case acknowledged
    case failed(String)
    /// Recently closed flows for the Live Traffic view (metadata only).
    case recentEvents([TrafficEvent])
    /// Ask mode: current unanswered questions.
    case pendingAsks([PendingAsk])

    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decoded(from data: Data) throws -> ProviderResponse {
        try JSONDecoder().decode(ProviderResponse.self, from: data)
    }
}

extension ProviderRequest {
    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decoded(from data: Data) throws -> ProviderRequest {
        try JSONDecoder().decode(ProviderRequest.self, from: data)
    }
}
