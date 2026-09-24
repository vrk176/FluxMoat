import Foundation

/// One unanswered "allow this destination?" question from Ask mode. The
/// flow was already handled by the profile default; the answer becomes a
/// rule for later flows.
public struct PendingAsk: Codable, Identifiable, Sendable, Hashable {
    public var id: UUID
    /// Domain when known, otherwise the IP.
    public var domain: String?
    public var remoteIP: String
    /// Port of the first flow that raised the question. Shown in the UI but
    /// not used for coalescing.
    public var firstPort: UInt16?
    /// What the profile default did with the flows so far (`.allow` let them
    /// through, `.deny` refused them). The UI must show this.
    public var appliedAction: RuleAction
    public var firstSeen: Date
    /// How many flows hit this destination while the question was pending.
    public var flowCount: Int

    public init(
        id: UUID = UUID(),
        domain: String?,
        remoteIP: String,
        firstPort: UInt16?,
        appliedAction: RuleAction,
        firstSeen: Date = Date(),
        flowCount: Int = 1
    ) {
        self.id = id
        self.domain = domain
        self.remoteIP = remoteIP
        self.firstPort = firstPort
        self.appliedAction = appliedAction
        self.firstSeen = firstSeen
        self.flowCount = flowCount
    }

    /// Coalescing key: one question per destination, regardless of port.
    public var targetKey: String { domain ?? remoteIP }
}

/// Collects Ask-mode questions in the extension: one per destination,
/// bounded, and expiring. Not thread-safe; confine it to the server's
/// serial queue.
///
/// Reading doesn't drain entries. A question stays pending until it is
/// answered or expires, so repeated polls see the same list.
public struct AskCenter: Sendable {
    public private(set) var pending: [PendingAsk] = []
    public let capacity: Int
    public let maxAge: TimeInterval

    public init(capacity: Int = 32, maxAge: TimeInterval = 24 * 3600) {
        self.capacity = max(1, capacity)
        self.maxAge = maxAge
    }

    /// Records one unmatched ask-mode flow. Returns the new question when this
    /// destination wasn't pending yet (so the caller can notify), or nil when an
    /// existing question absorbed the flow. At capacity, new destinations are
    /// dropped and existing questions keep their slot.
    @discardableResult
    public mutating func record(
        domain: String?,
        remoteIP: String,
        port: UInt16?,
        appliedAction: RuleAction,
        at now: Date = Date()
    ) -> PendingAsk? {
        expire(at: now)
        let key = domain ?? remoteIP
        if let index = pending.firstIndex(where: { $0.targetKey == key }) {
            pending[index].flowCount += 1
            return nil
        }
        guard pending.count < capacity else { return nil }
        let ask = PendingAsk(
            domain: domain, remoteIP: remoteIP, firstPort: port,
            appliedAction: appliedAction, firstSeen: now
        )
        pending.append(ask)
        return ask
    }

    /// Removes an answered question. Returns it, or nil if unknown or expired.
    @discardableResult
    public mutating func resolve(id: UUID) -> PendingAsk? {
        guard let index = pending.firstIndex(where: { $0.id == id }) else { return nil }
        return pending.remove(at: index)
    }

    /// Drops questions older than `maxAge`. Their flows were already handled
    /// by the profile default.
    public mutating func expire(at now: Date = Date()) {
        let cutoff = now.addingTimeInterval(-maxAge)
        pending.removeAll { $0.firstSeen < cutoff }
    }
}
