import Foundation

/// A daily local-time window in which Ask notifications stay silent, in
/// minutes since local midnight. A range crossing midnight (22:00 to 07:00,
/// stored as 1320/420) means overnight. Optional in the rule snapshot;
/// nil means no quiet hours.
public struct QuietHours: Codable, Sendable, Equatable {
    public var startMinute: Int
    public var endMinute: Int

    public init(startMinute: Int, endMinute: Int) {
        self.startMinute = startMinute
        self.endMinute = endMinute
    }

    /// Whether `minuteOfDay` (0 to 1439, local) falls inside the window.
    /// start == end is an empty window (never quiet), not all day; to silence
    /// everything, turn Ask mode off.
    public func contains(minuteOfDay: Int) -> Bool {
        if startMinute == endMinute { return false }
        if startMinute < endMinute {
            return minuteOfDay >= startMinute && minuteOfDay < endMinute
        }
        return minuteOfDay >= startMinute || minuteOfDay < endMinute
    }
}

/// Decides whether another Ask notification may be posted. The caller
/// owns the clock and the notification center; this type only holds the
/// policy:
///
///  1. Quiet hours: nothing posts (the app still lists every question).
///  2. Grouping: one banner per registrable domain per `groupTTL`, so
///     sub1.x.com after sub2.x.com doesn't alert again.
///  3. Cooldown: at most one banner per `cooldown` overall.
///
/// Suppressing a banner never drops a question; it only skips the alert.
public struct AskNotificationThrottle: Sendable {
    public enum Verdict: String, Sendable {
        case post
        case quietHours = "quiet"
        case groupCooldown = "group"
        case globalCooldown = "cooldown"
    }

    public var quietHours: QuietHours?
    public let cooldown: TimeInterval
    public let groupTTL: TimeInterval
    /// Bounded memory: oldest group entries are evicted past this.
    public let maxGroups: Int

    private var lastPostAt: Date?
    private var groupLastPost: [String: Date] = [:]

    public init(
        quietHours: QuietHours? = nil,
        cooldown: TimeInterval = 60,
        groupTTL: TimeInterval = 30 * 60,
        maxGroups: Int = 64
    ) {
        self.quietHours = quietHours
        self.cooldown = cooldown
        self.groupTTL = groupTTL
        self.maxGroups = maxGroups
    }

    /// Decides for one candidate notification about `group` (registrable
    /// domain or bare IP) at `now`. `minuteOfDay` is passed in so the policy
    /// doesn't depend on time zones. State changes only when the result is
    /// `.post`.
    public mutating func decide(group: String, now: Date, minuteOfDay: Int) -> Verdict {
        if let quietHours, quietHours.contains(minuteOfDay: minuteOfDay) {
            return .quietHours
        }
        if let last = groupLastPost[group], now.timeIntervalSince(last) < groupTTL {
            return .groupCooldown
        }
        if let lastPostAt, now.timeIntervalSince(lastPostAt) < cooldown {
            return .globalCooldown
        }
        lastPostAt = now
        groupLastPost[group] = now
        if groupLastPost.count > maxGroups {
            let cutoff = groupLastPost.values.sorted()[groupLastPost.count - maxGroups]
            groupLastPost = groupLastPost.filter { $0.value >= cutoff }
        }
        return .post
    }

    /// Approximate registrable domain (eTLD+1) for grouping notifications.
    /// Uses a small built-in list of common multi-part suffixes and otherwise
    /// the last two labels. A wrong guess only changes how notifications are
    /// grouped, never filtering. IPs and single labels group as themselves.
    public static func notificationGroup(for target: String) -> String {
        let labels = target.lowercased().split(separator: ".")
        guard labels.count >= 3, labels.allSatisfy({ !$0.isEmpty }),
              !target.contains(":"), // v6 literal
              labels.last?.allSatisfy(\.isNumber) != true // v4 literal
        else {
            return target.lowercased()
        }
        let lastTwo = labels.suffix(2).joined(separator: ".")
        let take = multiPartSuffixes.contains(lastTwo) ? 3 : 2
        return labels.suffix(take).joined(separator: ".")
    }

    /// Common two-part public suffixes. Not the full Public Suffix List; see
    /// `notificationGroup(for:)`.
    static let multiPartSuffixes: Set<String> = [
        "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "com.au", "net.au", "org.au", "com.br", "net.br",
        "co.jp", "ne.jp", "or.jp", "ac.jp",
        "co.kr", "or.kr", "com.tw", "org.tw", "com.hk",
        "com.sg", "com.mx", "com.ar", "com.tr", "co.in",
        "co.nz", "co.za", "com.sa", "com.eg", "com.my",
    ]
}
