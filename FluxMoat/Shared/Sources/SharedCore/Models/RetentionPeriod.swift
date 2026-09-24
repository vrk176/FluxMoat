import Foundation

/// How long flow history is kept. Stored in the rule snapshot as an optional
/// field; nil (older snapshots) decodes as `.default`, which is 30 days.
public enum RetentionPeriod: String, Codable, Sendable, CaseIterable, Identifiable {
    case days7
    case days30
    case days90
    case months6
    case months12

    public static let `default`: RetentionPeriod = .days30

    public var id: String { rawValue }

    public var maxAge: TimeInterval {
        TimeInterval(days) * 24 * 3600
    }

    public var days: Int {
        switch self {
        case .days7: 7
        case .days30: 30
        case .days90: 90
        case .months6: 182
        case .months12: 365
        }
    }

    /// Row cap scales with the window so long retention isn't cut short by a
    /// fixed cap, while still bounding disk use and prune cost. A row is about
    /// 200 bytes, so 200k rows is roughly a 40 MB database.
    public var maxRows: Int {
        switch self {
        case .days7: 20_000
        case .days30: 50_000
        case .days90: 100_000
        case .months6: 150_000
        case .months12: 200_000
        }
    }
}
