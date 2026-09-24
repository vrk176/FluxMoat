import Foundation

/// Calculations for the Insights share cards and the number format they use.
/// Kept out of the views so `swift test` covers them.
public enum ShareCardMath {
    /// Index of the bucket with the most blocked connections, or nil when
    /// nothing was blocked (the By day card then draws no annotation).
    /// Ties go to the earliest bucket, matching the stable sort of the table
    /// under the chart.
    public static func peakIndex(blockedPerBucket: [Int]) -> Int? {
        var best: (index: Int, value: Int)?
        for (index, value) in blockedPerBucket.enumerated() where value > 0 {
            if best == nil || value > best!.value {
                best = (index, value)
            }
        }
        return best?.index
    }

    /// `total` spread over `buckets`, rounded to the nearest whole number.
    /// Returns 0 for zero buckets.
    public static func perBucketAverage(total: Int, buckets: Int) -> Int {
        guard buckets > 0 else { return 0 }
        return Int((Double(total) / Double(buckets)).rounded())
    }

    /// Format for every number on a share card: grouped digits up to 9,999,
    /// abbreviated from 10,000 (cards are often viewed small in chat).
    /// Display only: all sums on the card are computed on the `Int`s first.
    public static func cardCount(_ count: Int) -> String {
        count >= 10_000 ? abbreviated(count) : count.formatted(.number.grouping(.automatic))
    }

    /// A count shortened with a suffix: 65,298 -> "65.2k", 1,234,567 -> "1.2M".
    /// Uses integer math and truncates rather than rounds:
    ///
    ///     999        -> "999"
    ///     1_000      -> "1k"       (no trailing ".0")
    ///     1_050      -> "1k"
    ///     24_963     -> "24.9k"
    ///     999_999    -> "999.9k"   (never rolls over to the next unit)
    ///     1_234_567  -> "1.2M"
    ///
    /// The "." is a literal, not the locale's decimal separator; the app ships
    /// in English only.
    public static func abbreviated(_ count: Int) -> String {
        // From a billion up, print the whole number rather than add a "B" unit.
        // This also keeps the x10 below far from Int overflow.
        guard count >= 1_000, count < 1_000_000_000 else { return count.formatted() }
        // Try thousands first. `scaled` returns nil once the value reaches a full
        // thousand thousands, so millions fall through.
        if let thousands = scaled(count, by: 1_000, suffix: "k") { return thousands }
        return scaled(count, by: 1_000_000, suffix: "M") ?? count.formatted()
    }

    /// `count / unit` to one decimal, truncated, with a trailing ".0" removed.
    /// Returns nil when the value reaches 1000 of the unit. Truncating means
    /// the number never overstates what was seen.
    private static func scaled(_ count: Int, by unit: Int, suffix: String) -> String? {
        let tenths = count * 10 / unit
        guard tenths < 10_000 else { return nil }
        let whole = tenths / 10
        let frac = tenths % 10
        return frac == 0 ? "\(whole)\(suffix)" : "\(whole).\(frac)\(suffix)"
    }
}
