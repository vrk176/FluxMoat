import SwiftUI

/// Current throughput for one target as two level meters: sent (pink, top) and
/// received (blue, bottom), six segments each, lit from the left.
///
/// The horizontal axis is magnitude, not time. Bytes are counted over the last
/// `windowSeconds`. Sent and received are shown separately so upload-heavy and
/// download-heavy targets look different.
///
/// Uses the fill colors (`TrafficPalette.sentFill`), which don't change with the
/// color scheme. Shared by Live Traffic and the dashboard's Recent targets so
/// both use the same scale.
struct MiniTrafficMeter: View {
    @Environment(\.colorScheme) private var colorScheme
    /// Bytes moved in the last `windowSeconds`, per direction. The caller does
    /// the windowing; this view only maps bytes to a segment count.
    let bytesUp: UInt64
    let bytesDown: UInt64

    static let segmentCount = 6
    /// Short so the meter drops soon after a target goes quiet, long enough
    /// that one chatty flow doesn't make it flicker. Callers window their bytes
    /// against this value.
    ///
    /// `nonisolated` so it can be read off the main actor.
    nonisolated static let windowSeconds: TimeInterval = 10

    /// Rung thresholds in bytes per window, each 4x the previous. Level 1 is any
    /// traffic; levels 2 to 6 start at 4 KB, 16 KB, 64 KB, 256 KB and 1 MB
    /// (roughly 400 B/s to 100 KB/s over 10 s).
    ///
    /// Logarithmic so small and large targets both land on distinct levels; a
    /// 10x step left typical traffic stuck on one level. Above ~100 KB/s the meter
    /// is pegged. The scale is absolute, not per row, so levels are comparable
    /// across rows and screens.
    private static let ladder: [UInt64] = [
        4_096,          // 4 KB   = 2^12
        16_384,         // 16 KB  = 2^14
        65_536,         // 64 KB  = 2^16
        262_144,        // 256 KB = 2^18
        1_048_576       // 1 MB   = 2^20
    ]

    /// Number of lit segments: 0 for no bytes, otherwise 1 plus one per rung
    /// cleared. Zero is separate so "silent" and "barely active" look different.
    static func level(for bytes: UInt64) -> Int {
        guard bytes > 0 else { return 0 }
        return 1 + ladder.filter { bytes >= $0 }.count
    }

    /// 6 pt segments with 2 pt gaps keep the meter at 46 pt wide, which leaves
    /// room for the target name on small phones.
    private let segmentWidth: CGFloat = 6
    private let segmentGap: CGFloat = 2
    /// Slightly shorter than the row's caption line.
    private let height: CGFloat = 22
    /// Gap between the sent and received rows.
    private let stackGap: CGFloat = 2

    private var segmentHeight: CGFloat { (height - stackGap) / 2 }
    private var width: CGFloat {
        CGFloat(Self.segmentCount) * segmentWidth + CGFloat(Self.segmentCount - 1) * segmentGap
    }

    /// Unlit segment color, same values as the dashboard chart's `trackFill`.
    private var trackFill: Color {
        colorScheme == .dark ? Color.white.opacity(0.10) : Color.black.opacity(0.07)
    }

    /// Sent above received, matching the dashboard chart and detail sheets.
    var body: some View {
        VStack(spacing: stackGap) {
            meter(TrafficPalette.sentFill, level: Self.level(for: bytesUp))
            meter(TrafficPalette.receivedFill, level: Self.level(for: bytesDown))
        }
        .frame(width: width, height: height)
        // The row itself is the accessibility element; the meter's numbers
        // are in the detail sheet.
        .accessibilityHidden(true)
    }

    /// One direction, lit from the left.
    private func meter(_ tint: Color, level: Int) -> some View {
        HStack(spacing: segmentGap) {
            ForEach(0..<Self.segmentCount, id: \.self) { index in
                RoundedRectangle(cornerRadius: 2, style: .continuous)
                    .fill(index < level ? tint : trackFill)
                    .frame(width: segmentWidth, height: segmentHeight)
            }
        }
    }
}
