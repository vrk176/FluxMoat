import SwiftUI

/// Colors for sent and received traffic.
///
/// Sent is pink, not red, because red means blocked throughout the app.
///
/// `sent`/`received` are for text and adapt to the scheme (contrast on the card
/// background: sent 4.8:1 dark / 5.1:1 light, received 4.8:1 / 5.4:1).
/// `sentFill`/`receivedFill` are for bars and meters and stay the same in both
/// schemes so charts look identical; they're about 2.0:1 on white, which is
/// acceptable because values are printed as text nearby.
enum TrafficPalette {
    static let sent = Color(uiColor: UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.95, green: 0.60, blue: 0.93, alpha: 1)
            : UIColor(red: 0.62, green: 0.10, blue: 0.58, alpha: 1)
    })

    static let received = Color(uiColor: UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.52, green: 0.74, blue: 1.00, alpha: 1)
            : UIColor(red: 0.10, green: 0.30, blue: 0.78, alpha: 1)
    })

    /// Bar and meter segment colors: the dark-mode ink values, fixed across
    /// schemes.
    static let sentFill = Color(red: 0.95, green: 0.60, blue: 0.93)

    static let receivedFill = Color(red: 0.52, green: 0.74, blue: 1.00)

    /// "Allowed" band in the Trends connections chart. Fixed across schemes
    /// like the other fills. Green matches the Allow swipe action and allowed
    /// row dots; the value is `systemGreen`'s dark variant.
    ///
    /// Close in luminance to `receivedFill` (about 1.03:1) and separated only by
    /// hue. That's fine while they never share a chart; use a different hue, not
    /// a darker green, if they ever do.
    static let allowedFill = Color(red: 0.19, green: 0.82, blue: 0.35)

    /// Background for `TrafficTotalsHeader` slabs. Unlike the pills, the number
    /// on top is neutral, so this can be a real pastel: the light tint mixed
    /// toward white in light mode, the bright tint at low alpha in dark mode.
    static let sentWash = Color(uiColor: UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.95, green: 0.60, blue: 0.93, alpha: 0.16)
            : UIColor(red: 0.72, green: 0.24, blue: 0.72, alpha: 0.18)
    })

    static let receivedWash = Color(uiColor: UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.52, green: 0.74, blue: 1.00, alpha: 0.16)
            : UIColor(red: 0.24, green: 0.46, blue: 0.92, alpha: 0.18)
    })
}

/// Label, SF Symbol and colors for one traffic direction. Both readouts use
/// this so their wording stays in sync.
enum TrafficDirection {
    case sent
    case received

    var label: String {
        switch self {
        case .sent: "sent"
        case .received: "received"
        }
    }

    var symbol: String {
        switch self {
        case .sent: "arrow.up"
        case .received: "arrow.down"
        }
    }

    var tint: Color {
        switch self {
        case .sent: TrafficPalette.sent
        case .received: TrafficPalette.received
        }
    }

    var wash: Color {
        switch self {
        case .sent: TrafficPalette.sentWash
        case .received: TrafficPalette.receivedWash
        }
    }
}

/// Sent and received totals as a pair of capsules, used by the dashboard hero.
/// Only offered as a pair: a lone tinted capsule would look like a button.
struct TrafficTotalPills: View {
    let sent: UInt64
    let received: UInt64

    var body: some View {
        HStack(spacing: 8) {
            pill(.sent, ByteFormat.volume(sent))
            pill(.received, ByteFormat.volume(received))
        }
    }

    /// Arrow and word leading, number trailing. When the pill is too narrow, the
    /// word is hidden rather than truncated. VoiceOver always gets the word.
    private func pill(_ direction: TrafficDirection, _ value: String) -> some View {
        ViewThatFits(in: .horizontal) {
            pillContent(direction, value, wordVisible: true)
            pillContent(direction, value, wordVisible: false)
        }
        .foregroundStyle(direction.tint)
        .lineLimit(1)
        .minimumScaleFactor(0.7)
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .frame(maxWidth: .infinity)
        .background(direction.tint.opacity(0.18), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(direction.label) \(value)")
    }

    private func pillContent(_ direction: TrafficDirection, _ value: String, wordVisible: Bool) -> some View {
        HStack(spacing: 5) {
            Image(systemName: direction.symbol)
                .font(.caption.weight(.bold))
            if wordVisible {
                Text(direction.label)
                    .font(.subheadline)
            }
            Spacer(minLength: 4)
            Text(value)
                .font(.subheadline.weight(.semibold).monospacedDigit())
                // `Color.primary`, not `.primary`: the pill sets the tint as the
                // foreground style, and bare `.primary` would resolve to it.
                .foregroundStyle(Color.primary)
                // The number keeps its width; the word gives way first.
                .layoutPriority(1)
        }
    }
}

/// Sent and received totals at the top of a detail sheet: two large slabs with
/// an arrow and a number, no words.
///
/// Only the arrow is tinted; the number uses the primary color like the rest of
/// the sheet. VoiceOver still gets the direction word via the label.
struct TrafficTotalsHeader: View {
    let sent: UInt64
    let received: UInt64

    var body: some View {
        HStack(spacing: 10) {
            block(.sent, ByteFormat.volume(sent))
            block(.received, ByteFormat.volume(received))
        }
    }

    /// Arrow leading, number trailing. Equal halves keep both numbers on
    /// the same right edge.
    private func block(_ direction: TrafficDirection, _ value: String) -> some View {
        HStack(spacing: 8) {
            Image(systemName: direction.symbol)
                .font(.title3.weight(.bold))
                .foregroundStyle(direction.tint)
            Spacer(minLength: 6)
            Text(value)
                .font(.title2.weight(.semibold).monospacedDigit())
                .foregroundStyle(.primary)
                .lineLimit(1)
                // No word beside the number here, so it can shrink further
                // before truncating.
                .minimumScaleFactor(0.6)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity)
        .background(direction.wash, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        // Explicit label: combining children would read "arrow up, 54 KB".
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(direction.label) \(value)")
    }
}
