import Charts
import SharedCore
import SwiftUI

// Insights share cards: Countries (where), By day (when), Blocked (what).
//
// Everything is laid out on a fixed 360 × 450 pt sheet with absolute coordinates
// in points. Fonts use `.system(size:weight:)` so Dynamic Type can't reflow an
// image that will be resized by a messaging app anyway.

// MARK: - Card style and options

/// The three cards, in picker order.
enum ShareStyle: String, CaseIterable, Identifiable {
    case countries
    case byDay
    case blocked

    var id: String { rawValue }

    /// Picker segment title.
    var segmentTitle: String {
        switch self {
        case .countries: "Countries"
        case .byDay: "By day"
        case .blocked: "Blocked"
        }
    }

    /// Card-specific part of the file name.
    var fileSlug: String {
        switch self {
        case .countries: "countries"
        case .byDay: "byday"
        case .blocked: "blocked"
        }
    }

    /// Shown before sharing: whether the card includes hostnames, and for Countries,
    /// that locations are estimated from IP addresses.
    ///
    /// `distinctCountries` is the rollup's count once loaded. When it's zero the text
    /// says nothing could be placed. nil (not loaded, or not Countries) gives the
    /// generic text.
    func disclosure(options: ShareOptions, distinctCountries: Int? = nil) -> String {
        switch self {
        case .countries: distinctCountries == 0
            ? "No country could be placed for these IPs."
            : "No hostnames. Countries are IP estimates."
        case .byDay: options.includesHostnames
            ? "Lists the 5 most contacted hostnames."
            : "No hostnames."
        case .blocked: "Lists blocked hostnames."
        }
    }
}

/// Per-share switches. `includesHostnames` only applies to By day (Blocked always
/// shows hostnames). `originCountry` only applies to Countries and is set only
/// while "Show my country" is on. It's a country code, never a coordinate.
struct ShareOptions: Hashable {
    var includesHostnames = false
    var originCountry: String?
}

// MARK: - Countries card data

/// The Map tab's country rollup shaped for the card: top five ledger rows with
/// names and flags resolved, and every placed country projected onto the map.
///
/// Kept out of `InsightsSummary` because it needs its own query
/// (`AppModel.insightsCountries`: GROUP BY IP plus a GeoIP lookup per address),
/// which only runs once the Countries card is shown.
struct CountriesSummary: Equatable {
    /// A ledger row: rollup numbers plus flag and localized name.
    struct Row: Equatable, Identifiable {
        let code: String
        let name: String
        let flag: String
        let flows: Int
        /// All blocks, including threats.
        let blocked: Int
        /// The part of `blocked` attributed to a threat list (violet band).
        let threat: Int
        var id: String { code }
    }

    /// A country on the map: centroid in map points and connection count (sets the glow).
    struct Lit: Equatable {
        let point: CGPoint
        let flows: Int
    }

    let rollup: CountriesCardMath.Rollup
    let top: [Row]
    /// Placed countries that have a centroid. Codes missing from the centroid table
    /// are still counted and can appear in the ledger, they just aren't drawn.
    let lit: [Lit]

    init(_ aggregates: [TrafficEventStore.CountryAggregate]) {
        let rollup = CountriesCardMath.Rollup(aggregates)
        self.rollup = rollup
        top = rollup.top.map {
            Row(
                code: $0.code, name: RecentTargets.countryName($0.code), flag: CountryFlag.emoji($0.code),
                flows: $0.flows, blocked: $0.blocked, threat: $0.threat
            )
        }
        lit = rollup.placed.compactMap { country in
            guard let point = WorldDotMap.point(forCountry: country.code) else { return nil }
            return Lit(point: point, flows: country.flows)
        }
    }

    var distinctCountries: Int { rollup.distinctCountries }
    var unplacedFlows: Int { rollup.unplacedFlows }
    var restCountries: Int { rollup.restCountries }
}

// MARK: - Geometry

/// Sheet dimensions in points, shared by all cards.
private enum Card {
    static let width: CGFloat = 360
    static let height: CGFloat = 450
    static let pad: CGFloat = 22
    static let contentWidth: CGFloat = width - 2 * pad
    static let trailing: CGFloat = width - pad

    /// Top of the ledger's header rule. Everything above is absolutely positioned,
    /// everything below flows from here.
    static let ledgerTop: CGFloat = 302

    /// Text opacities.
    static let ink55 = Color.white.opacity(0.55)
    static let ink50 = Color.white.opacity(0.50)
    static let ink42 = Color.white.opacity(0.42)
    static let ink30 = Color.white.opacity(0.30)

    /// Minimum drawn size for a non-zero share in the proportional graphics. The exact
    /// number is always printed next to it.
    static let stripFloor: CGFloat = 3
    static let bandFloor: CGFloat = 1.5
    static let arcFloorDegrees: Double = 3
}

/// Masthead lockup: the full logo, then the wordmark.
///
/// Uses the alpha version of `OnboardingLogo`; the navy-backed one would show its
/// square against the gradient. The art isn't centered in its canvas (the stream
/// trails left, the sparks sit right), so it's positioned by its visible ink bounds
/// (alpha > 60, measured on the 1024 px asset) rather than its frame.
private enum Mark {
    /// Visible ink bounds as fractions of the square image.
    static let inkLeft = 0.1396
    static let inkTop = 0.1787
    static let inkRight = 0.8770
    static let inkBottom = 0.7676

    /// Frame size of the asset. The ring inside comes out about 22 pt across, big
    /// enough to stay distinct from the stream at thumbnail size.
    static let side: CGFloat = 40

    static var inkWidth: CGFloat { side * CGFloat(inkRight - inkLeft) }
    static var inkHeight: CGFloat { side * CGFloat(inkBottom - inkTop) }

    /// Baseline shared by the wordmark and the date line.
    static let wordmarkBaseline: CGFloat = 32
    static let wordmarkSize: CGFloat = 15

    /// Frame origin such that the ink starts at the content margin and is centered on
    /// the wordmark's cap height (centering on the baseline looks low).
    static var frameLeading: CGFloat { Card.pad - side * CGFloat(inkLeft) }
    static var frameTop: CGFloat {
        let capHeight = UIFont.systemFont(ofSize: wordmarkSize, weight: .semibold).capHeight
        return wordmarkBaseline - capHeight / 2 - inkHeight / 2 - side * CGFloat(inkTop)
    }

    /// Wordmark x: a small gap past the ink's right edge (the sparks), leaving about
    /// 12 pt between the ring and the text.
    static var wordmarkLeading: CGFloat { Card.pad + inkWidth + 6.5 }
}

/// Converts a baseline position to the frame top for the given font, since SwiftUI
/// positions text by frame.
private func baselineTop(_ baseline: CGFloat, size: CGFloat, weight: UIFont.Weight = .regular, mono: Bool = false) -> CGFloat {
    let font = mono
        ? UIFont.monospacedSystemFont(ofSize: size, weight: weight)
        : UIFont.systemFont(ofSize: size, weight: weight)
    return baseline - font.ascender
}

private extension View {
    /// Places a fixed-size view at (`x`, `top`) inside a `.topLeading` ZStack.
    func at(x: CGFloat, top: CGFloat) -> some View {
        self.fixedSize().offset(x: x, y: top)
    }

    /// Same, but aligns the trailing edge to `trailing`.
    func at(trailing: CGFloat, top: CGFloat) -> some View {
        self.fixedSize()
            .frame(width: trailing, alignment: .trailing)
            .offset(y: top)
    }
}

/// A white hairline. `Rectangle` rather than `Divider` so color and thickness are ours.
private struct Hairline: View {
    let opacity: Double
    var body: some View {
        Rectangle().fill(Color.white.opacity(opacity)).frame(height: 0.5)
    }
}

/// Rendered width of `text`, including SF's small-size tracking. Used to shrink
/// lines to fit, because `minimumScaleFactor` truncates instead of scaling under
/// `ImageRenderer`.
///
/// `tabular` measures with tabular figures, matching the `monospacedDigit` used for
/// every number on the card; proportional "1"s would under-measure.
private func textWidth(_ text: String, size: CGFloat, weight: UIFont.Weight = .regular, tabular: Bool = true, mono: Bool = false) -> CGFloat {
    let font = mono
        ? UIFont.monospacedSystemFont(ofSize: size, weight: weight)
        : tabular
            ? UIFont.monospacedDigitSystemFont(ofSize: size, weight: weight)
            : UIFont.systemFont(ofSize: size, weight: weight)
    return (text as NSString).size(withAttributes: [.font: font]).width
}

/// Largest size from `size` down to `floor × size` at which `text` fits `width`.
/// The 2% margin covers differences between UIKit measurement and SwiftUI layout.
private func fittedSize(_ text: String, size: CGFloat, weight: UIFont.Weight = .regular, width: CGFloat, floor: CGFloat = 0.7) -> CGFloat {
    let needed = textWidth(text, size: size, weight: weight) * 1.02
    guard needed > width else { return size }
    return max(size * floor, size * width / needed)
}

/// "Sun 30 Aug". Built from two parts because a single format adds a comma after
/// the weekday in some locales.
private func dayLabel(_ date: Date) -> String {
    date.formatted(.dateTime.weekday(.abbreviated)) + " " + date.formatted(.dateTime.day().month(.abbreviated))
}

/// Formats every number on the card: grouped up to 9,999, then "12.3k" (see
/// `ShareCardMath.cardCount`). The ledger columns only fit four digits.
///
/// Abbreviation is display-only. All sums, bars, arcs and percentages are computed
/// from the underlying `Int`s.
private func cardNumber(_ n: Int) -> String {
    ShareCardMath.cardCount(n)
}

private func percent(_ part: Int, of whole: Int) -> String {
    guard whole > 0 else { return "0%" }
    return (Double(part) / Double(whole) * 100).formatted(.number.precision(.fractionLength(1))) + "%"
}

// MARK: - Card

/// Shared card layout: masthead, hero row, ledger, footnote, caveat slot, footer.
///
/// Fixed width, minimum height 450 pt. By day is always 450 pt. Cards with
/// hostnames grow when a name wraps, since the name is the point of the card.
/// `InsightsSummaryRenderer.proposedSize` leaves height nil so `ImageRenderer`
/// uses this view's ideal height; `ImageRenderer` clips to whatever size it's given,
/// so estimating the height separately cut off the footer.
struct InsightsShareCard: View {
    let summary: InsightsSummary
    let style: ShareStyle
    let options: ShareOptions
    /// Distinct destination count if fetched; nil drops the "of N" from the footnote.
    var distinctTargets: Int?
    /// Country rollup, only for the Countries card. The renderer won't draw that card
    /// without it.
    var countries: CountriesSummary?

    var body: some View {
        VStack(spacing: 0) {
            ZStack(alignment: .topLeading) {
                masthead
                switch style {
                case .countries:
                    if let countries {
                        CountriesTop(summary: summary, countries: countries, options: options)
                    }
                case .byDay: ByDayTop(summary: summary)
                case .blocked: BlockedTop(summary: summary)
                }
                ledgerHead
            }
            .frame(width: Card.width, height: Card.ledgerTop, alignment: .topLeading)

            ledgerRows

            tail
        }
        .frame(width: Card.width, alignment: .topLeading)
        .frame(minHeight: Card.height, alignment: .top)
        .background(surface)
        // The card is always dark. Without this it inherits the presenter's color scheme
        // and `BrandPalette.threat` would use its light-mode value.
        .environment(\.colorScheme, .dark)
    }

    /// Navy surface with one radial glow in the top-right corner. A gradient, not a blur.
    private var surface: some View {
        ZStack(alignment: .topLeading) {
            BrandPalette.darkSurface
            RadialGradient(
                colors: [BrandPalette.blueDeep.opacity(0.30), BrandPalette.blueDeep.opacity(0.08), .clear],
                center: UnitPoint(x: 0.92, y: 0.02),
                startRadius: 0,
                endRadius: Card.width * 0.55
            )
            .frame(width: Card.width, height: Card.height * 0.62)
        }
    }

    // MARK: Masthead

    /// Logo and wordmark on the left, window and date range on the right, all on one
    /// baseline above the header rule at y 46.
    private var masthead: some View {
        ZStack(alignment: .topLeading) {
            // The real asset with its glow, not the vector fallback.
            Image("OnboardingLogo")
                .resizable()
                .scaledToFit()
                .frame(width: Mark.side, height: Mark.side)
                .offset(x: Mark.frameLeading, y: Mark.frameTop)
            Text("FluxMoat")
                .font(.system(size: Mark.wordmarkSize, weight: .semibold))
                .kerning(-0.15)
                .foregroundStyle(BrandPalette.textPrimary)
                .at(
                    x: Mark.wordmarkLeading,
                    top: baselineTop(Mark.wordmarkBaseline, size: Mark.wordmarkSize, weight: .semibold)
                )
            // Same baseline as the wordmark.
            Text(windowLine)
                .font(.system(size: 8, weight: .semibold))
                .kerning(0.9)
                .foregroundStyle(BrandPalette.textSecondary)
                .at(trailing: Card.trailing, top: baselineTop(Mark.wordmarkBaseline, size: 8, weight: .semibold))
            Hairline(opacity: 0.16)
                .frame(width: Card.contentWidth)
                .offset(x: Card.pad, y: 46)
        }
    }

    /// e.g. `LAST 7 DAYS · 27 AUG – 2 SEP 2026`. The range spans the first and last bar.
    private var windowLine: String {
        var line = summary.window.annotation.uppercased()
        guard let first = summary.bars.first?.start, let last = summary.bars.last?.start else {
            return line
        }
        let cal = Calendar.current
        let year = last.formatted(.dateTime.year())
        let range: String
        if cal.isDate(first, inSameDayAs: last) {
            range = last.formatted(.dateTime.day().month(.abbreviated)) + " " + year
        } else if cal.isDate(first, equalTo: last, toGranularity: .month) {
            range = first.formatted(.dateTime.day()) + " – "
                + last.formatted(.dateTime.day().month(.abbreviated)) + " " + year
        } else if cal.isDate(first, equalTo: last, toGranularity: .year) {
            range = first.formatted(.dateTime.day().month(.abbreviated)) + " – "
                + last.formatted(.dateTime.day().month(.abbreviated)) + " " + year
        } else {
            // An All window can start in an earlier year; include the year on both ends so the
            // range doesn't look backwards.
            range = first.formatted(.dateTime.day().month(.abbreviated).year()) + " – "
                + last.formatted(.dateTime.day().month(.abbreviated)) + " " + year
        }
        line += " · " + range.uppercased()
        return line
    }

    // MARK: Ledger

    private var ledgerTitle: String {
        switch style {
        case .countries: "TOP COUNTRIES"
        case .byDay:
            options.includesHostnames ? "TOP DESTINATIONS"
                : (summary.window == .day ? "BUSIEST HOURS" : "BUSIEST DAYS")
        case .blocked: "TOP BLOCKED"
        }
    }

    /// Header at baseline 297, rule at 302. With hostnames there's an extra DATA column,
    /// so CONN. moves left.
    private var ledgerHead: some View {
        let top = baselineTop(297, size: 7.5, weight: .semibold)
        return ZStack(alignment: .topLeading) {
            Text(ledgerTitle)
                .font(.system(size: 7.5, weight: .semibold)).kerning(1.0)
                .foregroundStyle(BrandPalette.textSecondary)
                .at(x: Card.pad, top: top)
            Text("CONN.")
                .font(.system(size: 7.5, weight: .semibold)).kerning(0.8)
                .foregroundStyle(BrandPalette.textSecondary)
                .at(trailing: showsDataColumn ? 224 : 290, top: top)
            if showsDataColumn {
                Text("DATA")
                    .font(.system(size: 7.5, weight: .semibold)).kerning(0.8)
                    .foregroundStyle(BrandPalette.textSecondary)
                    .at(trailing: 290, top: top)
            }
            Text("BLOCKED")
                .font(.system(size: 7.5, weight: .semibold)).kerning(0.8)
                .foregroundStyle(BrandPalette.textSecondary)
                .at(trailing: Card.trailing, top: top)
            Hairline(opacity: 0.18)
                .frame(width: Card.contentWidth)
                .offset(x: Card.pad, y: Card.ledgerTop - 0.5)
        }
    }

    private var showsDataColumn: Bool { style == .byDay && options.includesHostnames }

    /// Five rows: dated rows with a three-band bar (By day), hostname rows with a DATA
    /// column (By day with hostnames), or hostname rows with a flux meter (Blocked).
    @ViewBuilder
    private var ledgerRows: some View {
        switch style {
        case .countries:
            let rows = countries?.top ?? []
            if rows.isEmpty {
                emptyLedger("No countries placed", pitch: CountryRow.pitch)
            } else {
                let peak = rows.first?.flows ?? 1
                VStack(spacing: 0) {
                    ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                        CountryRow(
                            rank: index + 1, row: row, maxFlows: peak,
                            isYou: options.originCountry == row.code, showsRule: index > 0
                        )
                    }
                }
                .frame(height: 5 * CountryRow.pitch, alignment: .top)
            }
        case .byDay where options.includesHostnames:
            if summary.rows.isEmpty {
                emptyLedger("No targets recorded", pitch: 18)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(summary.rows.enumerated()), id: \.element.id) { index, row in
                        HostRow(
                            rank: index + 1, target: row.target, flows: row.flows,
                            blocked: row.blocked, threat: row.threat,
                            meterFraction: nil, bytes: row.bytes, showsRule: index > 0
                        )
                    }
                }
                .frame(minHeight: 5 * HostRow.pitch, alignment: .top)
            }
        case .byDay:
            let ranked = summary.busiestBars
            let peak = ranked.first?.flows ?? 1
            // Always reserve five rows of height so the footnote and footer stay put.
            VStack(spacing: 0) {
                ForEach(Array(ranked.enumerated()), id: \.element.id) { index, bar in
                    DatedRow(rank: index + 1, bar: bar, label: bucketLabel(bar.start), maxFlows: peak, showsRule: index > 0)
                }
            }
            .frame(height: 5 * DatedRow.pitch, alignment: .top)
        case .blocked:
            if summary.totalBlocked == 0 {
                emptyLedger("Nothing was blocked", pitch: 18)
            } else if summary.blockedRows.isEmpty {
                emptyLedger("No targets recorded", pitch: 18)
            } else {
                let peak = summary.blockedRows.map(\.flows).max() ?? 1
                VStack(spacing: 0) {
                    ForEach(Array(summary.blockedRows.enumerated()), id: \.element.id) { index, row in
                        HostRow(
                            rank: index + 1, target: row.target, flows: row.flows,
                            blocked: row.blocked, threat: row.threat,
                            meterFraction: Double(row.flows) / Double(peak), bytes: nil, showsRule: index > 0
                        )
                    }
                }
                .frame(minHeight: 5 * HostRow.pitch, alignment: .top)
            }
        }
    }

    /// Empty-state ledger that still takes five rows of height.
    private func emptyLedger(_ text: String, pitch: CGFloat) -> some View {
        ZStack(alignment: .topLeading) {
            Text(text)
                .font(.system(size: 11.5, weight: .medium))
                .foregroundStyle(BrandPalette.textSecondary)
                .at(x: 33, top: baselineTop(14, size: 11.5, weight: .medium))
        }
        .frame(width: Card.width, height: 5 * pitch, alignment: .topLeading)
    }

    /// "Sun 30 Aug" for a day bar, "9 PM" for an hour bar.
    private func bucketLabel(_ date: Date) -> String {
        summary.window.calendarUnit == .hour ? date.formatted(.dateTime.hour()) : dayLabel(date)
    }

    // MARK: Tail (closing rule, footnote, caveat slot, footer)

    /// Everything under the ledger. The design baselines (393 / 404 / 415 / 430 / 439)
    /// assume five one-line rows, so they're converted to offsets from where such a
    /// ledger ends (a constant). The tail then follows the real ledger, so it keeps the
    /// same spacing when the ledger grows.
    private var tail: some View {
        let fixedEnd = Card.ledgerTop + 5 * Self.rowPitch(style: style, options: options)
        let height = Card.height - fixedEnd
        return ZStack(alignment: .topLeading) {
            Hairline(opacity: 0.18)
                .frame(width: Card.contentWidth)
                .offset(x: Card.pad, y: 393 - fixedEnd)
            let footnoteSize = fittedSize(footnote, size: 8, width: Card.contentWidth)
            Text(footnote)
                .font(.system(size: footnoteSize))
                .foregroundStyle(Card.ink55)
                .at(x: Card.pad, top: baselineTop(404, size: footnoteSize) - fixedEnd)
            if summary.showsThreatCaveat {
                // Threat-attribution caveat. The slot is reserved even when empty so the footer
                // doesn't move.
                HStack(alignment: .top, spacing: 4) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 8.5))
                    Text(InsightsCopy.threatCaveat)
                        .font(.system(size: 8.5))
                        .lineSpacing(0.4)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .foregroundStyle(BrandPalette.threat)
                .frame(width: Card.contentWidth, alignment: .topLeading)
                .offset(x: Card.pad, y: baselineTop(415, size: 8.5) - fixedEnd)
            }
            Hairline(opacity: 0.16)
                .frame(width: Card.contentWidth)
                .offset(x: Card.pad, y: 430 - fixedEnd)
            // Shrinks slightly rather than drop words; SF's small-size tracking makes it a bit
            // wider than the column.
            let footerSize = fittedSize(CapabilityCopy.deviceWide, size: 8, width: Card.contentWidth, floor: 0.85)
            Text(CapabilityCopy.deviceWide)
                .font(.system(size: footerSize))
                .foregroundStyle(Card.ink50)
                .at(x: Card.pad, top: baselineTop(439, size: footerSize) - fixedEnd)
        }
        .frame(width: Card.width, height: height, alignment: .topLeading)
    }

    /// Ledger row pitch: dated rows on By day, hostname rows otherwise.
    ///
    /// There's intentionally no height calculation here. The card is sized by the same
    /// layout pass that draws it, so wrapped names grow the ledger and the tail follows.
    /// A separate line-count estimate got hyphenated names wrong and clipped the footer.
    static func rowPitch(style: ShareStyle, options: ShareOptions) -> CGFloat {
        switch style {
        case .countries: CountryRow.pitch
        case .byDay: options.includesHostnames ? HostRow.pitch : DatedRow.pitch
        case .blocked: HostRow.pitch
        }
    }

    /// What the card didn't count. Every footnote states the remainder.
    private var footnote: String {
        switch style {
        case .countries:
            guard let countries else { return "" }
            let unplaced = countries.unplacedFlows
            // Nothing placed: say so, then how many connections that was.
            guard countries.distinctCountries > 0 else {
                return unplaced > 0
                    ? "No country could be placed for these IPs · \(cardNumber(unplaced)) connection\(unplaced == 1 ? "" : "s") unplaced"
                    : "No country could be placed for these IPs"
            }
            var parts: [String] = []
            let rest = countries.restCountries
            if rest > 0 {
                parts.append("+\(rest) more countr\(rest == 1 ? "y" : "ies")")
            }
            if unplaced > 0 {
                parts.append("\(cardNumber(unplaced)) connection\(unplaced == 1 ? "" : "s") unplaced (no country for the IP)")
            } else {
                parts.append("every connection placed to a country")
            }
            return parts.joined(separator: " · ")
        case .byDay where options.includesHostnames:
            if let distinctTargets, distinctTargets > summary.rows.count {
                return "Top \(summary.rows.count) of \(cardNumber(distinctTargets)) destinations by connections"
            }
            return "Top \(summary.rows.count) by connections"
        case .byDay:
            let unit = summary.window.calendarUnit == .hour ? "hour" : "day"
            var parts: [String] = []
            let quiet = summary.bars.count - summary.busiestBars.count
            if quiet > 0 {
                let quietFlows = summary.totalFlows - summary.busiestBars.reduce(0) { $0 + $1.flows }
                parts.append("+\(quiet) quieter \(unit)\(quiet == 1 ? "" : "s") · \(cardNumber(quietFlows)) connections")
            }
            if let last = summary.bars.last {
                parts.append("\(bucketLabel(last.start)) is still filling up")
            }
            return parts.joined(separator: " · ")
        case .blocked:
            let listed = summary.blockedRows.reduce(0) { $0 + $1.blocked }
            let rest = summary.totalBlocked - listed
            var parts: [String] = []
            if rest > 0 {
                parts.append("+\(cardNumber(rest)) blocked connection\(rest == 1 ? "" : "s") at other targets")
            }
            if !summary.blockedRows.isEmpty {
                parts.append("line under a name: that target’s connections")
            }
            return parts.joined(separator: " · ")
        }
    }
}

// MARK: - Hero

/// Eyebrow at 61, big number + noun on baseline 102, qualifier at 117.
private struct HeroLeft: View {
    let eyebrow: String
    let number: String
    let noun: String
    var nounColor: Color = BrandPalette.textPrimary
    var nounWeight: Font.Weight = .light
    var nounUIWeight: UIFont.Weight = .light
    let qualifier: Text
    /// Qualifier as plain text, for measuring.
    let qualifierText: String
    /// Width of the right column, so the left side stops short of it.
    let rightWidth: CGFloat
    let rightSublineWidth: CGFloat

    var body: some View {
        // Large numbers or a wide right column shrink number and noun together, keeping
        // the 52/24 ratio, down to 60% at most.
        let numberWidth = textWidth(number, size: 52, weight: .bold) - 2.2 * CGFloat(max(0, number.count - 1))
        let pairWidth = numberWidth + 9 + textWidth(noun, size: 24, weight: nounUIWeight)
        let pairRoom = Card.trailing - rightWidth - 10 - 20
        let scale = min(1, max(0.6, pairRoom / max(1, pairWidth * 1.04)))
        let qualifierRoom = Card.trailing - rightSublineWidth - 8 - Card.pad
        let qualifierSize = fittedSize(qualifierText, size: 10, width: qualifierRoom)
        ZStack(alignment: .topLeading) {
            Text(eyebrow)
                .font(.system(size: 8.5, weight: .semibold)).kerning(1.2)
                .foregroundStyle(BrandPalette.textSecondary)
                .at(x: Card.pad, top: baselineTop(61, size: 8.5, weight: .semibold))
            HStack(alignment: .lastTextBaseline, spacing: 9 * scale) {
                Text(number)
                    .font(.system(size: 52 * scale, weight: .bold)).kerning(-2.2 * scale)
                    .monospacedDigit()
                    .foregroundStyle(BrandPalette.textPrimary)
                Text(noun)
                    .font(.system(size: 24 * scale, weight: nounWeight)).kerning(-0.3)
                    .foregroundStyle(nounColor)
            }
            .at(x: 20, top: baselineTop(102, size: 52 * scale, weight: .bold))
            qualifier
                .font(.system(size: qualifierSize))
                .monospacedDigit()
                .at(x: Card.pad, top: baselineTop(117, size: qualifierSize))
        }
    }
}

/// Right-aligned secondary fact: 30 pt number + 14 pt word on baseline 96, a 10 pt
/// line on 110.
private struct HeroRight: View {
    let number: String
    let word: String
    let wordColor: Color
    let subline: String

    /// How far the number line extends left of the trailing edge.
    var width: CGFloat {
        textWidth(number, size: 30, weight: .bold) - 0.8 * CGFloat(max(0, number.count - 1))
            + textWidth(" " + word, size: 14, weight: .semibold)
    }

    var sublineWidth: CGFloat { textWidth(subline, size: 10) }

    var body: some View {
        ZStack(alignment: .topLeading) {
            (Text(number).font(.system(size: 30, weight: .bold)).kerning(-0.8)
                .foregroundStyle(BrandPalette.textPrimary)
             + Text(" " + word).font(.system(size: 14, weight: .semibold))
                .foregroundStyle(wordColor))
                .monospacedDigit()
                .at(trailing: Card.trailing, top: baselineTop(96, size: 30, weight: .bold))
            Text(subline)
                .font(.system(size: 10)).monospacedDigit()
                .foregroundStyle(BrandPalette.textSecondary)
                .at(trailing: Card.trailing, top: baselineTop(110, size: 10))
        }
    }
}

/// Allowed / blocked / threat as one 5 pt band at y 126, with a three-number legend
/// on 141. On By day this doubles as the chart legend.
private struct ProportionStrip: View {
    let allowed: Int
    let ruleBlocked: Int
    let threat: Int

    var body: some View {
        let total = max(1, allowed + ruleBlocked + threat)
        let width = Card.contentWidth
        var wa = width * CGFloat(allowed) / CGFloat(total)
        var wb = width * CGFloat(ruleBlocked) / CGFloat(total)
        var wt = width * CGFloat(threat) / CGFloat(total)
        // Apply the minimum width to each non-zero band, taken out of allowed.
        if threat > 0, wt < Card.stripFloor { wa -= Card.stripFloor - wt; wt = Card.stripFloor }
        if ruleBlocked > 0, wb < Card.stripFloor { wa -= Card.stripFloor - wb; wb = Card.stripFloor }
        let widths = (max(0, wa), wb, wt)
        return ZStack(alignment: .topLeading) {
            Capsule().fill(Color.white.opacity(0.08))
                .frame(width: width, height: 5)
                .offset(x: Card.pad, y: 126)
            HStack(spacing: 1) {
                Rectangle().fill(TrafficPalette.allowedFill).frame(width: widths.0)
                if ruleBlocked > 0 { Rectangle().fill(Color.red).frame(width: widths.1) }
                if threat > 0 { Rectangle().fill(BrandPalette.threat).frame(width: widths.2) }
            }
            .frame(width: width, height: 5, alignment: .leading)
            .clipShape(Capsule())
            .offset(x: Card.pad, y: 126)
            // Only explain "threat" when there are threat blocks. The row shrinks a little for
            // large counts.
            let threatWord = threat > 0 ? "threat · on a threat list, blocked too" : "threat"
            let keys: [(Color, Int, String)] = [
                (TrafficPalette.allowedFill, allowed, "allowed"),
                (.red, ruleBlocked, "blocked"),
                (BrandPalette.threat, threat, threatWord),
            ]
            let needed = keys.reduce(CGFloat(0)) { sum, key in
                sum + 9 + textWidth(cardNumber(key.1), size: 9, weight: .semibold) + textWidth(" " + key.2, size: 9) + 13
            } - 13
            let legendSize: CGFloat = needed * 1.02 > width ? max(7, 9 * width / (needed * 1.02)) : 9
            HStack(spacing: 13 * legendSize / 9) {
                ForEach(Array(keys.enumerated()), id: \.offset) { _, key in
                    LegendKey(color: key.0, count: key.1, word: key.2, size: legendSize)
                }
            }
            .fixedSize()
            .offset(x: Card.pad, y: baselineTop(141, size: legendSize, weight: .semibold) - 1)
        }
    }
}

/// Legend entry: 6 pt swatch, semibold number, secondary label. Zero counts get a
/// neutral swatch so red only appears when something was blocked.
private struct LegendKey: View {
    let color: Color
    let count: Int
    let word: String
    var size: CGFloat = 9

    var body: some View {
        HStack(spacing: 3) {
            RoundedRectangle(cornerRadius: 1.2)
                .fill(count > 0 ? color : Card.ink30)
                .frame(width: 6, height: 6)
            (Text(cardNumber(count)).fontWeight(.semibold)
                .foregroundStyle(count > 0 ? BrandPalette.textPrimary : BrandPalette.textSecondary)
             + Text(" " + word).foregroundStyle(BrandPalette.textSecondary))
                .font(.system(size: size)).monospacedDigit()
        }
    }
}

// MARK: - Ledger rows

/// Rank / label / three-band bar / CONN. / BLOCKED at a 17.5 pt pitch. Offsets are
/// from the row top: baseline 14 pt down, rule between rows 4.25 pt down.
private struct DatedRow: View {
    let rank: Int
    let bar: InsightsSummary.Bar
    let label: String
    let maxFlows: Int
    let showsRule: Bool

    static let pitch: CGFloat = 17.5

    var body: some View {
        let flows = bar.flows
        ZStack(alignment: .topLeading) {
            if showsRule {
                Hairline(opacity: 0.07).frame(width: Card.contentWidth)
                    .offset(x: Card.pad, y: 4.25)
            }
            RankNumber(rank: rank, baseline: 14)
            Text(label)
                .font(.system(size: 11.5, weight: .medium))
                .foregroundStyle(BrandPalette.textPrimary)
                .at(x: 33, top: baselineTop(14, size: 11.5, weight: .medium))
            ThreeBand(flows: flows, ruleBlocked: bar.blocked, threat: bar.threat, maxFlows: maxFlows)
                .offset(x: 160, y: 7.5)
            LedgerNumbers(flows: flows, blocked: bar.blocked + bar.threat, baseline: 14)
        }
        .frame(width: Card.width, height: Self.pitch, alignment: .topLeading)
    }
}

/// Hostname row: rank, monospaced name (wraps, never truncated), optional "on a
/// threat list" tag, then either a flux meter under the name (Blocked) or a DATA
/// column (By day with hostnames), then CONN. / BLOCKED.
///
/// 18 pt for a one-line name; taller when it wraps.
private struct HostRow: View {
    let rank: Int
    let target: String
    let flows: Int
    let blocked: Int
    let threat: Int
    /// Connections relative to the top row; nil means no meter.
    let meterFraction: Double?
    /// Byte total for the DATA column; nil means no column.
    let bytes: UInt64?
    let showsRule: Bool

    static let pitch: CGFloat = 18
    /// Meter length for the busiest target.
    private static let meterMax: CGFloat = 200

    var body: some View {
        // The numbers column has the tallest ascender, so it sets the first baseline and
        // the name's top padding is measured from it.
        let numbersAscent = UIFont.systemFont(ofSize: 11, weight: .semibold).ascender
        let topPad = 14 - numbersAscent
        // One line of name plus padding equals the pitch; extra lines add height.
        let lineHeight = UIFont.monospacedSystemFont(ofSize: 9.5, weight: .regular).lineHeight
        let bottomPad = max(0, Self.pitch - topPad - lineHeight)
        ZStack(alignment: .topLeading) {
            if showsRule {
                Hairline(opacity: 0.07).frame(width: Card.contentWidth)
                    .offset(x: Card.pad, y: 4)
            }
            RankNumber(rank: rank, baseline: 14)
            HStack(alignment: .firstTextBaseline, spacing: 0) {
                name
                    .frame(width: nameWidth, alignment: .topLeading)
                    .overlay(alignment: .bottomLeading) {
                        if let meterFraction {
                            FluxMeter(
                                length: Self.meterMax * meterFraction,
                                flows: flows, ruleBlocked: blocked - threat, threat: threat
                            )
                            // 3.6 pt below the baseline; the name's descender covers the first 2.3.
                            .offset(y: 1.3 + 2)
                        }
                    }
                Spacer(minLength: 0)
            }
            .frame(width: Card.contentWidth, alignment: .topLeading)
            .padding(.top, topPad)
            .padding(.bottom, bottomPad)
            .offset(x: 33)
            if let bytes {
                Text(ByteFormat.volume(bytes))
                    .font(.system(size: 11, weight: .medium)).monospacedDigit()
                    .foregroundStyle(BrandPalette.textPrimary)
                    .at(trailing: 290, top: baselineTop(14, size: 11, weight: .medium))
            }
            LedgerNumbers(flows: flows, blocked: blocked, baseline: 14, flowsTrailing: bytes == nil ? 290 : Self.connTrailingWithData)
        }
        .frame(width: Card.width, alignment: .topLeading)
        .frame(minHeight: Self.pitch, alignment: .top)
    }

    /// CONN. trailing edge when there's a DATA column.
    static let connTrailingWithData: CGFloat = 224

    /// Max name width before wrapping: up to the CONN. column minus a gutter.
    private var nameWidth: CGFloat { Self.nameWidth(hasData: bytes != nil) }

    static func nameWidth(hasData: Bool) -> CGFloat {
        (hasData ? connTrailingWithData : 290) - 33 - 48
    }

    /// Name and tag as one text run so the tag wraps with the name.
    private var name: some View {
        var run = Text(target)
            .font(.system(size: 9.5, design: .monospaced))
            .foregroundStyle(BrandPalette.textPrimary)
        if threat > 0 {
            run = run + Text("  on a threat list")
                .font(.system(size: 7.5, weight: .medium))
                .foregroundStyle(BrandPalette.threat)
        }
        // No `lineLimit`: a truncated hostname can't be recovered from an image.
        return run.fixedSize(horizontal: false, vertical: true)
    }
}

/// 7 pt rank, right-aligned to x 27.
private struct RankNumber: View {
    let rank: Int
    let baseline: CGFloat
    var body: some View {
        Text("\(rank)")
            .font(.system(size: 7, weight: .semibold)).monospacedDigit()
            .foregroundStyle(Card.ink42)
            .at(trailing: 27, top: baselineTop(baseline, size: 7, weight: .semibold))
    }
}

/// CONN. right-aligned at 290, BLOCKED at 338. BLOCKED is red when non-zero, a
/// neutral dash when zero; the column header keeps the meaning without color.
private struct LedgerNumbers: View {
    let flows: Int
    let blocked: Int
    let baseline: CGFloat
    var flowsTrailing: CGFloat = 290

    var body: some View {
        ZStack(alignment: .topLeading) {
            Text(cardNumber(flows))
                .font(.system(size: 11, weight: .medium)).monospacedDigit()
                .foregroundStyle(BrandPalette.textPrimary)
                .at(trailing: flowsTrailing, top: baselineTop(baseline, size: 11, weight: .medium))
            if blocked > 0 {
                Text(cardNumber(blocked))
                    .font(.system(size: 11, weight: .semibold)).monospacedDigit()
                    .foregroundStyle(.red)
                    .at(trailing: Card.trailing, top: baselineTop(baseline, size: 11, weight: .semibold))
            } else {
                Text("–")
                    .font(.system(size: 11))
                    .foregroundStyle(Card.ink30)
                    .at(trailing: Card.trailing, top: baselineTop(baseline, size: 11))
            }
        }
    }
}

/// 88 × 4 allowed / blocked / threat bar, length flows / maxFlows, on a white 8% track.
private struct ThreeBand: View {
    let flows: Int
    let ruleBlocked: Int
    let threat: Int
    let maxFlows: Int

    private static let width: CGFloat = 88

    var body: some View {
        let total = Self.width * CGFloat(flows) / CGFloat(max(1, maxFlows))
        let allowed = max(0, flows - ruleBlocked - threat)
        var wa = total * CGFloat(allowed) / CGFloat(max(1, flows))
        var wb = total * CGFloat(ruleBlocked) / CGFloat(max(1, flows))
        var wt = total * CGFloat(threat) / CGFloat(max(1, flows))
        if threat > 0, wt < Card.bandFloor { wa -= Card.bandFloor - wt; wt = Card.bandFloor }
        if ruleBlocked > 0, wb < Card.bandFloor { wa -= Card.bandFloor - wb; wb = Card.bandFloor }
        let widths = (max(0, wa), wb, wt)
        return ZStack(alignment: .leading) {
            Capsule().fill(Color.white.opacity(0.08))
            HStack(spacing: 0) {
                Rectangle().fill(TrafficPalette.allowedFill).frame(width: widths.0)
                if ruleBlocked > 0 { Rectangle().fill(Color.red).frame(width: widths.1) }
                if threat > 0 { Rectangle().fill(BrandPalette.threat).frame(width: widths.2) }
            }
            .frame(width: total, height: 4, alignment: .leading)
            .clipShape(Capsule())
        }
        .frame(width: Self.width, height: 4, alignment: .leading)
    }
}

/// 2 pt line under a blocked hostname: green allowed, red rule-blocked, violet
/// threat-blocked. Length is relative to the busiest target listed.
private struct FluxMeter: View {
    let length: CGFloat
    let flows: Int
    let ruleBlocked: Int
    let threat: Int

    var body: some View {
        let allowed = max(0, flows - ruleBlocked - threat)
        let unit = length / CGFloat(max(1, flows))
        HStack(spacing: 0) {
            if allowed > 0 { Capsule().fill(TrafficPalette.allowedFill).frame(width: unit * CGFloat(allowed)) }
            if ruleBlocked > 0 { Capsule().fill(Color.red).frame(width: unit * CGFloat(ruleBlocked)) }
            if threat > 0 { Capsule().fill(BrandPalette.threat).frame(width: unit * CGFloat(threat)) }
        }
        .frame(height: 2)
    }
}

// MARK: - By day card (hero, strip, chart)

private struct ByDayTop: View {
    let summary: InsightsSummary

    var body: some View {
        let isHourly = summary.window.calendarUnit == .hour
        // Lay out the right column first so the left side can avoid it. With nothing
        // blocked it's shown uncolored.
        let right = summary.totalBlocked > 0
            ? HeroRight(
                number: cardNumber(summary.totalBlocked), word: "blocked", wordColor: .red,
                subline: "\(percent(summary.totalBlocked, of: summary.totalFlows)) of connections"
            )
            : HeroRight(
                number: cardNumber(summary.totalFlows), word: "connections",
                wordColor: BrandPalette.textSecondary, subline: "nothing blocked"
            )
        ZStack(alignment: .topLeading) {
            HeroLeft(
                eyebrow: isHourly ? "HOUR BY HOUR" : "DAY BY DAY",
                number: cardNumber(summary.perBucketAverage),
                noun: isHourly ? "an hour" : "a day",
                qualifier: qualifier.text,
                qualifierText: qualifier.plain,
                rightWidth: right.width,
                rightSublineWidth: right.sublineWidth
            )
            right
            ProportionStrip(allowed: summary.allowedTotal, ruleBlocked: summary.ruleBlockedTotal, threat: summary.threatTotal)
            ByDayChart(summary: summary)
                .frame(width: Card.contentWidth, height: 131, alignment: .top)
                .offset(x: Card.pad, y: 152)
        }
    }

    /// e.g. `1,284 connections over 7 days · ↑ 412 MB ↓ 1.7 GB`. The only place sent
    /// and received appear on any card.
    private var qualifier: (text: Text, plain: String) {
        let span: String
        switch summary.window {
        case .day: span = "over 24 hours"
        case .week: span = "over 7 days"
        case .month: span = "over 30 days"
        case .all: span = "over \(summary.bars.count) day\(summary.bars.count == 1 ? "" : "s")"
        }
        let lead = "\(cardNumber(summary.totalFlows)) connections \(span) · "
        let up = "↑ \(ByteFormat.volume(summary.totalBytesUp))"
        let down = "↓ \(ByteFormat.volume(summary.totalBytesDown))"
        let text = Text(lead).foregroundStyle(BrandPalette.textSecondary)
            + Text(up).fontWeight(.semibold).foregroundStyle(TrafficPalette.sent)
            + Text("  ").foregroundStyle(BrandPalette.textSecondary)
            + Text(down).fontWeight(.semibold).foregroundStyle(TrafficPalette.received)
        return (text, lead + up + "  " + down)
    }
}

/// Same stacked bars as Trends, annotated with the bucket that had the most blocks.
/// Covers card y 152-283: annotation baseline 159, plot 168-262, ticks at 274.
private struct ByDayChart: View {
    let summary: InsightsSummary

    /// Plot top and bottom in chart coordinates (card y 168 / 262).
    private static let plotTop: CGFloat = 16
    private static let plotBottom: CGFloat = 110

    var body: some View {
        let unit = summary.window.calendarUnit
        let ticks = tickDates
        let lastStart = summary.bars.last?.start
        Chart(summary.bars) { bar in
            BarMark(
                x: .value("Time", bar.start, unit: unit),
                y: .value("Connections", bar.allowed),
                width: barWidth
            )
            .foregroundStyle(TrafficPalette.allowedFill)
            BarMark(
                x: .value("Time", bar.start, unit: unit),
                y: .value("Connections", bar.blocked),
                width: barWidth
            )
            .foregroundStyle(Color.red)
            BarMark(
                x: .value("Time", bar.start, unit: unit),
                y: .value("Connections", bar.threat),
                width: barWidth
            )
            .foregroundStyle(BrandPalette.threat)
        }
        .chartXScale(domain: summary.xDomain)
        .chartYScale(domain: 0...max(1, summary.peakFlows))
        .chartLegend(.hidden)
        // Ticks are drawn manually in the overlay: Charts' x-axis labels ended up inside
        // the plot under `ImageRenderer`.
        .chartXAxis(.hidden)
        // Two faint gridlines at round values below the peak, labeled in the right gutter.
        .chartYAxis {
            AxisMarks(position: .trailing, values: gridValues) { value in
                AxisGridLine().foregroundStyle(Color.white.opacity(0.10))
                AxisValueLabel(anchor: .leading) {
                    if let v = value.as(Int.self) {
                        // Abbreviated like every other number; the gutter can't fit five digits at 7 pt.
                        Text(cardNumber(v))
                            .font(.system(size: 7)).monospacedDigit()
                            .foregroundStyle(Card.ink42)
                    }
                }
            }
        }
        // Plot pinned to 94 pt with a 16 pt lane above for the annotation, so bars land at
        // card y 168-262 regardless of label sizes.
        .chartPlotStyle { plot in
            plot.frame(height: Self.plotBottom - Self.plotTop)
                .padding(.top, Self.plotTop)
        }
        .chartOverlay { proxy in
            GeometryReader { geo in
                if let plotFrame = proxy.plotFrame {
                    let plot = geo[plotFrame]
                    // Baseline under the bars, white 22%.
                    Rectangle().fill(Color.white.opacity(0.22))
                        .frame(width: plot.width, height: 0.5)
                        .position(x: plot.midX, y: plot.maxY + 0.5)
                    peakAnnotation(proxy: proxy, plot: plot, chartWidth: geo.size.width)
                    // Ticks: every bar on 7d, every sixth hour on 24h, Mondays on 30d. The last bar's
                    // tick is bold (it's still filling), and ticks within three slots of it are dropped.
                    ForEach(ticks, id: \.self) { date in
                        if let x = proxy.position(forX: date.addingTimeInterval(Double(summary.window.bucketSeconds) / 2)) {
                            let isLast = lastStart.map { $0 == date } ?? false
                            Text(tickLabel(date))
                                .font(.system(size: 8, weight: isLast ? .semibold : .regular))
                                .foregroundStyle(isLast ? BrandPalette.textPrimary : BrandPalette.textSecondary)
                                .fixedSize()
                                // Card baseline 274 = 122 here.
                                .position(x: plot.minX + x, y: baselineTop(122, size: 8) + 5)
                        }
                    }
                }
            }
        }
    }

    /// Bar width based on the busiest bucket, so the tallest bar reaches the top of the plot.
    private var barWidth: MarkDimension {
        summary.bars.count <= 7 ? .fixed(28) : .ratio(0.7)
    }

    private var gridValues: [Int] {
        let peak = summary.peakFlows
        guard peak > 0 else { return [] }
        // Pick a step that puts one or two gridlines under the peak.
        let candidates = [5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000, 10_000, 20_000, 50_000]
        let step = candidates.first { $0 * 3 > peak } ?? 100_000
        return [step, 2 * step].filter { $0 < peak }
    }

    /// Buckets that get a tick.
    private var tickDates: [Date] {
        let bars = summary.bars
        guard let last = bars.indices.last else { return [] }
        let count = bars.count
        let cal = Calendar.current
        var indices: [Int]
        if summary.window.calendarUnit == .hour {
            indices = bars.indices.filter { $0 % 6 == 0 }
        } else if count <= 7 {
            indices = Array(bars.indices)
        } else if count <= 60 {
            indices = bars.indices.filter { cal.component(.weekday, from: bars[$0].start) == 2 }
        } else {
            indices = bars.indices.filter { cal.component(.day, from: bars[$0].start) == 1 }
        }
        // Drop ticks within three slots of the last bar so labels don't collide. With seven
        // or fewer bars, label every bar.
        if count > 7 {
            indices = indices.filter { $0 < count - 3 }
            indices.append(last)
        }
        return indices.map { bars[$0].start }
    }

    private func tickLabel(_ date: Date) -> String {
        summary.window.calendarUnit == .hour
            ? date.formatted(.dateTime.hour())
            : date.formatted(.dateTime.weekday(.abbreviated)) + " " + date.formatted(.dateTime.day())
    }

    /// `31 blocked · Sun 30 Aug` above the bucket with the most blocks, with a 1 pt red
    /// tick down to the bar. Only drawn when something was blocked.
    @ViewBuilder
    private func peakAnnotation(proxy: ChartProxy, plot: CGRect, chartWidth: CGFloat) -> some View {
        if let index = summary.peakBlockedIndex, summary.bars.indices.contains(index) {
            let bar = summary.bars[index]
            let half = Double(summary.window.bucketSeconds) / 2
            if let x = proxy.position(forX: bar.start.addingTimeInterval(half)),
               let top = proxy.position(forY: Double(bar.flows)) {
                let cx = plot.minX + x
                let barTop = plot.minY + top
                let label = "\(cardNumber(bar.blocked + bar.threat)) blocked · \(annotationDate(bar.start))"
                // Card baseline 159 = 7 here; the tick starts at 162 (10).
                let labelTop = baselineTop(7, size: 8.5, weight: .semibold)
                Rectangle().fill(Color.red)
                    .frame(width: 1, height: max(0, barTop - 2 - 10))
                    .position(x: cx, y: 10 + max(0, barTop - 2 - 10) / 2)
                Text(label)
                    .font(.system(size: 8.5, weight: .semibold)).monospacedDigit()
                    .foregroundStyle(.red)
                    .fixedSize()
                    // Centered on the bar but clamped inside the card.
                    .position(x: clampedCenter(cx, labelWidth: labelWidth(label), in: chartWidth), y: labelTop + 6)
            }
        }
    }

    private func labelWidth(_ label: String) -> CGFloat {
        let font = UIFont.systemFont(ofSize: 8.5, weight: .semibold)
        return (label as NSString).size(withAttributes: [.font: font]).width
    }

    private func clampedCenter(_ x: CGFloat, labelWidth: CGFloat, in width: CGFloat) -> CGFloat {
        min(max(x, labelWidth / 2), width - labelWidth / 2)
    }

    private func annotationDate(_ date: Date) -> String {
        summary.window.calendarUnit == .hour ? date.formatted(.dateTime.hour()) : dayLabel(date)
    }
}

// MARK: - Blocked card (hero, logo, ledger arc, legend)

private struct BlockedTop: View {
    let summary: InsightsSummary

    /// Ring geometry measured on the OnboardingLogo asset, as fractions of the image: a
    /// circle fitted to the ring's visible outer edge (alpha > 120, sampled in the
    /// top-left quadrant, clear of the stream and sparkles). Lip angles are in SwiftUI
    /// convention (y down, clockwise positive).
    private static let logoCenter = (x: 0.4504, y: 0.4754)
    private static let logoRadius = 0.278
    private static let gapUpperLip = -34.0
    private static let gapLowerLip = 29.0

    /// Ring center on the card and its visible outer radius in points (50 plus glow).
    private static let ringCenter = CGPoint(x: 100, y: 208)
    private static let ringRadius: CGFloat = 52
    /// The ledger arc: one step outside the ring at radius 59.5, 3.6 pt wide.
    private static let arcRadius: CGFloat = 59.5
    private static let arcWidth: CGFloat = 3.6

    var body: some View {
        let blocked = summary.totalBlocked
        let right = HeroRight(
            number: cardNumber(summary.allowedTotal), word: "allowed",
            wordColor: BrandPalette.textSecondary,
            subline: "of \(cardNumber(summary.totalFlows)) connections"
        )
        ZStack(alignment: .topLeading) {
            HeroLeft(
                eyebrow: "AT THE MOAT",
                number: cardNumber(blocked),
                noun: "blocked",
                // Red only when something was blocked.
                nounColor: blocked > 0 ? .red : BrandPalette.textSecondary,
                nounWeight: .semibold,
                nounUIWeight: .semibold,
                qualifier: Text(qualifierText).foregroundStyle(BrandPalette.textSecondary),
                qualifierText: qualifierText,
                rightWidth: right.width,
                rightSublineWidth: right.sublineWidth
            )
            right
            logo
            ledgerArc
            legend
            let caption1 = "Outer ring: all \(cardNumber(summary.totalFlows)) connections ·"
            // Only mention colors that actually appear on the arc.
            let colours = switch (summary.ruleBlockedTotal > 0, summary.threatTotal > 0) {
            case (true, true): "red and violet"
            case (true, false): "red"
            default: "violet"
            }
            let caption2 = blocked > 0 ? "\(colours): the \(cardNumber(blocked)) blocked" : "nothing was blocked"
            let captionSize = min(
                fittedSize(caption1, size: 7, width: Card.trailing - 204),
                fittedSize(caption2, size: 7, width: Card.trailing - 204)
            )
            Text(caption1)
                .font(.system(size: captionSize)).monospacedDigit()
                .foregroundStyle(Card.ink42)
                .at(x: 204, top: baselineTop(275, size: captionSize))
            Text(caption2)
                .font(.system(size: captionSize)).monospacedDigit()
                .foregroundStyle(Card.ink42)
                .at(x: 204, top: baselineTop(284, size: captionSize))
        }
    }

    private var qualifierText: String {
        let threat = summary.threatTotal
        let share = "\(percent(summary.totalBlocked, of: summary.totalFlows)) of all connections"
        let lead = threat > 0
            ? "\(cardNumber(threat)) of them on a threat list"
            : "none on a threat list"
        return "\(lead) · \(share)"
    }

    /// The logo asset, scaled so the ring's outer radius is `ringRadius` and centered on
    /// `ringCenter`.
    private var logo: some View {
        let side = 2 * Self.ringRadius / (2 * Self.logoRadius)
        return Image("OnboardingLogo")
            .resizable()
            .scaledToFit()
            .frame(width: side, height: side)
            .offset(
                x: Self.ringCenter.x - Self.logoCenter.x * side,
                y: Self.ringCenter.y - Self.logoCenter.y * side
            )
    }

    /// A faint track along the ring's 297° sweep, with the blocked share in red and the
    /// threat share in violet, ending at the gap's upper lip. No green, so it doesn't
    /// read as a "percent protected" gauge.
    private var ledgerArc: some View {
        let sweep = (Self.gapUpperLip + 360) - Self.gapLowerLip
        let end = Self.gapUpperLip + 360
        let total = Double(max(1, summary.totalFlows))
        let rule = sweep * Double(summary.ruleBlockedTotal) / total
        // Minimum arc for a non-zero threat share (`Card.arcFloorDegrees`); the exact count
        // is in the legend.
        let threat = summary.threatTotal > 0
            ? max(sweep * Double(summary.threatTotal) / total, Card.arcFloorDegrees) : 0
        let side = 2 * Self.arcRadius
        let style = StrokeStyle(lineWidth: Self.arcWidth, lineCap: .butt)
        return ZStack {
            RingArcShape(start: .degrees(Self.gapLowerLip), sweep: .degrees(sweep), drawn: 1)
                .stroke(Color.white.opacity(0.11), style: style)
            if summary.ruleBlockedTotal > 0 {
                RingArcShape(start: .degrees(end - rule), sweep: .degrees(rule), drawn: 1)
                    .stroke(Color.red, style: style)
            }
            if summary.threatTotal > 0 {
                RingArcShape(start: .degrees(end - rule - threat), sweep: .degrees(threat), drawn: 1)
                    .stroke(BrandPalette.threat, style: style)
            }
        }
        .frame(width: side, height: side)
        .offset(x: Self.ringCenter.x - Self.arcRadius, y: Self.ringCenter.y - Self.arcRadius)
    }

    /// The three numbers the arc represents, at baselines 176 / 210 / 244.
    private var legend: some View {
        ZStack(alignment: .topLeading) {
            legendRow(color: TrafficPalette.allowedFill, count: summary.allowedTotal, word: "allowed", baseline: 176)
            legendRow(color: .red, count: summary.ruleBlockedTotal, word: "blocked", baseline: 210)
            legendRow(color: BrandPalette.threat, count: summary.threatTotal, word: "threat", baseline: 244)
            Text("on a threat list, blocked too")
                .font(.system(size: 8.5))
                .foregroundStyle(BrandPalette.textSecondary)
                .at(x: 217, top: baselineTop(256, size: 8.5))
        }
    }

    private func legendRow(color: Color, count: Int, word: String, baseline: CGFloat) -> some View {
        ZStack(alignment: .topLeading) {
            RoundedRectangle(cornerRadius: 1.6)
                .fill(count > 0 ? color : Card.ink30)
                .frame(width: 7, height: 7)
                .offset(x: 204, y: baseline - 12.5)
            (Text(cardNumber(count)).font(.system(size: 18, weight: .bold)).kerning(-0.4)
                .foregroundStyle(count > 0 ? BrandPalette.textPrimary : BrandPalette.textSecondary)
             + Text("  " + word).font(.system(size: 9.5))
                .foregroundStyle(BrandPalette.textSecondary))
                .monospacedDigit()
                .at(x: 217, top: baselineTop(baseline, size: 18, weight: .bold))
        }
    }
}

// MARK: - Countries card (hero, strip, dot-matrix world)

private struct CountriesTop: View {
    let summary: InsightsSummary
    let countries: CountriesSummary
    let options: ShareOptions

    var body: some View {
        // Right column first, as on By day.
        let right = summary.totalBlocked > 0
            ? HeroRight(
                number: cardNumber(summary.totalBlocked), word: "blocked", wordColor: .red,
                subline: "of \(cardNumber(summary.totalFlows)) connections"
            )
            : HeroRight(
                number: cardNumber(summary.totalFlows), word: "connections",
                wordColor: BrandPalette.textSecondary, subline: "nothing blocked"
            )
        let count = countries.distinctCountries
        // The hero number is an IP-based estimate, so say so right under it at 10 pt.
        let qualifierWords = "IP estimate (DB-IP) — can be wrong"
        ZStack(alignment: .topLeading) {
            HeroLeft(
                eyebrow: "DESTINATIONS IN",
                number: cardNumber(count),
                noun: count == 1 ? "country" : "countries",
                qualifier: Text(Image(systemName: "info.circle")).foregroundStyle(BrandPalette.textSecondary)
                    + Text(" " + qualifierWords).foregroundStyle(BrandPalette.textSecondary),
                qualifierText: "ⓘ " + qualifierWords,
                rightWidth: right.width,
                rightSublineWidth: right.sublineWidth
            )
            right
            ProportionStrip(allowed: summary.allowedTotal, ruleBlocked: summary.ruleBlockedTotal, threat: summary.threatTotal)
            WorldDotMap(countries: countries, originCountry: options.originCountry)
                .frame(width: WorldDots.width, height: WorldDots.height)
                .offset(y: Self.mapTop)
            // DB-IP attribution (CC BY 4.0), drawn on the map so it can't be cropped away from it.
            Text("IP Geolocation by DB-IP")
                .font(.system(size: 7, weight: .medium)).kerning(0.1)
                .foregroundStyle(Card.ink42)
                .at(x: Card.pad, top: baselineTop(Self.mapTop + WorldDots.height - 4, size: 7, weight: .medium))
        }
    }

    /// Map band: card y 152-283, full bleed.
    static let mapTop: CGFloat = 152
}

/// Dot-matrix world map. One masked `Canvas` draws the glow, land dots, country halos,
/// and optional origin arcs, faded at the edges. A second, unmasked `Canvas` draws
/// the ①-⑤ markers so they stay sharp.
///
/// Equirectangular at 1 pt per degree: x = lon + 180, y = 76 − lat, 131 pt tall
/// (`WorldDots`). Glows are centered on centroids; countries are never filled or
/// outlined, since an IP lookup doesn't know more than that.
///
/// No red on the map: blocked counts live in the ledger.
private struct WorldDotMap: View {
    let countries: CountriesSummary
    /// The user's own country, only while "Show my country" is on.
    let originCountry: String?

    private static let dotRadius: CGFloat = 0.78
    private static let markerRadius: CGFloat = 5.4

    /// A country's centroid on the map, or nil if the code isn't in the table.
    /// `nonisolated` since it only reads a constant table.
    nonisolated static func point(forCountry code: String) -> CGPoint? {
        guard let coord = CountryCentroids.coordinate(for: code) else { return nil }
        return CGPoint(x: coord.longitude + 180, y: WorldDots.latitudeTop - coord.latitude)
    }

    /// A lit country's glow: centroid, radius in degrees (= points here), and cos(lat)
    /// for distance calculations.
    private struct Halo {
        let centre: CGPoint
        let radius: Double
        let latitudeScale: Double
    }

    var body: some View {
        let halos = countries.lit.map { lit in
            Halo(
                centre: lit.point,
                radius: CountriesCardMath.haloRadius(flows: lit.flows),
                latitudeScale: cos((WorldDots.latitudeTop - lit.point.y) * .pi / 180)
            )
        }
        ZStack(alignment: .topLeading) {
            Canvas(rendersAsynchronously: false) { context, size in
                drawGlow(in: &context, size: size)
                drawHalos(halos, in: &context)
                drawDots(halos, in: &context)
                drawOrigin(in: &context)
            }
            // Fade the dots out at the edges: 4.5% horizontally and 7% vertically, as two masks
            // (their alphas multiply).
            .mask {
                LinearGradient(
                    stops: [.init(color: .clear, location: 0), .init(color: .black, location: 0.045),
                            .init(color: .black, location: 0.955), .init(color: .clear, location: 1)],
                    startPoint: .leading, endPoint: .trailing
                )
            }
            .mask {
                LinearGradient(
                    stops: [.init(color: .clear, location: 0), .init(color: .black, location: 0.07),
                            .init(color: .black, location: 0.93), .init(color: .clear, location: 1)],
                    startPoint: .top, endPoint: .bottom
                )
            }
            Canvas(rendersAsynchronously: false) { context, size in
                drawMarkers(in: &context, size: size)
            }
        }
    }

    /// One soft `blueDeep` glow behind the whole map, 0.20 -> 0.
    private func drawGlow(in context: inout GraphicsContext, size: CGSize) {
        let rect = CGRect(x: -20, y: -24, width: size.width + 40, height: size.height + 48)
        context.fill(
            Path(ellipseIn: rect),
            with: .radialGradient(
                Gradient(colors: [BrandPalette.blueDeep.opacity(0.20), BrandPalette.blueDeep.opacity(0)]),
                center: CGPoint(x: rect.midX, y: rect.midY), startRadius: 0, endRadius: rect.width * 0.55
            )
        )
    }

    /// A radial `blueDeep` spot under each lit country, 1.6 × its glow radius: 0.55 at
    /// the center, 0.18 at 55%, 0 at the edge.
    private func drawHalos(_ halos: [Halo], in context: inout GraphicsContext) {
        let gradient = Gradient(stops: [
            .init(color: BrandPalette.blueDeep.opacity(0.55), location: 0),
            .init(color: BrandPalette.blueDeep.opacity(0.18), location: 0.55),
            .init(color: BrandPalette.blueDeep.opacity(0), location: 1),
        ])
        for halo in halos where halo.radius > 0 {
            let r = halo.radius * 1.6
            context.fill(
                Path(ellipseIn: CGRect(x: halo.centre.x - r, y: halo.centre.y - r, width: 2 * r, height: 2 * r)),
                with: .radialGradient(gradient, center: halo.centre, startRadius: 0, endRadius: r)
            )
        }
    }

    /// Land dots. Dots inside a glow brighten from `blueLight` toward near-white by depth,
    /// grow slightly and become opaque; the rest are white at 16%. Base dots are drawn
    /// as one path with one fill, since thousands of separate fills make Canvas slow.
    private func drawDots(_ halos: [Halo], in context: inout GraphicsContext) {
        var base = Path()
        var lit: [(CGPoint, Double)] = []
        let r0 = Self.dotRadius
        for point in WorldDots.points {
            var level = 0.0
            for halo in halos where halo.radius > 0 {
                let dx = (point.x - halo.centre.x) * halo.latitudeScale
                let dy = point.y - halo.centre.y
                level = max(level, CountriesCardMath.glowLevel(distance: (dx * dx + dy * dy).squareRoot(), radius: halo.radius))
            }
            if level > 0 {
                lit.append((point, level))
            } else {
                base.addEllipse(in: CGRect(x: point.x - r0, y: point.y - r0, width: 2 * r0, height: 2 * r0))
            }
        }
        context.fill(base, with: .color(Color.white.opacity(0.16)))
        for (point, level) in lit {
            let r = r0 + 0.22 * level
            context.fill(
                Path(ellipseIn: CGRect(x: point.x - r, y: point.y - r, width: 2 * r, height: 2 * r)),
                with: .color(Self.litColor(level: level))
            )
        }
    }

    /// `BrandPalette.blueLight` (0.45, 0.68, 0.98) mixed toward #EAF3FF by 0.8 × level,
    /// at 0.55-1.0 opacity. Components are spelled out because a `Color` can't be read back.
    private static func litColor(level: Double) -> Color {
        let t = level * 0.8
        return Color(
            red: 0.45 + (0.918 - 0.45) * t,
            green: 0.68 + (0.953 - 0.68) * t,
            blue: 0.98 + (1.0 - 0.98) * t,
            opacity: 0.55 + 0.45 * level
        )
    }

    /// "Show my country": a white marker on the user's country centroid with thin arcs to
    /// each of the top five. White because the origin is neither allowed nor blocked.
    /// Only drawn to the centroid, never the actual location fix.
    private func drawOrigin(in context: inout GraphicsContext) {
        guard let originCountry, let origin = Self.point(forCountry: originCountry) else { return }
        let targets = countries.top.compactMap { row -> CGPoint? in
            guard row.code != originCountry else { return nil }
            return Self.point(forCountry: row.code)
        }
        for target in targets {
            let path = Self.arc(from: origin, to: target, bow: 0.22)
            context.stroke(path, with: .color(BrandPalette.blueDeep.opacity(0.32)), style: StrokeStyle(lineWidth: 3.2, lineCap: .round))
            context.stroke(path, with: .color(BrandPalette.blueLight.opacity(0.92)), style: StrokeStyle(lineWidth: 1.1, lineCap: .round))
        }
        context.fill(Path(ellipseIn: CGRect(x: origin.x - 7, y: origin.y - 7, width: 14, height: 14)), with: .color(Color.white.opacity(0.10)))
        context.stroke(Path(ellipseIn: CGRect(x: origin.x - 4.6, y: origin.y - 4.6, width: 9.2, height: 9.2)), with: .color(Color.white.opacity(0.85)), lineWidth: 1.1)
        context.fill(Path(ellipseIn: CGRect(x: origin.x - 1.9, y: origin.y - 1.9, width: 3.8, height: 3.8)), with: .color(.white))
    }

    /// Same curve as `TrafficArcShape` (a quadratic bowed by `bow` × chord), but always
    /// bowed north so arcs don't cut through the ledger.
    private static func arc(from a: CGPoint, to b: CGPoint, bow: CGFloat) -> Path {
        let mid = CGPoint(x: (a.x + b.x) / 2, y: (a.y + b.y) / 2)
        let dx = b.x - a.x, dy = b.y - a.y
        var control = CGPoint(x: mid.x - dy * bow, y: mid.y + dx * bow)
        if control.y > mid.y {
            control = CGPoint(x: mid.x + dy * bow, y: mid.y - dx * bow)
        }
        var path = Path()
        path.move(to: a)
        path.addQuadCurve(to: b, control: control)
        return path
    }

    /// ①-⑤ on the top five centroids, moved out on a leader line when they'd overlap
    /// (`CountriesCardMath.placeMarkers` decides).
    ///
    /// Ranks are carried with each anchor instead of derived from array position.
    /// `compactMap` drops codes missing from the centroid table, and renumbering the
    /// rest would put ② on rank 3. The ledger numbers by `countries.top` position, and
    /// the map has to match it.
    private func drawMarkers(in context: inout GraphicsContext, size: CGSize) {
        let ranked = countries.top.enumerated().compactMap { i, row in
            Self.point(forCountry: row.code).map { (rank: i + 1, anchor: $0) }
        }
        let r = Self.markerRadius
        let placed = CountriesCardMath.placeMarkers(
            anchors: ranked.map { CountriesCardMath.Point(x: $0.anchor.x, y: $0.anchor.y) },
            radius: r, size: CountriesCardMath.Point(x: size.width, y: size.height)
        )
        for (index, spot) in placed.enumerated() {
            let rank = ranked[index].rank
            let anchor = ranked[index].anchor
            let centre = CGPoint(x: spot.x, y: spot.y)
            if centre != anchor {
                // Leader from the centroid to the marker's edge, plus a dot at the centroid.
                let dx = centre.x - anchor.x, dy = centre.y - anchor.y
                let length = max(0.001, (dx * dx + dy * dy).squareRoot())
                var leader = Path()
                leader.move(to: anchor)
                leader.addLine(to: CGPoint(x: centre.x - dx / length * r, y: centre.y - dy / length * r))
                context.stroke(leader, with: .color(Color.white.opacity(0.45)), lineWidth: 0.6)
                context.fill(Path(ellipseIn: CGRect(x: anchor.x - 1.5, y: anchor.y - 1.5, width: 3, height: 3)), with: .color(Color.white.opacity(0.95)))
            }
            let circle = Path(ellipseIn: CGRect(x: centre.x - r, y: centre.y - r, width: 2 * r, height: 2 * r))
            context.fill(circle, with: .color(BrandPalette.surfaceTop.opacity(0.92)))
            context.stroke(circle, with: .color(BrandPalette.blueLight), lineWidth: 0.9)
            context.draw(
                Text("\(rank)")
                    .font(.system(size: 7, weight: .semibold)).monospacedDigit()
                    .foregroundStyle(BrandPalette.textPrimary),
                at: CGPoint(x: centre.x, y: centre.y + 0.2), anchor: .center
            )
        }
    }
}

/// Rank / flag + name / three-band bar / CONN. / BLOCKED at the 17.5 pt dated-row
/// pitch. The name truncates with an ellipsis since localized names can be long and
/// the columns are fixed. Appends "· you" for the user's own country when shown.
private struct CountryRow: View {
    let rank: Int
    let row: CountriesSummary.Row
    let maxFlows: Int
    let isYou: Bool
    let showsRule: Bool

    static let pitch: CGFloat = DatedRow.pitch
    /// From the name's left edge (52) to the bar's (160), minus a gutter.
    private static let nameWidth: CGFloat = 160 - 52 - 6

    var body: some View {
        ZStack(alignment: .topLeading) {
            if showsRule {
                Hairline(opacity: 0.07).frame(width: Card.contentWidth)
                    .offset(x: Card.pad, y: 4.25)
            }
            RankNumber(rank: rank, baseline: 14)
            Text(row.flag)
                .font(.system(size: 11.5))
                .at(x: 33, top: baselineTop(14, size: 11.5))
            name
                .lineLimit(1)
                .truncationMode(.tail)
                .frame(width: Self.nameWidth, alignment: .leading)
                .offset(x: 52, y: baselineTop(14, size: 11.5, weight: .medium))
            ThreeBand(flows: row.flows, ruleBlocked: row.blocked - row.threat, threat: row.threat, maxFlows: maxFlows)
                .offset(x: 160, y: 7.5)
            LedgerNumbers(flows: row.flows, blocked: row.blocked, baseline: 14)
        }
        .frame(width: Card.width, height: Self.pitch, alignment: .topLeading)
    }

    private var name: Text {
        var run = Text(row.name)
            .font(.system(size: 11.5, weight: .medium))
            .foregroundStyle(BrandPalette.textPrimary)
        if isYou {
            // "(approx.)" because nearest-centroid is a rough guess for large countries: Seattle
            // is closer to Canada's centroid than to the US's. A distance threshold can't fix
            // that without also hiding the toggle for people it gets right.
            run = run + Text(" · you (approx.)")
                .font(.system(size: 9, weight: .medium))
                .foregroundStyle(BrandPalette.textSecondary)
        }
        return run
    }
}
