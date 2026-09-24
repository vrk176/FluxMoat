import Charts
import CoreTransferable
import SharedCore
import SwiftUI
import UniformTypeIdentifiers
import os

/// Logs counts and window names only, never hostnames (see `InsightsSummaryRenderer.render`).
private let insightsLog = Logger(subsystem: "fluxmoat", category: "insights")

/// The time window shared by Trends and Map, so switching surfaces keeps the same period.
enum InsightsWindow: String, CaseIterable, Identifiable {
    case day = "24h"
    case week = "7d"
    case month = "30d"
    case all = "All"

    var id: String { rawValue }

    /// The window spelled out for use in headers and prose. `rawValue` ("7d") is for the picker.
    var annotation: String {
        switch self {
        case .day: "Last 24 hours"
        case .week: "Last 7 days"
        case .month: "Last 30 days"
        case .all: "All time"
        }
    }

    /// Number of buckets in the window, which is also the number of bars drawn.
    /// nil for All, which covers whatever retention still holds.
    ///
    /// The window is defined in whole buckets rather than as a sliding interval. A
    /// sliding 24 h starts mid-hour and spans 25 hourly buckets, so the chart would
    /// draw a partial bar at each end. The last bucket is the one still filling.
    var barCount: Int? {
        switch self {
        case .day: 24
        case .week: 7
        case .month: 30
        case .all: nil
        }
    }

    /// Start of the bucket containing `date`, on the same grid the SQL uses:
    /// `floor((ts + offset) / bucketSeconds)` with `TimeZone.current.secondsFromGMT()`.
    ///
    /// The chart's zero-fill uses this too, so keep a single copy; a start that's off
    /// by any amount never matches a row. The offset is read for now, not for `date`,
    /// to match the store, which takes one offset per query. Across a DST change this
    /// is off by an hour, but it stays in sync with the SQL.
    func alignedStart(of date: Date) -> Date {
        let offset = Double(TimeZone.current.secondsFromGMT())
        let index = ((date.timeIntervalSince1970 + offset) / Double(bucketSeconds))
            .rounded(.down)
        return Date(timeIntervalSince1970: index * Double(bucketSeconds) - offset)
    }

    /// Lower bound of the window. nil means unbounded (the store's rollups treat nil as
    /// "no WHERE clause"). Stable within a bucket. Use `bounds(now:)` when you need the
    /// current and prior windows from a single clock read.
    var since: Date? { bounds()?.since }

    /// The current window and the prior one, all edges from one `now`. nil for All.
    ///
    /// The current window starts on a bucket boundary and has no upper edge
    /// (`until: nil`), so it is exactly `barCount` buckets and nothing falls between
    /// the clock read and the query.
    ///
    /// The prior window is period-to-date: the current window shifted back `barCount`
    /// buckets, including its upper edge, so both sides cover the same elapsed time.
    /// Comparing a partial current bucket against a full prior period made deltas read
    /// low (up to 14% on 7d right after midnight). As a result there is a gap between
    /// `priorUntil` and `since` equal to the unfinished part of the current bucket.
    func bounds(now: Date = Date()) -> (since: Date, priorSince: Date, priorUntil: Date)? {
        guard let barCount else { return nil }
        let period = Double(barCount) * Double(bucketSeconds)
        let since = alignedStart(of: now)
            .addingTimeInterval(-Double(barCount - 1) * Double(bucketSeconds))
        return (
            since: since,
            priorSince: since.addingTimeInterval(-period),
            priorUntil: now.addingTimeInterval(-period)
        )
    }

    /// The prior window as a phrase. nil for All, which has no prior window, so all
    /// deltas are hidden there.
    var priorAnnotation: String? {
        switch self {
        case .day: "prior 24 hours"
        case .week: "prior 7 days"
        case .month: "prior 30 days"
        case .all: nil
        }
    }

    /// The window as a phrase that fits mid-sentence, for spoken chart summaries.
    /// `annotation` is capitalized and meant to stand alone.
    var spokenSpan: String {
        switch self {
        case .day: "in the last 24 hours"
        case .week: "in the last 7 days"
        case .month: "in the last 30 days"
        case .all: "across all recorded history"
        }
    }

    /// Bar size: hourly for 24h, daily for everything else. Retention caps out at a
    /// year, so All is at most 365 daily bars.
    var bucketSeconds: Int {
        self == .day ? 3600 : 86_400
    }

    var calendarUnit: Calendar.Component {
        self == .day ? .hour : .day
    }
}

/// A value compared with the same value one period earlier.
///
/// Deliberately uncolored: in this app red means blocked and green means allowed,
/// and more traffic is not a verdict. No arrows either, since `arrow.up`/`arrow.down`
/// already mean sent and received. The sign carries the direction.
struct InsightsDelta: Equatable {
    let current: Int
    let previous: Int

    /// Below this baseline a percentage is noise (2 -> 8 is "+300%"), so the raw change
    /// is shown instead.
    static let minimumBaseline = 10

    /// At or above this ratio a rise is shown as a multiplier ("12×") instead of a
    /// percentage. Falls bottom out at -100% and never reach it.
    static let multiplierRatio = 10.0

    /// Which form the delta takes, decided once so the printed and spoken versions
    /// always agree. In order:
    ///
    /// - Previous window empty: "New" (a row missing from the previous window is the same case).
    /// - Both windows empty: nil.
    /// - Ratio at least `multiplierRatio`: "12×". Only rises get here.
    /// - Baseline below `minimumBaseline`: raw change, "+3".
    /// - Otherwise: "+240%" / "−18%".
    private enum Reading {
        case new
        case unchanged
        case multiple(Int)
        case count(Int)
        case percent(Int)
    }

    private var reading: Reading? {
        if previous == 0 { return current > 0 ? .new : nil }
        let change = current - previous
        if change == 0 { return .unchanged }
        let ratio = Double(current) / Double(previous)
        if ratio >= Self.multiplierRatio { return .multiple(Int(ratio.rounded())) }
        if previous < Self.minimumBaseline { return .count(change) }
        return .percent(Int((Double(change) / Double(previous) * 100).rounded()))
    }

    /// The badge text next to the figure. nil when there's nothing to show.
    var short: String? {
        switch reading {
        case nil: nil
        case .new: "New"
        case .unchanged: "No change"
        case .multiple(let times): "\(times)×"
        case .count(let change): signed(change)
        case .percent(let change): signed(change) + "%"
        }
    }

    /// The reading with the baseline spelled out, for section headers.
    func headline(vs prior: String) -> String? {
        guard let short else { return nil }
        return "\(short) vs \(prior)"
    }

    /// The reading as a sentence for VoiceOver. The on-screen text omits the baseline
    /// and "×" would be read as a symbol name.
    func spoken(vs prior: String) -> String? {
        switch reading {
        case nil: nil
        // No "versus" here: a new target has nothing to compare against.
        case .new: "new in this period"
        case .unchanged: "no change versus \(prior)"
        case .multiple(let times): "\(times) times \(prior)"
        case .count(let change): "\(spokenSign(change)) versus \(prior)"
        case .percent(let change): "\(spokenSign(change)) percent versus \(prior)"
        }
    }

    /// Uses a real minus sign so "+12" and "−12" are the same width with monospaced digits.
    private func signed(_ value: Int) -> String {
        value < 0 ? "−\(abs(value))" : "+\(value)"
    }

    /// Spoken sign, since some voices skip "−" and others read "dash".
    private func spokenSign(_ value: Int) -> String {
        value < 0 ? "minus \(abs(value))" : "plus \(value)"
    }
}

/// The delta as secondary, uncolored text. Used by section headers.
///
/// Rows use `inline` instead and append it to the figure's `Text`, so the pair
/// wraps as one line rather than competing for width as two views.
struct InsightsDeltaBadge: View {
    let text: String
    /// Spoken form. When nil VoiceOver reads the printed text, which is wrong for
    /// headers ("vs" is spelled out, "×" becomes a symbol name).
    var spoken: String?

    var body: some View {
        Self.inline(text)
            .lineLimit(1)
            .accessibilityLabel(spoken ?? text)
    }

    /// The badge as a `Text` to concatenate onto a row. Uses weight, not color, so it
    /// inherits the row's secondary style. Monospaced digits keep columns from jittering
    /// on refresh.
    static func inline(_ text: String) -> Text {
        Text(text).fontWeight(.semibold).monospacedDigit()
    }
}

/// Copy shared by the two Insights surfaces.
enum InsightsCopy {
    /// Same wording as the export-failure alert in Settings.
    static let storeUnreadable = "The history database could not be read."

    /// Also printed on the shared summary image, so it lives here instead of inline.
    static let threatCaveat = "Threat counts before 25 August 2026 read high: until then, blocks made by an ad-filtering DNS resolver were recorded as threats."

    /// Shared by the New targets section and the target sheet.
    static let firstSeenInWindow = "First seen during this period — never contacted before in your retained history."

    /// Shared by the map's list footer and the country sheet.
    static let countryEstimate = "Aggregated from traffic history on this device. Countries are estimated from IP addresses (DB-IP) and can be wrong — especially for servers that answer from many places at once."

    /// Spoken summary of a window's totals, used by the Trends charts instead of
    /// letting Charts read every bar.
    static func spokenTotals(flows: Int, blocked: Int, window: InsightsWindow) -> String {
        let count = "\(flows) connection\(flows == 1 ? "" : "s") \(window.spokenSpan)"
        guard flows > 0 else { return count }
        let share = Int((Double(blocked) / Double(flows) * 100).rounded())
        return "\(count), \(blocked) blocked, \(share) percent of the total"
    }
}

/// Insights tab: hosts Trends (history charts) and Map as sibling surfaces.
struct InsightsView: View {
    @Environment(AppModel.self) private var model

    private enum Mode: String, CaseIterable, Identifiable {
        case trends = "Trends"
        case map = "Map"
        var id: String { rawValue }
    }

    /// Scene-persisted so returning to the tab keeps the same surface.
    @SceneStorage("insights.mode") private var mode: Mode = .trends
    /// Scene-persisted and shared by both surfaces. Unknown raw values fall back to
    /// the default.
    @SceneStorage("insights.window") private var window: InsightsWindow = .day

    /// Current Trends data for the share button. nil when there's nothing to share
    /// (not loaded yet, store unreadable, or empty window), which disables the button.
    /// Trends keeps updating this while Map is showing, since both stay mounted.
    @State private var summary: InsightsSummary?
    /// Non-nil while the share sheet is up. The sheet renders cards on demand and
    /// drops them on dismiss, since each 3× card is several MB.
    @State private var shareRequest: ShareRequest?

    var body: some View {
        NavigationStack {
            // Keep both surfaces mounted and only toggle which one is visible. Swapping view
            // types lets SwiftUI destroy the hidden one's @State, which reset the map camera
            // and `positionedByUser` every time you switched back.
            ZStack {
                // All three are needed: `opacity` only hides pixels, the hidden layer would still
                // take hits and be visible to VoiceOver.
                HistoryView(window: $window, summary: $summary)
                    .opacity(mode == .trends ? 1 : 0)
                    .allowsHitTesting(mode == .trends)
                    .accessibilityHidden(mode != .trends)
                // Only the map needs to know it's hidden, so it can skip the location prompt and
                // GeoIP work. See `isActive`.
                WorldMapView(window: $window, isActive: mode == .map)
                    .opacity(mode == .map ? 1 : 0)
                    .allowsHitTesting(mode == .map)
                    .accessibilityHidden(mode != .map)
            }
            // Covers WorldMapView, which doesn't apply it itself. HistoryView applies it too;
            // applying it twice is harmless.
            .brandDarkBackground()
            // Hidden by the principal item, but still used for the back button title and by
            // VoiceOver.
            .navigationTitle("Insights")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                // The mode switch goes in the principal slot since it changes the whole page.
                ToolbarItem(placement: .principal) {
                    Picker("Insights", selection: $mode) {
                        ForEach(Mode.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                    .frame(maxWidth: 200)
                }
                // `.menu` style rather than a custom `Menu`, so VoiceOver announces the "Period"
                // label instead of just "7d, pop up button".
                ToolbarItem(placement: .topBarTrailing) {
                    Picker("Period", selection: $window) {
                        ForEach(InsightsWindow.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.menu)
                    // Otherwise the menu picker expands to fill the bar and pushes the mode switch off
                    // center.
                    .fixedSize()
                }
                // A button that opens a sheet which renders on demand. A `ShareLink` would need the
                // image up front, and this toolbar rebuilds on every window change and 15 s reload.
                // The sheet also shows exactly what will be shared before anything leaves the
                // device, which matters because one card can include the user's hostnames.
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        guard let summary else { return }
                        shareRequest = ShareRequest(summary: summary)
                    } label: {
                        Image(systemName: "square.and.arrow.up")
                    }
                    // Icon-only button.
                    .accessibilityLabel("Share summary")
                    // Disabled rather than hidden so the toolbar doesn't shift as data loads.
                    .disabled(summary == nil)
                }
            }
            .sheet(item: $shareRequest) { SummaryShareSheet(summary: $0.summary) }
            // A cold launch from a notification can set the destination before this view
            // exists, so check on appear as well as on change. See `AppModel.PendingDestination`.
            .onAppear(perform: consumePendingDestination)
            .onChange(of: model.pendingDestination) { _, _ in consumePendingDestination() }
        }
    }

    /// Final step of the weekly-summary deep link: RootView selects the tab, this sets
    /// the window and clears the pending destination. It's cleared here rather than in
    /// RootView so a not-yet-built Insights tab still sees it.
    private func consumePendingDestination() {
        guard model.pendingDestination == .insightsWeeklySummary else { return }
        window = .week
        // The notification is about the week's traffic, which is on Trends.
        mode = .trends
        model.pendingDestination = nil
        insightsLog.notice("✅ app:insights deepLink VERIFY destination=weeklySummary window=\(window.rawValue, privacy: .public)")
    }
}

// MARK: - Share summary

/// A snapshot of what the shared image shows, copied from Trends at its last reload.
///
/// A value rather than a live reference so a render can't mix data from two reloads.
struct InsightsSummary: Equatable {
    /// One bar, pre-split into the three stacked bands so the card and the page agree
    /// on what "blocked" excludes.
    struct Bar: Equatable, Identifiable {
        let start: Date
        let allowed: Int
        /// Blocked by a rule (`blockedFlows − threatFlows`). Red on the card.
        let blocked: Int
        /// Blocked by a threat list. Violet on the card.
        let threat: Int
        var id: Date { start }
        var flows: Int { allowed + blocked + threat }
    }

    struct Row: Equatable, Identifiable {
        let target: String
        let flows: Int
        let bytes: UInt64
        /// All blocks, including threats.
        let blocked: Int
        /// The part of `blocked` attributed to a threat list.
        let threat: Int
        var id: String { target }
    }

    let window: InsightsWindow
    let bars: [Bar]
    /// Pinned like the on-screen chart's x axis. See `HistoryView.zeroFilled`.
    let xDomain: ClosedRange<Date>
    /// Top five by connections. Five because the image is often viewed as a thumbnail.
    let rows: [Row]
    /// Top five by blocks, from the page's Top blocked section (no extra query).
    let blockedRows: [Row]
    let totalFlows: Int
    /// All blocks in the window, including threats (sum of `blockedFlows`).
    let totalBlocked: Int
    let totalBytesUp: UInt64
    let totalBytesDown: UInt64
    /// Lower edge the rows were rolled up from, so the share sheet's own query uses the
    /// same period. nil on All.
    let since: Date?
    /// The clock read `reload()` used as the upper edge of its queries. The share
    /// sheet's Countries rollup queries `since...until` with this so its totals match
    /// the rest of the card.
    let until: Date
    /// Whether the window includes rows recorded under the old threat attribution.
    let showsThreatCaveat: Bool

    // Derived from one set of bars so the cards, legend and footnote agree.
    // `ruleBlockedTotal + threatTotal == totalBlocked` by construction.

    var allowedTotal: Int { bars.reduce(0) { $0 + $1.allowed } }
    var ruleBlockedTotal: Int { bars.reduce(0) { $0 + $1.blocked } }
    var threatTotal: Int { bars.reduce(0) { $0 + $1.threat } }

    /// Tallest bar; the chart's y scale and gridlines are based on it.
    var peakFlows: Int { bars.map(\.flows).max() ?? 0 }

    /// Bucket with the most blocks, annotated on the By day card. nil when nothing
    /// was blocked.
    var peakBlockedIndex: Int? {
        ShareCardMath.peakIndex(blockedPerBucket: bars.map { $0.blocked + $0.threat })
    }

    /// "183 a day" (or an hour): window total divided by bar count.
    var perBucketAverage: Int {
        ShareCardMath.perBucketAverage(total: totalFlows, buckets: bars.count)
    }

    /// The five busiest buckets, busiest first, ties by date. Empty buckets are skipped.
    var busiestBars: [Bar] {
        bars.enumerated()
            .filter { $0.element.flows > 0 }
            .sorted { a, b in
                a.element.flows != b.element.flows ? a.element.flows > b.element.flows : a.offset < b.offset
            }
            .prefix(5)
            .map(\.element)
    }
}

/// The summary as it was when the share button was tapped. New id per tap so each
/// tap presents a new sheet.
struct ShareRequest: Identifiable {
    let id = UUID()
    let summary: InsightsSummary
}

/// PNG data and a filename, which is all that needs to be `Sendable` for `Transferable`.
struct InsightsShareImage: Transferable {
    let data: Data
    let fileName: String

    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .png) { $0.data }
            .suggestedFileName { $0.fileName }
    }
}

/// A rendered card waiting to be shared.
struct RenderedSummary: Identifiable {
    let id = UUID()
    /// Preview in the sheet. Kept separate from `share` (see `InsightsShareImage`).
    let preview: UIImage
    let share: InsightsShareImage
    /// Title shown in the share sheet header.
    let title: String
}

/// Renders an `InsightsSummary` to an image.
@MainActor
enum InsightsSummaryRenderer {
    /// 3× so caption-size text stays legible after messaging apps resize and recompress it.
    static let scale: CGFloat = 3

    /// Card size in points: 360 wide (1080 px), normally 450 tall (4:5).
    ///
    /// Height is left nil so `ImageRenderer` asks the view for its ideal height at this
    /// width, using the same text layout that draws it. Estimating wrap lines separately
    /// under-counted hyphenated hostnames, and `ImageRenderer` clipped the footer instead
    /// of growing. The card has `minHeight: Card.height` and no max, so it only grows
    /// when a `HostRow` name wraps.
    static func proposedSize(_ summary: InsightsSummary, style: ShareStyle, options: ShareOptions) -> ProposedViewSize {
        ProposedViewSize(width: 360, height: nil)
    }

    /// Returns nil if the renderer produced nothing, leaving the preview empty instead
    /// of showing a blank card.
    static func render(
        _ summary: InsightsSummary, style: ShareStyle, options: ShareOptions,
        distinctTargets: Int?, countries: CountriesSummary? = nil, generated: Date = Date()
    ) -> RenderedSummary? {
        // Don't render the Countries card until its rollup is available.
        if style == .countries, countries == nil {
            insightsLog.error("❌ app:insightsShare render FAILED style=countries reason=noCountries window=\(summary.window.rawValue, privacy: .public)")
            return nil
        }
        // `generated` isn't drawn on the card, but it's used for the file name.
        let renderer = ImageRenderer(
            content: InsightsShareCard(
                summary: summary, style: style, options: options,
                distinctTargets: distinctTargets, countries: countries
            )
        )
        renderer.scale = scale
        renderer.proposedSize = proposedSize(summary, style: style, options: options)
        let hosts = style == .byDay && options.includesHostnames
        guard let image = renderer.uiImage, let data = image.pngData() else {
            insightsLog.error("❌ app:insightsShare render FAILED style=\(style.rawValue, privacy: .public) window=\(summary.window.rawValue, privacy: .public)")
            return nil
        }
        // Counts only. One card can show the user's hostnames, and domains must never be
        // logged at any privacy level. For Countries, log only the placed and unplaced
        // counts and the origin toggle, never a country code or coordinate.
        let px = "\(Int(image.size.width * image.scale))x\(Int(image.size.height * image.scale))"
        insightsLog.notice("✅ app:insightsShare render VERIFY style=\(style.rawValue, privacy: .public) hosts=\(hosts, privacy: .public) origin=\(options.originCountry != nil, privacy: .public) window=\(summary.window.rawValue, privacy: .public) bars=\(summary.bars.count, privacy: .public) rows=\(summary.rows.count, privacy: .public) blockedRows=\(summary.blockedRows.count, privacy: .public) countries=\(countries?.distinctCountries ?? 0, privacy: .public) unplaced=\(countries?.unplacedFlows ?? 0, privacy: .public) caveat=\(summary.showsThreatCaveat, privacy: .public) px=\(px, privacy: .public) bytes=\(data.count, privacy: .public)")
        let stamp = generated.formatted(.iso8601.year().month().day())
        return RenderedSummary(
            preview: image,
            share: InsightsShareImage(
                data: data,
                fileName: "FluxMoat-\(style.fileSlug)\(hosts ? "-hosts" : "")-\(summary.window.rawValue.lowercased())-\(stamp).png"
            ),
            title: "FluxMoat · \(summary.window.annotation)"
        )
    }
}

/// Shows the exact image that will be shared, then the share button.
///
/// The three cards are pages in a pager. Each is rendered when first shown and
/// cached for the life of the sheet, and its neighbours are prerendered so swipes
/// don't land on a placeholder. The Countries rollup isn't fetched until that page
/// is shown.
private struct SummaryShareSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme
    @Environment(AppModel.self) private var model
    let summary: InsightsSummary

    /// Remembered across sheets. Defaults to Countries; older stored values still parse.
    @SceneStorage("insights.share.style") private var style: ShareStyle = .countries
    /// Reset every time the sheet opens. Including hostnames should be a deliberate
    /// choice each time.
    @State private var includesHostnames = false
    /// Reset every time, same reason. Only shown when the Map tab already has a fix
    /// (see `hasOriginFix`).
    @State private var showsOrigin = false
    @State private var cache: [CacheKey: RenderedSummary] = [:]
    /// Fetched once per sheet; nil until then or if the query fails, in which case the
    /// "of N" footnote is omitted.
    @State private var distinctTargets: Int?
    /// Countries rollup: fetched the first time that page is shown, then kept.
    @State private var countries: CountriesSummary?
    /// One timestamp for the whole sheet so all cards match.
    @State private var generated = Date()

    private struct CacheKey: Hashable {
        let style: ShareStyle
        let options: ShareOptions
    }

    /// Each toggle only applies to its own card. Evaluated per page because neighbours
    /// are prerendered too and mustn't pick up another card's toggle.
    private func options(for page: ShareStyle) -> ShareOptions {
        ShareOptions(
            includesHostnames: page == .byDay && includesHostnames,
            originCountry: page == .countries && showsOrigin ? originCountry : nil
        )
    }

    /// Whether the Map tab already has a fix inside some country. This sheet never
    /// requests location; with no fix there is no toggle. A fix far from any centroid
    /// (open ocean) resolves to no country, so the toggle is hidden then too.
    private var hasOriginFix: Bool { originCountry != nil }

    /// The fix reduced to a country code, the only form the card uses. nil when there
    /// is no fix or it's not near any centroid.
    private var originCountry: String? {
        guard let fix = MapOriginLocator.latestFix else { return nil }
        return CountriesCardMath.nearestCountry(
            latitude: fix.latitude, longitude: fix.longitude, among: CountryCentroids.all
        )
    }

    private var options: ShareOptions { options(for: style) }
    private func key(for page: ShareStyle) -> CacheKey {
        CacheKey(style: page, options: options(for: page))
    }
    private var key: CacheKey { key(for: style) }
    private var rendered: RenderedSummary? { cache[key] }
    private var title: String { "FluxMoat · \(summary.window.annotation)" }

    /// The card's aspect ratio (360 × 450, see `InsightsSummaryRenderer.proposedSize`).
    /// The placeholder uses it too so pages don't resize when the render arrives.
    private static let cardAspect: CGFloat = 360.0 / 450.0

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                pager
                SharePageDots(current: style)
                // Describes what the card in view includes, e.g. whether hostnames are on it.
                Text(style.disclosure(options: options, distinctCountries: countries?.distinctCountries))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                if style == .byDay {
                    Toggle("Include hostnames", isOn: $includesHostnames)
                        .font(.subheadline)
                }
                if style == .countries, hasOriginFix {
                    Toggle(isOn: $showsOrigin) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Show my country")
                                .font(.subheadline)
                            Text("Country level only, from the Map tab’s fix. Nearest match, can be off.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                if let rendered {
                    ShareLink(
                        item: rendered.share,
                        preview: SharePreview(rendered.title, image: Image(uiImage: rendered.preview))
                    ) {
                        Label("Share image", systemImage: "square.and.arrow.up")
                    }
                    .buttonStyle(.borderedProminent)
                    .brandProminentLabel(colorScheme == .dark)
                } else {
                    Button {} label: { Label("Share image", systemImage: "square.and.arrow.up") }
                        .buttonStyle(.borderedProminent)
                        .disabled(true)
                }
            }
            .padding()
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .onAppear(perform: renderIfNeeded)
            .onChange(of: key) { _, _ in renderIfNeeded() }
            .task(id: style) {
                // Fetch the Countries rollup (per-IP rollup plus app-side GeoIP) the first time
                // that page is shown, and keep it. `renderPage` skips Countries until it's loaded,
                // so prefetching never triggers the query. A failure here only affects this card,
                // so `disablesHistory` is left alone.
                guard style == .countries, countries == nil else { return }
                let rows = await model.insightsCountries(
                    since: summary.since, until: summary.until, disablesHistory: false)
                guard !Task.isCancelled else { return }
                countries = CountriesSummary(rows)
                // Countries may be the page in view or a neighbour by now. This is also the first
                // chance to prefetch if the sheet opened on Countries.
                renderPage(.countries)
                prefetchNeighbours()
            }
            .task(id: includesHostnames) {
                // COUNT(DISTINCT) over the window, only run when the hostnames toggle is on.
                // Fast enough to await directly: 0.01-0.18 s on an 841k-row store.
                guard includesHostnames, distinctTargets == nil else { return }
                distinctTargets = await model.insightsDistinctTargets(
                    since: summary.since, until: summary.until)
                // The toggle may have been turned off while this awaited. If it's still on,
                // rerender the By day card directly (it might be a neighbour now) rather than via
                // `renderIfNeeded`, which would log a cache hit for whatever page is in view.
                guard !Task.isCancelled, includesHostnames else { return }
                cache.removeValue(forKey: CacheKey(style: .byDay, options: ShareOptions(includesHostnames: true)))
                renderPage(.byDay)
            }
        }
    }

    /// The three cards in a `.page` TabView with its index hidden (see `SharePageDots`).
    ///
    /// Takes all remaining vertical space. On most phones that's more than the card
    /// needs, so only the slack changes when a toggle appears or disappears.
    private var pager: some View {
        TabView(selection: $style) {
            ForEach(ShareStyle.allCases) { page in
                card(page).tag(page)
            }
        }
        .tabViewStyle(.page(indexDisplayMode: .never))
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(style.segmentTitle) card, page \(pageNumber) of \(ShareStyle.allCases.count)")
    }

    private var pageNumber: Int {
        (ShareStyle.allCases.firstIndex(of: style) ?? 0) + 1
    }

    /// One page: the rendered card, or a same-size navy placeholder while it renders.
    private func card(_ page: ShareStyle) -> some View {
        Group {
            if let preview = cache[key(for: page)]?.preview {
                Image(uiImage: preview)
                    .resizable()
                    .scaledToFit()
                    // VoiceOver can't read into the image; the page behind the sheet has the same
                    // numbers as text.
                    .accessibilityLabel("Preview of the \(page.segmentTitle) card")
            } else {
                Rectangle()
                    .fill(BrandPalette.darkSurface)
                    .aspectRatio(Self.cardAspect, contentMode: .fit)
                    // Label on the spinner, since a Shape isn't an accessibility element.
                    .overlay {
                        ProgressView()
                            .tint(.white)
                            .accessibilityLabel("Rendering the \(page.segmentTitle) card")
                    }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// Renders the visible card if needed, then prefetches its neighbours. Cache hits
    /// on the visible page are logged, so an unexpected rerender shows up.
    private func renderIfNeeded() {
        if cache[key] != nil {
            insightsLog.notice("✅ app:insightsShare cache HIT style=\(style.rawValue, privacy: .public) hosts=\(options.includesHostnames, privacy: .public) origin=\(options.originCountry != nil, privacy: .public)")
        } else {
            renderPage(style)
        }
        prefetchNeighbours()
    }

    /// Renders one page into the cache if it isn't there yet. Countries waits for its
    /// rollup, so prefetch never triggers that query.
    private func renderPage(_ page: ShareStyle) {
        let pageKey = key(for: page)
        guard cache[pageKey] == nil else { return }
        if page == .countries, countries == nil { return }
        cache[pageKey] = InsightsSummaryRenderer.render(
            summary, style: page, options: pageKey.options,
            distinctTargets: distinctTargets, countries: countries, generated: generated
        )
    }

    /// Prerenders the adjacent pages. Hops through the main actor first so the visible
    /// card is painted before the extra `ImageRenderer` passes.
    private func prefetchNeighbours() {
        guard cache[key] != nil else { return }
        let current = style
        Task { @MainActor in
            // Page changed meanwhile; that page's render will prefetch its own neighbours.
            guard style == current else { return }
            for page in current.neighbours { renderPage(page) }
        }
    }
}

private extension ShareStyle {
    /// Adjacent pages in `allCases` order.
    var neighbours: [ShareStyle] {
        let all = ShareStyle.allCases
        guard let here = all.firstIndex(of: self) else { return [] }
        return [here - 1, here + 1].filter { all.indices.contains($0) }.map { all[$0] }
    }
}

/// Custom page dots. `UIPageControl`'s white dots disappear on the light sheet, so
/// these use the brand blue: full for the current page, 25% for the others.
private struct SharePageDots: View {
    @Environment(\.colorScheme) private var colorScheme
    let current: ShareStyle

    var body: some View {
        let blue = colorScheme == .dark ? BrandPalette.blueLight : BrandPalette.blueDeep
        HStack(spacing: 8) {
            ForEach(ShareStyle.allCases) { page in
                Circle()
                    .fill(blue.opacity(page == current ? 1 : 0.25))
                    .frame(width: 7, height: 7)
            }
        }
        // The pager already announces the page to VoiceOver.
        .accessibilityHidden(true)
    }
}
