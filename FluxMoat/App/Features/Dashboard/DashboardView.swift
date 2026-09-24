import Charts
import Combine
import SharedCore
import SwiftUI
import os

/// Row counts and flags only, never a destination.
private let dashboardLog = Logger(subsystem: "fluxmoat", category: "dashboard")

struct DashboardView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Read here rather than inside the sheet: a sheet's own content reports
    /// compact on iPad. See `adaptiveSheetDetents`.
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    /// One-minute buckets for the last hour, loaded on appear and on each tick.
    /// Uses the same SQL rollup as History, never raw rows.
    @State private var traffic: [TrafficEventStore.TimeBucketAggregate] = []
    /// Pinned when the window loads so the chart's x domain and the bars share
    /// one instant. Computing `now` at render time made the last bar drift off
    /// the right edge between ticks.
    @State private var windowStart = DashboardView.alignedWindowStart()
    /// The tapped minute, snapped to the bucket grid. nil shows the whole hour.
    @State private var selectedSlot: Date?
    /// Expanded "Recent targets" countries and level-2 groups, tracked separately
    /// so opening one country doesn't collapse another. Group ids are prefixed
    /// with their country id, so the same domain under two countries expands
    /// independently.
    @State private var expandedCountries: Set<String> = []
    @State private var expandedGroups: Set<String> = []
    /// The leaf whose half sheet is showing, if any.
    @State private var selectedLeaf: TargetLeaf?
    /// Country row order: busiest first, with hysteresis so rows don't swap under
    /// the user's finger (these rows swipe to create a country policy, so a
    /// mis-tap can block the wrong country).
    ///
    /// Countries are ranked by `MiniTrafficMeter.level` of their windowed bytes
    /// (0...6, each level 4× the previous). The order is only re-decided when a
    /// country changes level; within a level the previous order is kept. Idle
    /// countries sink together and keep their relative order.
    ///
    /// Recomputed at most once a second, never while the tree is frozen. See
    /// `syncCountryOrder`.
    @State private var countryOrder: [String] = []
    /// Snapshot used while any level is expanded. `recentFlows` changes every
    /// second under traffic, and new flows can reorder countries and the groups
    /// inside them, so taps land on rows that have moved. Freezing the input
    /// also freezes ranking: level 1 because the tick skips re-ranking while this
    /// is set, levels 2 and 3 because they sort off frozen flows and a frozen clock
    /// (see `RecentTargets.groupOrder`). Cleared when the last level collapses.
    @State private var frozenRecent: [TrafficEvent]?
    /// End of each row's meter window. A 1 Hz clock moves the window forward so
    /// meters decay to zero when traffic stops; otherwise nothing would redraw
    /// and the last level would stay lit. `refreshTick` (15 s) is too slow for a
    /// 10 s window.
    @State private var meterClock = Date()
    /// Captured together with `frozenRecent`. Frozen flows alone aren't enough:
    /// against a moving window they would still drain to zero while the tree is
    /// open. Live Traffic's `frozenClock` does the same.
    @State private var frozenMeterClock = Date()

    private static let windowSeconds: TimeInterval = 3600
    /// One bar per minute, so a burst that just happened is visible.
    private static let bucketSeconds = 60

    /// Floors to a whole minute to match the SQL rollup's buckets
    /// (`TrafficEventStore.bucketAggregates`). Otherwise the first bucket starts
    /// before the x domain and Charts clips it to half a bar.
    private static func alignedWindowStart(now: Date = Date()) -> Date {
        let start = now.timeIntervalSince1970 - windowSeconds
        return Date(timeIntervalSince1970: (start / Double(bucketSeconds)).rounded(.down) * Double(bucketSeconds))
    }

    /// Keeps the dashboard current while left open. One rollup query every 15 s
    /// is cheap.
    private let refreshTick = Timer.publish(every: 15, on: .main, in: .common).autoconnect()

    /// Only dark mode uses the brand styling for now; light mode keeps the stock
    /// grouped look.
    private var isDark: Bool { colorScheme == .dark }

    /// Pure white is harsh on the dark gradient and the system secondary grey
    /// looks muddy on it, so both levels are set on the list and every
    /// `.secondary` inside inherits them. Light mode returns the stock pair.
    private var primaryText: AnyShapeStyle {
        isDark ? AnyShapeStyle(BrandPalette.textPrimary) : AnyShapeStyle(ForegroundStyle())
    }

    private var secondaryText: AnyShapeStyle {
        isDark ? AnyShapeStyle(BrandPalette.textSecondary) : AnyShapeStyle(HierarchicalShapeStyle.secondary)
    }

    private var totalUp: UInt64 { traffic.reduce(0) { $0 + $1.bytesUp } }
    private var totalDown: UInt64 { traffic.reduce(0) { $0 + $1.bytesDown } }

    /// Every minute in the window, including empty ones. Built from `windowStart`
    /// because the SQL rollup omits empty buckets.
    ///
    /// Inclusive on both ends, so 61 columns: the last is the current minute,
    /// on the x domain's upper bound.
    private var minuteSlots: [Date] {
        (0...(Int(Self.windowSeconds) / Self.bucketSeconds)).map {
            windowStart.addingTimeInterval(Double($0 * Self.bucketSeconds))
        }
    }

    /// The bucket for the selected column, if it had traffic. Compares with one
    /// second of tolerance since both dates went through SQLite as floating point.
    private var selectedBucket: TrafficEventStore.TimeBucketAggregate? {
        guard let selectedSlot else { return nil }
        return traffic.first { abs($0.bucketStart.timeIntervalSince(selectedSlot)) < 1 }
    }

    /// Pills show the hour by default and the selected minute otherwise. An empty
    /// selected minute shows 0 KB rather than falling back to the hour.
    private var shownUp: UInt64 { selectedSlot == nil ? totalUp : (selectedBucket?.bytesUp ?? 0) }
    private var shownDown: UInt64 { selectedSlot == nil ? totalDown : (selectedBucket?.bytesDown ?? 0) }

    /// States the window length (not inferable from a chart without y labels).
    /// While a column is selected, names that minute in the x axis's time format.
    @ViewBuilder private var windowCaption: some View {
        if let selectedSlot {
            Text(selectedSlot, format: .dateTime.hour(.defaultDigits(amPM: .omitted)).minute())
        } else {
            Text("Last hour")
        }
    }

    /// The last hour of traffic: totals on top, a mirrored chart below with sent
    /// above the axis and received below.
    private var heroCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            TrafficTotalPills(sent: shownUp, received: shownDown)
            // Tighter spacing so the caption reads as the chart's label.
            VStack(alignment: .leading, spacing: 4) {
                windowCaption
                    .font(.caption)
                    .foregroundStyle(.secondary)
                // Drawn even when empty so an idle hour shows as empty tracks, not a gap.
                trafficChart
            }
        }
        .padding(.vertical, 4)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Each half is normalized to its own peak (sent 0...1, received 0...-1), so
    /// they don't share a scale. Downstream is typically an order of magnitude
    /// larger, and on a shared scale the sent side would vanish. The chart shows
    /// shape over time; the pills carry the byte totals. Returns 0 for a zero peak.
    private func normalized(_ bytes: UInt64, peak: UInt64) -> Double {
        peak > 0 ? Double(bytes) / Double(peak) : 0
    }

    /// Track for empty minutes. Kept faint so it doesn't read as data. Values
    /// tuned by eye: dark sits on `cardFill` over the gradient, light on white.
    private var trackFill: Color {
        isDark ? Color.white.opacity(0.10) : Color.black.opacity(0.07)
    }

    /// Band behind the selected column: visible but wider and fainter than a bar.
    private var selectionFill: Color {
        isDark ? Color.white.opacity(0.24) : Color.black.opacity(0.17)
    }

    private var trafficChart: some View {
        let peakUp = traffic.reduce(UInt64(0)) { max($0, $1.bytesUp) }
        let peakDown = traffic.reduce(UInt64(0)) { max($0, $1.bytesDown) }
        return Chart {
            // Tracks first so every other mark draws on top.
            ForEach(minuteSlots, id: \.self) { slot in
                BarMark(
                    x: .value("Time", slot),
                    yStart: .value("Track", -1.0),
                    yEnd: .value("Track", 1.0),
                    width: .fixed(4)
                )
                .foregroundStyle(trackFill)
                .cornerRadius(2)
            }
            if let selectedSlot {
                BarMark(
                    x: .value("Time", selectedSlot),
                    yStart: .value("Track", -1.0),
                    yEnd: .value("Track", 1.0),
                    width: .fixed(9)
                )
                .foregroundStyle(selectionFill)
                .cornerRadius(3)
            }
            // About 60 bars across the card, roughly 5 pt each; 4 pt leaves a gap.
            ForEach(traffic, id: \.bucketStart) { bucket in
                BarMark(
                    x: .value("Time", bucket.bucketStart),
                    y: .value("Sent", normalized(bucket.bytesUp, peak: peakUp)),
                    width: .fixed(4)
                )
                // Fill colors, not the text colors used by the pills. Same pair in both
                // color schemes. See `TrafficPalette`.
                .foregroundStyle(TrafficPalette.sentFill)
                .cornerRadius(2)
                BarMark(
                    x: .value("Time", bucket.bucketStart),
                    y: .value("Received", -normalized(bucket.bytesDown, peak: peakDown)),
                    width: .fixed(4)
                )
                .foregroundStyle(TrafficPalette.receivedFill)
                .cornerRadius(2)
            }
        }
        // No labels, just the zero rule that makes the halves read as a mirror.
        .chartYAxis {
            AxisMarks(values: [0.0]) {
                AxisGridLine().foregroundStyle(.secondary.opacity(0.4))
            }
        }
        // Fixed because both halves are pre-normalized.
        .chartYScale(domain: -1.0...1.0)
        // Pinned to the full window so a few buckets don't stretch across the width.
        .chartXScale(domain: windowStart...windowStart.addingTimeInterval(Self.windowSeconds))
        .chartXAxis {
            AxisMarks(values: .stride(by: .minute, count: 15)) {
                // No AM/PM: it doubles the label width and a one-hour window doesn't need it.
                AxisValueLabel(format: .dateTime.hour(.defaultDigits(amPM: .omitted)).minute())
            }
        }
        .frame(height: 120)
        // Custom tap handling rather than `.chartXSelection`, which is built for
        // scrubbing. Mapping the tap ourselves allows two ways to deselect: tap the
        // selected column again or tap outside the plot.
        .chartOverlay { proxy in
            GeometryReader { geo in
                Rectangle()
                    .fill(.clear)
                    .contentShape(Rectangle())
                    .gesture(
                        SpatialTapGesture().onEnded { tap in
                            handleChartTap(at: tap.location, proxy: proxy, geo: geo)
                        }
                    )
            }
        }
        .accessibilityHidden(true)
    }

    /// Nearest minute on the grid, clamped to the window. Charts returns a
    /// continuous date between columns.
    private func snapToSlot(_ date: Date) -> Date {
        let slotCount = Int(Self.windowSeconds) / Self.bucketSeconds
        let raw = date.timeIntervalSince(windowStart) / Double(Self.bucketSeconds)
        let index = min(max(Int(raw.rounded()), 0), slotCount)
        return windowStart.addingTimeInterval(Double(index * Self.bucketSeconds))
    }

    private func handleChartTap(at location: CGPoint, proxy: ChartProxy, geo: GeometryProxy) {
        // Taps on the axis labels or padding outside the plot clear the selection.
        guard let plotFrame = proxy.plotFrame else { return }
        let plot = geo[plotFrame]
        guard plot.contains(location),
              let date = proxy.value(atX: location.x - plot.minX, as: Date.self) else {
            clearSelection()
            return
        }
        let slot = snapToSlot(date)
        if let selectedSlot, abs(selectedSlot.timeIntervalSince(slot)) < 1 {
            // Tapping the selected column again returns to the hour.
            clearSelection()
        } else {
            selectedSlot = slot
        }
    }

    private func clearSelection() {
        guard selectedSlot != nil else { return }
        selectedSlot = nil
        // Ticks were skipped while a minute was selected, so catch up now.
        reloadTraffic()
    }

    /// Reloads regardless of protection state: the window's trailing edge keeps
    /// moving, and with one-minute buckets that's visible.
    private func reloadTraffic() {
        windowStart = Self.alignedWindowStart()
        traffic = model.historyBuckets(bucketSeconds: Self.bucketSeconds, since: windowStart)
    }

    /// The whole buffer (AppModel caps it at 200), since country rows summarize
    /// everything seen. The frozen copy wins while anything is expanded.
    private var sourceFlows: [TrafficEvent] {
        frozenRecent ?? model.recentFlows
    }

    /// The clock meters are measured against, frozen or live. Always read with
    /// `sourceFlows`.
    private var sourceClock: Date {
        frozenRecent == nil ? meterClock : frozenMeterClock
    }

    /// Rebuilt on every body pass; grouping 200 flows is cheap and caching it
    /// would add state that can go stale. Only the row order is persisted (see
    /// `countryOrder`), and `build` only reads it.
    private var countryGroups: [CountryGroup] {
        RecentTargets.build(from: sourceFlows, order: countryOrder, clock: sourceClock)
    }

    /// Countries present in the buffer. The membership resync watches this rather
    /// than counts, which change on every sample. Uses the same `groupingCode` as
    /// the tree, so unlocated flows are excluded from both.
    private var presentCountryCodes: Set<String> {
        Set(sourceFlows.compactMap(RecentTargets.groupingCode))
    }

    /// Re-derives the order. With `reset` the whole list is ranked from scratch;
    /// otherwise existing countries keep their place, new ones are appended (so
    /// they land at the end of their level), and countries no longer in the
    /// buffer are dropped.
    ///
    /// Uses `sourceClock` because ranking is by meter level: ranking against
    /// `Date()` would use a different window than the one on screen, especially
    /// while frozen.
    private func syncCountryOrder(reset: Bool) {
        let seated = RecentTargets.build(
            from: sourceFlows,
            order: reset ? [] : countryOrder,
            clock: sourceClock
        )
        applyCountryOrder(RecentTargets.reranked(seated).map(\.id))
    }

    /// Writes a new order with animation, only when it changed. This runs once a
    /// second, and an unconditional write would start an animation every tick.
    /// Uses a spring, unlike the easeOut in `mutateExpansion`, so reordering
    /// reads as one row overtaking another.
    private func applyCountryOrder(_ next: [String]) {
        guard next != countryOrder else { return }
        withAnimation(reduceMotion ? nil : .spring(response: 0.38, dampingFraction: 0.82)) {
            countryOrder = next
        }
    }

    private var isAnythingExpanded: Bool {
        !expandedCountries.isEmpty || !expandedGroups.isEmpty
    }

    /// Freezes the feed on the first expansion and releases it when the last level
    /// closes. Wraps every mutation so the section can't stay frozen with nothing open.
    private func mutateExpansion(_ change: () -> Void) {
        withAnimation(reduceMotion ? nil : .easeOut(duration: 0.2)) {
            if !isAnythingExpanded {
                frozenRecent = model.recentFlows
                frozenMeterClock = meterClock
            }
            change()
            if !isAnythingExpanded {
                frozenRecent = nil
                // Reset the window to now before unfreezing. The tick doesn't update
                // `meterClock` while frozen, so the meters would otherwise draw one frame
                // against a stale window.
                meterClock = Date()
            }
        }
        // Ranking was frozen too, so re-rank now. Outside the animation block since
        // it applies its own spring. Only runs once the freeze has actually lifted.
        if frozenRecent == nil { syncCountryOrder(reset: false) }
    }

    private func toggleCountry(_ id: String) {
        mutateExpansion {
            if expandedCountries.remove(id) != nil {
                // Remove this country's expanded groups too, or `isAnythingExpanded` would stay
                // true with nothing visibly open and the section would stay frozen.
                expandedGroups = expandedGroups.filter { !$0.hasPrefix(id + "/") }
            } else {
                expandedCountries.insert(id)
            }
        }
    }

    private func toggleGroup(_ id: String) {
        mutateExpansion {
            if expandedGroups.remove(id) == nil { expandedGroups.insert(id) }
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Toggle(isOn: .init(
                        get: { model.isProtectionOn },
                        set: { model.setProtection($0) }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Protection").font(.headline)
                            Text(model.isProtectionOn ? "Filtering device traffic" : "Off — traffic is not filtered")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let error = model.protectionError {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
                .brandCardRows(isDark)

                // An app or iOS encrypted-DNS client is bypassing filtering. Blocking
                // encrypted DNS is off by default and must only be turned on by the user,
                // because it changes the device's DNS behavior. So the banner routes to the
                // setting, where its trade-off is explained, rather than flipping it here.
                if model.showEncryptedDNSBypassBanner {
                    Section {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("Encrypted DNS is bypassing filtering", systemImage: "exclamationmark.shield.fill")
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(.orange)
                            Text("An app or system service is using its own encrypted DNS, so FluxMoat's domain rules and blocklists don't apply to it. Settings has a switch that blocks it, and explains what turning it on affects.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            HStack {
                                Button("Open DNS settings") {
                                    model.pendingDestination = .settingsEncryptedDNS
                                }
                                .buttonStyle(.borderedProminent)
                                .brandProminentLabel(isDark)
                                Button("Dismiss") { model.encryptedDNSBypassBannerDismissed = true }
                                    .buttonStyle(.bordered)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .brandCardRows(isDark)
                }

                // Enabled blocklists do nothing until downloaded; nudge first-run users.
                if model.showBlocklistDownloadNudge {
                    Section {
                        VStack(alignment: .leading, spacing: 8) {
                            Label("Blocklists aren't downloaded yet", systemImage: "arrow.down.circle.dotted")
                                .font(.subheadline.weight(.semibold))
                            Text("Your enabled blocklists are empty until they're downloaded, so ads and trackers aren't being blocked yet.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            HStack {
                                if model.updatingBlocklistIDs.isEmpty {
                                    Button("Download now") {
                                        Task { await model.updateAllBlocklistSources() }
                                    }
                                    .buttonStyle(.borderedProminent)
                                    .brandProminentLabel(isDark)
                                } else {
                                    ProgressView().padding(.horizontal, 12)
                                }
                                Button("Later") { model.blocklistNudgeDismissed = true }
                                    .buttonStyle(.bordered)
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .brandCardRows(isDark)
                }

                if !model.pendingAsks.isEmpty {
                    Section {
                        ForEach(model.pendingAsks) { ask in
                            PendingAskRow(ask: ask)
                        }
                    } header: {
                        Text("Pending decisions")
                    } footer: {
                        // Decisions are asynchronous: these flows were already handled by the
                        // profile default, and the UI must say so.
                        Text("These connections were already handled by the profile's default action. Your answer becomes a rule for future connections.")
                    }
                    .brandCardRows(isDark)
                }

                // Not a button: taps on the card belong to the chart's minute selection.
                Section {
                    heroCard
                }
                .brandCardRows(isDark)

                // Three levels flattened into list rows: country, then registrable domain or
                // IP addresses, then the concrete domain or IP.
                Section {
                    let countries = countryGroups
                    if countries.isEmpty {
                        Text("No traffic yet")
                            .foregroundStyle(.secondary)
                    } else {
                        // Hoisted out of the ForEach so the leaf tap can log the list size.
                        let rows = RecentTargets.rows(
                            countries,
                            expandedCountries: expandedCountries,
                            expandedGroups: expandedGroups
                        )
                        ForEach(rows) { row in
                            // The tap is on the label only, not the whole row, because the row also has a
                            // chevron button. Swipe actions are attached here since they decorate the list
                            // cell this ForEach produces, same as Live Traffic.
                            switch row {
                            case .country(let country, let expanded):
                                CountryTargetRow(country: country, isExpanded: expanded) {
                                    toggleCountry(country.id)
                                }
                                .targetRuleSwipe(country.ruleSubject)
                            case .group(let group, let expanded):
                                TargetGroupRow(group: group, isExpanded: expanded) {
                                    toggleGroup(group.id)
                                }
                                .targetRuleSwipe(group.ruleSubject)
                            case .leaf(let leaf):
                                TargetLeafRow(leaf: leaf) {
                                    // Log whether the feed was frozen and how many rows were shown, since neither
                                    // can be reconstructed later.
                                    dashboardLog.notice("✅ app:dashboard leafSheet VERIFY rows=\(rows.count, privacy: .public) frozen=\(frozenRecent != nil, privacy: .public)")
                                    selectedLeaf = leaf
                                }
                                .targetRuleSwipe(leaf.ruleSubject)
                            }
                        }
                    }
                } header: {
                    HStack {
                        Text("Recent targets")
                        Spacer()
                        // Entry point to Live Traffic. textCase(nil) keeps "See all" as written.
                        NavigationLink {
                            LiveTrafficView()
                        } label: {
                            Text("See all")
                                .font(.footnote.weight(.semibold))
                                .foregroundStyle(Color.accentColor)
                                .textCase(nil)
                                // The glyphs are only ~18 pt tall, so enlarge the tap target without
                                // changing the visible layout.
                                .padding(.vertical, 10)
                                .padding(.leading, 24)
                                .contentShape(Rectangle())
                        }
                    }
                }
                .brandCardRows(isDark)

                Section {
                    Text(CapabilityCopy.deviceWide)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                .brandCardRows(isDark)
            }
            .foregroundStyle(primaryText, secondaryText)
            .readableWidth()
            .brandDarkBackground()
            // A large title sits at the window edge, away from the readable column, so
            // regular width uses an inline title like Insights. Compact keeps the large one.
            .navigationTitle("FluxMoat")
            .navigationBarTitleDisplayMode(
                horizontalSizeClass == .regular ? .inline : .large
            )
            .onAppear {
                // Any previous selection is stale on return; show the totals.
                selectedSlot = nil
                reloadTraffic()
                // Rank from scratch on arrival, unless a drill-down is still open; then keep
                // the order so rows don't move under the user.
                syncCountryOrder(reset: !isAnythingExpanded)
            }
            // Only when the set of countries changes: new countries need a slot.
            // Count changes are handled by the tick.
            .onChange(of: presentCountryCodes) { _, _ in
                syncCountryOrder(reset: false)
            }
            // 1 Hz clock for the meters and the country ranking. Separate from
            // `refreshTick`, which runs an hourly SQL rollup every 15 s. This only
            // advances a Date so rows re-fold the existing buffer, and it lets meters
            // decay when traffic stops. Ranking uses the same tick so rows reorder in
            // step with the levels on screen. Both writes are skipped while the tree is
            // frozen. The task stops automatically when the view leaves the hierarchy.
            .task {
                while !Task.isCancelled {
                    if frozenRecent == nil {
                        meterClock = Date()
                        syncCountryOrder(reset: false)
                    }
                    try? await Task.sleep(for: .seconds(1))
                }
            }
            .onReceive(refreshTick) { _ in
                // Don't reload while a minute is selected: reloading shifts the window and the
                // selected bucket would slide away. `clearSelection` reloads afterwards.
                guard selectedSlot == nil else { return }
                reloadTraffic()
            }
            // Half height by default so the leaf row stays visible behind it. Same
            // detents as Live Traffic's FlowDetailSheet.
            .sheet(item: $selectedLeaf) { leaf in
                TargetDetailSheet(leaf: leaf)
                    .adaptiveSheetDetents(
                        [.medium, .large], regularWidth: horizontalSizeClass == .regular
                    )
            }
        }
    }
}

/// One unanswered Ask-mode question: the destination, what the default already
/// did, and Allow/Block buttons that create a rule.
struct PendingAskRow: View {
    @Environment(AppModel.self) private var model
    let ask: PendingAsk

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(ask.targetKey)
                    .font(.body.monospaced())
                    .lineLimit(1)
                Text("\(ask.appliedAction == .allow ? "Allowed" : "Blocked") by default · \(ask.flowCount) connection\(ask.flowCount == 1 ? "" : "s")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Block") {
                model.resolveAsk(ask, action: .deny)
            }
            .buttonStyle(.bordered)
            .tint(.red)
            Button("Allow") {
                model.resolveAsk(ask, action: .allow)
            }
            .buttonStyle(.borderedProminent)
            .tint(.green)
        }
    }
}

