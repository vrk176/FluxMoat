import Charts
import Combine
import SharedCore
import SwiftUI

/// Trends: history charts, rankings and spike markers, built from the store's SQL
/// rollups (raw rows are never loaded). Day buckets align to local midnight.
struct HistoryView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    /// Read here rather than inside the sheet: sheet content reports compact on iPad.
    /// See `adaptiveSheetDetents`.
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    /// Only dark mode uses the brand styling for now.
    private var isDark: Bool { colorScheme == .dark }

    /// Owned by the Insights shell so Trends and Map share one window. Read-only here.
    @Binding var window: InsightsWindow

    /// The current page as a share summary, handed up to the shell's share button.
    /// Written at the end of every `reload`, so it always matches what's on screen.
    /// nil when there's nothing to share, which disables the button.
    @Binding var summary: InsightsSummary?

    /// Refreshes every 15 s like the dashboard, since this page is often left open.
    /// Keeps running while Map is showing because the shell keeps both surfaces mounted.
    private let refreshTick = Timer.publish(every: 15, on: .main, in: .common).autoconnect()

    /// Before this date (2026-08-25 00:00 UTC) the tunnel counted blocks from a filtering
    /// DoH resolver as threats. Old rows were never rewritten and the threat query has
    /// no date bound, so windows reaching back past this show an inflated threat count
    /// and get a caveat.
    private static let threatAttributionFixDate = Date(timeIntervalSince1970: 1_787_616_000)

    /// How many prior-period targets to fetch for row deltas. Not a display limit. If
    /// the result comes back under the limit it's complete, so a missing target really
    /// is new; if it's full, absence proves nothing (see `PriorWindow.delta`). LIMIT only
    /// truncates the output, so a generous value costs nothing.
    private static let priorLookupLimit = 500

    /// Rows per ranking section. Also bounds the flag lookup: at most 15 names across
    /// three sections, usually fewer since sections overlap.
    private static let rankLimit = 5

    @State private var buckets: [ChartBucket] = []
    /// Pinned x range so a few busy days in a long window still look sparse. See `zeroFilled`.
    @State private var xDomain: ClosedRange<Date> = Date()...Date()
    @State private var topTargets: [TrafficEventStore.TargetAggregate] = []
    @State private var topBlocked: [TrafficEventStore.TargetAggregate] = []
    @State private var newTargets: [TrafficEventStore.TargetAggregate] = []
    /// Country code each listed target last connected to, keyed by target name. Missing
    /// entries get the globe (see `AppModel.insightsTargetCountries`). Filled by one query
    /// across all three sections so overlapping rows share the same flag.
    @State private var flags: [String: String] = [:]
    /// The same rollups for the previous period, used for deltas. Empty on All.
    @State private var prior = PriorWindow()
    /// Connections this period vs last, for the section header. Computed from the bucket
    /// rollups because the header shows a total and the ranking is only a top N.
    @State private var connectionsDelta: InsightsDelta?
    /// False until the first rollup returns, so "no traffic" and "not loaded yet" look
    /// different.
    @State private var hasLoaded = false
    /// Incremented by the refresh timer. Part of the `.task` id so the timer can trigger
    /// an async reload.
    @State private var refreshCount = 0
    /// The lower edge the on-screen rows were rolled up from, passed to sheets so they
    /// use the same window. Recomputing at tap time can slide an hour if a bucket
    /// boundary passes in between. nil on All.
    @State private var loadedSince: Date?
    /// The clock read `reload()` used as its upper edge. Passed through `InsightsSummary`
    /// so the share sheet's Countries rollup can query `since...until` and match the
    /// page's totals exactly.
    @State private var loadedUntil: Date = Date()
    /// The ranking row the user tapped, captured at tap time (see `InsightsTargetSelection`).
    @State private var selectedTarget: InsightsTargetSelection?
    /// Selected bar in each chart, by bucket start, or nil.
    ///
    /// Separate per chart: tapping one chart shouldn't change the readout of the other,
    /// which may be scrolled off screen.
    @State private var pickedFlowsBar: Date?
    @State private var pickedBytesBar: Date?

    /// Buckets are zero-filled, so check flows rather than the array count.
    private var hasTraffic: Bool { buckets.contains { $0.flows > 0 } }

    /// Window totals from the bucket rollup (the ranking is only a top N). Same source as
    /// `connectionsDelta`, so the header and the spoken summary agree.
    private var totalFlows: Int { buckets.reduce(0) { $0 + $1.flows } }
    private var totalBlocked: Int { buckets.reduce(0) { $0 + $1.blockedFlows } }

    /// Byte totals for the mirror chart's readout. `&+` because these are sums of the
    /// store's counters and a wrap should give a wrong number, not a crash.
    private var totalBytesUp: UInt64 { buckets.reduce(UInt64(0)) { $0 &+ $1.bytesUp } }
    private var totalBytesDown: UInt64 { buckets.reduce(UInt64(0)) { $0 &+ $1.bytesDown } }

    /// True when there's nothing to chart and nothing to list.
    ///
    /// Checks both because they come from different queries (time rollup vs target
    /// rollup). A flat chart alone isn't a reason to hide a list that has rows.
    private var isFullyEmpty: Bool {
        !hasTraffic && topTargets.isEmpty && topBlocked.isEmpty && newTargets.isEmpty
    }

    /// Spike buckets: at least 2× the window's average flows. The floor and minimum
    /// sample size keep near-empty windows from flagging noise. The average includes
    /// empty buckets.
    private var spikeStarts: Set<Date> {
        guard buckets.count >= 4 else { return [] }
        let average = Double(buckets.reduce(0) { $0 + $1.flows }) / Double(buckets.count)
        return Set(buckets.filter {
            Double($0.flows) >= 2 * average && $0.flows >= 10
        }.map(\.start))
    }

    /// Whether the New targets section can say anything meaningful for this window.
    ///
    /// "First seen" is based on the rows the store still holds. When retention is no
    /// longer than the window, every surviving row is inside the window, so every target
    /// looks new. In that case the section is hidden, as on All. A proper fix would be a
    /// first-seen table that retention doesn't prune.
    private var newTargetsIsAnswerable: Bool {
        guard let barCount = window.barCount else { return false }
        return model.historyRetention.maxAge > Double(barCount) * Double(window.bucketSeconds)
    }

    /// Whether the window includes rows recorded under the old threat attribution.
    /// All always does; a bounded window does if it starts before the fix date. Hidden
    /// when there's no traffic.
    private var showsThreatCaveat: Bool {
        guard hasTraffic else { return false }
        guard let since = window.since else { return true }
        return since < Self.threatAttributionFixDate
    }

    var body: some View {
        content
            // Applied to the `content` switch rather than each `List` so the
            // `ContentUnavailableView` branches are centered on the same column.
            .readableWidth()
            .brandDarkBackground()
            // Keyed on window, tick and retention so SwiftUI cancels an in-flight load when any
            // changes. `reload` writes nothing after cancellation, so a quick window switch
            // can't put old rows on the new window.
            //
            // Existing data stays on screen during a reload instead of blanking the page.
            .task(id: ReloadKey(
                window: window, tick: refreshCount, retention: model.historyRetention
            )) { await reload() }
            .onReceive(refreshTick) { _ in refreshCount &+= 1 }
            // Clear the picked bars when the window changes, since the buckets are different.
            // The 15 s refresh keeps the same grid, so it doesn't clear them.
            .onChange(of: window) { _, _ in
                pickedFlowsBar = nil
                pickedBytesBar = nil
            }
            // Half-height by default so the row stays visible behind it. Same detents as the
            // Live Traffic and dashboard sheets.
            .sheet(item: $selectedTarget) { selection in
                InsightsTargetSheet(selection: selection)
                    .adaptiveSheetDetents(
                        [.medium, .large], regularWidth: horizontalSizeClass == .regular
                    )
            }
            // Dismiss the sheet when leaving the tab. It isn't reachable by hand right now (the
            // sheet's scrim blocks the tab bar), but its lifetime shouldn't depend on that.
            // Switching Trends/Map doesn't trigger this, since both stay mounted.
            .onDisappear { selectedTarget = nil }
    }

    /// Identifies a reload. `.task(id:)` won't rerun for an equal key.
    private struct ReloadKey: Equatable {
        let window: InsightsWindow
        let tick: Int
        /// Included because it decides whether the New targets query runs
        /// (`newTargetsIsAnswerable`). Without it, widening retention would show "No new
        /// targets" until the next tick.
        let retention: RetentionPeriod
    }

    /// Page-level states: error, loading, empty, or the list. `ContentUnavailableView`
    /// is meant to own the screen, so it isn't drawn inside a list row.
    @ViewBuilder
    private var content: some View {
        if model.storeUnavailable {
            // Checked before the empty case: an unreadable database is not the same as no traffic.
            ContentUnavailableView(
                "History unavailable",
                systemImage: "exclamationmark.triangle",
                description: Text(InsightsCopy.storeUnreadable)
            )
        } else if !hasLoaded {
            // Checked before the empty case too, so a cold open doesn't flash "No traffic" while
            // the off-main-thread rollups are still running.
            placeholder
        } else if isFullyEmpty {
            ContentUnavailableView(
                "No traffic in this period",
                systemImage: "chart.bar",
                // Protection being off is the most likely reason for an empty history, so say so.
                // Same wording as Live Traffic.
                description: Text(model.isProtectionOn
                    ? "History appears here once protection has observed traffic."
                    : "Turn on protection to observe traffic.")
            )
        } else {
            list
        }
    }

    /// Redacted skeleton of the page while loading: one chart card and a few rows.
    ///
    /// A separate skeleton because the real list can't be fed fake rows:
    /// `TargetAggregate`'s memberwise init is internal to SharedCore. The strings below
    /// only set the width of the redaction bars.
    private var placeholder: some View {
        List {
            Section("Connections") {
                Rectangle()
                    .fill(.secondary.opacity(0.15))
                    .frame(height: 220)
                    .padding(.vertical, 4)
            }
            .brandCardRows(isDark)

            Section("Top targets") {
                // Five one-line rows, matching the real sections.
                ForEach(0..<Self.rankLimit, id: \.self) { _ in
                    HStack(spacing: 8) {
                        Text(CountryFlag.unknown)
                        Text("placeholder.example")
                            .font(.callout.monospaced())
                    }
                }
            }
            .brandCardRows(isDark)
        }
        .redacted(reason: .placeholder)
        // Placeholder only: no hit testing, no accessibility.
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private var list: some View {
        List {
            Section {
                if hasTraffic {
                    // Readout above, plot below, both leading-aligned. The readout replaces the y axis
                    // labels (see `connectionsReadout`).
                    VStack(alignment: .leading, spacing: 6) {
                        connectionsReadout
                        flowsChart
                            .frame(height: 220)
                    }
                    .padding(.vertical, 4)
                } else {
                    // Only reachable when the target rollup returned rows but the time rollup didn't.
                    // Keep the section with a placeholder line rather than removing it.
                    Text("No connections in this period")
                        .foregroundStyle(.secondary)
                }
            } header: {
                // `deltaHeader` draws no badge on All, which has no prior period.
                deltaHeader("Connections", delta: connectionsDelta)
            } footer: {
                if !spikeStarts.isEmpty || showsThreatCaveat {
                    VStack(alignment: .leading, spacing: 4) {
                        if !spikeStarts.isEmpty {
                            Text("▲ marks spikes: at least twice the period's average.")
                        }
                        if showsThreatCaveat {
                            // Shared with the summary image (see `InsightsCopy.threatCaveat`).
                            Text(InsightsCopy.threatCaveat)
                        }
                    }
                }
            }
            .brandCardRows(isDark)

            if hasTraffic {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        volumeReadout
                        bytesChart
                            .frame(height: 140)
                    }
                    .padding(.vertical, 4)
                } header: {
                    Text("Data volume")
                } footer: {
                    // Nothing else on this page says which half is which, and color alone isn't enough
                    // for someone who hasn't seen the dashboard's mirror chart.
                    Text("Sent above the line, received below.")
                }
                .brandCardRows(isDark)
            }

            // Keep each section even when empty, with a placeholder line, so the page layout
            // doesn't change between windows.
            Section("Top targets") {
                if topTargets.isEmpty {
                    Text("No targets recorded")
                        .foregroundStyle(.secondary)
                } else {
                    // The delta is for the metric the section ranks by (connections here, blocks below).
                    // It isn't drawn on the row, but the sheet shows it, and only this call site knows
                    // which metric applies.
                    ForEach(topTargets, id: \.target) {
                        rankingRow($0, delta: prior.flowsDelta(for: $0.target, current: $0.flows))
                    }
                }
            }
            .brandCardRows(isDark)

            Section {
                if topBlocked.isEmpty {
                    Text("No blocked targets")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(topBlocked, id: \.target) {
                        rankingRow($0, delta: prior.blockedDelta(for: $0.target, current: $0.blockedFlows))
                    }
                }
            } header: {
                Text("Top blocked")
            } footer: {
                Text("Targets ranked by how often they were blocked in this period.")
            }
            .brandCardRows(isDark)

            // Hidden on All: every target the store holds was first seen within "all history",
            // so the section would just be Top targets reordered. `reload` skips the query too.
            // Also hidden when retention is too short to answer (see `newTargetsIsAnswerable`).
            if window.since != nil, newTargetsIsAnswerable {
                Section {
                    if newTargets.isEmpty {
                        Text("No new targets")
                            .foregroundStyle(.secondary)
                    } else {
                        // No deltas here: every row is new, so the previous count is zero by definition.
                        ForEach(newTargets, id: \.target) {
                            rankingRow($0, delta: nil, isNew: true)
                        }
                    }
                } header: {
                    HStack {
                        Text("New targets")
                        Spacer()
                        // Show the retention setting this section depends on, with a link to change it.
                        Button("Keeping \(model.historyRetention.displayName)") {
                            model.pendingDestination = .settingsHistoryRetention
                        }
                        .buttonStyle(.borderless)
                        // The list style uppercases headers; keep this as written.
                        .textCase(nil)
                        .font(.caption)
                    }
                } footer: {
                    // Shared with the target sheet (see `InsightsCopy.firstSeenInWindow`).
                    Text(InsightsCopy.firstSeenInWindow)
                }
                .brandCardRows(isDark)
            }
        }
    }

    /// A ranked target row with its swipe action.
    ///
    /// `swipeActions` has to be attached to the list cell, which is what this ForEach
    /// produces; on the row's own body it never fires. The row is also a plain-styled
    /// Button that fills the cell, which doesn't interfere with the swipe.
    ///
    /// Targets with an empty name (a flow with neither domain nor address) get a plain
    /// row, since `.domain("")` would match nothing. Same guard as `TargetLeaf.ruleTargets`.
    @ViewBuilder
    private func rankingRow(
        _ aggregate: TrafficEventStore.TargetAggregate,
        delta: InsightsDelta?,
        isNew: Bool = false
    ) -> some View {
        let subject = aggregate.ruleSubject
        // Look up once and pass to both the row and the sheet so they can't show different
        // flags if the page reloads in between.
        let country = flags[aggregate.target]
        let row = TargetRow(target: aggregate, countryCode: country) {
            selectedTarget = InsightsTargetSelection(
                aggregate: aggregate,
                countryCode: country,
                delta: delta,
                prior: window.priorAnnotation,
                window: window,
                // The edge the on-screen rows used, not a fresh one (see `loadedSince`).
                since: loadedSince,
                isNew: isNew
            )
        }
        if subject.targets.isEmpty {
            row
        } else {
            row.targetRuleSwipe(subject)
        }
    }

    /// Section title with its period-over-period badge, or just the title.
    ///
    /// No badge on All (no prior period to compare with) or when both periods are empty.
    @ViewBuilder
    private func deltaHeader(_ title: String, delta: InsightsDelta?) -> some View {
        if let prior = window.priorAnnotation,
           let text = delta?.headline(vs: prior) {
            HStack {
                Text(title)
                Spacer()
                // Short text on screen, full sentence for VoiceOver; some voices spell out "vs".
                InsightsDeltaBadge(text: text, spoken: delta?.spoken(vs: prior))
            }
        } else {
            Text(title)
        }
    }

    /// Runs the rollups off the main thread (via the store's `HistoryStoreGate`) and,
    /// for bounded windows, the same rollups over the prior period. The flag lookup is
    /// one query for the whole page, not one per row (see
    /// `TrafficEventStore.latestRemoteIPs`).
    ///
    /// Uses a single clock read so both windows' edges come from the same instant.
    /// Separate reads could straddle an hour boundary and shift one window by a bucket.
    private func reload() async {
        let now = Date()
        let bounds = window.bounds(now: now)
        let since = bounds?.since

        let rows = await model.insightsBuckets(
            bucketSeconds: window.bucketSeconds, since: since)
        let targets = await model.insightsTopTargets(since: since, limit: Self.rankLimit)
        let blocked = await model.insightsTopBlocked(since: since, limit: Self.rankLimit)
        // Skipped on All (see the New targets section), which is why the store's
        // `newTargets(since:)` can take a non-optional Date. Also skipped when retention
        // can't answer (`newTargetsIsAnswerable`), since hidden rows would still count
        // toward `isFullyEmpty`.
        var fresh: [TrafficEventStore.TargetAggregate] = []
        if let since, newTargetsIsAnswerable {
            fresh = await model.insightsNewTargets(since: since, limit: Self.rankLimit)
        }

        // One lookup for every flag on the page, after the rankings since it needs their
        // names. Uses the same window so flags reflect the displayed period.
        let countries = await model.insightsTargetCountries(
            for: (targets + blocked + fresh).map(\.target), since: since)

        // Prior queries use `priorSince..<priorUntil`, the current window shifted back one
        // period (see `InsightsWindow.bounds`). The upper edge keeps the comparison to
        // equal elapsed time.
        var priorWindow = PriorWindow()
        var totalDelta: InsightsDelta?
        if let bounds {
            let priorRows = await model.insightsBuckets(
                bucketSeconds: window.bucketSeconds,
                since: bounds.priorSince, until: bounds.priorUntil)
            totalDelta = InsightsDelta(
                current: rows.reduce(0) { $0 + $1.flows },
                previous: priorRows.reduce(0) { $0 + $1.flows }
            )
            priorWindow = PriorWindow(rows: await model.insightsTopTargets(
                since: bounds.priorSince, until: bounds.priorUntil,
                limit: Self.priorLookupLimit
            ), limit: Self.priorLookupLimit)
        }

        // The window may have changed during the awaits above, and `.task(id:)` cancels
        // this task when it does. Don't write stale results.
        guard !Task.isCancelled else { return }
        (buckets, xDomain) = Self.zeroFilled(rows, window: window, since: since)
        topTargets = targets
        topBlocked = blocked
        newTargets = fresh
        flags = countries
        prior = priorWindow
        connectionsDelta = totalDelta
        // Stored with the rows so a tap passes the sheet the matching window.
        loadedSince = since
        loadedUntil = now
        hasLoaded = true
        summary = shareableSummary
    }

    /// The page as a share summary, or nil when there's nothing to share.
    ///
    /// Computed from state after `reload` writes it, so the image matches what the page
    /// shows. nil when the store is unreadable, so the image never claims "0 connections"
    /// when the database couldn't be opened.
    private var shareableSummary: InsightsSummary? {
        guard !model.storeUnavailable, !isFullyEmpty else { return nil }
        return InsightsSummary(
            window: window,
            bars: buckets.map {
                // Split the same way `flowsChart` stacks them.
                InsightsSummary.Bar(
                    start: $0.start,
                    allowed: $0.flows - $0.blockedFlows,
                    blocked: $0.blockedFlows - $0.threatFlows,
                    threat: $0.threatFlows
                )
            },
            xDomain: xDomain,
            rows: topTargets.prefix(5).map(Self.summaryRow),
            // Rows already fetched for Top blocked, so the Blocked card needs no query.
            blockedRows: topBlocked.prefix(5).map(Self.summaryRow),
            totalFlows: totalFlows,
            totalBlocked: totalBlocked,
            totalBytesUp: totalBytesUp,
            totalBytesDown: totalBytesDown,
            since: loadedSince,
            until: loadedUntil,
            showsThreatCaveat: showsThreatCaveat
        )
    }

    /// A ranking row for the card. `blocked` is every deny, `threat` the subset from a
    /// threat list.
    private static func summaryRow(_ row: TrafficEventStore.TargetAggregate) -> InsightsSummary.Row {
        InsightsSummary.Row(
            target: row.target,
            flows: row.flows,
            bytes: row.bytesUp &+ row.bytesDown,
            blocked: row.blockedFlows,
            threat: row.threatFlows
        )
    }

    /// Fills in every bucket in the window, merges the SQL rows into it, and returns the
    /// chart rows plus the x domain to pin.
    ///
    /// The store only returns buckets that had traffic, and Charts sizes its x axis to
    /// the data, so without this a few busy days in 30d would stretch across the full
    /// width.
    ///
    /// Bucket starts come from `InsightsWindow.alignedStart(of:)`, the same arithmetic as
    /// the SQL and `bounds(now:)`, so merging is an exact key match. A bounded window is
    /// exactly `barCount` bars counted forward from the queried `since`.
    ///
    /// Internal because the target sheet's sparkline uses it too.
    static func zeroFilled(
        _ rows: [TrafficEventStore.TimeBucketAggregate], window: InsightsWindow,
        since: Date?
    ) -> ([ChartBucket], ClosedRange<Date>) {
        let step = TimeInterval(window.bucketSeconds)
        // Anchor to the edge the rows were queried with, not a fresh clock read. If a bucket
        // boundary passes in between (reload has several awaits, and a sheet can open much
        // later), the grid would shift forward one bucket and the oldest bucket's row would
        // be dropped. On a target sheet for a brand-new target that can be its only bucket.
        let start: Date
        let end: Date
        switch (since, window.barCount) {
        case let (.some(edge), .some(bars)):
            start = edge
            end = edge.addingTimeInterval(Double(bars - 1) * step)
        default:
            // All has no lower edge, so it ends at the current bucket and starts at the oldest
            // bucket the store has (rows are ascending). At least two buckets, since an area
            // mark needs two points.
            end = window.alignedStart(of: Date())
            start = min(rows.first?.bucketStart ?? end, end.addingTimeInterval(-step))
        }

        var byStart: [Date: TrafficEventStore.TimeBucketAggregate] = [:]
        for row in rows { byStart[row.bucketStart] = row }

        var filled: [ChartBucket] = []
        var cursor = start
        while cursor <= end {
            filled.append(ChartBucket(start: cursor, row: byStart[cursor]))
            cursor.addTimeInterval(step)
        }
        // Extend the domain one bucket past the last so the trailing bar isn't clipped.
        return (filled, start...end.addingTimeInterval(step))
    }

    // MARK: - Readouts

    /// The connections chart's numbers as text above the plot, replacing y axis labels:
    /// window totals when nothing is picked, the picked bar's numbers otherwise.
    ///
    /// The window name isn't repeated here since the toolbar picker shows it. A picked
    /// bar has no label of its own, so its time is shown on the right.
    ///
    /// `ViewThatFits` picks full or abbreviated figures based on the space left in the
    /// row (see `readoutRow`).
    private var connectionsReadout: some View {
        let picked = pickedFlowsBar.flatMap(bucket(at:))
        let flows = picked?.flows ?? totalFlows
        let blocked = picked?.blockedFlows ?? totalBlocked
        return readoutRow(picked) {
            ViewThatFits(in: .horizontal) {
                connectionsFacts(flows: flows, blocked: blocked, abbreviated: false)
                connectionsFacts(flows: flows, blocked: blocked, abbreviated: true)
            }
            .font(.subheadline.weight(.semibold))
            // VoiceOver always gets the full numbers, whichever variant is visible.
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(spokenConnectionFacts(flows: flows, blocked: blocked))
        }
    }

    /// Readout layout: facts on the left and, while a bar is picked, its time on the right.
    ///
    /// One row so the block keeps the same height whether or not a bar is picked and the
    /// chart doesn't jump. Aligned on baselines since the two sides use different sizes.
    ///
    /// The `lineLimit`s and scale factor keep it on one line: without them the facts wrap
    /// when the time appears. The time gets `fixedSize` since it's shorter and useless if
    /// clipped. The widest case is a dated weekday on 30d; check that one on a device.
    ///
    /// `ViewThatFits` measures candidates at natural size, so the scale factor only ever
    /// applies to the abbreviated fallback: full numbers, then abbreviated, then slightly
    /// shrunk abbreviated at large Dynamic Type sizes.
    private func readoutRow<Facts: View>(
        _ picked: ChartBucket?,
        @ViewBuilder facts: () -> Facts
    ) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            facts()
                .lineLimit(1)
                .minimumScaleFactor(0.75)
            Spacer(minLength: 8)
            if let picked {
                Text(barCaption(picked))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .fixedSize()
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// "1,240 connections · 12 blocked" as one text run so both halves lay out and scale
    /// together. The blocked part is red only when non-zero.
    ///
    /// `abbreviated` only changes the digits (via `ShareCardMath.abbreviated`); plurals
    /// still use the real counts. No threshold here because `ViewThatFits` already
    /// decided the full figures don't fit.
    private func connectionsFacts(flows: Int, blocked: Int, abbreviated: Bool) -> Text {
        let digits = { (count: Int) in
            abbreviated ? ShareCardMath.abbreviated(count) : count.formatted()
        }
        let head = Text("\(digits(flows)) connection\(flows == 1 ? "" : "s")")
        guard blocked > 0 else { return head }
        return head + Text(" · ")
            + Text("\(digits(blocked)) blocked").foregroundStyle(.red)
    }

    /// Full-precision spoken version. Uses a comma instead of "·", which VoiceOver can't
    /// read usefully.
    private func spokenConnectionFacts(flows: Int, blocked: Int) -> String {
        let count = "\(flows.formatted()) connection\(flows == 1 ? "" : "s")"
        guard blocked > 0 else { return count }
        return "\(count), \(blocked.formatted()) blocked"
    }

    /// The mirror chart's readout: sent and received, for the window or the picked bar.
    ///
    /// Each half of the mirror is normalized to its own peak, so the chart hides the
    /// sent/received ratio. These totals make it visible.
    private var volumeReadout: some View {
        let picked = pickedBytesBar.flatMap(bucket(at:))
        return readoutRow(picked) {
            HStack(alignment: .firstTextBaseline, spacing: 14) {
                directionFact(.sent, picked?.bytesUp ?? totalBytesUp)
                directionFact(.received, picked?.bytesDown ?? totalBytesDown)
            }
            .font(.subheadline.weight(.semibold))
        }
    }

    /// Arrow and figure in the direction's ink color (text, adapts to color scheme). The
    /// bars use the fixed fill colors; see `TrafficPalette`.
    private func directionFact(_ direction: TrafficDirection, _ bytes: UInt64) -> some View {
        let value = ByteFormat.volume(bytes)
        return HStack(spacing: 4) {
            Image(systemName: direction.symbol)
                .font(.caption2.weight(.bold))
            Text(value)
        }
        .foregroundStyle(direction.tint)
        // The arrow is visual only, so put the direction in the label.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(direction.label) \(value)")
    }

    /// The picked bar's time: a clock range for hourly bars, a dated weekday for daily.
    /// The hour range uses 24 h numerals to match the axis labels.
    private func barCaption(_ bucket: ChartBucket) -> String {
        let calendar = Calendar.current
        guard window.calendarUnit == .hour else {
            return bucket.start.formatted(
                .dateTime.weekday(.abbreviated).day().month(.abbreviated))
        }
        let hour = calendar.component(.hour, from: bucket.start)
        return String(format: "%02d:00 – %02d:00", hour, (hour + 1) % 24)
    }

    /// X label format per window: time of day, weekday, date, or month.
    private enum BarLabelStyle {
        case hourOfDay
        case weekday
        case dayOfMonth
        case month
    }

    private var barLabelStyle: BarLabelStyle {
        switch window {
        case .day: .hourOfDay
        case .week: .weekday
        case .month: .dayOfMonth
        // All spans anything from days to a year. Use month labels only when at least two
        // month starts fall in the window; otherwise use dates.
        case .all: monthStarts.count >= 2 ? .month : .dayOfMonth
        }
    }

    private var monthStarts: [Date] {
        let calendar = Calendar.current
        return buckets.map(\.start).filter { calendar.component(.day, from: $0) == 1 }
    }

    /// Bars that get an axis label.
    ///
    /// Picked from actual bucket starts instead of a `.stride`, which counts from the
    /// domain edge and would drift off the bars since the domain extends one bucket past
    /// the last one (see `zeroFilled`).
    ///
    /// Thinning varies by style: all seven weekdays are labeled, hourly labels go every
    /// four. Thinned styles skip the last bar's label: it sits a few points from the
    /// plot's edge and Charts truncates it to "…".
    private var barLabelDates: [Date] {
        let starts = buckets.map(\.start)
        guard !starts.isEmpty else { return [] }
        // With four bars or fewer, label all of them. There's room, and otherwise the
        // newest bar could go unlabeled.
        if starts.count <= 4 { return starts }
        switch barLabelStyle {
        case .weekday:
            return starts
        case .hourOfDay:
            return Swift.stride(from: 0, to: max(1, starts.count - 1), by: 4).map { starts[$0] }
        case .dayOfMonth:
            // Aim for about five labels regardless of span.
            let usable = max(1, starts.count - 1)
            let step = max(1, Int((Double(usable) / 5).rounded()))
            return Swift.stride(from: 0, to: usable, by: step).map { starts[$0] }
        case .month:
            return monthStarts.filter { $0 != starts.last }
        }
    }

    /// A single axis label from the calendar, using the locale's short weekday and month
    /// symbols. Hours are clock hours (0-23), not a 1-24 sequence, since the 24h window
    /// slides and people read the axis for time of day.
    private func barLabel(_ date: Date) -> String {
        let calendar = Calendar.current
        switch barLabelStyle {
        case .hourOfDay:
            return "\(calendar.component(.hour, from: date))"
        case .weekday:
            return calendar.shortWeekdaySymbols[calendar.component(.weekday, from: date) - 1]
        case .dayOfMonth:
            return "\(calendar.component(.day, from: date))"
        case .month:
            return calendar.shortMonthSymbols[calendar.component(.month, from: date) - 1]
        }
    }

    /// The bar covering a tapped x position: the last bucket starting at or before it.
    /// Falls back to the first bar for taps left of it (reachable via domain padding).
    private func bucket(at date: Date) -> ChartBucket? {
        buckets.last { $0.start <= date } ?? buckets.first
    }

    /// Tap-to-select, hand-rolled like the dashboard's hero chart. `.chartXSelection` is
    /// designed for scrubbing; here a single tap selects, and tapping the selected bar
    /// or outside the plot deselects.
    private func pickOverlay(_ proxy: ChartProxy, _ picked: Binding<Date?>) -> some View {
        GeometryReader { geo in
            Rectangle()
                .fill(.clear)
                .contentShape(Rectangle())
                .gesture(
                    SpatialTapGesture().onEnded { tap in
                        handlePick(at: tap.location, proxy: proxy, geo: geo, picked: picked)
                    }
                )
        }
    }

    private func handlePick(
        at location: CGPoint, proxy: ChartProxy, geo: GeometryProxy, picked: Binding<Date?>
    ) {
        // Taps below the plot (labels) or in the side padding deselect.
        guard let plotFrame = proxy.plotFrame else { return }
        let plot = geo[plotFrame]
        guard plot.contains(location),
              let date = proxy.value(atX: location.x - plot.minX, as: Date.self),
              let hit = bucket(at: date) else {
            picked.wrappedValue = nil
            return
        }
        picked.wrappedValue = picked.wrappedValue == hit.start ? nil : hit.start
    }

    /// Unselected bars fade while a bar is picked. Opacity rather than color, since every
    /// color here already means something (blocked, threat, direction).
    private func barOpacity(_ start: Date, picked: Date?) -> Double {
        guard let picked else { return 1 }
        return picked == start ? 1 : 0.3
    }

    /// Stacked bars: allowed + blocked, with threat blocks split out. Red = blocked,
    /// violet = threat (a red-family threat color was indistinguishable next to red),
    /// orange = noteworthy only, never a block.
    private var flowsChart: some View {
        let picked = pickedFlowsBar
        return Chart(buckets) { bucket in
            BarMark(
                x: .value("Time", bucket.start, unit: window.calendarUnit),
                y: .value("Connections", bucket.flows - bucket.blockedFlows)
            )
            .foregroundStyle(by: .value("Kind", "Allowed"))
            .opacity(barOpacity(bucket.start, picked: picked))
            BarMark(
                x: .value("Time", bucket.start, unit: window.calendarUnit),
                y: .value("Connections", bucket.blockedFlows - bucket.threatFlows)
            )
            .foregroundStyle(by: .value("Kind", "Blocked"))
            .opacity(barOpacity(bucket.start, picked: picked))
            BarMark(
                x: .value("Time", bucket.start, unit: window.calendarUnit),
                y: .value("Connections", bucket.threatFlows)
            )
            .foregroundStyle(by: .value("Kind", "Threat"))
            .opacity(barOpacity(bucket.start, picked: picked))

            if spikeStarts.contains(bucket.start) {
                PointMark(
                    x: .value("Time", bucket.start, unit: window.calendarUnit),
                    y: .value("Connections", bucket.flows)
                )
                .symbol(.triangle)
                // Spike markers are orange so they aren't read as part of the blocked stack.
                .foregroundStyle(.orange)
                // Fade with the bar underneath.
                .opacity(barOpacity(bucket.start, picked: picked))
            }
        }
        // Palette tokens so these match the same labels elsewhere in the app. See
        // `allowedFill` for the choice of green.
        .chartForegroundStyleScale([
            "Allowed": TrafficPalette.allowedFill,
            "Blocked": Color.red,
            "Threat": BrandPalette.threat,
        ])
        .chartXScale(domain: xDomain)
        // No y axis labels; the readout above the plot gives exact numbers instead, and the
        // bars get the width back.
        //
        // Keep a zero rule with no label, same as the mirror chart below, so both charts
        // share a baseline and an empty period doesn't look like a broken card.
        .chartYAxis {
            AxisMarks(values: [0]) {
                AxisGridLine().foregroundStyle(.secondary.opacity(0.4))
            }
        }
        .chartXAxis {
            // Labels only, no ticks or grid.
            AxisMarks(values: barLabelDates) { value in
                AxisValueLabel {
                    // `?? ""` is just a fallback; every value in `barLabelDates` is a Date.
                    Text(value.as(Date.self).map(barLabel) ?? "")
                }
            }
        }
        .chartOverlay { proxy in pickOverlay(proxy, $pickedFlowsBar) }
        // Otherwise Charts gives VoiceOver one stop per bar (up to 366), each with a date and
        // three numbers. One sentence with the total and blocked share instead.
        // TODO: an `AXChartDescriptorRepresentable` would add audio graph navigation.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Connections over time")
        .accessibilityValue(InsightsCopy.spokenTotals(
            flows: totalFlows, blocked: totalBlocked, window: window
        ))
    }

    /// Mirror chart like the dashboard hero, at Trends timescales: sent above the zero
    /// line, received below. Direction is shown by position and the two fixed fills.
    private var bytesChart: some View {
        // Each half is scaled to its own peak, like the dashboard: a phone receives far
        // more than it sends, and a shared scale would flatten the sent half. The readout
        // above shows the actual totals.
        let peakUp = buckets.reduce(UInt64(0)) { max($0, $1.bytesUp) }
        let peakDown = buckets.reduce(UInt64(0)) { max($0, $1.bytesDown) }
        let picked = pickedBytesBar
        // `.ratio` width instead of the dashboard's `.fixed(4)`: the dashboard always has
        // about 60 bars, but here it ranges from 7 to 366.
        return Chart(buckets) { bucket in
            BarMark(
                x: .value("Time", bucket.start, unit: window.calendarUnit),
                y: .value("Sent", Self.normalized(bucket.bytesUp, peak: peakUp)),
                width: .ratio(0.7)
            )
            // The fixed fill color, not the ink one (see `TrafficPalette`).
            .foregroundStyle(TrafficPalette.sentFill)
            .cornerRadius(2)
            .opacity(barOpacity(bucket.start, picked: picked))
            BarMark(
                x: .value("Time", bucket.start, unit: window.calendarUnit),
                // Negated so received draws downward from the shared baseline.
                y: .value("Received", -Self.normalized(bucket.bytesDown, peak: peakDown)),
                width: .ratio(0.7)
            )
            .foregroundStyle(TrafficPalette.receivedFill)
            .cornerRadius(2)
            .opacity(barOpacity(bucket.start, picked: picked))
        }
        .chartXScale(domain: xDomain)
        // Fixed, since both halves are normalized into -1...1.
        .chartYScale(domain: -1.0...1.0)
        .chartYAxis {
            // Only the zero rule, no labels. Same axis as the dashboard hero; the readout above
            // gives the totals.
            AxisMarks(values: [0.0]) {
                AxisGridLine().foregroundStyle(.secondary.opacity(0.4))
            }
        }
        .chartXAxis {
            // Same labels and thinning as the connections chart so both charts line up.
            AxisMarks(values: barLabelDates) { value in
                AxisValueLabel {
                    Text(value.as(Date.self).map(barLabel) ?? "")
                }
            }
        }
        .chartOverlay { proxy in pickOverlay(proxy, $pickedBytesBar) }
        // Unlike the dashboard, keep a spoken summary: the readout covers the totals, but the
        // peaks (which the normalized shape hides) aren't in text anywhere.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Data volume")
        // Totals first, then peaks, matching the connections chart's order.
        .accessibilityValue(
            "\(ByteFormat.volume(totalBytesUp)) sent and \(ByteFormat.volume(totalBytesDown)) received \(window.spokenSpan), peaking at \(ByteFormat.volume(peakUp)) sent and \(ByteFormat.volume(peakDown)) received in one \(window.calendarUnit == .hour ? "hour" : "day")"
        )
    }

    /// Maps bytes to 0...1 against the half's peak. An all-zero half stays flat.
    private static func normalized(_ value: UInt64, peak: UInt64) -> Double {
        peak == 0 ? 0 : Double(value) / Double(peak)
    }
}

/// One chart bucket, including empty ones.
///
/// `TimeBucketAggregate` can't be used for this: it has no public memberwise init, so
/// the zeros can't be built outside SharedCore. Internal because `zeroFilled` returns
/// these and the target sheet uses it.
struct ChartBucket: Identifiable {
    let start: Date
    let flows: Int
    let blockedFlows: Int
    let threatFlows: Int
    /// Kept separate for the mirror chart.
    let bytesUp: UInt64
    let bytesDown: UInt64
    var id: Date { start }

    /// nil row means a bucket the SQL didn't return, i.e. no traffic.
    init(start: Date, row: TrafficEventStore.TimeBucketAggregate?) {
        self.start = start
        self.flows = row?.flows ?? 0
        self.blockedFlows = row?.blockedFlows ?? 0
        self.threatFlows = row?.threatFlows ?? 0
        self.bytesUp = row?.bytesUp ?? 0
        self.bytesDown = row?.bytesDown ?? 0
    }
}

/// Per-target counts for the previous period, as far as they can be proven.
///
/// One ranking rollup over `priorSince..<priorUntil` (the window shifted back one
/// period, same elapsed time). `TargetAggregate` has both flows and denies, so one
/// query serves both ranking sections.
private struct PriorWindow {
    private var flows: [String: Int] = [:]
    private var blocked: [String: Int] = [:]
    /// Whether the lookup returned the whole previous period or was cut off at the limit.
    /// "New" depends on this (see `delta`).
    private var isComplete = false

    init() {}

    init(rows: [TrafficEventStore.TargetAggregate], limit: Int) {
        for row in rows {
            flows[row.target] = row.flows
            blocked[row.target] = row.blockedFlows
        }
        // Under the limit means the table covers the whole previous period, so absence means
        // no traffic. At the limit, absence only means "not in the top N".
        isComplete = rows.count < limit
    }

    func flowsDelta(for target: String, current: Int) -> InsightsDelta? {
        delta(current: current, previous: flows[target])
    }

    func blockedDelta(for target: String, current: Int) -> InsightsDelta? {
        delta(current: current, previous: blocked[target])
    }

    /// Known targets get a comparison. Unknown targets get "New", but only if the table
    /// is complete; otherwise the target may have just fallen past the limit, so no
    /// delta is shown.
    private func delta(current: Int, previous: Int?) -> InsightsDelta? {
        if let previous { return InsightsDelta(current: current, previous: previous) }
        return isComplete ? InsightsDelta(current: current, previous: 0) : nil
    }
}

// MARK: - Rule subject for a ranking row

/// What a swipe on a ranking row writes rules against.
///
/// Uses leaf semantics like `TargetLeaf.ruleSubject`, not the domain group's apex +
/// wildcard pair. Rollups group by `COALESCE(NULLIF(domain, ''), remote_ip)`, so each
/// row is one concrete host, and writing the pair would block the whole site.
/// Internal because the target sheet's button uses the same subject.
extension TrafficEventStore.TargetAggregate {
    /// The rule dimension, based on what the string actually is rather than which column
    /// it came from. Some sources put an address in `domain`, and `.domain("8.8.8.8")`
    /// would never match.
    ///
    /// Normalized (lowercased, trailing dot dropped) so the Rules page shows it the same
    /// way the dashboard does. Matching already normalizes, so this is cosmetic.
    var ruleTargets: [RuleTarget] {
        let name = RecentTargets.normalizedDomain(target)
        guard !name.isEmpty else { return [] }
        return IPAddress.parse(name) != nil ? [.ip(name)] : [.domain(name)]
    }

    var ruleSubject: TargetRuleSubject {
        TargetRuleSubject(
            targets: ruleTargets,
            // The name as shown on screen, for VoiceOver.
            name: target,
            // Differs from the dashboard's "From Recent targets" so these rules can be found by
            // searching notes on the Rules page.
            note: "From Insights",
            resolverOnlyBlocks: resolverOnlyBlocks
        )
    }

    /// True when every block on this row came from a resolver sink (not just some of
    /// them). Same test as the dashboard's `TargetStats.resolverOnlyBlocks`, using
    /// `TargetAggregate.resolverBlockedFlows`.
    ///
    /// Rows covered by a wildcard whose blocks came from the blocklist or a threat feed
    /// still get the Allow swipe, since an Allow there takes effect
    /// (`RuleTarget.derivedPriority`).
    var resolverOnlyBlocks: Bool {
        blockedFlows > 0 && resolverBlockedFlows == blockedFlows
    }
}

/// A ranked row showing only flag and name. No rank number, no meter, no figures.
///
/// Order conveys rank, matching the dashboard's rows. There's no level meter because
/// `MiniTrafficMeter` shows the last ten seconds, which means nothing next to a
/// rollup over days. The figures are in the sheet the row opens.
///
/// The row doesn't show its rule state visually (the Rules page and the swipe verb
/// do), but VoiceOver still gets it as the accessibility value.
private struct TargetRow: View {
    @Environment(AppModel.self) private var model
    let target: TrafficEventStore.TargetAggregate
    /// Country this target last connected to in the window, or nil if unknown (see
    /// `AppModel.insightsTargetCountries`). Passed in so the row and its sheet match.
    let countryCode: String?
    /// Opens the sheet. The whole row is a real Button rather than an `onTapGesture`
    /// on a container, which can fire two actions for one tap.
    let onTap: () -> Void

    var body: some View {
        let reading = TargetRuleReading(subject: target.ruleSubject, model: model)
        return Button(action: onTap) {
            row
        }
        .buttonStyle(.plain)
        // One VoiceOver element per row with the rule state as its value, like the
        // dashboard's `RowLabelButton`. Applied to the button so the stop keeps its button
        // trait. Reads country, name and state, same as a Live row. No change figure, since
        // the row doesn't show one.
        .accessibilityElement(children: .combine)
        .accessibilityValue(reading.spokenState)
    }

    /// The row content inside the button.
    private var row: some View {
        HStack(spacing: 8) {
            // Flag first, like Live Traffic rows. It adds location info without extra height.
            Text(CountryFlag.emoji(countryCode))
                // A flag emoji reads poorly in VoiceOver, so use the country name ("Unknown" for
                // the globe), as Live rows do.
                .accessibilityLabel(RecentTargets.countryName(countryCode))
            Text(target.target)
                .font(.callout.monospaced())
                .lineLimit(1)
                // Middle truncation like other identifiers in the app: both the start and the
                // registrable domain at the end matter.
                .truncationMode(.middle)
            // Keeps flag and name leading-aligned.
            Spacer(minLength: 6)
        }
        // Makes the whole row width tappable, not just the text.
        .contentShape(Rectangle())
    }
}
