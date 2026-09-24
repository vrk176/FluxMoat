import SharedCore
import SwiftUI

/// One target (a full hostname or a bare address) and the aggregate of its
/// flows. Flat, unlike the dashboard's eTLD+1 rollup; see `groupKey`. Rows
/// don't expand; per-connection detail is in `FlowDetailSheet`.
private struct FlowGroup: Identifiable {
    let id: String
    /// Display string, e.g. `cdn.photos.example` or `8.8.8.8`.
    let title: String
    /// The newest flow in the group. It supplies the flag, the target for swipe
    /// rules and the connection shown in the detail sheet. Newest rather than a
    /// consensus because the row describes where the target is talking now.
    /// The multi-country case is untested since mock GeoIP returns one address
    /// per domain.
    let newest: TrafficEvent
    /// Number of flows in the group after the current filter.
    let total: Int
    /// Summed over the same filtered flows, so under Blocked these are blocked bytes only.
    let bytesDown: UInt64
    let bytesUp: UInt64
    let blocked: Int
    /// Currently unused by any view. Kept as the count a "Threats" row would
    /// show, as the dashboard's target sheet does.
    let threats: Int
    /// Distinct remote ports and protocols across the filtered flows, so the
    /// sheet describes the target and doesn't flicker with each new sample.
    let ports: Set<UInt16>
    let protocols: Set<UInt8>
    /// Bytes per direction within the last `MiniTrafficMeter.windowSeconds`; the
    /// meter's only input. Distinct from `bytesUp`/`bytesDown`, which cover the
    /// whole buffer.
    let recentUp: UInt64
    let recentDown: UInt64

    /// nil is expected (private ranges, TEST-NET, new allocations);
    /// `CountryFlag.emoji` shows 🌐 for it.
    var countryCode: String? { newest.countryCode }
}

/// Blocks that no allow rule can undo. The DoH sinkhole acts after the rule
/// check has already allowed the CONNECT: only allowed connections reach the
/// resolver, and its sink answer turns them into a deny. User allow rules are
/// evaluated earlier in `CompiledRuleSet.evaluate`, so an allow for these
/// targets would appear on the Rules page and change nothing.
///
/// Every surface that offers Allow checks this first and hides the offer or
/// explains what works instead (changing the resolver). Lives next to
/// `FlowRow.isThreat` because several surfaces must read it the same way.
enum ResolverBlock {
    /// Whether a DoH resolver sank this flow. Both `.filteringResolver` (built-in
    /// threat preset) and `.customResolver` count: they're labeled differently
    /// but use the same sinking mechanism.
    static func sank(_ event: TrafficEvent) -> Bool {
        guard event.verdict == .deny else { return false }
        return event.verdictSource == .filteringResolver || event.verdictSource == .customResolver
    }

    /// Shared text for both sheets that explain this. Points to Settings, where
    /// choosing another resolver (or Off) actually unblocks the target.
    static let cannotAllowNote =
        "Blocked by your DNS resolver. Choose a different resolver in Settings to allow."
}

struct LiveTrafficView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    /// Under Reduce Motion rows still reorder, just without animation. Read by `applyOrder`.
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Read here rather than inside the sheet: a sheet's own content reports
    /// compact on iPad. See `adaptiveSheetDetents`.
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    /// Freezes a snapshot so rows stop moving while the user reads them; the
    /// stream continues underneath and catches up on resume. Freezes content,
    /// meter window and ranking: the tick skips re-ranking while paused as well
    /// as the clock.
    @State private var isPaused = false
    @State private var frozenFlows: [TrafficEvent] = []
    /// The tapped row, snapshotted at tap time. The sheet shows the target's totals
    /// and the newest connection.
    @State private var selectedGroup: FlowGroup?
    /// Row order: busiest first, with hysteresis so rows don't move between render
    /// and touch (a tap opens a sheet and a swipe writes a rule, so a moving row
    /// means acting on the wrong target).
    ///
    /// Rows are ranked by `MiniTrafficMeter.level` of their windowed bytes (0...6,
    /// each level 4× the previous), and the order is only recomputed when a row
    /// changes level. Within a level the previous order is kept, so normal jitter
    /// moves nothing. Idle rows sink together and keep their relative order.
    ///
    /// Seeded on appear and on filter change, re-ranked at most once a second
    /// (never while paused), with newcomers placed at the end of their level.
    /// See `syncGroupOrder`.
    @State private var groupOrder: [String] = []
    /// End of each row's meter window. A 1 Hz clock moves the window forward so
    /// meters decay to zero when traffic stops; otherwise nothing would redraw
    /// and the last level would stay lit.
    @State private var clock = Date()
    /// Captured together with `frozenFlows`. Frozen flows alone aren't enough:
    /// against a moving window they would still drain to zero while paused.
    /// Resume resets it to now (see the toolbar button).
    @State private var frozenClock = Date()

    private enum VerdictFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case blocked = "Blocked"
        case allowed = "Allowed"
        var id: String { rawValue }

        /// Written per case rather than derived from the segment label.
        var emptyTitle: String {
            switch self {
            case .all: "No traffic yet"
            case .blocked: "No blocked connections"
            case .allowed: "No allowed connections"
            }
        }
    }
    // SceneStorage so the filter survives re-pushing this page. Pause is
    // intentionally not persisted: re-entering should show the live feed.
    @SceneStorage("live.filter") private var filter: VerdictFilter = .all

    /// A plain list's opaque row background covers the brand gradient in dark
    /// mode, so clear it there. Light mode keeps the stock row.
    private var rowBackground: Color? {
        colorScheme == .dark ? .clear : nil
    }

    /// Frozen snapshot while paused, otherwise the live buffer.
    private var sourceFlows: [TrafficEvent] {
        isPaused ? frozenFlows : model.recentFlows
    }

    /// The clock meters are measured against, frozen or live. Always read with
    /// `sourceFlows`.
    private var sourceClock: Date {
        isPaused ? frozenClock : clock
    }

    private var displayedFlows: [TrafficEvent] {
        let base = sourceFlows
        switch filter {
        case .all: return base
        case .blocked: return base.filter { $0.verdict == .deny }
        case .allowed: return base.filter { $0.verdict == .allow }
        }
    }

    /// The target a flow is grouped under, or nil if it has neither name nor address.
    ///
    /// Uses the full observed name, not the registrable domain: `cdn.photos.example`
    /// is its own row. The dashboard's Recent targets provides the hierarchy, so
    /// `RecentTargets.registrableDomain` is intentionally not used here.
    /// `normalizedDomain` is reused for lowercasing and trailing-dot cleanup, and
    /// IP literals in the `domain` field are treated as addresses.
    private func groupKey(for event: TrafficEvent) -> String? {
        let name = RecentTargets.normalizedDomain(event.domain)
        if !name.isEmpty, IPAddress.parse(name) == nil {
            return "d/" + name
        }
        guard !event.remoteIP.isEmpty else { return nil }
        return "a/" + event.remoteIP
    }

    /// The filter is applied to flows first, so group counts always match what's
    /// listed, and a group with no matching flows has no row.
    private var flowGroups: [FlowGroup] { buildGroups(order: groupOrder) }

    /// Groups the displayed flows and lays them out in `order`. Separate from
    /// `flowGroups` so `syncGroupOrder` reads ids from the exact list being
    /// rendered. Mirrors `RecentTargets.build(from:order:)`.
    private func buildGroups(order: [String]) -> [FlowGroup] {
        // Explicitly newest first. `recentFlows` inserts each drain batch as a block,
        // so buffer position isn't strictly chronological. Offset breaks ties because
        // `sorted` isn't stable.
        let ordered = displayedFlows.enumerated()
            .sorted { a, b in
                a.element.timestamp == b.element.timestamp
                    ? a.offset < b.offset
                    : a.element.timestamp > b.element.timestamp
            }
            .map(\.element)

        // Fixed before the loop so every row is measured against the same window.
        //
        // A sliding window rather than a snapped grid: with a grid the newest bucket
        // ranges from 0 to 10 seconds old, so levels would climb and then drop to
        // zero at each rollover.
        //
        // No upper bound: the clock ticks at 1 Hz and drain batches arrive whenever,
        // so an event can be slightly newer than the clock and must still count.
        let meterWindowStart = sourceClock.addingTimeInterval(-MiniTrafficMeter.windowSeconds)

        var keys: [String] = []
        var buckets: [String: [TrafficEvent]] = [:]
        // Summed in the same pass as `buckets`, instead of each row rescanning the
        // 200-event buffer on every body pass.
        var recentUp: [String: UInt64] = [:]
        var recentDown: [String: UInt64] = [:]
        for event in ordered {
            guard let key = groupKey(for: event) else { continue }
            if buckets[key] == nil { keys.append(key) }
            buckets[key, default: []].append(event)
            if event.timestamp >= meterWindowStart {
                // Wrapping add, same as the totals below.
                recentUp[key, default: 0] &+= event.bytesUp
                recentDown[key, default: 0] &+= event.bytesDown
            }
        }
        // First appearance in a newest-first list gives most-recently-active first.
        // The drawn order comes from `seated(_:to:)` and `reranked(_:)` on top of that.
        let groups = keys.compactMap { key -> FlowGroup? in
            let flows = buckets[key] ?? []
            // `flows` is newest first, so its head is the newest event. Every key has at
            // least one event; the guard just unwraps the optional.
            guard let newest = flows.first else { return nil }
            let denied = flows.filter { $0.verdict == .deny }
            return FlowGroup(
                id: key,
                title: String(key.dropFirst(2)),
                newest: newest,
                total: flows.count,
                // Wrapping add. The values can't approach UInt64.max, but a body pass
                // shouldn't be able to trap.
                bytesDown: flows.reduce(0) { $0 &+ $1.bytesDown },
                bytesUp: flows.reduce(0) { $0 &+ $1.bytesUp },
                blocked: denied.count,
                threats: denied.filter(FlowRow.isThreat).count,
                // `compactMap` drops flows with no port (nil), which isn't the same as port 0.
                ports: Set(flows.compactMap(\.remotePort)),
                protocols: Set(flows.map(\.protocolNumber)),
                // Missing means no bytes in the window, i.e. a real zero.
                recentUp: recentUp[key] ?? 0,
                recentDown: recentDown[key] ?? 0
            )
        }
        return seated(groups, to: order)
    }

    /// Groups placed in the positions from the last ranking, newcomers appended.
    /// A pure lookup: the body pass never re-sorts, so rows only move when
    /// `groupOrder` is rewritten. Same idea as `RecentTargets.seated(_:to:)`.
    /// Since the caller re-ranks before storing the order, a newcomer settles at
    /// the end of its level.
    private func seated(_ groups: [FlowGroup], to order: [String]) -> [FlowGroup] {
        guard !order.isEmpty else { return groups }
        let rank = Dictionary(order.enumerated().map { ($0.element, $0.offset) }) { first, _ in first }
        let known = groups
            .filter { rank[$0.id] != nil }
            .sorted { (rank[$0.id] ?? 0) < (rank[$1.id] ?? 0) }
        return known + groups.filter { rank[$0.id] == nil }
    }

    /// Ranking key: the meter level of both directions summed. Each level is 4×
    /// the previous, so one row only overtakes another when it's clearly busier,
    /// and the change is visible in its meter at the same moment.
    private func rankLevel(_ group: FlowGroup) -> Int {
        MiniTrafficMeter.level(for: group.recentUp &+ group.recentDown)
    }

    /// Busiest level first; ties keep their current order. `sorted(by:)` isn't
    /// stable, so stability is enforced by tie-breaking on the original offset.
    /// That's what keeps rows that didn't change level in place.
    private func reranked(_ groups: [FlowGroup]) -> [FlowGroup] {
        groups.enumerated()
            .sorted { a, b in
                let left = rankLevel(a.element)
                let right = rankLevel(b.element)
                return left == right ? a.offset < b.offset : left > right
            }
            .map(\.element)
    }

    /// The set of targets with a row. The membership resync watches this rather
    /// than counts, which change on every sample. Built from `displayedFlows`, so
    /// it follows the filter and doesn't change while paused.
    private var presentGroupKeys: Set<String> {
        Set(displayedFlows.compactMap { groupKey(for: $0) })
    }

    /// Re-derives the order. With `reset` the current most-recent-first list is
    /// ranked from scratch; otherwise existing targets keep their place, new ones
    /// are appended (so they land at the end of their level), and targets no
    /// longer in the buffer are dropped. Called from the 1 Hz tick.
    private func syncGroupOrder(reset: Bool) {
        applyOrder(reranked(buildGroups(order: reset ? [] : groupOrder)).map(\.id))
    }

    /// Writes a new order with animation, only when it changed. This runs once a
    /// second, and an unconditional write would start an animation every tick.
    /// Uses a spring so reordering reads as one row overtaking another.
    private func applyOrder(_ next: [String]) {
        guard next != groupOrder else { return }
        withAnimation(reduceMotion ? nil : .spring(response: 0.38, dampingFraction: 0.82)) {
            groupOrder = next
        }
    }

    // No NavigationStack here: this is pushed onto the dashboard's stack, and
    // nesting another would break the back button and toolbar.
    var body: some View {
        // Computed once per body pass since it walks the whole buffer.
        let groups = flowGroups
        return Group {
            if groups.isEmpty {
                ContentUnavailableView(
                    filter.emptyTitle,
                    systemImage: "waveform.path.ecg",
                    description: Text(model.isProtectionOn
                        ? "Connections will appear here as they happen."
                        : "Turn on protection to observe traffic.")
                )
            } else {
                List {
                    ForEach(groups) { group in
                        LiveTargetRow(group: group) {
                            // Pass the whole group, not just its newest event, so the sheet's totals
                            // match the row. The sheet shows the target's totals and one real connection
                            // separately rather than a synthetic combined event.
                            selectedGroup = group
                        }
                        .swipeActions(edge: .trailing) {
                            // `ruleButton` targets the name if present, otherwise the address, which is
                            // the key this group was built on. Any flow in the group gives the same rule.
                            ruleButton(for: group.newest)
                        }
                        .listRowBackground(rowBackground)
                    }
                }
                .listStyle(.plain)
            }
        }
        .readableWidth()
        .brandDarkBackground()
        .navigationTitle("Live Traffic")
        // Inline title: the filter bar's inset leaves a gap where a large title would collapse.
        .navigationBarTitleDisplayMode(.inline)
        .safeAreaInset(edge: .top, spacing: 0) {
            VStack(spacing: 4) {
                Picker("Filter", selection: $filter) {
                    ForEach(VerdictFilter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                // iOS doesn't expose the source app, so the origin is always the whole device.
                // Placed under the picker so the segments aren't squeezed at large text sizes.
                Text("All traffic on this device")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
            .padding(.horizontal)
            // Constrained to the rows' column. The `.bar` material behind it still spans
            // the window.
            .readableWidth()
            .padding(.bottom, 6)
            .background(.bar)
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button(
                    isPaused ? "Resume updates" : "Pause updates",
                    systemImage: isPaused ? "play.fill" : "pause.fill"
                ) {
                    // Capture whatever the list is currently drawn from.
                    if isPaused {
                        // On resume, reset the window to now before unfreezing. `clock` isn't updated
                        // while paused, so the meters would otherwise draw one frame against a stale window.
                        clock = Date()
                        isPaused = false
                        // Re-rank immediately so resume shows a settled list instead of the old
                        // order followed by a reshuffle on the next tick.
                        syncGroupOrder(reset: false)
                    } else {
                        // Freeze content and window together; see `frozenClock`. Ranking stops too,
                        // since only the tick re-ranks.
                        frozenFlows = sourceFlows
                        frozenClock = clock
                        isPaused = true
                    }
                }
            }
        }
        .onAppear {
            // Rank from scratch on appear, unless paused. @State is rebuilt on push, so
            // the first appear always seeds.
            syncGroupOrder(reset: !isPaused)
        }
        // 1 Hz clock for the meters and the ranking. Advancing the window lets meters
        // decay to zero when a target goes quiet; otherwise its last level would stay
        // lit. Ranking uses the same tick so rows reorder in step with the levels on
        // screen. Both writes are skipped while paused. Cancelled with the view.
        .task {
            while !Task.isCancelled {
                if !isPaused {
                    clock = Date()
                    syncGroupOrder(reset: false)
                }
                try? await Task.sleep(for: .seconds(1))
            }
        }
        // Only when the set of targets changes: new targets need a slot at the end
        // of their level. Count changes are handled by the tick. Also covers targets
        // that changed during a pause, without reseeding the rows being read.
        .onChange(of: presentGroupKeys) { _, _ in
            syncGroupOrder(reset: false)
        }
        // A filter change produces a different set of rows, so reseed. Order relative
        // to the resync above doesn't matter; whichever runs second is a no-op.
        .onChange(of: filter) { _, _ in
            syncGroupOrder(reset: true)
        }
        .sheet(item: $selectedGroup) { group in
            FlowDetailSheet(group: group)
                .adaptiveSheetDetents(
                    [.medium, .large], regularWidth: horizontalSizeClass == .regular
                )
        }
    }

    /// Blocks an allowed flow's destination or re-allows a blocked one, targeting
    /// the domain if known, else the IP. Takes effect on the next connection.
    ///
    /// Replaces the target's existing rule rather than appending. Appending let
    /// Allow-then-Block leave both rules, and the engine resolves allow over deny,
    /// so the block never fired.
    @ViewBuilder
    private func ruleButton(for event: TrafficEvent) -> some View {
        let name = event.domain ?? event.remoteIP
        if event.verdict == .deny {
            // No Allow for a resolver sink: the rule would have no effect (see
            // `ResolverBlock`). The detail sheet explains why.
            if !ResolverBlock.sank(event) {
                Button {
                    model.addRule(for: event, action: .allow)
                } label: {
                    Label("Allow \(name)", systemImage: "checkmark.circle")
                }
                .tint(.green)
            }
        } else {
            Button(role: .destructive) {
                model.addRule(for: event, action: .deny)
            } label: {
                // Just the verb; a long domain would be truncated at swipe width. VoiceOver
                // keeps the name since it can't see which row is open.
                Text("Block")
            }
            .accessibilityLabel("Block \(name)")
        }
    }
}

/// One row per target with no inline controls; rules come from the swipe.
/// That lets the whole row be a single button and a single VoiceOver element.
private struct LiveTargetRow: View {
    let group: FlowGroup
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            HStack(spacing: 8) {
                // Show the flag rather than a name/address glyph: the identifier already
                // makes that distinction, and nothing else on the row shows the country.
                Text(CountryFlag.emoji(group.countryCode))
                    // VoiceOver reads a flag emoji poorly, so use the country name.
                    // `countryName` returns "Unknown" for a miss.
                    .accessibilityLabel(RecentTargets.countryName(group.countryCode))
                Text(group.title)
                    .font(.body.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer(minLength: 6)
                // Current activity rather than buffer totals: the totals are in the sheet,
                // and a live feed needs to show what's busy now. The meter ends the row.
                MiniTrafficMeter(bytesUp: group.recentUp, bytesDown: group.recentDown)
                // No chevron: the row opens a sheet, not a deeper level.
            }
            .padding(.vertical, 2)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        // VoiceOver still hears the block count the row doesn't show visually.
        .accessibilityValue(spokenBlocked)
        // No hint: the label and value already describe the row.
    }

    /// An empty string means VoiceOver reads no value.
    private var spokenBlocked: String {
        group.blocked > 0 ? "\(group.blocked) blocked" : ""
    }
}

/// Flow details plus allow/block actions for the domain and the IP
/// separately (the row's swipe only offers the best-guess target).
///
/// Two scopes on one page: totals, ports, protocols and connection counts
/// cover the whole target and match the row; address, country, decision and
/// time describe the newest connection. Each is labeled as such.
private struct FlowDetailSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let group: FlowGroup

    /// The connection described by the per-connection rows.
    private var event: TrafficEvent { group.newest }

    var body: some View {
        NavigationStack {
            List {
                // The target's totals, matching the tapped row.
                Section {
                    TrafficTotalsHeader(sent: group.bytesUp, received: group.bytesDown)
                        // The blocks are their own background, so drop the row's background and insets.
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                }

                Section {
                    LabeledContent("Destination") {
                        Text(event.domain ?? event.remoteIP)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                    }
                    if event.domain != nil {
                        LabeledContent("IP address") {
                            Text(event.remoteIP)
                                .font(.callout.monospaced())
                                .textSelection(.enabled)
                        }
                    }
                    if event.domain == nil, let inferred = event.inferredDomain {
                        LabeledContent("Likely domain") {
                            Text("~\(inferred)").italic()
                        }
                    }
                    if let country = event.countryCode {
                        // Flag plus full name rather than a bare country code.
                        LabeledContent("Country", value: "\(CountryFlag.emoji(country)) \(RecentTargets.countryName(country))")
                    }
                    // Target-scoped: every port and protocol seen in the buffer, not just the
                    // newest connection's. Omitted when none was seen (see `RecentTargets.portField`).
                    if let ports = RecentTargets.portField(group.ports) {
                        LabeledContent("Port", value: ports)
                    }
                    if let protocols = RecentTargets.protocolField(group.protocols) {
                        LabeledContent("Protocol", value: protocols)
                    }
                    // Target-scoped and filter-scoped. Blocked is shown with the total so the
                    // ratio is clear; under the Blocked filter the two are equal.
                    LabeledContent("Connections") {
                        Text("\(group.total)").foregroundStyle(.secondary)
                    }
                    LabeledContent("Blocked") {
                        // Red only when non-zero, since red means blocked. Plain `.red` even for
                        // threats; the threat is named in words under Decision.
                        Text("\(group.blocked)")
                            .foregroundStyle(group.blocked > 0 ? Color.red : Color.secondary)
                    }
                    LabeledContent("Decision", value: decisionText)
                    LabeledContent("Seen", value: event.timestamp.formatted(date: .omitted, time: .standard))
                } footer: {
                    if event.domain == nil, event.inferredDomain != nil {
                        Text("\u{201C}Likely domain\u{201D} means FluxMoat's resolver recently resolved this name to the IP. It is attribution only and never used for blocking decisions.")
                    }
                }

                Section {
                    if ResolverBlock.sank(event) {
                        // Replaces the section: every button here writes an allow, and an allow
                        // can't affect this flow. Block isn't offered instead, since no other denied
                        // flow gets a Block button; the swipe on Recent targets covers that.
                        Text(ResolverBlock.cannotAllowNote)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        if let domain = event.domain {
                            actionButton(target: .domain(domain), label: domain)
                        }
                        actionButton(target: .ip(event.remoteIP), label: event.remoteIP)
                    }
                } header: {
                    Text("Rules")
                } footer: {
                    // Only shown alongside buttons that write a rule.
                    if !ResolverBlock.sank(event) {
                        Text("A rule applies to future connections; this one was already \(event.verdict == .deny ? "blocked" : "allowed").")
                    }
                }
            }
            .navigationTitle("Connection")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private var decisionText: String {
        guard event.verdict == .deny else { return "Allowed" }
        switch event.verdictSource {
        case .filteringResolver: return "Blocked (threat, DNS resolver)"
        // Not labeled a threat: for a Custom resolver we know the mechanism, not the reason.
        case .customResolver: return "Blocked (DNS resolver)"
        case .threatFeed: return "Blocked (threat feed)"
        case .blocklist: return "Blocked (blocklist)"
        case .userRule: return "Blocked (your rule)"
        default: return "Blocked"
        }
    }

    /// Both actions replace the target's existing rule (`setUserRule`), so
    /// allow-then-block leaves only the block.
    @ViewBuilder
    private func actionButton(target: RuleTarget, label: String) -> some View {
        if event.verdict == .deny {
            Button {
                model.setUserRule(target: target, action: .allow, note: "From Live Traffic")
                dismiss()
            } label: {
                Label("Allow \(label)", systemImage: "checkmark.circle")
            }
        } else {
            Button(role: .destructive) {
                model.setUserRule(target: target, action: .deny, note: "From Live Traffic")
                dismiss()
            } label: {
                Label("Block \(label)", systemImage: "nosign")
            }
        }
    }
}

/// One connection event as a list row. The view currently has no callers;
/// the statics `isThreat` and `protocolName` are used across the app so
/// every surface agrees on what counts as a threat and how protocols are named.
struct FlowRow: View {
    let event: TrafficEvent
    /// No default so each call site decides explicitly.
    let detailVisible: Bool

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            // The flag stands in for the country code.
            Text(CountryFlag.emoji(event.countryCode))
            VStack(alignment: .leading, spacing: 2) {
                Text(event.domain ?? event.remoteIP)
                    .font(.body.monospaced())
                    .lineLimit(1)
                if detailVisible {
                    HStack(spacing: 6) {
                        // Inferred attribution: "~" plus italics means our resolver recently resolved
                        // this name to the IP, as opposed to an observed domain.
                        if event.domain == nil, let inferred = event.inferredDomain {
                            Text("~\(inferred)")
                                .italic()
                                .lineLimit(1)
                        }
                        if let port = event.remotePort {
                            Text(":\(String(port))")
                        }
                        Text(protocolName)
                        Text("↓\(ByteFormat.volume(event.bytesDown)) ↑\(ByteFormat.volume(event.bytesUp))")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
            Spacer()
            Text(badgeText)
                .font(.caption.weight(.semibold))
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(badgeColor.opacity(0.15), in: Capsule())
                .foregroundStyle(badgeColor)
        }
        .padding(.vertical, 2)
    }

    /// Both threat-intel layers count: the filtering resolver sinking a name and
    /// a local IOC feed hit. Matches the history SQL and the tunnel's threat counter.
    ///
    /// Static so the dashboard's Recent targets rollup uses the same rule.
    /// `nonisolated` because the rollup isn't main-actor isolated and this only
    /// reads fields of a Sendable struct.
    nonisolated static func isThreat(_ event: TrafficEvent) -> Bool {
        event.verdictSource == .filteringResolver || event.verdictSource == .threatFeed
    }

    private var isThreat: Bool { Self.isThreat(event) }

    private var badgeText: String {
        guard event.verdict == .deny else { return "Allowed" }
        return isThreat ? "Threat" : "Blocked"
    }

    /// Keyed off the same conditions as `badgeText` so word and color can't
    /// diverge. Threats use `BrandPalette.threat`.
    private var badgeColor: Color {
        guard event.verdict == .deny else { return .green }
        return isThreat ? BrandPalette.threat : .red
    }

    private var protocolName: String { Self.protocolName(event.protocolNumber) }

    /// `nonisolated` for the same reason as `isThreat`; `RecentTargets.protocolField`
    /// calls it from nonisolated code.
    nonisolated static func protocolName(_ number: UInt8) -> String {
        switch number {
        case 1: "ICMP"
        case 6: "TCP"
        case 17: "UDP"
        default: "#\(number)"
        }
    }
}
