import Charts
import SharedCore
import SwiftUI

/// The detail sheets opened by tapping an Insights row.
///
/// They render the aggregate the row already holds instead of re-querying, so a
/// sheet can never show a different total from the row behind it. Only the target
/// sparkline is fetched.

// MARK: - Selections

/// A tapped Trends ranking row, captured at tap time.
///
/// Carries the page's `since` instead of recomputing it. `InsightsWindow.since` snaps
/// to a bucket boundary, so recomputing near the top of an hour could shift the
/// sheet's window one bucket away from the totals on the page.
struct InsightsTargetSelection: Identifiable {
    let aggregate: TrafficEventStore.TargetAggregate
    /// The flag the row showed, passed through so the sheet can't disagree with it
    /// after a reload. nil means no country (globe).
    let countryCode: String?
    /// Change versus the prior period, as shown on the row. nil on All and when
    /// absence can't be proven (see `PriorWindow`).
    let delta: InsightsDelta?
    /// Label for the comparison baseline, e.g. "prior 7 days".
    let prior: String?
    let window: InsightsWindow
    /// Lower edge of the window from the page's last reload. nil for All.
    let since: Date?
    /// True when the row came from the New targets section.
    let isNew: Bool

    var id: String { aggregate.target }
}

/// A tapped country row. No `since`, since this sheet fetches nothing.
struct InsightsCountrySelection: Identifiable {
    let aggregate: TrafficEventStore.CountryAggregate
    /// Localized name shown on the row; nil for the no-country bucket.
    let name: String?
    let delta: InsightsDelta?
    let prior: String?
    let window: InsightsWindow

    /// Only the Unknown bucket has no code and there is exactly one, so "" is unique.
    var id: String { aggregate.countryCode ?? "" }
}

// MARK: - Shared fact rows

/// A label/value row for a count.
///
/// The number goes through `Text` interpolation, not a `String`, so it gets
/// grouping separators ("20,418" rather than "20418") like the rest of Insights.
private struct InsightsCountFact: View {
    let label: LocalizedStringKey
    let count: Int

    var body: some View {
        LabeledContent(label) {
            Text("\(count)").foregroundStyle(.secondary)
        }
    }
}

/// "Blocked  240". Red only when the count is non-zero; zero stays secondary.
/// Shared by both sheets so they stay consistent.
private struct InsightsBlockedFact: View {
    let count: Int

    var body: some View {
        LabeledContent("Blocked") {
            Text("\(count)").foregroundStyle(count > 0 ? Color.red : Color.secondary)
        }
    }
}

/// "Change  +240% vs prior 7 days", or nothing.
///
/// Spells out the baseline because the sheet has no section header to explain
/// "prior". Omitted on All and when the comparison can't be proven.
private struct InsightsChangeFact: View {
    let delta: InsightsDelta?
    let prior: String?

    var body: some View {
        if let prior, let text = delta?.headline(vs: prior) {
            LabeledContent("Change") {
                InsightsDeltaBadge(text: text, spoken: delta?.spoken(vs: prior))
            }
        }
    }
}

// MARK: - Trends: one target

/// One destination over the selected period: byte totals, counts, change versus
/// the prior period, and a sparkline.
///
/// The flag is passed in from the row (see `InsightsTargetSelection.countryCode`).
/// It comes from GeoIP on the last remote IP the target dialed, looked up in the app.
struct InsightsTargetSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let selection: InsightsTargetSelection

    /// Sparkline buckets, zero-filled onto the page's grid.
    @State private var buckets: [ChartBucket] = []
    /// Pinned x range so a few busy days in a long window still look sparse.
    @State private var xDomain: ClosedRange<Date> = Date()...Date()
    /// False until the sparkline query returns. Nothing else on the sheet loads.
    @State private var hasLoaded = false

    private var aggregate: TrafficEventStore.TargetAggregate { selection.aggregate }
    private var window: InsightsWindow { selection.window }

    var body: some View {
        NavigationStack {
            List {
                // Clear background and zero insets, matching the other traffic sheets.
                // The totals slabs draw their own background.
                Section {
                    TrafficTotalsHeader(sent: aggregate.bytesUp, received: aggregate.bytesDown)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                } header: {
                    // Every reading here is period-scoped, so state the period under the totals.
                    Text(window.annotation)
                }

                Section {
                    LabeledContent("Target") {
                        // Monospaced and selectable like the other sheets, but wrapped so a long
                        // hostname can be read in full.
                        Text(aggregate.target)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    // Flag plus name. The code is passed in, not looked up here.
                    LabeledContent(
                        "Country",
                        value: "\(CountryFlag.emoji(selection.countryCode)) \(RecentTargets.countryName(selection.countryCode))"
                    )
                    InsightsCountFact(label: "Connections", count: aggregate.flows)
                    InsightsBlockedFact(count: aggregate.blockedFlows)
                    InsightsChangeFact(delta: selection.delta, prior: selection.prior)
                } footer: {
                    // Same wording as the New targets section.
                    if selection.isNew {
                        Text(InsightsCopy.firstSeenInWindow)
                    }
                }

                Section {
                    sparkline
                } header: {
                    Text("Connections")
                }

                actions
            }
            .navigationTitle("Target")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        // Load once on appear. No refresh timer, so the sheet doesn't drift from the
        // row behind it.
        .task { await load() }
    }

    /// This target's connections over the window, allowed stacked under blocked.
    ///
    /// Two bands instead of the page's three: at this size a separate threat band is
    /// unreadable, and exact counts are shown above.
    @ViewBuilder
    private var sparkline: some View {
        if hasLoaded {
            Chart(buckets) { bucket in
                BarMark(
                    x: .value("Time", bucket.start, unit: window.calendarUnit),
                    y: .value("Connections", bucket.flows - bucket.blockedFlows)
                )
                .foregroundStyle(TrafficPalette.allowedFill)
                BarMark(
                    x: .value("Time", bucket.start, unit: window.calendarUnit),
                    y: .value("Connections", bucket.blockedFlows)
                )
                .foregroundStyle(Color.red)
            }
            // Same domain pinning as the page charts.
            .chartXScale(domain: xDomain)
            // Axes are hidden: the window and totals are printed above, and a date axis at
            // this height is just overlapping labels.
            .chartXAxis(.hidden)
            // Keep the zero baseline so a mostly-empty sparkline, or an empty one, still
            // reads as a chart rather than a blank card.
            .chartYAxis {
                AxisMarks(values: [0]) {
                    AxisGridLine().foregroundStyle(.secondary.opacity(0.4))
                }
            }
            .frame(height: 70)
            .padding(.vertical, 4)
            // Otherwise VoiceOver reads every bucket (up to 366). One summary sentence instead.
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Connections over time")
            .accessibilityValue(InsightsCopy.spokenTotals(
                flows: aggregate.flows, blocked: aggregate.blockedFlows, window: window
            ))
        } else {
            // Placeholder while loading, same as the Trends page.
            Rectangle()
                .fill(.secondary.opacity(0.15))
                .frame(height: 70)
                .padding(.vertical, 4)
                .redacted(reason: .placeholder)
                .accessibilityHidden(true)
        }
    }

    /// The same rule action the row's swipe offers.
    ///
    /// Uses the same `TargetRuleReading` as the swipe and its accessibility value, and
    /// the same writers. No confirmation, like other rule paths in the app.
    @ViewBuilder
    private var actions: some View {
        let subject = aggregate.ruleSubject
        // A flow with neither name nor address has nothing to write a rule against;
        // `.domain("")` would match nothing. Same guard as the row's swipe.
        if !subject.targets.isEmpty || aggregate.resolverOnlyBlocks {
            Section {
                if !subject.targets.isEmpty {
                    actionButton(TargetRuleReading(subject: subject, model: model), subject)
                }
                // Resolver-only blocks: explain them whether or not Allow is offered. When Allow
                // is still offered (the row also has its own deny), this is why allowing changes
                // less than it seems.
                if aggregate.resolverOnlyBlocks {
                    Text(ResolverBlock.cannotAllowNote)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder
    private func actionButton(
        _ reading: TargetRuleReading, _ subject: TargetRuleSubject
    ) -> some View {
        if reading.state == .deny {
            // Hidden when only the resolver blocks this target, as on the swipe: the rule
            // would be saved but have no effect.
            if !reading.allowIsDead {
                Button {
                    subject.release(model)
                    dismiss()
                } label: {
                    Text(reading.releaseVerb)
                }
                .tint(.green)
                // The button just says the verb; give VoiceOver the target name too.
                .accessibilityLabel("\(reading.releaseVerb) \(subject.name)")
            }
        } else {
            Button(role: .destructive) {
                subject.block(model)
                dismiss()
            } label: {
                Text("Block")
            }
            .accessibilityLabel("Block \(subject.name)")
        }
    }

    /// Fetches the sparkline off the main thread through the shared Insights query gate.
    private func load() async {
        let rows = await model.insightsTargetBuckets(
            target: aggregate.target,
            bucketSeconds: window.bucketSeconds,
            since: selection.since
        )
        guard !Task.isCancelled else { return }
        // Reuse the page's zero-fill with the same `since` the query used, so the grid
        // lines up with the rows.
        (buckets, xDomain) = HistoryView.zeroFilled(
            rows, window: window, since: selection.since
        )
        hasLoaded = true
    }
}

// MARK: - Map: one country

/// One country over the selected period, plus its block/unblock action.
///
/// This is the only place per-country counts are shown; the map row only has
/// flag, name and a meter. Bytes are split into sent and received, like the
/// target sheet.
///
/// Presented docked below the map panel instead of at `.medium` so it doesn't
/// cover the country the map frames (see `WorldMapView`).
///
/// No per-country target list: the store has no country column (GeoIP never runs
/// in the tunnel), so it would mean geolocating every address in the window.
struct InsightsCountrySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let selection: InsightsCountrySelection

    private var aggregate: TrafficEventStore.CountryAggregate { selection.aggregate }

    var body: some View {
        NavigationStack {
            List {
                // Clear background and zero insets, same as the target sheet. Sent and received
                // come straight from `CountryAggregate`, the same aggregate the row holds.
                Section {
                    TrafficTotalsHeader(sent: aggregate.bytesUp, received: aggregate.bytesDown)
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                } header: {
                    // Every reading here is period-scoped.
                    Text(selection.window.annotation)
                }

                Section {
                    InsightsCountFact(label: "Connections", count: aggregate.flows)
                    InsightsBlockedFact(count: aggregate.blockedFlows)
                    InsightsChangeFact(delta: selection.delta, prior: selection.prior)
                }

                policy
            }
            // Flag and name, matching the row and map marker.
            .navigationTitle("\(CountryFlag.emoji(aggregate.countryCode)) \(selection.name ?? RecentTargets.unknownCountryName)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    /// Block or Unblock, or the reason neither is offered.
    ///
    /// Country policies only block; there is no country allow, since it would exempt
    /// a whole country from the blocklist and threat feed.
    @ViewBuilder
    private var policy: some View {
        if let subject = aggregate.ruleSubject {
            let reading = TargetRuleReading(subject: subject, model: model)
            Section {
                if reading.state == .deny {
                    // Red, like every other "blocked" in the app.
                    LabeledContent("Policy") {
                        Text("Blocked").foregroundStyle(.red)
                    }
                    Button {
                        subject.release(model)
                        dismiss()
                    } label: {
                        Text(reading.releaseVerb)
                    }
                    .tint(.green)
                    .accessibilityLabel("\(reading.releaseVerb) \(subject.name)")
                } else {
                    Button(role: .destructive) {
                        subject.block(model)
                        dismiss()
                    } label: {
                        Text("Block")
                    }
                    .accessibilityLabel("Block \(subject.name)")
                }
            } footer: {
                Text(InsightsCopy.countryEstimate)
            }
        } else {
            // No action for the no-country bucket: GeoIP misses have nothing in common, so a
            // rule over them makes no sense. Same reason `RecentTargets.groupingCode` excludes
            // it. Individual flows are still reachable in Live Traffic.
            Section {
                Text("These addresses could not be placed, and they have nothing in common with each other — so there is no single rule to write for them.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } footer: {
                Text(InsightsCopy.countryEstimate)
            }
        }
    }
}
