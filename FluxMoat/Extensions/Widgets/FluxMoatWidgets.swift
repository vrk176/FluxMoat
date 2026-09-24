import SharedCore
import SwiftUI
import WidgetKit

/// Home and lock screen widgets showing protection state and today's counters.
/// Reads App Group data only: state from `WidgetStateStore`, counters from the
/// shared event store's rollup. Files are unreadable before first unlock, so
/// every read falls back to a placeholder instead of an error.

struct FluxMoatEntry: TimelineEntry {
    let date: Date
    let protectionOn: Bool?
    let flowsToday: Int
    let blockedToday: Int
    let threatsToday: Int
}

struct FluxMoatTimelineProvider: TimelineProvider {
    func placeholder(in context: Context) -> FluxMoatEntry {
        FluxMoatEntry(date: Date(), protectionOn: true, flowsToday: 1284, blockedToday: 37, threatsToday: 2)
    }

    func getSnapshot(in context: Context, completion: @escaping (FluxMoatEntry) -> Void) {
        completion(context.isPreview ? placeholder(in: context) : currentEntry())
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<FluxMoatEntry>) -> Void) {
        // 15 minutes stays within the WidgetKit refresh budget; the app also
        // reloads timelines when protection state changes.
        completion(Timeline(
            entries: [currentEntry()],
            policy: .after(Date(timeIntervalSinceNow: 15 * 60))
        ))
    }

    private func currentEntry() -> FluxMoatEntry {
        let state = WidgetStateStore.appGroup()?.read()

        var flows = 0, blocked = 0, threats = 0
        if let container = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: WidgetStateStore.appGroupID) {
            let store = TrafficEventStore(
                directoryURL: container.appendingPathComponent("Events", isDirectory: true))
            let midnight = Calendar.current.startOfDay(for: Date())
            if let today = try? store.bucketAggregates(
                bucketSeconds: 86_400,
                offsetSeconds: TimeZone.current.secondsFromGMT(),
                since: midnight
            ).last {
                flows = today.flows
                blocked = today.blockedFlows
                threats = today.threatFlows
            }
        }
        return FluxMoatEntry(
            date: Date(), protectionOn: state?.protectionOn,
            flowsToday: flows, blockedToday: blocked, threatsToday: threats
        )
    }
}

// MARK: - Views

struct FluxMoatWidgetView: View {
    @Environment(\.widgetFamily) private var family
    let entry: FluxMoatEntry

    var body: some View {
        switch family {
        case .accessoryCircular:
            circular
        case .accessoryRectangular:
            rectangular
        case .systemMedium:
            medium
        default:
            small
        }
    }

    private var shieldName: String {
        switch entry.protectionOn {
        case true: "shield.lefthalf.filled"
        case false: "shield.slash"
        case nil: "shield"
        }
    }

    private var stateText: String {
        switch entry.protectionOn {
        case true: "On"
        case false: "Off"
        case nil: "—"
        }
    }

    private var stateColor: Color {
        entry.protectionOn == true ? .green : .secondary
    }

    /// Copy of `BrandPalette.threat` (light and dark), since the widget target
    /// can't see App sources. Keep the two in sync.
    private static let threat = Color(uiColor: UIColor { trait in
        trait.userInterfaceStyle == .dark
            ? UIColor(red: 0.78, green: 0.54, blue: 1.00, alpha: 1)
            : UIColor(red: 0.55, green: 0.22, blue: 0.92, alpha: 1)
    })

    private var small: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: shieldName)
                    .foregroundStyle(stateColor)
                Text(stateText)
                    .font(.headline)
            }
            Spacer()
            Text("\(entry.blockedToday)")
                .font(.system(.title, design: .rounded).weight(.semibold))
                .foregroundStyle(entry.blockedToday > 0 ? .red : .secondary)
            Text("blocked today")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var medium: some View {
        HStack {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    Image(systemName: shieldName)
                        .foregroundStyle(stateColor)
                    Text(stateText)
                        .font(.headline)
                }
                Text("FluxMoat")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            statColumn("\(entry.flowsToday)", "connections")
            statColumn("\(entry.blockedToday)", "blocked",
                       tint: entry.blockedToday > 0 ? .red : .secondary)
            if entry.threatsToday > 0 {
                statColumn("\(entry.threatsToday)", "threats", tint: Self.threat)
            }
        }
    }

    private func statColumn(_ value: String, _ label: String, tint: Color = .primary) -> some View {
        VStack(spacing: 2) {
            Text(value)
                .font(.system(.title3, design: .rounded).weight(.semibold))
                .foregroundStyle(tint)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
                // Shrink "connections" slightly rather than wrap or clip.
                .lineLimit(1)
                .minimumScaleFactor(0.7)
        }
        .frame(minWidth: 52)
    }

    private var circular: some View {
        VStack(spacing: 2) {
            Image(systemName: shieldName)
            Text("\(entry.blockedToday)")
                .font(.system(.body, design: .rounded).weight(.semibold))
        }
    }

    private var rectangular: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 4) {
                Image(systemName: shieldName)
                Text("FluxMoat · \(stateText)")
                    .font(.headline)
            }
            // "connections" doesn't fit on this lock screen line, so it's omitted.
            Text("\(entry.blockedToday) blocked · \(entry.flowsToday) total")
                .font(.caption)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct FluxMoatStatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "FluxMoatStatus", provider: FluxMoatTimelineProvider()) { entry in
            FluxMoatWidgetView(entry: entry)
                .containerBackground(.fill.tertiary, for: .widget)
        }
        .configurationDisplayName("FluxMoat Status")
        .description("Protection state and today's blocked connections.")
        .supportedFamilies([.systemSmall, .systemMedium, .accessoryCircular, .accessoryRectangular])
    }
}

@main
struct FluxMoatWidgetBundle: WidgetBundle {
    var body: some Widget {
        FluxMoatStatusWidget()
    }
}
