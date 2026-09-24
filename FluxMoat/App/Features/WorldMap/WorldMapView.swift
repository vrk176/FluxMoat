import Combine
import MapKit
import SharedCore
import SwiftUI
import UIKit

/// World map of traffic aggregated by GeoIP country, built from SQL rollups (never
/// raw rows). Countries are pinned at their centroid. Countries without a centroid,
/// and the no-country bucket (private ranges, unresolved IPs), still appear in the
/// list so the totals match the store.
struct WorldMapView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    /// Used only to detect landscape (see `panelWidthChanged`). On iPhone this only
    /// happens in full screen.
    @Environment(\.verticalSizeClass) private var verticalSizeClass
    /// Regular width affects the map card's column and height, the page background,
    /// whether full screen fits the pins, and whether exiting full screen waits for a
    /// rotation. It does not affect the country sheet's detent (see `dockedDetent`).
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass

    /// Only dark mode uses the brand styling for now.
    private var isDark: Bool { colorScheme == .dark }

    /// Owned by the Insights shell so Map and Trends share one window. The country
    /// rollup only needs a lower bound, and the camera ignores the window
    /// (see `aimIfNeeded`).
    @Binding var window: InsightsWindow

    /// Whether Map (rather than Trends) is the visible surface.
    ///
    /// The shell keeps both surfaces mounted, so `onAppear` fires on entering the
    /// Insights tab, not on opening the map. This gates the location prompt and the
    /// per-flow GeoIP work in `liveCountries`.
    let isActive: Bool
    /// Whether the map is actually visible: `isActive` and the Insights tab on screen.
    ///
    /// Kept as state because `releaseFocus` runs from the sheet's `onDismiss` closure,
    /// which captured `isActive` before the switch. On a switch to Trends that captured
    /// value is still `true` while this is already `false`.
    @State private var onScreen = false

    @State private var aggregates: [TrafficEventStore.CountryAggregate] = []
    /// Connections per country in the previous period, for the delta badges. Empty on All.
    /// The country rollup has no LIMIT, so this is complete and a missing country really
    /// is new.
    @State private var priorFlows: [String?: Int] = [:]
    /// Connections this period vs last, for the list header.
    @State private var connectionsDelta: InsightsDelta?
    /// False until the first rollup returns, so the empty state doesn't flash before rows
    /// arrive.
    @State private var hasLoaded = false
    /// Part of the `.task` id, incremented by `refreshTick`.
    @State private var refreshCount = 0
    /// The tapped country row, or nil. Carries the row's own aggregate so the sheet shows
    /// the same totals.
    @State private var selectedCountry: InsightsCountrySelection?
    /// The country the map is focused on while its sheet is open, uppercased. When set,
    /// only the arc to this country is drawn; pins and labels stay.
    ///
    /// Separate from `selectedCountry` because the Unknown bucket opens a sheet but has
    /// no centroid to focus on.
    @State private var focusedCode: String?
    /// The panel's camera when focus began, restored on dismiss. Uses `liveCamera` because
    /// a `MapCamera` can't be read back out of a user-positioned `MapCameraPosition`.
    @State private var cameraBeforeFocus: MapCamera?
    /// `camera` when focus began. Only used when `cameraBeforeFocus` is nil (MapKit hadn't
    /// reported a frame yet), in which case this is still the opening `.camera(…)`.
    @State private var positionBeforeFocus: MapCameraPosition?
    /// Sticky "user has moved the map" flag. `camera.positionedByUser` only reflects the
    /// current binding value, and a focus round trip writes it twice, which resets it.
    /// Without this, the aim logic could re-aim a map the user had positioned.
    /// Set when focus begins and never cleared.
    @State private var userPositionedMap = false
    /// Arc origin (approximate device location). nil if denied or no fix yet; the map
    /// then shows pins only and never prompts again.
    @State private var origin = MapOriginLocator()
    /// How good the opening aim is. Location and pins can both arrive after the first
    /// frame, so the camera starts on the fallback and upgrades. Each step fires at most
    /// once, never downgrades, and stops once the user moves the map. See `aimIfNeeded`.
    private enum Aim: Int, Comparable {
        case fallback, centroid, origin
        static func < (lhs: Aim, rhs: Aim) -> Bool { lhs.rawValue < rhs.rawValue }
    }

    @State private var aim: Aim = .fallback
    /// A binding rather than an initial value so the aim can move the camera after the
    /// first frame, and so MapKit can report `positionedByUser`.
    @State private var camera: MapCameraPosition = .camera(WorldMapView.fallbackOpeningCamera)
    /// Recency cutoff for arcs. `recentFlows` only re-renders the map while traffic is
    /// flowing, so without a timer arcs would stay green after it stops. Updated on
    /// `refreshTick`, the same tick as the country list.
    @State private var clock = Date()

    /// Whether the map is full screen. The cover renders the same `MapCanvas`; this only
    /// changes the frame, orientation and corner button direction.
    @State private var isFullScreen = false
    /// Full screen has its own camera, seeded on entry (see `enterFullScreen`): on regular
    /// width from a region fitting all pins, otherwise from `liveCamera`. Sharing `camera`
    /// would move the panel map behind the cover while panning.
    @State private var fullScreenCamera: MapCameraPosition = .automatic
    /// The panel's current camera as reported by MapKit. The `camera` binding can't give
    /// this back once the user has panned. Used to restore after focus and to seed full
    /// screen.
    @State private var liveCamera: MapCamera?
    /// True from dismissing full screen until the page is back in portrait. The panel map
    /// stays unmounted during that time (see `panelWidthChanged`).
    @State private var restoringPanel = false
    /// Panel width in portrait. Landscape is wider, so this is also used to detect when
    /// the rotation back has finished.
    @State private var portraitPanelWidth: CGFloat = 0
    /// Width available to the map card, before its insets. Kept separate from
    /// `portraitPanelWidth`, which is only for the rotation check.
    @State private var panelContainerWidth: CGFloat = 0
    /// Bottom edge of the map panel in window coordinates, where the country sheet's top
    /// should sit. 0 until measured (see `dockedDetent`).
    ///
    /// Also updates while Trends is showing and the map is at opacity 0, where layout
    /// differs slightly. That's fine: it's only read when presenting the sheet, and
    /// becoming visible re-measures it.
    @State private var mapPanelBottom: CGFloat = 0
    /// Correction added to "window height minus map bottom" so the sheet actually lands
    /// on the map's bottom edge, learned from the sheet itself.
    ///
    /// A `.height` detent isn't a position: iOS insets and slightly scales the sheet
    /// inside its detent (100 pt of detent moved the top edge 96 pt in testing), so the
    /// plain calculation lands about 23 pt too high. These values vary by device and OS,
    /// so they're measured rather than hardcoded. See `dockLanded`.
    @State private var dockSlack: CGFloat = 0
    /// True once the sheet's top edge matches the map's bottom edge. No more measuring
    /// after that.
    @State private var dockCalibrated = false

    /// How recently a country must have had traffic for its arc to show as live. Long
    /// enough not to flicker during brief pauses, short enough to go grey soon after.
    private static let liveWindow: TimeInterval = 60

    /// Single refresh tick for arcs and the country list, same 15 s cadence as the
    /// dashboard, so they can't disagree.
    ///
    /// With a 60 s `liveWindow`, arcs can turn grey up to 15 s late. Keeps running while
    /// Trends or another tab is showing, since the shell keeps this view mounted.
    private let refreshTick = Timer.publish(every: 15, on: .main, in: .common).autoconnect()

    /// Camera distance for the opening frame: zoomed out as far as MapKit allows.
    ///
    /// A full-globe frame isn't possible (undocumented, measured). `.rect(.world)` gives a
    /// 141.3° wide view. A camera 100,000 km up clamps to 39,806,233 m, which is 164.3° of
    /// longitude by 108.9° of latitude, for the standard style flat or not. So request one
    /// Earth circumference and take the clamp.
    ///
    /// Since 164° isn't 360°, the center matters; it follows the user's data
    /// (`aimIfNeeded`) so, for example, a user in Singapore doesn't open on the Atlantic.
    private static let openingDistance: CLLocationDistance = 40_000_000

    /// Max latitude a data-driven center may use. Uncapped, a fix in Reykjavík would open
    /// mostly on the Arctic.
    private static let openingLatitudeLimit: CLLocationDegrees = 25

    /// Fallback center when there's no fix and no pins. At −35° the 164° view holds both
    /// Americas, Europe, Africa and western Asia, and it's as far west as you can go
    /// while keeping Africa whole. The Pacific rim doesn't fit from here.
    private static let fallbackOpeningCamera = openingCamera(
        centeredOn: CLLocationCoordinate2D(latitude: 15, longitude: -35)
    )

    /// Opening frame at a different center. Distance stays at the maximum; latitude is
    /// clamped to `openingLatitudeLimit`.
    private static func openingCamera(centeredOn coord: CLLocationCoordinate2D) -> MapCamera {
        MapCamera(
            centerCoordinate: CLLocationCoordinate2D(
                latitude: min(max(coord.latitude, -openingLatitudeLimit), openingLatitudeLimit),
                longitude: coord.longitude
            ),
            distance: openingDistance
        )
    }

    /// Countries with a flow inside `liveWindow`, keyed like the pins (GeoIP on the remote
    /// IP). The store saves `countryCode` as nil and geo is merged on read, so the event's
    /// own country field is only a fallback.
    private var liveCountries: Set<String> {
        // Skip while hidden: this runs on every update of the live flow buffer, which is often.
        guard isActive else { return [] }
        let cutoff = clock.addingTimeInterval(-Self.liveWindow)
        var seenIPs: Set<String> = []
        var codes: Set<String> = []
        for flow in model.recentFlows where flow.timestamp >= cutoff {
            // One lookup per distinct IP, not per flow.
            guard seenIPs.insert(flow.remoteIP).inserted else { continue }
            if let code = GeoIPService.shared.countryCode(for: flow.remoteIP) ?? flow.countryCode {
                codes.insert(code.uppercased())
            }
        }
        return codes
    }

    /// Bytes per country over the last `MiniTrafficMeter.windowSeconds`, for the row meters.
    ///
    /// Uses the same grouping key (`RecentTargets.groupingCode`), accumulator
    /// (`TargetStats.absorb`) and window as the dashboard, so the meter means the same
    /// thing on every screen. Unlike the dashboard, the nil (no-country) key is kept,
    /// because the map lists an Unknown row.
    ///
    /// Windowed against `Date()`, not `clock`: `clock` can be up to 15 s old, which is
    /// fine for a 60 s cutoff but not for a 10 s meter.
    ///
    /// Skipped while hidden, like `liveCountries`; reading `model.recentFlows` subscribes
    /// to every live buffer update.
    private var recentByCountry: [String?: TargetStats] {
        guard isActive else { return [:] }
        let windowStart = Date().addingTimeInterval(-MiniTrafficMeter.windowSeconds)
        var stats: [String?: TargetStats] = [:]
        for flow in model.recentFlows {
            stats[RecentTargets.groupingCode(flow), default: TargetStats()]
                .absorb(flow, meterWindowStart: windowStart)
        }
        return stats
    }

    private var pinned: [MapPin] {
        let live = liveCountries
        return aggregates.compactMap { agg in
            guard let code = agg.countryCode,
                  let coord = CountryCentroids.coordinate(for: code) else { return nil }
            return MapPin(code: code, coord: coord, agg: agg, isLive: live.contains(code.uppercased()))
        }
    }

    /// Extra horizontal inset to keep the map in the same column `readableWidth()` uses
    /// for the rows. Zero at compact width. The math lives in `ReadableWidth` so both
    /// stay in sync.
    private var readableInset: CGFloat {
        guard horizontalSizeClass == .regular else { return 0 }
        return ReadableWidth.inset(in: panelContainerWidth)
    }

    /// Map card height: 320 on phones (the docked sheet was tuned for this). On regular
    /// width it scales with the card's width, capped so the country rows stay on screen.
    private var panelHeight: CGFloat {
        guard horizontalSizeClass == .regular else { return Self.compactPanelHeight }
        let cardWidth = panelContainerWidth - 2 * (Self.panelCardInset + readableInset)
        guard cardWidth > 0 else { return Self.compactPanelHeight }
        return min(Self.regularPanelHeightCeiling, cardWidth * Self.regularPanelAspect)
    }

    /// Card margin, matching an inset-grouped list. Must match the padding below, or the
    /// height is computed from the wrong width.
    private static let panelCardInset: CGFloat = 20
    private static let compactPanelHeight: CGFloat = 320
    private static let regularPanelHeightCeiling: CGFloat = 640
    private static let regularPanelAspect: CGFloat = 0.6

    var body: some View {
        let pins = pinned
        VStack(spacing: 0) {
            // Opens on the world view (see `openingDistance`) rather than fitting the current
            // pins, so the camera doesn't re-aim on every window change. The binding only carries
            // the opening aim (see `aimIfNeeded`); user pan/zoom and reloads don't move it.
            ZStack(alignment: .bottomTrailing) {
                if isFullScreen || restoringPanel {
                    // The panel map only exists while the page is portrait and not covered. A `Map` laid
                    // out too wide exceeds MapKit's zoom-out limit, gets clamped, and never recovers
                    // (a world view at 39,806,233 m came back at 15,392,655 m after one round trip).
                    //
                    // `isFullScreen` covers going to full screen (it flips before the rotation).
                    // `restoringPanel` covers coming back: the size class and `isFullScreen` both change
                    // at the start of the rotation while the window is still wide, so
                    // `panelWidthChanged` waits for the width instead.
                    Color.clear
                } else {
                    MapCanvas(
                        position: $camera,
                        pins: pins,
                        origin: origin.coordinate,
                        focusedCode: focusedCode,
                        // Record each settled frame so full screen knows where the panel is. Only the panel
                        // reports.
                        onCameraChange: { liveCamera = $0 }
                    )
                    MapCornerToggle(isFullScreen: false, action: { enterFullScreen(fitting: pins) })
                }
            }
            .frame(maxHeight: panelHeight)
            // Clipped and inset so the map is a card lined up with the rows below. 10 pt radius
            // and 20 pt margin match UIKit's inset-grouped list on iPhone.
            //
            // Don't raise the radius to 16: MapKit's legal attribution sits near the bottom-left
            // corner and a larger radius clips it. The clip uses a shape so a shorter panel still
            // gets its own corners.
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            // Plus the extra inset on regular width, so the card lines up with the rows.
            .padding(.horizontal, Self.panelCardInset + readableInset)
            // Top only; the list below already has section spacing.
            .padding(.top, 8)
            // Measured outside the padding. `panelWidthChanged` only compares against a portrait
            // width measured the same way, so the comparison stays consistent.
            .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { panelWidthChanged($0) }
            // Same value, stored separately: `portraitPanelWidth` is only for the rotation check.
            // This one sizes the card.
            .onGeometryChange(for: CGFloat.self) { $0.size.width } action: { panelContainerWidth = $0 }
            // Where the map's bottom edge lands, for docking the country sheet. Measured because
            // it depends on bars, Dynamic Island, Dynamic Type and width. Global coordinates
            // because the sheet is laid out in the window.
            .onGeometryChange(for: CGFloat.self) { $0.frame(in: .global).maxY } action: {
                mapBottomChanged($0)
            }

            countries
                .readableWidth()
        }
        // Page background behind the whole surface. This half is a VStack, not a List, so
        // otherwise only the rows paint the grouped background. On regular width the card
        // is inset a lot and the gap would be plain white. Light mode only; dark already has
        // the brand gradient from the shell.
        .background {
            if !isDark, horizontalSizeClass == .regular {
                Color(uiColor: .systemGroupedBackground).ignoresSafeArea()
            }
        }
        // The same canvas, full screen and landscape. The cover has no navigation bar, so
        // the mode switch and period picker stay on the shell.
        //
        // `pins` is recomputed on every `clock` tick, so arcs in the cover age along with the
        // panel's.
        .fullScreenCover(isPresented: $isFullScreen) {
            ZStack(alignment: .bottomTrailing) {
                // Never focused: focus comes from tapping a country row, and the cover has no rows.
                MapCanvas(
                    position: $fullScreenCamera, pins: pins,
                    origin: origin.coordinate, focusedCode: nil
                )
                    // Only the map ignores safe areas; the button is a sibling and stays inside them.
                    .ignoresSafeArea()
                MapCornerToggle(isFullScreen: true, action: exitFullScreen)
            }
            // Request the rotation here, not in the button. `requestGeometryUpdate` can rotate
            // synchronously inside the button action, before SwiftUI removes the panel map; the
            // panel map would then get clamped at landscape width and write that back through
            // the binding. By `onAppear`, the page has already rendered without it.
            .onAppear { Self.allowLandscape(true) }
            // Always release the landscape mask, however the cover is dismissed.
            .onDisappear { Self.allowLandscape(false) }
        }
        // Reload off the main thread, keyed on window and tick. Old aggregates stay on screen
        // while the new window loads so the pins don't disappear and refill.
        .task(id: ReloadKey(window: window, tick: refreshCount)) { await reload() }
        // Docked under the map instead of half-height like other detail sheets, because the
        // map shows the answer: it frames the user's location and this country with the
        // other arcs hidden. The resting detent is measured from the window bottom to the
        // map panel's bottom. Swiping up still gives a normal `.large` sheet.
        //
        // Background interaction up through that detent keeps the map live (no dimming,
        // arcs still update, pan and zoom work). At `.large` the default behavior returns.
        .sheet(item: $selectedCountry, onDismiss: releaseFocus) { selection in
            InsightsCountrySheet(selection: selection)
                .presentationDetents([dockedDetent, .large])
                .presentationBackgroundInteraction(.enabled(upThrough: dockedDetent))
                // The sheet's top edge in window coordinates, to check the docked height against the
                // map's bottom edge. `ignoresSafeArea` to measure the card, not its content. See
                // `dockLanded`.
                .background(
                    Color.clear
                        .ignoresSafeArea()
                        .onGeometryChange(for: CGFloat.self) { $0.frame(in: .global).minY }
                            action: { dockLanded(at: $0) }
                )
        }
        .onAppear {
            // Set here too: `Timer` doesn't fire on subscribe, so without this the first frame
            // after appearing would use a stale `clock` and old arcs could still show green.
            clock = Date()
            onScreen = isActive
            aimIfNeeded()
            // Only when Map is visible. `onAppear` fires on entering the Insights tab, and a user
            // reading Trends shouldn't get a location prompt.
            if isActive { origin.request() }
        }
        // Fires when leaving the Insights tab. Switching Trends/Map doesn't (see
        // `onChange(of: isActive)`), and neither does the full-screen cover. The country
        // sheet allows background interaction, so it could otherwise outlive the surface
        // under it. The tab bar is currently under the docked sheet so this can't be hit by
        // hand, but the sheet's lifetime shouldn't depend on that.
        .onDisappear {
            onScreen = false
            selectedCountry = nil
        }
        // Ask for location the first time the map is shown. `MapOriginLocator.request()` is
        // a no-op once the system has an answer.
        .onChange(of: isActive) {
            onScreen = isActive
            guard isActive else {
                // Switching to Trends doesn't remove this view, so dismiss the country sheet
                // explicitly. `releaseFocus` then runs from the sheet's `onDismiss` and restores the
                // arcs and camera.
                selectedCountry = nil
                return
            }
            clock = Date()
            origin.request()
        }
        // Arcs read `clock` and the list reads `aggregates`; update both on the same tick.
        .onReceive(refreshTick) { _ in
            clock = Date()
            refreshCount &+= 1
        }
        // Re-aim when aggregates change (the location fix is handled separately). This fires
        // every 15 s, which is safe: `aimIfNeeded` returns early once the user has moved the
        // map and each aim step only fires once.
        .onChange(of: aggregates) { aimIfNeeded() }
        .onChange(of: originKey) { aimIfNeeded() }
    }

    /// The country list, or why there isn't one. Same empty-state treatment as Live
    /// Traffic, including the protection-off message.
    ///
    /// Unlike Live Traffic, the map above stays visible in all states, since it still
    /// shows the world and the user's location without any data.
    @ViewBuilder
    private var countries: some View {
        if model.storeUnavailable {
            // Separate from the empty case: an unreadable store isn't the same as a quiet period.
            ContentUnavailableView(
                "History unavailable",
                systemImage: "exclamationmark.triangle",
                description: Text(InsightsCopy.storeUnreadable)
            )
        } else if !hasLoaded {
            // Placeholder while the first rollup loads, so a cold open doesn't flash the empty
            // state. Same as Trends.
            countriesPlaceholder
        } else if aggregates.isEmpty {
            ContentUnavailableView(
                "No traffic in this period",
                systemImage: "globe",
                description: Text(model.isProtectionOn
                    ? "Countries appear here as traffic is observed."
                    : "Turn on protection to observe traffic.")
            )
        } else {
            // Compute once per body pass, not per row, to avoid walking the live buffer per country.
            let recent = recentByCountry
            List {
                Section {
                    ForEach(aggregates, id: \.countryCode) { agg in
                        let name = agg.countryCode.map(countryName)
                        let rowDelta = delta(for: agg)
                        let row = CountryRow(
                            agg: agg,
                            name: name,
                            recent: recent[agg.countryCode?.uppercased()] ?? TargetStats(),
                            delta: rowDelta,
                            prior: window.priorAnnotation
                        ) {
                            // Start the camera move first so it runs while the sheet slides up.
                            focusMap(on: agg)
                            // Unknown opens a sheet too (it has totals and a meter), but offers no action.
                            selectedCountry = InsightsCountrySelection(
                                aggregate: agg,
                                name: name,
                                delta: rowDelta,
                                prior: window.priorAnnotation,
                                window: window
                            )
                        }
                        // `swipeActions` must be on the cell, which is what this ForEach produces. No swipe
                        // for the Unknown bucket.
                        if let subject = agg.ruleSubject {
                            row.targetRuleSwipe(subject)
                        } else {
                            row
                        }
                    }
                } header: {
                    // Show the window in the header since this list is scoped by it and the toolbar may
                    // be out of mind. No delta on All.
                    //
                    // Short delta form here, unlike Trends: the header already names the period, and the
                    // long form overflows at 24h.
                    if let prior = window.priorAnnotation,
                       let text = connectionsDelta?.short {
                        HStack {
                            Text("Countries · \(window.annotation)")
                            Spacer()
                            // Short on screen, full sentence for VoiceOver.
                            InsightsDeltaBadge(
                                text: text, spoken: connectionsDelta?.spoken(vs: prior)
                            )
                        }
                    } else {
                        Text("Countries · \(window.annotation)")
                    }
                } footer: {
                    // Shared with the country sheet (see `InsightsCopy.countryEstimate`).
                    Text(InsightsCopy.countryEstimate)
                }
                // The shell hides the list's scroll background for the gradient; without card rows
                // they'd stay opaque grey.
                .brandCardRows(isDark)
            }
        }
    }

    /// Redacted skeleton for the list while the first rollup loads. The strings only set
    /// the width of the redaction bars.
    private var countriesPlaceholder: some View {
        List {
            Section("Countries · \(window.annotation)") {
                ForEach(0..<5, id: \.self) { _ in
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Placeholder country")
                        Text("000 connections · 0 KB")
                            .font(.caption)
                    }
                }
            }
            .brandCardRows(isDark)
        }
        .redacted(reason: .placeholder)
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    /// Identifies a reload. `.task(id:)` won't rerun for an equal key.
    private struct ReloadKey: Equatable {
        let window: InsightsWindow
        let tick: Int
    }

    /// Loads the country rollup, and the prior-period rollup on bounded windows, off the
    /// main thread. One clock read for both via `bounds(now:)` so the periods line up.
    private func reload() async {
        let bounds = window.bounds()
        let since = bounds?.since
        let rows = await model.insightsCountries(since: since)

        var previous: [String?: Int] = [:]
        var totalDelta: InsightsDelta?
        if let bounds {
            // Up to `priorUntil`, not `since`: the prior period covers the same elapsed time.
            // Trends computes its deltas the same way (see `InsightsWindow.bounds`).
            let priorRows = await model.insightsCountries(
                since: bounds.priorSince, until: bounds.priorUntil)
            for row in priorRows { previous[row.countryCode] = row.flows }
            totalDelta = InsightsDelta(
                current: rows.reduce(0) { $0 + $1.flows },
                previous: priorRows.reduce(0) { $0 + $1.flows }
            )
        }

        // `.task(id:)` cancels this if the window changed during the awaits. Don't write
        // stale results.
        guard !Task.isCancelled else { return }
        aggregates = rows
        priorFlows = previous
        connectionsDelta = totalDelta
        hasLoaded = true
    }

    /// Change vs the previous period. nil on All. A country missing from `priorFlows` gets
    /// a zero baseline, since that table is complete.
    private func delta(for aggregate: TrafficEventStore.CountryAggregate) -> InsightsDelta? {
        guard window.priorAnnotation != nil else { return nil }
        return InsightsDelta(
            current: aggregate.flows, previous: priorFlows[aggregate.countryCode] ?? 0
        )
    }

    /// Opens full screen in landscape.
    ///
    /// On regular width, seeds the cover's camera with a region fitting all pins and the
    /// origin. A region adapts to the view's aspect ratio, whereas copying the panel's
    /// `MapCamera` keeps a phone-shaped frame and left pins outside on iPad.
    ///
    /// On phones (or with nothing to fit) it copies the panel's camera, so a user's pan
    /// and zoom carry over. The rotation is requested by the cover's `onAppear` (see there).
    private func enterFullScreen(fitting pins: [MapPin]) {
        let fitted = horizontalSizeClass == .regular
            ? Self.fittingRegion(pins: pins, origin: origin.coordinate)
            : nil
        fullScreenCamera = fitted.map { .region($0) }
            ?? liveCamera.map { .camera($0) }
            ?? camera
        isFullScreen = true
    }

    /// Smallest padded region holding every pin and the origin, or nil for zero or one
    /// point. A single point would get floored to a 12° regional box by `focusSpan`; the
    /// caller falls back to the world view instead.
    ///
    /// Longitudes are collected as offsets from a reference point, wrapped into
    /// −180...180, so a set spanning the antimeridian gets a 2° span instead of 358°.
    /// Uses the same padding and limits as the country focus.
    private static func fittingRegion(
        pins: [MapPin], origin: CLLocationCoordinate2D?
    ) -> MKCoordinateRegion? {
        var coords = pins.map(\.coord)
        if let origin { coords.append(origin) }
        guard coords.count > 1, let reference = coords.first else { return nil }

        var minimumLatitude = reference.latitude, maximumLatitude = reference.latitude
        var minimumOffset: CLLocationDegrees = 0, maximumOffset: CLLocationDegrees = 0
        for coord in coords {
            minimumLatitude = min(minimumLatitude, coord.latitude)
            maximumLatitude = max(maximumLatitude, coord.latitude)
            let offset = wrappedDegrees(coord.longitude - reference.longitude)
            minimumOffset = min(minimumOffset, offset)
            maximumOffset = max(maximumOffset, offset)
        }

        return MKCoordinateRegion(
            center: CLLocationCoordinate2D(
                latitude: (minimumLatitude + maximumLatitude) / 2,
                longitude: wrappedDegrees(
                    reference.longitude + (minimumOffset + maximumOffset) / 2
                )
            ),
            span: MKCoordinateSpan(
                latitudeDelta: focusSpan(
                    maximumLatitude - minimumLatitude, ceiling: focusMaximumLatitudeSpan
                ),
                longitudeDelta: focusSpan(
                    maximumOffset - minimumOffset, ceiling: focusMaximumLongitudeSpan
                )
            )
        )
    }

    /// Rotates back to portrait first, then dismisses the cover, so the page is never seen
    /// sideways. The panel map stays unmounted (`restoringPanel`) until
    /// `panelWidthChanged` releases it.
    private func exitFullScreen() {
        // Only wait for the width change if the scene actually rotates back. On a regular-width
        // window in portrait nothing rotates, the width never changes, and the panel would stay
        // blank. A compact vertical size class means landscape, including large phones that
        // report regular width there.
        let turning = !(horizontalSizeClass == .regular && verticalSizeClass != .compact)
        restoringPanel = turning
        Self.allowLandscape(false)
        isFullScreen = false
    }

    /// Called with the panel width after every layout.
    ///
    /// Normally it records the portrait width. After full screen it's the reliable signal
    /// that the rotation back has finished: the size class, `isFullScreen` and the cover's
    /// `onDisappear` all change while the window is still wide, which is when a rebuilt
    /// map gets clamped.
    private func panelWidthChanged(_ width: CGFloat) {
        guard isFullScreen || restoringPanel else {
            portraitPanelWidth = width
            return
        }
        guard !isFullScreen, verticalSizeClass != .compact else { return }
        // `<=` so a width that never exactly matches again (e.g. a resized iPad window)
        // still releases the map.
        if portraitPanelWidth == 0 || width <= portraitPanelWidth {
            restoringPanel = false
        }
    }

    // MARK: - Focusing one country

    /// Frames the arc to the selected country and hides the other arcs.
    ///
    /// Frames the arc's two ends (origin and country centroid). Without an origin it just
    /// centers the country. GeoIP only resolves to country level, so there is one
    /// coordinate per country and no per-city arcs.
    ///
    /// Does nothing for the Unknown bucket, which has no centroid.
    private func focusMap(on aggregate: TrafficEventStore.CountryAggregate) {
        guard let code = aggregate.countryCode,
              let coord = CountryCentroids.coordinate(for: code) else { return }
        // Only the first focus records the restore point. Otherwise a second focus would
        // save the first focus's frame. Not reachable today (rows are behind the sheet), but
        // the restore shouldn't rely on that.
        if focusedCode == nil {
            // Read before the write below resets it. See `userPositionedMap`.
            userPositionedMap = userPositionedMap || camera.positionedByUser
            cameraBeforeFocus = liveCamera
            positionBeforeFocus = camera
        }
        focusedCode = code.uppercased()
        withAnimation(.easeInOut(duration: Self.focusDuration)) {
            camera = .region(Self.focusRegion(origin: origin.coordinate, country: coord))
        }
    }

    /// Restores all arcs and the panel's previous camera. Runs on every sheet dismissal:
    /// Done, swipe down, Block, switching to Trends, or leaving the tab.
    private func releaseFocus() {
        focusedCode = nil
        let restore = cameraBeforeFocus.map { MapCameraPosition.camera($0) } ?? positionBeforeFocus
        cameraBeforeFocus = nil
        positionBeforeFocus = nil
        guard let restore else { return }
        // Always restore the camera; only animate when the map is visible. Otherwise just set
        // it so MapKit doesn't animate off screen.
        guard onScreen else {
            camera = restore
            return
        }
        withAnimation(.easeInOut(duration: Self.focusDuration)) { camera = restore }
    }

    /// Long enough to show where the map moved, short enough not to wait on.
    private static let focusDuration: TimeInterval = 0.45

    /// Padding around the pair so neither end sits at the edge.
    private static let focusPadding: Double = 1.5

    /// Minimum span. Neighboring centroids are only a few degrees apart, and fitting them
    /// tightly zooms in to a regional level.
    private static let focusMinimumSpan: CLLocationDegrees = 12

    /// MapKit's max span for this style (164.3° by 108.9°, see `openingDistance`). Larger
    /// requests get clamped, which can move the center; staying within the limit keeps
    /// the computed center, so far-apart pairs stay symmetric.
    private static let focusMaximumLatitudeSpan: CLLocationDegrees = 108
    private static let focusMaximumLongitudeSpan: CLLocationDegrees = 164

    /// Region holding both ends of the arc, padded and clamped.
    ///
    /// Longitude difference is taken the short way around: +170° and −170° are 20° apart
    /// across the Pacific, not 340°.
    private static func focusRegion(
        origin: CLLocationCoordinate2D?, country: CLLocationCoordinate2D
    ) -> MKCoordinateRegion {
        guard let origin else {
            return MKCoordinateRegion(
                center: country,
                span: MKCoordinateSpan(
                    latitudeDelta: focusMinimumSpan, longitudeDelta: focusMinimumSpan
                )
            )
        }
        let deltaLongitude = wrappedDegrees(country.longitude - origin.longitude)
        let deltaLatitude = country.latitude - origin.latitude
        return MKCoordinateRegion(
            center: CLLocationCoordinate2D(
                latitude: (origin.latitude + country.latitude) / 2,
                longitude: wrappedDegrees(origin.longitude + deltaLongitude / 2)
            ),
            span: MKCoordinateSpan(
                latitudeDelta: focusSpan(abs(deltaLatitude), ceiling: focusMaximumLatitudeSpan),
                longitudeDelta: focusSpan(abs(deltaLongitude), ceiling: focusMaximumLongitudeSpan)
            )
        )
    }

    private static func focusSpan(
        _ separation: CLLocationDegrees, ceiling: CLLocationDegrees
    ) -> CLLocationDegrees {
        min(max(separation * focusPadding, focusMinimumSpan), ceiling)
    }

    /// Wraps a longitude, or a difference of two, into −180...180.
    private static func wrappedDegrees(_ degrees: CLLocationDegrees) -> CLLocationDegrees {
        var wrapped = degrees.truncatingRemainder(dividingBy: 360)
        if wrapped > 180 { wrapped -= 360 }
        if wrapped < -180 { wrapped += 360 }
        return wrapped
    }

    /// Resting detent for the country sheet: level with the bottom of the map, or
    /// `.medium` before the panel has been measured (safer than a guessed height).
    private var dockedDetent: PresentationDetent {
        dockedSheetHeight > 0 ? .height(dockedSheetHeight) : .medium
    }

    /// The docked detent height: space under the map plus `dockSlack`. Floored so a bad
    /// correction can't leave Done off screen.
    private var dockedSheetHeight: CGFloat {
        guard mapPanelBottom > 0, let window = Self.windowHeight,
              window > mapPanelBottom else { return 0 }
        return max(Self.minimumDockedHeight, window - mapPanelBottom + dockSlack)
    }

    private func mapBottomChanged(_ mapBottom: CGFloat) {
        mapPanelBottom = mapBottom
    }

    /// Called with the sheet's top edge in window coordinates, same space as the map's
    /// bottom edge.
    ///
    /// The difference goes into `dockSlack`. The detent-to-position ratio is close to 1:1,
    /// so one or two passes converge; it then latches and stops measuring.
    ///
    /// Readings far from the map edge are ignored (that's `.large` or mid-drag), and the
    /// correction is bounded so it gives up rather than oscillating.
    private func dockLanded(at sheetTop: CGFloat) {
        guard !dockCalibrated, mapPanelBottom > 0 else { return }
        let error = sheetTop - mapPanelBottom
        guard abs(error) > Self.dockTolerance else {
            dockCalibrated = true
            return
        }
        guard abs(error) < Self.dockCorrectionLimit else { return }
        guard abs(dockSlack + error) <= Self.dockCorrectionLimit else {
            dockCalibrated = true
            return
        }
        dockSlack += error
    }

    /// Close enough to stop measuring.
    private static let dockTolerance: CGFloat = 1

    /// Max correction, and max distance from the map edge for a reading to count as the
    /// docked detent.
    private static let dockCorrectionLimit: CGFloat = 120

    /// Minimum docked height (roughly a nav bar and one row) so Done stays reachable when
    /// the map's bottom edge is very low.
    private static let minimumDockedHeight: CGFloat = 120

    /// Height of the key window of the active scene. Uses the window, not the screen
    /// (`UIScreen.main` is deprecated anyway), because `.frame(in: .global)` measures in
    /// window coordinates.
    @MainActor
    private static var windowHeight: CGFloat? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .first { $0.activationState == .foregroundActive }?
            .keyWindow?.bounds.height
    }

    /// Updates the app-wide orientation mask and asks the scene to rotate. Both are needed:
    /// `AppDelegate`'s mask is what UIKit checks, and `requestGeometryUpdate` actually
    /// rotates. Set the mask first, or the request is rejected.
    ///
    /// Always returns to `.portrait`, since that's the only orientation the rest of the
    /// app supports.
    @MainActor
    private static func allowLandscape(_ allowed: Bool) {
        AppDelegate.supportedOrientations = allowed ? .landscape : .portrait
        guard let scene = UIApplication.shared.connectedScenes
            .compactMap({ $0 as? UIWindowScene })
            .first(where: { $0.activationState == .foregroundActive })
        else { return }
        // Makes UIKit re-query the delegate before evaluating the request.
        scene.keyWindow?.rootViewController?.setNeedsUpdateOfSupportedInterfaceOrientations()
        // The only error is asking for an orientation the mask forbids, which the line above
        // prevents. Nothing useful to do on failure anyway.
        scene.requestGeometryUpdate(
            .iOS(interfaceOrientations: allowed ? .landscapeRight : .portrait)
        )
    }

    /// `CLLocationCoordinate2D` isn't Equatable, so pass the fix to `onChange` as numbers.
    private var originKey: [CLLocationDegrees]? {
        origin.coordinate.map { [$0.latitude, $0.longitude] }
    }

    /// Aims the opening frame at the user's data as it arrives: their location if shared,
    /// otherwise the center of their traffic, otherwise the Atlantic. Follows the `Aim`
    /// ladder, so each step fires at most once and only upgrades. Ignores `window`, so
    /// a period switch doesn't move the camera.
    ///
    /// Only writes the panel's `camera`; full screen has its own.
    private func aimIfNeeded() {
        // The user moving the map overrides everything. `userPositionedMap` covers the case
        // where a focus round trip reset the binding's flag.
        guard !camera.positionedByUser, !userPositionedMap else { return }
        // Don't re-aim while a country is focused or its restore frame is pending. `reload`
        // runs every 15 s and could otherwise move the map under an open sheet.
        guard focusedCode == nil, cameraBeforeFocus == nil else { return }
        if aim < .origin, let coord = origin.coordinate {
            aim = .origin
            camera = .camera(Self.openingCamera(centeredOn: coord))
        } else if aim < .centroid, let coord = Self.weightedCenter(of: aggregates) {
            aim = .centroid
            camera = .camera(Self.openingCamera(centeredOn: coord))
        }
    }

    /// Flow-weighted center of the pinned countries (same filter as `pinned`, without the
    /// live lookup), so a stray connection far away doesn't pull the frame.
    ///
    /// Longitudes are averaged as unit vectors: the plain mean of +170° and −170° is 0°.
    /// Returns nil when the vectors nearly cancel (pins spread around the globe).
    private static func weightedCenter(
        of aggregates: [TrafficEventStore.CountryAggregate]
    ) -> CLLocationCoordinate2D? {
        var x = 0.0, y = 0.0, latitude = 0.0, total = 0.0
        for agg in aggregates {
            guard agg.flows > 0,
                  let code = agg.countryCode,
                  let coord = CountryCentroids.coordinate(for: code) else { continue }
            let weight = Double(agg.flows)
            let radians = coord.longitude * .pi / 180
            x += weight * cos(radians)
            y += weight * sin(radians)
            latitude += weight * coord.latitude
            total += weight
        }
        guard total > 0, (x * x + y * y).squareRoot() > 0.01 * total else { return nil }
        return CLLocationCoordinate2D(
            latitude: latitude / total,
            longitude: atan2(y, x) * 180 / .pi
        )
    }

}

private func countryName(_ code: String) -> String {
    Locale.current.localizedString(forRegionCode: code) ?? code
}

/// A country as drawn on the map: position, totals, and whether it's live.
private struct MapPin: Identifiable {
    let code: String
    let coord: CLLocationCoordinate2D
    let agg: TrafficEventStore.CountryAggregate
    let isLive: Bool
    var id: String { code }
}

/// The map itself, used by both the panel and the full-screen cover so they render
/// identically. Only the camera binding and frame differ.
private struct MapCanvas: View {
    /// Read here so the cover gets its own trait rather than the page's.
    @Environment(\.colorScheme) private var colorScheme
    @Binding var position: MapCameraPosition
    let pins: [MapPin]
    /// Arc origin (approximate device location). nil if denied or no fix yet; pins only.
    let origin: CLLocationCoordinate2D?
    /// The only country whose arc is drawn, uppercased, or nil for all. Affects arcs only;
    /// all pins and labels are always drawn.
    let focusedCode: String?
    /// Called when a camera move settles. Only the panel sets this.
    var onCameraChange: ((MapCamera) -> Void)?

    private var isDark: Bool { colorScheme == .dark }

    /// Pins that get an arc. One arc per country, so a focus leaves exactly one.
    private var arcPins: [MapPin] {
        guard let focusedCode else { return pins }
        return pins.filter { $0.code.uppercased() == focusedCode }
    }

    /// Arc widths. Thick on purpose: at world zoom a hairline looks like a rendering glitch.
    /// Live arcs are wider as well as a different color, for color-blind users.
    private static let liveArcWidth: CGFloat = 4.5
    private static let pastArcWidth: CGFloat = 2.75

    var body: some View {
        Map(position: $position) {
            // Geodesic contour draws each arc along its great-circle path.
            if let origin {
                ForEach(arcPins) { pin in
                    MapPolyline(coordinates: [origin, pin.coord], contourStyle: .geodesic)
                        .stroke(
                            arcColor(isLive: pin.isLive),
                            style: StrokeStyle(
                                lineWidth: pin.isLive ? Self.liveArcWidth : Self.pastArcWidth,
                                lineCap: .round
                            )
                        )
                }
            }
            ForEach(pins) { pin in
                Annotation(countryName(pin.code), coordinate: pin.coord) {
                    marker(for: pin.agg)
                }
            }
        }
        .mapStyle(.standard(elevation: .flat))
        .onMapCameraChange(frequency: .onEnd) { context in
            onCameraChange?(context.camera)
        }
    }

    /// Arc color only shows recency: green if the country had traffic within `liveWindow`,
    /// grey otherwise. Separate from marker tint, where red means something was blocked.
    /// Arcs must never be red, and markers must never be green for being recent.
    private func arcColor(isLive: Bool) -> Color {
        guard !isLive else { return .green }
        // Standard tiles are pale in light mode and near-black in dark, so one grey doesn't
        // work for both. Values picked by eye.
        return isDark ? Color(white: 0.82) : Color(white: 0.30)
    }

    /// Marker accent: red if anything was blocked, otherwise the accent. No severity scale;
    /// graded opacity was indistinguishable in practice, and exact counts are in the list.
    /// Orange isn't used because it doesn't mean "blocked" anywhere in the app.
    private func tint(for agg: TrafficEventStore.CountryAggregate) -> Color {
        let share = agg.flows > 0 ? Double(agg.blockedFlows) / Double(agg.flows) : 0
        return share > 0 ? .red : .accentColor
    }

    /// Marker: flag + flow count.
    private func marker(for agg: TrafficEventStore.CountryAggregate) -> some View {
        let tint = tint(for: agg)
        return HStack(spacing: 3) {
            if let code = agg.countryCode {
                Text(CountryFlag.emoji(code))
            }
            Text("\(agg.flows)")
                .font(.caption2.weight(.semibold).monospacedDigit())
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
        .background(.thinMaterial, in: Capsule())
        .overlay(Capsule().strokeBorder(tint, lineWidth: 1.5))
    }
}

/// Corner button that toggles full screen. Same position and size in both states so it's
/// under your finger to exit; `fullScreenCover` has no swipe-down, so this is the only
/// way out.
private struct MapCornerToggle: View {
    let isFullScreen: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: isFullScreen
                  ? "arrow.down.right.and.arrow.up.left"
                  : "arrow.up.left.and.arrow.down.right")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(.primary)
                // A full 44 pt circle so the visible shape is the tap target.
                .frame(width: 44, height: 44)
                // Same material as the country markers.
                .background(.thinMaterial, in: Circle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel(isFullScreen ? "Exit full screen" : "Enter full screen")
        // Clear of MapKit's attribution along the bottom edge.
        .padding(.trailing, 10)
        .padding(.bottom, 26)
    }
}

// MARK: - Rule subject for a country row

/// What a swipe on a country row acts on. Mirrors the dashboard's
/// `CountryGroup.ruleSubject` so "block Canada" means the same thing in both places.
/// Internal because the country sheet uses the same subject.
extension TrafficEventStore.CountryAggregate {
    /// nil for the no-country bucket: no swipe, and no rule state read to VoiceOver.
    ///
    /// GeoIP misses (private ranges, documentation blocks, new allocations, LAN devices)
    /// have nothing in common, so a single rule over them makes no sense. The row stays so
    /// the totals add up; individual flows are in Live Traffic.
    var ruleSubject: TargetRuleSubject? {
        guard let code = countryCode, !code.isEmpty else { return nil }
        return TargetRuleSubject(
            // Country isn't a rule dimension: the engine doesn't know about countries and GeoIP
            // stays in the app. The swipe creates or removes a single country policy, which the
            // app compiles into rules (`AppModel.derivedCountryRules`). Policies only block;
            // there is no country allow.
            targets: [],
            name: RecentTargets.countryName(code),
            note: "",
            // Always false here, like the dashboard's country row: unblocking removes a policy
            // rather than writing an Allow, so it works regardless of what blocked the traffic.
            resolverOnlyBlocks: false,
            countryCode: code
        )
    }
}

private struct CountryRow: View {
    @Environment(AppModel.self) private var model
    let agg: TrafficEventStore.CountryAggregate
    let name: String?
    /// Traffic in the last `MiniTrafficMeter.windowSeconds`, from `recentByCountry`. Only
    /// the two `recent` byte fields are used.
    let recent: TargetStats
    /// Change vs the previous period; nil on All.
    let delta: InsightsDelta?
    /// The baseline in words ("prior 7 days") for the spoken value. nil on All.
    let prior: String?
    /// Opens the row's sheet. A real Button covering the whole row, like other tappable
    /// rows in the app.
    let onTap: () -> Void

    var body: some View {
        let reading = agg.ruleSubject.map { TargetRuleReading(subject: $0, model: model) }
        return Button(action: onTap) {
            row
        }
        .buttonStyle(.plain)
        // One element with the rule state as its value.
        .accessibilityElement(children: .combine)
        // Empty for Unknown, which has no rule state or swipe. The row doesn't show the state
        // visually (the Rules page and swipe verb do), so VoiceOver users need it here.
        .accessibilityValue(spokenValue(reading))
    }

    /// Flag, name and live meter only. Counts, bytes, delta and blocked count are in the
    /// sheet. The meter reads the same live buffer as the arcs, which is why it belongs
    /// here and not on the Trends rows (see `TargetRow`).
    private var row: some View {
        HStack {
            Text(CountryFlag.emoji(agg.countryCode))
            Text(name ?? "Unknown")
            Spacer()
            MiniTrafficMeter(bytesUp: recent.recentUp, bytesDown: recent.recentDown)
        }
        // The whole row is the tap target, gaps included.
        .contentShape(Rectangle())
    }

    /// Rule state, then change vs the prior period, same order as the Trends rows. The
    /// baseline is spelled out since the header that names it is far away in VoiceOver.
    ///
    /// Unknown has no rule state but still gets its delta. This is the only place the
    /// change is available without opening the sheet.
    private func spokenValue(_ reading: TargetRuleReading?) -> String {
        let state = reading?.spokenState ?? ""
        guard let prior, let change = delta?.spoken(vs: prior) else { return state }
        return state.isEmpty ? change : "\(state), \(change)"
    }
}
