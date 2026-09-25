import CryptoKit
import NetworkExtension
import os
import SharedCore
import SwiftUI

private let settingsLog = Logger(subsystem: "fluxmoat", category: "settings")

/// Same 8-hex SHA-256 prefix as the tunnel's `ssidHashPrefix`, so app and
/// tunnel logs about one network can be matched. Never log the SSID itself.
private func ssidHashPrefix(_ ssid: String) -> String {
    SHA256.hash(data: Data(ssid.utf8)).prefix(4).map { String(format: "%02x", $0) }.joined()
}

/// DoH upstream presets. The raw value is the RFC 8484 endpoint stored in the
/// snapshot; `custom` covers any user-entered endpoint (NextDNS profiles etc.).
enum DoHPreset: String, CaseIterable, Identifiable {
    case off = ""
    case quad9 = "https://dns.quad9.net/dns-query"
    case cloudflareSecurity = "https://security.cloudflare-dns.com/dns-query"
    case cloudflare = "https://cloudflare-dns.com/dns-query"
    case custom

    var id: String { rawValue }

    var label: String {
        switch self {
        case .off: "Off (system DNS)"
        case .quad9: "Quad9 (blocks malware, recommended)"
        case .cloudflareSecurity: "Cloudflare Security (1.1.1.2)"
        case .cloudflare: "Cloudflare (no filtering)"
        case .custom: "Custom (NextDNS, …)"
        }
    }

    /// Whether this resolver's sinks count as threats. Only the two
    /// malware-filtering presets do. Cloudflare's plain endpoint doesn't filter,
    /// and a Custom endpoint is usually an ad blocker. Errs toward not claiming
    /// a threat.
    var isThreatIntelFiltering: Bool {
        switch self {
        case .quad9, .cloudflareSecurity: true
        case .off, .cloudflare, .custom: false
        }
    }

    /// The flag stored in the snapshot for a URL. An endpoint matching no preset
    /// is Custom and never counts as threat filtering.
    static func threatIntelFiltering(forURL raw: String?) -> Bool {
        guard let raw else { return false }
        return (DoHPreset(rawValue: raw) ?? .custom).isThreatIntelFiltering
    }

    /// Same check the tunnel applies before building a resolver: https with a
    /// host. Validating here keeps a typo from silently disabling encrypted DNS.
    static func isValidCustomURL(_ raw: String) -> Bool {
        guard let url = URL(string: raw), url.scheme?.lowercased() == "https",
              let host = url.host, !host.isEmpty else { return false }
        return true
    }
}

extension RetentionPeriod {
    var displayName: String {
        switch self {
        case .days7: "7 days"
        case .days30: "30 days"
        case .days90: "90 days"
        case .months6: "6 months"
        case .months12: "12 months"
        }
    }
}

// Also used by the mode-switching App Intent.
extension RunMode {
    var displayName: String {
        switch self {
        case .standard: "Standard"
        case .ask: "Ask"
        case .strict: "Strict"
        // Retired and unreachable: the picker uses `RunMode.liveCases`, the Shortcuts
        // enum omits them, and decoding maps them to `.standard`. Still given their
        // real names so debug output isn't misleading.
        case .learning: "Learning"
        case .pause: "Pause"
        }
    }
}

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    /// Returning to the app is when the displayed Wi-Fi network is most likely stale.
    @Environment(\.scenePhase) private var scenePhase
    /// Read here rather than inside the sheets: a sheet's own content reports
    /// compact on iPad. See `adaptiveSheetDetents`.
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @State private var confirmingClear = false
    /// Off by default and only turned on once iOS grants permission. Stored
    /// locally, not in the settings snapshot: the tunnel doesn't need it and it's
    /// a per-device preference that shouldn't sync.
    @AppStorage("weeklySummaryEnabled") private var weeklySummaryEnabled = false
    /// Remembers a declined permission so the footnote pointing to the Settings
    /// app shows only when needed. iOS won't show the prompt again, so otherwise
    /// the toggle would silently refuse to turn on.
    @AppStorage("weeklySummaryDenied") private var weeklySummaryDenied = false
    @State private var ssidState: SSIDState = .idle
    /// SceneStorage because the tab root is `.id()`'d on the color scheme
    /// (RootView.token): an appearance change while suspended rebuilds this view
    /// and would reset the picker mid-edit.
    @SceneStorage("settings.wifi.assignKind") private var wifiAssignKind: Profile.Kind = .publicNetwork
    @State private var showingModeSheet = false
    @State private var showingProfileSheet = false
    @State private var showingResetSheet = false
    /// A built diagnostic report waiting for the user to review and share it.
    @State private var diagnosticRequest: DiagnosticReportRequest?
    /// abuse.ch key editor. nil while showing the stored key; set while typing;
    /// back to nil on submit, so the Keychain is written once rather than per keystroke.
    ///
    /// Deliberately `@State`, unlike the other drafts here, which use
    /// `@SceneStorage`. SceneStorage is written to disk for state restoration, and
    /// a half-typed API key must not be. Losing it on a rebuild is acceptable.
    @State private var authKeyDraft: String?

    /// Scroll anchors for sections other screens deep-link to. Attached to each
    /// section's first row, since `ScrollViewReader` can only find rendered rows.
    private static let dataAnchor = "settings.section.data"
    private static let dnsAnchor = "settings.section.dns"

    /// Only dark mode uses the brand styling for now.
    private var isDark: Bool { colorScheme == .dark }

    /// Progress of the Wi-Fi name read. Separate states so the "Reading..."
    /// text only shows while a request is actually in flight.
    ///
    /// `notConnected` rather than `none` so it can't be confused with
    /// `Optional.none` at the `??` and `switch` sites.
    private enum SSIDState: Equatable {
        /// Protection is off. The read requires FluxMoat's own VPN session.
        case idle
        /// A `fetchCurrent` call is in flight.
        case fetching
        /// The read finished with no Wi-Fi name: cellular, entitlement refused, or
        /// not joined. These can't be told apart from a nil result.
        case notConnected
        case connected(String)
    }

    /// The SSID as a plain optional, for the profile sheet.
    private var currentSSID: String? {
        if case .connected(let ssid) = ssidState { return ssid }
        return nil
    }

    /// Reads the SSID via NEHotspotNetwork. Requires the Access Wi-Fi Information
    /// entitlement (without it nehelper denies with result code 1) and an active
    /// FluxMoat VPN session. No location permission needed. `.idle` when
    /// protection is off, as the section's copy explains.
    private func refreshCurrentSSID() {
        guard model.isProtectionOn else {
            settingsLog.info("✅ app:wifi fetch VERIFY called=skip reason=protectionOff")
            ssidState = .idle
            return
        }
        settingsLog.info("✅ app:wifi fetch VERIFY called=begin protectionOn=true")
        ssidState = .fetching
        NEHotspotNetwork.fetchCurrent { network in
            // Extract the Sendable String before hopping actors; NEHotspotNetwork isn't Sendable.
            let ssid = network?.ssid
            settingsLog.info("✅ app:wifi fetch VERIFY result got=\(ssid != nil, privacy: .public) ssidHash=\(ssid.map(ssidHashPrefix) ?? "-", privacy: .public)")
            Task { @MainActor in
                // Protection may have turned off while the callback was pending; report idle then.
                guard model.isProtectionOn else {
                    ssidState = .idle
                    return
                }
                ssidState = ssid.map(SSIDState.connected) ?? .notConnected
            }
        }
    }

    private func profileName(for kind: Profile.Kind) -> String {
        model.profiles.first { $0.kind == kind }?.name ?? kind.rawValue
    }

    private var cloudSyncStatusText: String {
        switch model.cloudSyncStatus {
        case .idle: "Waiting"
        case .syncing: "Syncing…"
        case .synced(let date): "Synced \(date.formatted(date: .omitted, time: .shortened))"
        case .accountUnavailable: "Sign in to iCloud in the Settings app"
        case .error(let message): message
        }
    }

    /// Converts between quiet-hours picker dates and minutes since midnight (the
    /// snapshot's time-zone-free representation).
    static func date(minuteOfDay: Int) -> Date {
        Calendar.current.date(
            bySettingHour: minuteOfDay / 60, minute: minuteOfDay % 60, second: 0, of: Date()
        ) ?? Date()
    }

    static func minuteOfDay(_ date: Date) -> Int {
        Calendar.current.component(.hour, from: date) * 60
            + Calendar.current.component(.minute, from: date)
    }

    /// A finished export awaiting the share decision. Shows row count and size
    /// first so the user sees what leaves the device.
    @State private var exportedFile: ExportedFile?
    @State private var exportFailed = false
    /// Custom DoH editing state. `customSelected` keeps the Custom row active
    /// while the URL is being typed; the model only changes on a valid submit.
    ///
    /// SceneStorage because the tab root is `.id()`'d on the color scheme
    /// (RootView.token): an appearance change while suspended would otherwise
    /// discard a half-typed endpoint. The URL isn't secret (it's in the synced
    /// snapshot); the abuse.ch key above is handled differently.
    @SceneStorage("settings.doh.customSelected") private var customDoHSelected = false
    @SceneStorage("settings.doh.draft") private var customDoHDraft = ""

    /// The value the editor would submit. Shared by the submit guard and the
    /// field hints so they agree.
    private var trimmedDoHDraft: String {
        customDoHDraft.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Off, preset or custom, derived from the model. A stored URL that matches
    /// no preset is custom.
    private var dohSelection: DoHPreset {
        if customDoHSelected { return .custom }
        guard let url = model.dohServerURL else { return .off }
        return DoHPreset(rawValue: url) ?? .custom
    }

    // Section order: Protection first. DNS and Data next because other screens
    // deep-link into them (the Dashboard's bypass banner, Trends' retention
    // caption). Reset stays the last control. Help & Support sits next to About.
    // Community and the sibling app go last because they leave the app.
    var body: some View {
        NavigationStack {
            // The reader wraps only the List, so the modifiers below still apply to the List.
            ScrollViewReader { proxy in
                List {
                    protectionSection
                    dnsSection
                    dataSection
                    notificationsSection
                    wifiSection
                    cloudSection
                    threatSection
                    resetSection
                    supportSection
                    aboutSections
                    communitySection
                    siblingAppSection
                }
                // On a cold tab switch the pending destination is already set when this
                // view appears (same handshake as Insights, `AppModel.PendingDestination`).
                .onAppear { consumePendingDestination(proxy) }
                .onChange(of: model.pendingDestination) { _, _ in
                    consumePendingDestination(proxy)
                }
                .readableWidth()
                .brandDarkBackground()
            }
            // A large title sits at the window edge, away from the readable column, so
            // regular width uses an inline title like Insights. Compact keeps the large one.
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(
                horizontalSizeClass == .regular ? .inline : .large
            )
            .confirmationDialog(
                "Clear all locally stored traffic history?",
                isPresented: $confirmingClear,
                titleVisibility: .visible
            ) {
                Button("Clear history", role: .destructive) {
                    model.clearHistory()
                }
            }
            .sheet(item: $exportedFile) { file in
                ExportShareSheet(file: file)
            }
            .alert("Export failed", isPresented: $exportFailed) {
                Button("OK", role: .cancel) {}
            } message: {
                Text("The history database could not be read.")
            }
            // Detents are set here because they depend on the presenter's size class; a
            // sheet's content reports compact even on a full-width iPad (see
            // `adaptiveSheetDetents`).
            .sheet(item: $diagnosticRequest) { request in
                DiagnosticReportSheet(report: request.text)
                    .adaptiveSheetDetents(
                        [.medium, .large], regularWidth: horizontalSizeClass == .regular
                    )
            }
            // Starts at half height so the row stays visible behind the sheet.
            .sheet(isPresented: $showingModeSheet) {
                ModeSheet()
                    .adaptiveSheetDetents(
                        [.medium, .large], regularWidth: horizontalSizeClass == .regular
                    )
            }
            .sheet(isPresented: $showingProfileSheet) {
                // Pass the SSID already read here: `NEHotspotNetwork.fetchCurrent` needs the
                // VPN session, and a second call from the sheet would race this one.
                ProfileSheet(currentSSID: currentSSID)
                    .adaptiveSheetDetents(
                        [.medium, .large], regularWidth: horizontalSizeClass == .regular
                    )
            }
            // Large only, so the full scope of an irreversible action is readable without
            // dragging the sheet.
            .sheet(isPresented: $showingResetSheet) {
                ResetConfigurationSheet()
                    .presentationDetents([.large])
            }
        }
    }

    /// Final step of a deep link: RootView has already shown the Settings tab, and
    /// this scrolls to the section. This view clears the pending destination
    /// (see `AppModel.PendingDestination`). The scroll is deferred one hop
    /// because on a cold tab switch the List hasn't laid out rows yet.
    private func consumePendingDestination(_ proxy: ScrollViewProxy) {
        let anchor: String
        switch model.pendingDestination {
        case .settingsHistoryRetention: anchor = Self.dataAnchor
        case .settingsEncryptedDNS: anchor = Self.dnsAnchor
        case .insightsWeeklySummary, nil: return
        }
        model.pendingDestination = nil
        settingsLog.notice("✅ app:settings deepLink VERIFY anchor=\(anchor, privacy: .public)")
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(50))
            withAnimation { proxy.scrollTo(anchor, anchor: .top) }
        }
    }

    /// Mode and Profile as rows showing the current value; explanations live in
    /// the sheets behind them.
    private var protectionSection: some View {
        Section {
            SettingsDisclosureRow(title: "Mode", value: model.mode.displayName) {
                showingModeSheet = true
            }
            SettingsDisclosureRow(
                title: "Profile",
                value: model.activeProfile?.name ?? "—"
            ) {
                showingProfileSheet = true
            }
        } header: {
            Text("Protection")
        } footer: {
            // The final step of the precedence order, after everything on the Rules page.
            Text("When no rule and no list matches, the mode decides: Standard allows it, Strict blocks it, Ask applies the current profile\u{2019}s default and asks you afterwards.")
        }
        .brandCardRows(isDark)
    }

    /// Two sections, one per decision. Each explanation sits under the control
    /// it describes.
    @ViewBuilder
    private var dnsSection: some View {
                Section {
                    Picker("Encrypted DNS", selection: .init(
                        get: { dohSelection },
                        set: { picked in
                            switch picked {
                            case .custom:
                                // Selecting Custom only opens the editor. The previous upstream stays active
                                // until a valid URL is submitted.
                                customDoHDraft = model.dohServerURL ?? ""
                                customDoHSelected = true
                            case .off:
                                customDoHSelected = false
                                model.dohServerURL = nil
                            default:
                                customDoHSelected = false
                                model.dohServerURL = picked.rawValue
                            }
                        }
                    )) {
                        ForEach(DoHPreset.allCases) { preset in
                            Text(preset.label).tag(preset)
                        }
                    }
                    .pickerStyle(.navigationLink)
                    // Deep-link target for the Dashboard's bypass banner.
                    .id(Self.dnsAnchor)

                    if dohSelection == .custom {
                        TextField("https://dns.nextdns.io/abc123", text: $customDoHDraft)
                            .keyboardType(.URL)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .onSubmit {
                                guard DoHPreset.isValidCustomURL(trimmedDoHDraft) else { return }
                                model.dohServerURL = trimmedDoHDraft
                            }
                        // Show a hint only when return would actually change something; an empty
                        // field doesn't count.
                        if !trimmedDoHDraft.isEmpty, !DoHPreset.isValidCustomURL(trimmedDoHDraft) {
                            Text("Enter a full https:// resolver URL.")
                                .font(.footnote)
                                .foregroundStyle(.red)
                        } else if !trimmedDoHDraft.isEmpty, model.dohServerURL != trimmedDoHDraft {
                            Text("Press return to apply.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                } header: {
                    Text("DNS")
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        // Describes the picker above: where names are resolved and what happens when
                        // the resolver is unreachable.
                        Text("Hostnames are resolved over encrypted DNS inside the tunnel; filtering resolvers also block known malware domains. If the resolver is unreachable, FluxMoat falls back to system DNS to keep you online.")
                        // The tunnel can't tell a malware sink from an ad blocker's, so the threat
                        // classification comes from this picker. Tell users picking Custom how that
                        // affects the Threat numbers in Insights.
                        Text("Only Quad9 and Cloudflare Security count as malware filtering — blocks from other resolvers are shown as blocked, not as threats.")
                    }
                }
                .brandCardRows(isDark)
                .onAppear {
                    // A stored non-preset URL means Custom was configured earlier; show it in the
                    // editor. Only into an empty field: this runs on every scene rebuild and the
                    // draft survives rebuilds, so seeding unconditionally would overwrite it.
                    guard customDoHDraft.isEmpty else { return }
                    if let url = model.dohServerURL, DoHPreset(rawValue: url) == nil {
                        customDoHSelected = true
                        customDoHDraft = url
                    }
                }
                // The stored value changed underneath the editor (Reset, a sync from another
                // device, or a preset picked). Otherwise the picker could read "Custom" over a
                // stale endpoint.
                .onChange(of: model.dohServerURL) { _, url in
                    let stillCustom = url.map { DoHPreset(rawValue: $0) == nil } ?? false
                    guard !stillCustom else { return }
                    customDoHSelected = false
                    customDoHDraft = ""
                }

                Section {
                    Toggle("Block other encrypted DNS", isOn: .init(
                        get: { model.blockEncryptedDNS },
                        set: { model.blockEncryptedDNS = $0 }
                    ))
                } footer: {
                    // Required disclosure for the "Block other encrypted DNS" switch. Keep the
                    // wording intact and next to the switch; add new text beside it, not inside it.
                    Text("\u{201C}Block other encrypted DNS\u{201D} stops apps from bypassing domain filtering with their own public DoH/DoT resolvers — your selected resolver is never blocked, and apps using a private resolver can still bypass filtering.")
                }
                .brandCardRows(isDark)
    }

    private var threatSection: some View {
                Section {
                    // A draft committed on return. Binding straight to the model did a Keychain
                    // delete-and-add per keystroke, storing partial credentials along the way.
                    SecureField("abuse.ch Auth-Key", text: .init(
                        // A nil draft shows the stored key. Deliberately not seeded in onAppear: List
                        // recycles rows, and seeding there would wipe a half-typed key when the
                        // section scrolls back into view.
                        get: { authKeyDraft ?? model.abuseChAuthKey },
                        set: { authKeyDraft = $0 }
                    ))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .onSubmit { commitAuthKey() }
                    // Shows what the Keychain holds, which a SecureField can't: a key is stored,
                    // none is, or the field has uncommitted changes.
                    if isAuthKeyDirty {
                        Text("Press return to save.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else if model.abuseChKeyStored {
                        Label("Key saved", systemImage: "checkmark.circle.fill")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Label("No key", systemImage: "circle.dashed")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    // Link to Blocklists, where manifest feeds are added.
                    NavigationLink {
                        BlocklistsView()
                    } label: {
                        Label("Blocklists", systemImage: "shield.slash")
                    }
                } header: {
                    Text("Threat intelligence")
                } footer: {
                    Text("ThreatFox already works — FluxMoat ships with a subscription to its own mirror of the feed, rebuilt every 6 hours, no account and no key. A free abuse.ch Auth-Key is optional: paste one here to pull ThreatFox and URLhaus straight from abuse.ch as a \u{201C}JSON manifest\u{201D} blocklist, which updates sooner than the mirror. The key is stored in the Keychain and only ever sent to abuse.ch.")
                }
                .brandCardRows(isDark)
                // The stored key changed (a commit, or Reset). Drop the draft so the field
                // shows what's stored.
                .onChange(of: model.abuseChAuthKey) { _, _ in authKeyDraft = nil }
    }

    /// Whether the field has changes not yet written to the Keychain.
    private var isAuthKeyDirty: Bool {
        guard let authKeyDraft else { return false }
        return authKeyDraft.trimmingCharacters(in: .whitespacesAndNewlines) != model.abuseChAuthKey
    }

    /// Writes the trimmed key. The model's didSet ignores unchanged values, so
    /// submitting an unchanged field doesn't touch the Keychain.
    private func commitAuthKey() {
        guard let authKeyDraft else { return }
        model.abuseChAuthKey = authKeyDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        // Reset to mirroring the model so the "press return" hint clears even when
        // the trimmed value equals what was stored.
        self.authKeyDraft = nil
    }

    private var dataSection: some View {
                Section {
                    Picker("Keep history", selection: .init(
                        get: { model.historyRetention },
                        set: { model.historyRetention = $0 }
                    )) {
                        ForEach(RetentionPeriod.allCases) { period in
                            Text(period.displayName).tag(period)
                        }
                    }
                    // Deep-link target for Trends' retention caption.
                    .id(Self.dataAnchor)
                    // Same wording Insights uses for this failure (`InsightsCopy.storeUnreadable`).
                    if model.storeUnavailable {
                        Label(InsightsCopy.storeUnreadable, systemImage: "exclamationmark.triangle.fill")
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                    Button("Export traffic history") {
                        do {
                            let (url, rows) = try model.exportHistory()
                            exportedFile = ExportedFile(url: url, rows: rows)
                        } catch {
                            exportFailed = true
                        }
                    }
                    Button("Clear traffic history", role: .destructive) {
                        confirmingClear = true
                    }
                } header: {
                    Text("Data")
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Older connection records are deleted automatically and the database is compacted. Choosing a shorter period deletes the excess immediately. Export produces a CSV you can share or save — it contains the same fields shown in Live Traffic.")
                        // Insights decides a target is "new" by searching the retained history, so a
                        // short retention makes almost everything look new.
                        Text("This also decides how far back Insights can look before calling a target \u{201C}new\u{201D}. A short period leaves it less history to judge against.")
                    }
                }
                .brandCardRows(isDark)
    }

    /// Two unrelated switches, so two sections with their own footers.
    @ViewBuilder
    private var notificationsSection: some View {
                Section {
                    // First because it's the only item here that turns notifications on.
                    Toggle("Weekly summary", isOn: .init(
                        get: { weeklySummaryEnabled },
                        // Wrapped in a closure instead of passing `setWeeklySummary` directly: the
                        // bare method reference makes the compiler emit an `@isolated(any)` thunk,
                        // which crashes the Swift 6.2 frontend in Xcode 26.
                        set: { setWeeklySummary($0) }
                    ))
                } header: {
                    Text("Notifications")
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        // A reminder, not a report: a repeating local notification can't carry
                        // figures that stay accurate. See `WeeklySummaryNotifier`.
                        Text("A weekly reminder to look at Insights, delivered Monday mornings. It carries no figures: the numbers are computed when you open the app, not when the reminder was scheduled.")
                        if weeklySummaryDenied {
                            // Shown only after a decline. Worded as where to go rather than as an error;
                            // the app can't ask for the permission a second time.
                            Text("Notifications are turned off for FluxMoat. Turn them on in the Settings app to receive the weekly summary.")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .brandCardRows(isDark)
                // Permission can be revoked in the Settings app while this app is suspended,
                // with no callback, so re-check whenever this screen appears.
                .task { await reconcileWeeklySummary() }

                Section {
                    Toggle("Quiet hours", isOn: .init(
                        get: { model.askQuietHours != nil },
                        set: { on in
                            model.askQuietHours = on
                                ? QuietHours(startMinute: 22 * 60, endMinute: 7 * 60)
                                : nil
                        }
                    ))
                    if let quiet = model.askQuietHours {
                        DatePicker("From", selection: .init(
                            get: { Self.date(minuteOfDay: quiet.startMinute) },
                            set: { model.askQuietHours?.startMinute = Self.minuteOfDay($0) }
                        ), displayedComponents: .hourAndMinute)
                        DatePicker("Until", selection: .init(
                            get: { Self.date(minuteOfDay: quiet.endMinute) },
                            set: { model.askQuietHours?.endMinute = Self.minuteOfDay($0) }
                        ), displayedComponents: .hourAndMinute)
                    }
                } footer: {
                    Text("Ask-mode alerts are aggregated into a single banner with a one-minute cooldown, and repeated alerts for the same site are muted for 30 minutes. During quiet hours no banners appear; pending decisions still collect on the Dashboard.")
                }
                .brandCardRows(isDark)
    }

    /// Turns the weekly summary on or off. Requests permission first and only
    /// stores the flag once it's granted, so the toggle never shows on for a
    /// notification that won't arrive.
    private func setWeeklySummary(_ wanted: Bool) {
        guard wanted else {
            weeklySummaryEnabled = false
            weeklySummaryDenied = false
            WeeklySummaryNotifier.cancel()
            return
        }
        Task {
            let granted = await WeeklySummaryNotifier.requestAuthorization()
            weeklySummaryEnabled = granted
            weeklySummaryDenied = !granted
            guard granted else { return }
            await WeeklySummaryNotifier.schedule()
        }
    }

    /// Syncs the switch with what iOS allows. If permission is gone but the flag
    /// is on, turn it off and show the footnote. If both are on, reschedule;
    /// that's cheap (`add` replaces the same identifier) and recovers a missing
    /// request after a restore or reinstall.
    private func reconcileWeeklySummary() async {
        guard weeklySummaryEnabled else { return }
        let authorized = await WeeklySummaryNotifier.isAuthorized()
        guard authorized else {
            weeklySummaryEnabled = false
            weeklySummaryDenied = true
            settingsLog.notice("✅ app:notifications weekly VERIFY revoked externally → toggle off")
            return
        }
        weeklySummaryDenied = false
        await WeeklySummaryNotifier.schedule()
    }

    private var wifiSection: some View {
                Section {
                    if case .connected(let ssid) = ssidState {
                        LabeledContent("Current Wi-Fi", value: ssid)
                        if !model.wifiAutoProfiles.contains(where: { $0.ssid == ssid }) {
                            // Built from the profile list rather than hard-coded labels so it can't offer
                            // a profile that no longer exists.
                            Picker("Switch here to", selection: $wifiAssignKind) {
                                ForEach(model.profiles) { profile in
                                    Text(profile.name).tag(profile.kind)
                                }
                            }
                            Button {
                                let action = model.profiles.first { $0.kind == wifiAssignKind }?
                                    .unmatchedAction ?? .allow
                                model.addWifiAssignment(
                                    ssid: ssid, profileKind: wifiAssignKind, unmatchedAction: action
                                )
                            } label: {
                                Text("Add rule for this network")
                            }
                        }
                    } else {
                        // The ellipsis only appears while a read is in flight.
                        Text(ssidUnavailableText)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(model.wifiAutoProfiles, id: \.ssid) { assignment in
                        LabeledContent(assignment.ssid,
                                       value: profileName(for: assignment.profileKind))
                            // Full swipe disabled and an explicit Delete button, so a row can't be removed
                            // by a stray swipe.
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button("Delete", role: .destructive) {
                                    model.wifiAutoProfiles.removeAll { $0.ssid == assignment.ssid }
                                }
                            }
                    }
                    if !model.isProtectionOn, !model.wifiAutoProfiles.isEmpty {
                        // The rules are still listed while protection is off, but they can't run:
                        // the SSID is only readable through FluxMoat's VPN session.
                        Text("Paused while protection is off — the network name can only be read through the tunnel.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("Wi-Fi automation")
                } footer: {
                    Text("Joining a listed network switches the active profile automatically. The network name is read through the active VPN session — FluxMoat never asks for location access. Swipe a rule to delete it.")
                }
                .brandCardRows(isDark)
                .onAppear(perform: refreshCurrentSSID)
                .onChange(of: model.isProtectionOn) { refreshCurrentSSID() }
                // Networks change while the app is in the background, so refresh on return.
                .onChange(of: scenePhase) { _, phase in
                    guard phase == .active else { return }
                    refreshCurrentSSID()
                }
    }

    /// Text for when there's no network name to show.
    private var ssidUnavailableText: String {
        switch ssidState {
        case .idle: "Turn protection on to read the current Wi-Fi network."
        case .fetching: "Reading current Wi-Fi…"
        case .notConnected: "Not connected to Wi-Fi"
        // Unreachable: the caller only asks when there's no name.
        case .connected(let ssid): ssid
        }
    }

    private var cloudSection: some View {
                Section {
                    Toggle("Sync rules & settings", isOn: .init(
                        get: { model.iCloudSyncEnabled },
                        set: { model.setICloudSync($0) }
                    ))
                    if model.iCloudSyncEnabled {
                        LabeledContent("Status", value: cloudSyncStatusText)
                        // Disabled during a sync; the status row above shows "Syncing..." meanwhile
                        // (AppModel.runCloudSync).
                        Button("Sync now") { model.cloudSyncOnForeground() }
                            .disabled(model.cloudSyncStatus == .syncing)
                    }
                } header: {
                    Text("iCloud Sync")
                } footer: {
                    // iCloud sync consent text: the scope, what never syncs and the 30-day
                    // deletion caveat are the terms the user opts in under. Keep the whole text
                    // together and next to the switch.
                    Text("Syncs rules, settings, Wi-Fi automation and blocklist subscriptions between your devices through your private iCloud database. Traffic history and the abuse.ch key never sync. A rule deleted on one device stays deleted; if a device was offline for more than 30 days, the rule may reappear there and need deleting again.")
                }
                .brandCardRows(isDark)
    }

    /// Erases configuration. Placed near the bottom, away from Data's history
    /// erase button, so the two destructive actions aren't confused.
    private var resetSection: some View {
                Section {
                    SettingsDisclosureRow(title: "Reset configuration") {
                        showingResetSheet = true
                    }
                } header: {
                    Text("Reset")
                } footer: {
                    Text("Removes the rules, lists and preferences you have set up on this device. Traffic history is kept — that has its own button under Data.")
                }
                .brandCardRows(isDark)
    }

    /// Support rows. Rows that need an external address appear only once the
    /// address is set in `SupportCopy`; no placeholder addresses. The diagnostic
    /// report needs nothing external and is shown before it can be shared.
    @ViewBuilder
    private var supportSection: some View {
                Section {
                    if let helpURL = SupportCopy.helpURL {
                        Link("Help", destination: helpURL)
                    }
                    if let mailto = SupportCopy.supportMailto(
                        version: Bundle.main.versionLabel
                    ) {
                        Link("Contact support", destination: mailto)
                    }
                    SettingsDisclosureRow(title: "Report a problem") {
                        // Built at tap time so it reflects the current settings.
                        diagnosticRequest = DiagnosticReportRequest(
                            text: DiagnosticReport.build(from: model)
                        )
                    }
                } header: {
                    Text("Help & Support")
                } footer: {
                    // States the scope before the tap; the sheet then shows the actual text.
                    Text("\u{201C}Report a problem\u{201D} builds a short summary of this install \u{2014} your settings and how many rules and lists you have. It shows you the whole thing before you share it, and it contains no browsing history, domains or network names.")
                }
                .brandCardRows(isDark)
    }

    @ViewBuilder
    private var aboutSections: some View {
                Section("Privacy") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("All analysis happens on this device.")
                        Text("Traffic history never leaves this device unless you export it. No payloads, page contents or credentials are ever stored — only domains, IP addresses, ports, protocols and byte counts.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    .padding(.vertical, 4)
                }
                .brandCardRows(isDark)

                Section("Limitations") {
                    VStack(alignment: .leading, spacing: 8) {
                        // Same list onboarding shows, from `CapabilityCopy`.
                        ForEach(CapabilityCopy.boundaries, id: \.self) { line in
                            LimitationRow(text: line)
                        }
                        // Limitations specific to controls on this page and the rule editor.
                        LimitationRow(text: CapabilityCopy.encryptedDNSBypass)
                        LimitationRow(text: CapabilityCopy.icmpUnfiltered)
                    }
                    .padding(.vertical, 4)
                }
                .brandCardRows(isDark)

                Section("About") {
                    LabeledContent("Version", value: Bundle.main.versionLabel)
                    // Only shown once `SupportCopy` has an address; no placeholder.
                    if let policyURL = SupportCopy.privacyPolicyURL {
                        Link("Privacy Policy", destination: policyURL)
                    }
                    // Required CC BY 4.0 attribution for the bundled country database. Do not remove.
                    Link(destination: URL(string: "https://db-ip.com")!) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("IP Geolocation by DB-IP")
                            Text("Country data © DB-IP, licensed under CC BY 4.0. Lookups happen entirely on this device.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                            // Build date read from the MMDB's `build_epoch`
                            // (`GeoIPService.databaseBuildDate`), so it updates with the database. Hidden
                            // when the file has no build date.
                            if let built = GeoIPService.shared.databaseBuildDate {
                                Text("Database built \(built.formatted(.dateTime.month(.wide).year())).")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .brandCardRows(isDark)
    }

    /// Community link. A plain `Link` that opens Safari, so Settings makes no
    /// network requests. Hidden when its `SupportCopy` constant is nil.
    @ViewBuilder
    private var communitySection: some View {
        if let communityURL = SupportCopy.communityURL {
            Section("Community") {
                Link(destination: communityURL) {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Join the Discord")
                            Text("Questions, feedback, and other FluxMoat users.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } icon: {
                        // Template rendering so the mark takes the link tint and stays visible in dark mode.
                        Image("DiscordMark")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 22, height: 22)
                            .accessibilityHidden(true)
                    }
                }
            }
            .brandCardRows(isDark)
        }
    }

    /// Link to our other app, in its own section since it's a store listing
    /// rather than a community. A plain `Link` to the App Store app, so nothing
    /// is fetched here. Hidden when its `SupportCopy` constant is nil.
    @ViewBuilder
    private var siblingAppSection: some View {
        if let siblingAppURL = SupportCopy.siblingAppURL {
            Section("Also from the developer") {
                Link(destination: siblingAppURL) {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(SupportCopy.siblingAppName)
                            // Tagline comes from `SupportCopy` so it matches the store listing.
                            Text("\(SupportCopy.siblingAppTagline).")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } icon: {
                        // Traced from the app's artwork and rendered as a template, like the Discord mark.
                        Image("TimeBackMark")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 22, height: 22)
                            .accessibilityHidden(true)
                    }
                }
            }
            .brandCardRows(isDark)
        }
    }
}

/// Itemizes what "Reset configuration" erases and what it keeps, with the
/// button at the bottom. A sheet rather than a confirmation dialog because a
/// dialog can't fit both lists. Shows counts, not names.
private struct ResetConfigurationSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ResetScopeRow(icon: "list.bullet.rectangle", title: "Rules",
                                  detail: count(model.rules.count, "rule", "rules"))
                    ResetScopeRow(icon: "flag", title: "Country policies",
                                  detail: count(model.countryPolicies.count, "country", "countries"))
                    ResetScopeRow(icon: "shield.slash", title: "Blocklists",
                                  detail: blocklistDetail)
                    ResetScopeRow(icon: "wifi", title: "Wi-Fi automation",
                                  detail: count(model.wifiAutoProfiles.count, "network", "networks"))
                    ResetScopeRow(icon: "lock.shield", title: "Encrypted DNS choice",
                                  detail: model.dohServerURL == nil ? "Off" : "Back to system DNS")
                    ResetScopeRow(icon: "moon", title: "Quiet hours",
                                  detail: model.askQuietHours == nil ? "Off" : "Turned off")
                    ResetScopeRow(icon: "key", title: "abuse.ch key",
                                  detail: model.abuseChKeyStored ? "Deleted from the Keychain" : "None stored")
                } header: {
                    Text("Cleared")
                }

                Section {
                    ResetScopeRow(icon: "clock.arrow.circlepath", title: "Traffic history",
                                  detail: "Cleared separately, under Data")
                    ResetScopeRow(icon: "shield.lefthalf.filled", title: "Mode and profile",
                                  detail: "\(model.mode.displayName) \u{00B7} \(model.activeProfile?.name ?? "—")")
                    ResetScopeRow(icon: "externaldrive", title: "Keep history",
                                  detail: model.historyRetention.displayName)
                    ResetScopeRow(icon: "network.badge.shield.half.filled",
                                  title: "Block other encrypted DNS",
                                  detail: model.blockEncryptedDNS ? "On" : "Off")
                } header: {
                    Text("Kept")
                } footer: {
                    // The cross-device effect. With sync on, the reset propagates; with it off,
                    // only this device forgets, and turning sync on later adopts what's in iCloud.
                    if model.iCloudSyncEnabled {
                        Text("iCloud Sync is on, so this also clears the same configuration on your other devices.")
                    } else {
                        Text("iCloud Sync is off, so this only affects this device. Turning sync on later restores whatever your account still holds.")
                    }
                }

                Section {
                    // Destructive button alone in its own section, like `RuleDetailSheet`.
                    Button("Erase configuration", role: .destructive) {
                        model.resetAllConfiguration()
                        dismiss()
                    }
                }
            }
            .navigationTitle("Reset configuration")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    /// Subscriptions and imported domains share one row even though the store
    /// keeps them separate.
    private var blocklistDetail: String {
        var parts = [count(model.blocklistSources.count, "subscription", "subscriptions")]
        if !model.blocklistDomains.isEmpty {
            parts.append(count(model.blocklistDomains.count, "imported domain", "imported domains"))
        }
        return parts.joined(separator: " \u{00B7} ")
    }

    private func count(_ n: Int, _ singular: String, _ plural: String) -> String {
        n == 0 ? "None" : "\(n) \(n == 1 ? singular : plural)"
    }
}

/// One line of the reset scope: label on the left, current value on the right.
private struct ResetScopeRow: View {
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack {
            Label(title, systemImage: icon)
            Spacer()
            Text(detail)
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
        }
        .accessibilityElement(children: .combine)
    }
}

/// A finished CSV export: file location and contents.
private struct ExportedFile: Identifiable {
    let url: URL
    let rows: Int
    var id: String { url.path }

    var sizeLabel: String {
        let bytes = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int) ?? nil
        return ByteFormat.volume(Int64(bytes ?? 0))
    }
}

/// Summary plus ShareLink: the user sees what the file contains before
/// choosing where it goes.
private struct ExportShareSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme
    let file: ExportedFile

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Image(systemName: "doc.text")
                    .font(.system(size: 44))
                    .foregroundStyle(.secondary)
                Text(file.url.lastPathComponent)
                    .font(.callout.monospaced())
                Text("\(file.rows) connection record\(file.rows == 1 ? "" : "s") · \(file.sizeLabel)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                ShareLink(item: file.url) {
                    Label("Share or save", systemImage: "square.and.arrow.up")
                }
                .buttonStyle(.borderedProminent)
                .brandProminentLabel(colorScheme == .dark)
            }
            .padding()
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .presentationDetents([.medium])
        }
    }
}

/// A settings row that looks like a `Picker` but opens a sheet: title on the
/// left, optional value or subtitle, chevron. All sheet-opening rows on this
/// page use it so they look and behave the same. `.plain` only hit-tests what
/// it draws, hence the `contentShape`.
private struct SettingsDisclosureRow: View {
    let title: String
    var subtitle: String? = nil
    var value: String = ""
    let open: () -> Void

    var body: some View {
        Button(action: open) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .foregroundStyle(.primary)
                    if let subtitle {
                        Text(subtitle)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if !value.isEmpty {
                    Text(value)
                        .foregroundStyle(.secondary)
                }
                Image(systemName: "chevron.right")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
            .padding(.vertical, subtitle == nil ? 0 : 2)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        // Reads like a Picker ("Mode, Standard, button"). Not `.combine`, which would
        // read the value twice and speak the chevron's symbol name.
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
        // Speak whichever the row shows; a subtitle stands in for a value too long
        // for one line.
        .accessibilityValue(value.isEmpty ? (subtitle ?? "") : value)
        .accessibilityAddTraits(.isButton)
    }
}

private struct LimitationRow: View {
    let text: String

    var body: some View {
        Label {
            Text(text).font(.footnote)
        } icon: {
            Image(systemName: "info.circle").font(.footnote)
        }
    }
}

extension Bundle {
    /// "1.0 (1)". Shown on the About row and used in the diagnostic report and
    /// the support email subject, so all three name the same build. Includes the
    /// build number to tell TestFlight builds apart. Falls back to a dash when
    /// both keys are missing rather than inventing a version.
    var versionLabel: String {
        let short = infoDictionary?["CFBundleShortVersionString"] as? String
        let build = infoDictionary?["CFBundleVersion"] as? String
        switch (short, build) {
        case (let short?, let build?): return "\(short) (\(build))"
        case (let short?, nil): return short
        case (nil, let build?): return "build \(build)"
        case (nil, nil): return "\u{2014}"
        }
    }
}
