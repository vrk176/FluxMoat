import SharedCore
import SwiftUI
import UniformTypeIdentifiers
import os

/// Counts, the filter name and booleans only. Never log a rule's target.
private let rulesLog = Logger(subsystem: "fluxmoat", category: "rules")

/// Single-selection list filter. Raw values are persisted via `@SceneStorage`;
/// removed values (e.g. "disabled", "expired") decode to nil and fall back to `.all`.
enum RuleListFilter: String, CaseIterable, Identifiable {
    case all
    case allow
    case block
    /// A rule with an expiry that hasn't passed yet.
    case temporary

    var id: String { rawValue }

    var menuLabel: String {
        switch self {
        case .all: "All rules"
        case .allow: "Allow only"
        case .block: "Block only"
        case .temporary: "Temporary"
        }
    }

    /// How the empty message names the thing it found none of.
    var emptyPhrase: String {
        switch self {
        case .all: "here"
        case .allow: "set to Allow"
        case .block: "set to Block"
        case .temporary: "temporary"
        }
    }

    func matches(_ rule: Rule) -> Bool {
        switch self {
        case .all: true
        case .allow: rule.action == .allow
        case .block: rule.action == .deny
        // Lapsed rules are purged from `model.rules`, so no `hasLapsed` check is needed.
        case .temporary: rule.expiresAt != nil
        }
    }

    /// Country policies always block and never expire, but they still honor the
    /// filter so the Countries section doesn't contradict an "Allow only" list.
    func matches(_ policy: CountryPolicy) -> Bool {
        switch self {
        case .all, .block: true
        case .allow, .temporary: false
        }
    }
}

/// Sort order for the rule list. Every case falls back to the id as a final
/// tie-breaker: `sorted(by:)` isn't stable, so without a total order rules
/// with equal keys can swap places whenever the array changes.
enum RuleListSort: String, CaseIterable, Identifiable {
    /// The case name and raw value are persisted by `@SceneStorage("rules.sort")`;
    /// renaming them would reset users' saved sort. Rename `menuLabel` instead.
    case priority
    case recent
    case target

    var id: String { rawValue }

    var menuLabel: String {
        switch self {
        case .priority: "Scope"
        case .recent: "Recently added"
        case .target: "Target A–Z"
        }
    }

    /// Label for the active-filter chip; not just the menu label lowercased.
    var chipLabel: String {
        switch self {
        case .priority: "by scope"
        case .recent: "newest first"
        case .target: "A–Z by target"
        }
    }

    /// Within the same scope, newest first.
    func precedes(_ a: Rule, _ b: Rule) -> Bool {
        switch self {
        case .priority:
            if a.priority != b.priority { return a.priority > b.priority }
            if a.createdAt != b.createdAt { return a.createdAt > b.createdAt }
        case .recent:
            if a.createdAt != b.createdAt { return a.createdAt > b.createdAt }
        case .target:
            let comparison = a.target.displayText.localizedCaseInsensitiveCompare(b.target.displayText)
            if comparison != .orderedSame { return comparison == .orderedAscending }
        }
        return a.id.uuidString < b.id.uuidString
    }
}

struct RulesView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    /// Read here rather than inside the sheets: a sheet's own content reports
    /// compact on iPad. See `adaptiveSheetDetents`.
    @Environment(\.horizontalSizeClass) private var horizontalSizeClass
    @State private var showingEditor = false
    @State private var showingImporter = false
    @State private var showingCountryPicker = false
    /// A parsed file awaiting confirmation. Nothing has been written while this is set.
    @State private var pendingImport: PendingImport?
    /// Import failures only; success counts are shown on the import sheet.
    @State private var importError: String?
    /// A written export awaiting preview. The file stays local until the user
    /// picks a destination in the share sheet.
    @State private var exportedRules: ExportedRules?
    @State private var exportError: String?
    @State private var selectedRule: Rule?
    @State private var selectedPolicy: CountryPolicy?
    // SceneStorage rather than State: the tab root is `.id()`'d on the color
    // scheme (RootView.token), so an appearance change, including the automatic
    // one while suspended, rebuilds this view and would clear search and filter.
    @SceneStorage("rules.search") private var searchText = ""
    @SceneStorage("rules.filter") private var filter: RuleListFilter = .all
    @SceneStorage("rules.sort") private var sort: RuleListSort = .priority

    /// Only dark mode uses the brand styling for now.
    private var isDark: Bool { colorScheme == .dark }

    private var needle: String {
        searchText.trimmingCharacters(in: .whitespaces).lowercased()
    }

    /// Search matches target and note, the filter narrows by action or status,
    /// and the sort is a total order (see `RuleListSort`).
    private var filteredRules: [Rule] {
        model.rules
            .filter { rule in
                guard filter.matches(rule) else { return false }
                guard !needle.isEmpty else { return true }
                return rule.target.displayText.lowercased().contains(needle)
                    || (rule.note?.lowercased().contains(needle) ?? false)
            }
            .sorted(by: sort.precedes)
    }

    /// Country policies are searchable by localized name or ISO code (so "US"
    /// finds United States).
    private var filteredCountryPolicies: [CountryPolicy] {
        model.countryPolicies.filter { policy in
            guard filter.matches(policy) else { return false }
            guard !needle.isEmpty else { return true }
            return RecentTargets.countryName(policy.countryCode).lowercased().contains(needle)
                || policy.countryCode.lowercased().contains(needle)
        }
    }

    /// Whether search, filter or sort differs from the default view.
    private var isNarrowed: Bool {
        !needle.isEmpty || filter != .all || sort != .priority
    }

    var body: some View {
        NavigationStack {
            List {
                // Show an explicit row with a way out whenever the list is narrowed; the
                // filter lives in an overflow menu, so there's no toolbar indicator.
                if isNarrowed {
                    Section {
                        HStack(spacing: 8) {
                            Image(systemName: "line.3.horizontal.decrease.circle.fill")
                                .foregroundStyle(.secondary)
                            Text(narrowingSummary)
                                .font(.subheadline)
                                .lineLimit(1)
                            Spacer()
                            Button("Clear") { clearNarrowing() }
                                .font(.subheadline)
                                // Borderless so only the word is tappable, not the whole row.
                                .buttonStyle(.borderless)
                        }
                        .accessibilityElement(children: .combine)
                    }
                    .brandCardRows(isDark)
                }
                Section {
                    NavigationLink {
                        BlocklistsView()
                    } label: {
                        HStack {
                            Label("Blocklists", systemImage: "shield.slash")
                            Spacer()
                            Text(blocklistSummary)
                                .foregroundStyle(.secondary)
                        }
                    }
                } footer: {
                    // These footers state the precedence order where it applies.
                    Text("Your rules below override these lists.")
                }
                .brandCardRows(isDark)
                // Countries go above the rule list: there are only a few, while the list
                // can run to hundreds after an import.
                if !filteredCountryPolicies.isEmpty {
                    Section {
                        ForEach(filteredCountryPolicies) { policy in
                            CountryPolicyRow(
                                policy: policy,
                                onOpen: { selectedPolicy = policy }
                            )
                            // Delete only, and no full swipe: a stray swipe just opens the tray. A
                            // country policy only blocks, so there is nothing to flip.
                            .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                                Button("Delete", role: .destructive) {
                                    model.removeCountryPolicies(ids: [policy.id])
                                }
                            }
                        }
                    } header: {
                        Text("Countries")
                    } footer: {
                        Text(CountryPolicyCopy.coverage)
                    }
                    .brandCardRows(isDark)
                }
                Section {
                    ForEach(filteredRules) { rule in
                        RuleRow(
                            rule: rule,
                            onFlip: { model.flipRule(rule.id) },
                            onOpen: {
                                // Records whether the list was narrowed when a sheet opened, to help
                                // diagnose "missing rule" reports.
                                rulesLog.notice("✅ app:rules sheetOpen VERIFY filtered=\(filteredRules.count, privacy: .public) policies=\(filteredCountryPolicies.count, privacy: .public) filter=\(filter.rawValue, privacy: .public) narrowed=\(isNarrowed, privacy: .public)")
                                selectedRule = rule
                            }
                        )
                        // Delete only, with full swipe disabled: elsewhere in the app a left swipe
                        // writes a reversible rule, so a full swipe must not delete here. Flipping
                        // is done with `RuleFlipControl` on the row.
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button("Delete", role: .destructive) {
                                model.removeRules(ids: [rule.id])
                            }
                        }
                    }
                    if model.rules.isEmpty {
                        // True empty state. Second line depends on whether protection is on, same
                        // as Live Traffic and the map's country list.
                        ContentUnavailableView(
                            "No rules yet",
                            systemImage: "list.bullet.rectangle",
                            description: Text(model.isProtectionOn
                                ? "Allow or block a target from any traffic row, or add one here — a domain like *.example.com, an IP, a network range or a port."
                                : "Turn on protection to see what this device is talking to. Anything you allow or block from those rows lands here.")
                        )
                    } else if filteredRules.isEmpty {
                        // Separate from the empty state above: rules exist but the current search or
                        // filter hides them, and the message says which.
                        ContentUnavailableView(
                            "No rules match",
                            systemImage: "line.3.horizontal.decrease.circle",
                            description: Text(narrowedEmptyDescription)
                        )
                    }
                } header: {
                    Text("Your rules")
                } footer: {
                    // Precedence from most to least specific. Country policies are named because
                    // they compile into the user rule layer rather than forming a layer of their own.
                    // Matches the Protection section footer in Settings.
                    Text("A rule for an exact target beats a site-wide rule, a site-wide rule beats a country policy, and a port or protocol rule sits under all three. When two rules reach equally far and disagree, Allow wins. Rules — including country policies — are checked before threat feeds and blocklists. What none of them matched is left to the mode: Standard allows it, Strict blocks it, Ask applies the current profile\u{2019}s default and asks you afterwards.")
                }
                .brandCardRows(isDark)
            }
            .readableWidth()
            .brandDarkBackground()
            // Keyed on rule ids: one query covers the page, and only a change in the rule
            // set changes what needs answering. New traffic doesn't re-key it; a slightly
            // stale count is fine. Kept at page level (rather than on sheet open) so
            // `ruleHitsKnown` is already resolved when `RuleDetailSheet` reads it.
            .task(id: model.rules.map(\.id)) { await model.refreshRuleHits() }
            // A large title sits at the window edge, away from the readable column, so
            // regular width uses an inline title like Insights. Compact keeps the large one.
            .navigationTitle("Rules")
            .navigationBarTitleDisplayMode(
                horizontalSizeClass == .regular ? .inline : .large
            )
            .searchable(text: $searchText, prompt: "Domain, IP, note or country")
            // Two toolbar items, matching the other tabs.
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        // Inline so the options show as a titled group instead of submenus.
                        Picker("Sort by", selection: $sort) {
                            ForEach(RuleListSort.allCases) { option in
                                Text(option.menuLabel).tag(option)
                            }
                        }
                        .pickerStyle(.inline)
                        Picker("Show", selection: $filter) {
                            ForEach(RuleListFilter.allCases) { option in
                                Text(option.menuLabel).tag(option)
                            }
                        }
                        .pickerStyle(.inline)
                        Divider()
                        Button("Import rules…", systemImage: "square.and.arrow.down") {
                            showingImporter = true
                        }
                        // Two items rather than a format picker in the sheet: choose the format
                        // before anything is written.
                        Button("Export rules…", systemImage: "square.and.arrow.up") {
                            exportJSON()
                        }
                        Button("Export for Little Snitch…", systemImage: "arrow.up.doc") {
                            exportLSRules()
                        }
                        // An empty rule set would produce a .lsrules file that `LSRulesImporter`
                        // rejects (it throws when rules, domains and skips are all empty). The JSON
                        // format has no such restriction.
                        .disabled(!canExportLSRules)
                    } label: {
                        Label("More", systemImage: "ellipsis.circle")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    // Add menu also creates country policies, so a country can be blocked
                    // before it appears in traffic.
                    Menu {
                        Button("New rule", systemImage: "plus") {
                            rulesLog.notice("✅ app:rules editorOpen VERIFY editing=\(false, privacy: .public)")
                            showingEditor = true
                        }
                        Button("Country policy…", systemImage: "flag") { showingCountryPicker = true }
                    } label: {
                        Label("Add", systemImage: "plus")
                    }
                }
            }
            .sheet(isPresented: $showingEditor) {
                RuleEditorView { model.commitRule($0, replacing: $1) }
            }
            .sheet(item: $exportedRules) { export in
                RuleExportSheet(export: export)
            }
            .sheet(isPresented: $showingCountryPicker) {
                CountryPolicyPicker()
            }
            .sheet(item: $selectedPolicy) { policy in
                CountryPolicySheet(initial: policy)
                    .adaptiveSheetDetents(
                        [.medium, .large], regularWidth: horizontalSizeClass == .regular
                    )
            }
            // Starts at half height so the row stays visible behind the sheet.
            .sheet(item: $selectedRule) { rule in
                RuleDetailSheet(initial: rule)
                    .adaptiveSheetDetents(
                        [.medium, .large], regularWidth: horizontalSizeClass == .regular
                    )
            }
            .fileImporter(
                isPresented: $showingImporter,
                allowedContentTypes: [.json, UTType(filenameExtension: "lsrules") ?? .json]
            ) { result in
                stageImport(result)
            }
            .sheet(item: $pendingImport) { pending in
                RuleImportSheet(pending: pending)
                    .adaptiveSheetDetents(
                        [.medium, .large], regularWidth: horizontalSizeClass == .regular
                    )
            }
            .alert(
                ".lsrules import",
                isPresented: .init(get: { importError != nil }, set: { if !$0 { importError = nil } })
            ) {
                Button("OK") { importError = nil }
            } message: {
                Text(importError ?? "")
            }
            // Separate from the import alert so an export failure isn't titled as an import error.
            .alert(
                "Export failed",
                isPresented: .init(get: { exportError != nil }, set: { if !$0 { exportError = nil } })
            ) {
                Button("OK") { exportError = nil }
            } message: {
                Text(exportError ?? "")
            }
        }
    }

    /// Chip text: only the active criteria, search term first.
    private var narrowingSummary: String {
        var parts: [String] = []
        let typed = searchText.trimmingCharacters(in: .whitespaces)
        if !typed.isEmpty { parts.append("“\(typed)”") }
        if filter != .all { parts.append(filter.menuLabel) }
        if sort != .priority { parts.append(sort.chipLabel) }
        return parts.joined(separator: " · ")
    }

    /// Explains why the list is empty when rules exist.
    private var narrowedEmptyDescription: String {
        let typed = searchText.trimmingCharacters(in: .whitespaces)
        let reason: String
        switch (typed.isEmpty, filter == .all) {
        case (false, false): reason = "Nothing matches “\(typed)” with this filter."
        case (false, true): reason = "Nothing matches “\(typed)”."
        // Filter only: search empty, filter set. Both empty can't reach here since
        // `isNarrowed` would be false.
        default: reason = "No rule is \(filter.emptyPhrase)."
        }
        return "\(reason) Clear it above to show every rule again."
    }

    private func clearNarrowing() {
        searchText = ""
        filter = .all
        sort = .priority
    }

    /// Pluralized via `count` ("1 domain", not "1 domains").
    private var blocklistSummary: String {
        let enabled = model.blocklistSources.filter(\.enabled)
        let entries = enabled.reduce(model.blocklistDomains.count) { $0 + $1.entryCount }
        guard entries > 0 else { return "\(enabled.count) enabled" }
        return "\(entries) \(entries == 1 ? "domain" : "domains")"
    }

    /// An empty rule set produces a .lsrules file the importer rejects; see the menu item.
    private var canExportLSRules: Bool {
        !model.rules.isEmpty || !model.blocklistDomains.isEmpty
    }

    /// Writes the backup file and shows the preview. Nothing leaves the device until
    /// the user uses the share sheet.
    private func exportJSON() {
        do {
            let export = try model.exportRulesJSON()
            var parts = [Self.count(export.rules, "rule", "rules")]
            if export.countryPolicies > 0 {
                parts.append(Self.count(export.countryPolicies, "country policy", "country policies"))
            }
            if export.blocklistDomains > 0 {
                parts.append(Self.count(export.blocklistDomains, "blocked domain", "blocked domains"))
            }
            exportedRules = ExportedRules(
                url: export.url,
                summary: parts.joined(separator: " · "),
                loss: nil
            )
        } catch {
            exportError = error.localizedDescription
        }
    }

    private func exportLSRules() {
        do {
            let export = try model.exportRulesLSRules()
            var parts = [Self.count(export.rules, "rule", "rules")]
            if export.blocklistDomains > 0 {
                parts.append(Self.count(export.blocklistDomains, "blocked domain", "blocked domains"))
            }
            exportedRules = ExportedRules(
                url: export.url,
                summary: parts.joined(separator: " · "),
                // Always set for this format: ids and creation dates can't be represented.
                loss: RuleExporter.lossCaption(export.loss)
            )
        } catch {
            exportError = error.localizedDescription
        }
    }

    /// "1 rule", "12 rules". Centralized pluralization.
    private static func count(_ value: Int, _ singular: String, _ plural: String) -> String {
        "\(value) \(value == 1 ? singular : plural)"
    }

    /// Parses the picked file only. Nothing touches the model until the user
    /// confirms in the import sheet.
    private func stageImport(_ result: Result<URL, any Error>) {
        switch result {
        case .failure(let error):
            importError = "Import failed: \(error.localizedDescription)"
        case .success(let url):
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            do {
                let report = try LSRulesImporter.parse(try Data(contentsOf: url))
                pendingImport = PendingImport(report: report, fileName: url.lastPathComponent)
            } catch let error as LSRulesImporter.ParseError {
                importError = "Import failed: \(error.reason)"
            } catch {
                importError = "Import failed: \(error.localizedDescription)"
            }
        }
    }
}

/// A written export not yet shared: file location, contents and what the
/// format couldn't represent.
struct ExportedRules: Identifiable {
    let url: URL
    /// Counts only. Shown in the sheet, not logged.
    let summary: String
    /// nil for the JSON format, which loses nothing. `.lsrules` always has something to report.
    let loss: String?
    var id: String { url.path }
}

/// Summary plus ShareLink, like `SettingsView.ExportShareSheet`: the user sees
/// what the file contains before choosing where it goes.
private struct RuleExportSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme
    let export: ExportedRules

    var body: some View {
        NavigationStack {
            VStack(spacing: 16) {
                Image(systemName: "doc.text")
                    .font(.system(size: 44))
                    .foregroundStyle(.secondary)
                Text(export.url.lastPathComponent)
                    .font(.callout.monospaced())
                Text("\(export.summary) · \(sizeLabel)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                if let loss = export.loss {
                    // Shown before the share button so it informs the choice. Secondary color:
                    // it's a format limitation, not an error.
                    Text(loss)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
                ShareLink(item: export.url) {
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

    private var sizeLabel: String {
        let bytes = (try? FileManager.default.attributesOfItem(atPath: export.url.path)[.size] as? Int) ?? nil
        return ByteFormat.volume(Int64(bytes ?? 0))
    }
}

/// A parsed .lsrules file awaiting confirmation.
struct PendingImport: Identifiable {
    let id = UUID()
    let report: LSRulesImporter.Report
    let fileName: String
}

/// Two phases in one sheet: the file's contents, then what the merge added.
/// Shows net adds so they can be compared with the file's counts.
private struct RuleImportSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let pending: PendingImport
    /// nil until the merge runs; then the merge's own summary.
    @State private var summary: String?

    private var report: LSRulesImporter.Report { pending.report }

    var body: some View {
        NavigationStack {
            List {
                if let summary {
                    Section {
                        Text(summary)
                    }
                } else {
                    Section {
                        // Only counts a merge can change; "0 skipped" on a clean file adds nothing.
                        LabeledContent("Rules", value: "\(report.rules.count)")
                        if !report.blocklistDomains.isEmpty {
                            LabeledContent("Blocked domains", value: "\(report.blocklistDomains.count)")
                        }
                        if !report.skipped.isEmpty {
                            LabeledContent("Skipped", value: "\(report.skipped.count)")
                        }
                    } header: {
                        // The file name, not the group name or description inside it, which are
                        // untrusted free text.
                        Text(pending.fileName)
                    } footer: {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Rules already in your list are skipped.")
                            // Same lines the summary prints, from the same function, so they can't drift.
                            ForEach(AppModel.importDowngradeLines(report), id: \.self) { line in
                                Text(line)
                            }
                        }
                    }
                }
            }
            // "Import rules" rather than "Import" so the title doesn't duplicate the
            // confirm button.
            .navigationTitle("Import rules")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if summary == nil {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Import") { summary = model.applyImport(report) }
                    }
                } else {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { dismiss() }
                    }
                }
            }
        }
    }
}

/// A country policy row: flag and localized name, tappable to open
/// `CountryPolicySheet`. No controls: a policy that exists is enforced, and
/// removing it is a swipe. Re-adding it via the picker keeps its targets
/// (`AppModel.setCountryPolicy`). The action isn't shown since a country
/// policy always blocks (`CountryPolicy.derivedAction`).
struct CountryPolicyRow: View {
    let policy: CountryPolicy
    let onOpen: () -> Void

    var body: some View {
        HStack {
            Button(action: onOpen) {
                HStack {
                    Text(CountryFlag.emoji(policy.countryCode))
                    Text(RecentTargets.countryName(policy.countryCode))
                        .lineLimit(1)
                }
                // The full row width opens the sheet, as with rule rows.
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            // VoiceOver still hears the action even though the row doesn't show it. It's
            // "Block" (what the policy does), matching the sheet's Policy row. The target
            // count isn't spoken because it isn't shown anywhere in the app.
            .accessibilityValue("Block")
        }
    }
}

/// A rule row: the target and a flip control. Everything else (action, scope,
/// expiry, note, overrides, recent matches) is in `RuleDetailSheet`.
/// The text half is a button that opens the sheet; the flip control is a
/// sibling, and the plain button style keeps the row's own colors.
struct RuleRow: View {
    let rule: Rule
    let onFlip: () -> Void
    let onOpen: () -> Void

    var body: some View {
        HStack {
            Button(action: onOpen) {
                Text(rule.target.displayText)
                    .font(.body.monospaced())
                    .lineLimit(1)
                    // Full width is tappable, otherwise short domains are hard to hit.
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            // Action is spoken with the target so VoiceOver reads both in one element.
            // Matches the flip control, the detail sheet's Action row and the swipe button.
            .accessibilityValue(rule.action == .allow ? "Allow" : "Block")
            RuleFlipControl(action: rule.action, flip: onFlip)
        }
    }
}

/// Capsule showing the rule's current action; tapping flips it. Sized like a
/// switch to keep the row's layout, but it has no off state.
///
/// The label is the current action, not what a tap will do, so a scanned list
/// shows what rules do. Swipe buttons use the verb reading instead.
///
/// Fill colors are darker than `.red`/`.green` for contrast with white text;
/// see the constants below.
struct RuleFlipControl: View {
    /// Under Reduce Motion the flip still happens, just without animation.
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let action: RuleAction
    let flip: () -> Void

    /// #D32F2F, white text at 4.98:1 (AA at any size). `.red` (#FF3B30) gives
    /// only 3.55:1.
    private static let blockFill = Color(red: 0.827, green: 0.184, blue: 0.184)
    /// #15803D, white text at 5.02:1. `.green` (#34C759) gives only 2.2:1.
    /// Close in luminance to the block fill (0.159 vs 0.161) so the states differ
    /// only in hue and word.
    private static let allowFill = Color(red: 0.082, green: 0.502, blue: 0.239)

    private var word: String { action == .allow ? "Allow" : "Block" }
    private var opposite: String { action == .allow ? "Block" : "Allow" }

    var body: some View {
        Button(action: flip) {
            Text(word)
                .font(.footnote.weight(.semibold))
                .foregroundStyle(.white)
                // Cross-fade the word instead of snapping it.
                .contentTransition(.opacity)
                .padding(.horizontal, 12)
                // A UISwitch is 51×31. Minimums rather than a fixed size so the word isn't
                // clipped at accessibility text sizes.
                .frame(minWidth: 58, minHeight: 30)
                .background(action == .allow ? Self.allowFill : Self.blockFill, in: Capsule())
                // 44 pt tap target around the 30 pt capsule; the row is 44 pt tall anyway.
                .frame(minHeight: 44)
                .contentShape(Rectangle())
        }
        // Plain style, or the row's two buttons merge into one blue tap target.
        .buttonStyle(.plain)
        .animation(reduceMotion ? nil : .easeOut(duration: 0.2), value: action)
        // Label "Action" with the current action as the value. A label of "Block"
        // would announce what the button does, and tapping does the opposite.
        .accessibilityLabel("Action")
        .accessibilityValue(word)
        .accessibilityHint("Double tap to \(opposite.lowercased()).")
    }
}

extension AppModel.RuleOverride {
    var caption: String {
        switch self {
        case .blocklist: "Overrides a blocklist entry"
        case .threatFeed: "Overrides a threat feed entry"
        }
    }
}

extension RuleTarget {
    /// Human-readable form of `derivedPriority`, shown as the detail sheet's Scope row.
    var scopeText: String {
        switch self {
        case .domain(let value):
            DomainName.normalize(value).hasPrefix("*.") ? "Site-wide" : "Exact target"
        case .ip: "Exact target"
        case .cidr: "Network range"
        case .port: "Any destination on this port"
        case .network: "Any destination on this protocol"
        }
    }

    /// Human-readable target: the rule row's primary line and what Rules search
    /// matches against.
    var displayText: String {
        switch self {
        case .domain(let value): value
        case .ip(let value): value
        case .cidr(let value): value
        case .port(let range):
            range.lowerBound == range.upperBound
                ? "Port \(range.lowerBound)"
                : "Ports \(range.lowerBound)–\(range.upperBound)"
        case .network(let proto, let port):
            // Use `FlowRow.protocolName` so this matches Live Traffic ("TCP" rather than
            // "Protocol 6"). Unnamed protocols come out as "#41".
            "\(FlowRow.protocolName(proto))" + (port.map { " ports \($0.lowerBound)–\($0.upperBound)" } ?? "")
        }
    }
}
