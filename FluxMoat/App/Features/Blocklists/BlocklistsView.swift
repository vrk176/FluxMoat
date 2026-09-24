import SharedCore
import SwiftUI

/// Blocklist subscriptions: enable, update and delete per source; pull to refresh
/// updates every enabled list. The first download of a list always needs a tap.
/// After that `AppModel.refreshBlocklistsOnForeground` keeps it current.
struct BlocklistsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    @State private var showingAdd = false
    @State private var confirmingManualDelete = false

    /// Pushed from Rules in the same stack, so it uses the same background.
    private var isDark: Bool { colorScheme == .dark }

    var body: some View {
        List {
            Section {
                ForEach(model.blocklistSources) { source in
                    BlocklistSourceRow(
                        source: source,
                        isUpdating: model.updatingBlocklistIDs.contains(source.id),
                        onToggle: { model.toggleBlocklistSource(source.id) },
                        onUpdate: { Task { await model.updateBlocklistSource(source.id) } }
                    )
                }
                .onDelete { model.deleteBlocklistSources(at: $0) }
                // Imported domains are a source like any other (`manualDomainsID`), but have
                // no URL to re-fetch and nothing to toggle, so the row has neither control.
                if !model.blocklistDomains.isEmpty {
                    ImportedDomainsRow(count: model.blocklistDomains.count)
                        // Stricter than subscriptions: a deleted subscription can be fetched again,
                        // imported domains are gone unless the user still has the file.
                        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
                            Button("Delete", role: .destructive) {
                                confirmingManualDelete = true
                            }
                        }
                }
            } footer: {
                Text("Enabled lists refresh themselves when you open the app — checked every few hours at most, and left alone on Low Data Mode. A new subscription waits for your first Update.")
            }
            .brandCardRows(isDark)
        }
        .confirmationDialog(
            "Delete \(model.blocklistDomains.count) imported domains?",
            isPresented: $confirmingManualDelete,
            titleVisibility: .visible
        ) {
            Button("Delete domains", role: .destructive) {
                model.removeManualDomains()
            }
        } message: {
            Text("They came from a .lsrules file, so there is nothing to re-download them from. Your subscriptions are not affected.")
        }
        .overlay {
            if model.blocklistSources.isEmpty {
                ContentUnavailableView(
                    "No blocklists",
                    systemImage: "shield.slash",
                    description: Text("Subscribe to a hosts or domain list to block ads, trackers and malware domains.")
                )
            }
        }
        .readableWidth()
        .brandDarkBackground()
        .navigationTitle("Blocklists")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                // Explicit download button. Swipe and pull alone left first-run users with
                // enabled but empty lists.
                if model.updatingBlocklistIDs.isEmpty {
                    Button("Update all", systemImage: "arrow.clockwise") {
                        Task { await model.updateAllBlocklistSources() }
                    }
                    .disabled(model.blocklistSources.allSatisfy { !$0.enabled })
                } else {
                    ProgressView()
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button("Add", systemImage: "plus") { showingAdd = true }
            }
        }
        .refreshable { await model.updateAllBlocklistSources() }
        .sheet(isPresented: $showingAdd) {
            AddBlocklistSourceView { name, url, format, category in
                model.addBlocklistSource(name: name, url: url, format: format, category: category)
            }
        }
    }
}

private struct ImportedDomainsRow: View {
    let count: Int

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Imported domains")
                .lineLimit(1)
            Text("\(count) domains · from .lsrules import")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

private struct BlocklistSourceRow: View {
    let source: BlocklistSource
    let isUpdating: Bool
    let onToggle: () -> Void
    let onUpdate: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(source.name).lineLimit(1)
                    if source.category == .threat {
                        Text("THREAT")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 5).padding(.vertical, 1)
                            .background(BrandPalette.threat.opacity(0.18), in: Capsule())
                            .foregroundStyle(BrandPalette.threat)
                    }
                }
                if let error = source.updateError {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .lineLimit(2)
                } else {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if isUpdating {
                ProgressView()
            } else {
                Button(action: onUpdate) {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .disabled(!source.enabled)
                Toggle("", isOn: .init(get: { source.enabled }, set: { _ in onToggle() }))
                    .labelsHidden()
            }
        }
        .swipeActions(edge: .leading) {
            Button("Update", systemImage: "arrow.clockwise", action: onUpdate)
                .tint(.blue)
        }
    }

    private var detail: String {
        let kind: String
        switch source.format {
        case .hosts: kind = "hosts"
        case .domainList: kind = "domains"
        case .ipList: kind = "IPs"
        case .cidrList: kind = "CIDRs"
        case .jsonManifest: kind = "JSON"
        case .lsrules: kind = "rules"
        }
        var parts = [kind]
        if source.entryCount > 0 {
            parts.append("\(source.entryCount) entries")
        }
        if let updated = source.lastUpdatedAt {
            parts.append("updated \(updated.formatted(.relative(presentation: .named)))")
        } else {
            parts.append("not downloaded yet")
        }
        return parts.joined(separator: " · ")
    }
}

private struct AddBlocklistSourceView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var urlText = ""
    @State private var format: BlocklistSource.Format = .hosts
    @State private var category: BlocklistSource.Category = .adTracker
    let onAdd: (String, URL, BlocklistSource.Format, BlocklistSource.Category) -> Void

    /// HTTPS is enforced again at download time; checking here just gives earlier feedback.
    private var url: URL? {
        guard let url = URL(string: urlText), url.scheme?.lowercased() == "https" else { return nil }
        return url
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $name)
                    TextField("https://…", text: $urlText)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Picker("Format", selection: $format) {
                        Text("Hosts file").tag(BlocklistSource.Format.hosts)
                        Text("Domain list").tag(BlocklistSource.Format.domainList)
                        Text("IP list").tag(BlocklistSource.Format.ipList)
                        Text("CIDR list").tag(BlocklistSource.Format.cidrList)
                        Text("JSON manifest (ThreatFox)").tag(BlocklistSource.Format.jsonManifest)
                    }
                    Picker("Category", selection: $category) {
                        Text("Ads & trackers").tag(BlocklistSource.Category.adTracker)
                        Text("Threat (malware/C2)").tag(BlocklistSource.Category.threat)
                    }
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Threat feeds are broken out as \u{201C}Threat\u{201D} in the Insights charts. IP/CIDR feeds are always treated as threat indicators.")
                        // Without this, a ThreatFox download fails with a 401 the user can't tie to a
                        // missing key. Only abuse.ch-hosted feeds need the key; the bundled ThreatFox
                        // subscription comes from our own mirror and doesn't.
                        Text("A \u{201C}JSON manifest\u{201D} feed hosted by abuse.ch needs the Auth-Key from Settings \u{2192} Threat intelligence, or the download is rejected. The FluxMoat feeds mirror needs no key \u{2014} the ThreatFox subscription that comes with the app is served from there.")
                    }
                }
            }
            .navigationTitle("Add Blocklist")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        if let url {
                            onAdd(name.isEmpty ? (url.host() ?? "Blocklist") : name, url, format, category)
                            dismiss()
                        }
                    }
                    .disabled(url == nil)
                }
            }
        }
    }
}
