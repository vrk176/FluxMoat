import Foundation
import SwiftUI

/// Text produced by "Report a problem". Counts, booleans and labels only:
/// never domains, IP addresses, SSIDs, custom resolver endpoints (a NextDNS
/// profile ID identifies the user) or stored keys.
///
/// No log files are attached. iOS doesn't let an app read its own OSLog store
/// through `OSLogStore` the way macOS does.
enum DiagnosticReport {
    /// Shown on the report itself so the sender knows what is and isn't included.
    static let scopeNote =
        "Settings and counts only. No logs, domains, IP addresses, network names or keys are included."

    @MainActor
    static func build(from model: AppModel, now: Date = .now) -> String {
        var lines: [String] = []

        lines.append("FluxMoat diagnostics — \(now.formatted(date: .abbreviated, time: .shortened))")
        lines.append("")
        lines.append("App: \(Bundle.main.versionLabel)")
        lines.append("iOS: \(systemVersion)")
        lines.append("Device: \(deviceModel)")

        lines.append("")
        lines.append("Protection: \(model.isProtectionOn ? "On" : "Off")")
        lines.append("Mode: \(model.mode.displayName)")
        // The profile kind, not its name: custom profile names are user-typed text.
        lines.append("Profile: \(model.activeProfile?.kind.rawValue ?? "none")")
        lines.append("Keep history: \(model.historyRetention.displayName)")
        lines.append("Encrypted DNS: \(dohLabel(model.dohServerURL))")
        lines.append("Block other encrypted DNS: \(model.blockEncryptedDNS ? "On" : "Off")")
        lines.append("abuse.ch key: \(model.abuseChKeyStored ? "stored" : "none")")
        // Just the switch. `cloudSyncStatus` can hold an arbitrary CloudKit error string.
        lines.append("iCloud Sync: \(model.iCloudSyncEnabled ? "On" : "Off")")

        lines.append("")
        lines.append("Rules: \(model.rules.count)")
        lines.append("Country policies: \(model.countryPolicies.count)")
        lines.append("Blocklist subscriptions: \(model.blocklistSources.count)")
        lines.append("Imported blocklist domains: \(model.blocklistDomains.count)")
        lines.append("Wi-Fi automation rules: \(model.wifiAutoProfiles.count)")
        lines.append("Pending decisions: \(model.pendingAsks.count)")
        // When the store can't be opened, Insights, Live Traffic and export all stop
        // together, which otherwise looks like three separate bugs.
        lines.append("History database: \(model.storeUnavailable ? "unreadable" : "readable")")

        lines.append("")
        lines.append(scopeNote)

        return lines.joined(separator: "\n")
    }

    /// The resolver's picker label. An endpoint matching no preset is reported as
    /// Custom; the URL itself is never included.
    private static func dohLabel(_ stored: String?) -> String {
        guard let stored else { return DoHPreset.off.label }
        return (DoHPreset(rawValue: stored) ?? .custom).label
    }

    /// Trailing zeros dropped, e.g. "26.1" rather than "26.1.0".
    private static var systemVersion: String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        return version.patchVersion == 0
            ? "\(version.majorVersion).\(version.minorVersion)"
            : "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
    }

    /// Hardware model string such as "iPhone17,3". Not a device identifier; every
    /// device of that model reports the same value.
    ///
    /// Check the simulator first: there `uname` reports the Mac's architecture
    /// ("arm64"), while `SIMULATOR_MODEL_IDENTIFIER` holds the simulated model.
    private static var deviceModel: String {
        if let simulated = ProcessInfo.processInfo
            .environment["SIMULATOR_MODEL_IDENTIFIER"], !simulated.isEmpty {
            return "\(simulated) (Simulator)"
        }
        var system = utsname()
        uname(&system)
        // The bytes belong to `system` and must not escape the closure.
        return withUnsafeBytes(of: &system.machine) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
    }
}

/// A built report waiting to be shown. Uses `.sheet(item:)` like `ExportedFile`
/// because the text is computed at tap time; an `isPresented` closure would
/// capture a stale value.
struct DiagnosticReportRequest: Identifiable {
    let id = UUID()
    let text: String
}

/// Shows the full report text before it can be shared.
struct DiagnosticReportSheet: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme
    let report: String

    var body: some View {
        NavigationStack {
            ScrollView {
                Text(report)
                    .font(.footnote.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            // Pinned to the bottom so the share button is always visible.
            .safeAreaInset(edge: .bottom) {
                ShareLink(item: report) {
                    Label("Share or save", systemImage: "square.and.arrow.up")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .brandProminentLabel(colorScheme == .dark)
                .padding()
                .background(.bar)
            }
            .navigationTitle("Report a problem")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
            }
            // Detents are set by the presenting Settings row: on a wide window the sheet's
            // own content still reports a compact size class.
        }
    }
}
