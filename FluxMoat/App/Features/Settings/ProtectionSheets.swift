import SharedCore
import SwiftUI

// Sheets behind the Protection section's two rows. Each row shows a name and
// the current value; the explanations live in the sheet.

extension RunMode {
    /// The modes offered in the UI, in the order the section footer lists them.
    /// Not `allCases`: `.learning` and `.pause` are retired and must stay off screen.
    static let liveCases: [RunMode] = [.standard, .strict, .ask]

    /// What the engine does with an unmatched connection. Mirrors
    /// `RunMode.defaultAction(profileDefault:)`; keep them in sync.
    var explanation: String {
        switch self {
        case .standard:
            "Allows connections no rule and no list matched. Blocklists and threat feeds still block."
        case .strict:
            "Blocks connections no rule and no list matched. Anything you want through needs an Allow rule."
        case .ask:
            "Applies the current profile's default to unmatched connections, then notifies you so you can decide."
        // Retired and unreachable: only `liveCases` builds rows, and decoding maps
        // both to `.standard`.
        case .learning, .pause:
            "Allows connections no rule and no list matched."
        }
    }
}

/// Run mode picker with each mode's behavior described next to it.
struct ModeSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(RunMode.liveCases, id: \.self) { mode in
                        Button {
                            model.mode = mode
                            dismiss()
                        } label: {
                            HStack(alignment: .firstTextBaseline) {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(mode.displayName)
                                        .foregroundStyle(.primary)
                                    Text(mode.explanation)
                                        .font(.footnote)
                                        .foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                                Spacer()
                                if model.mode == mode {
                                    Image(systemName: "checkmark")
                                        .font(.footnote.weight(.semibold))
                                        .foregroundStyle(.tint)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(model.mode == mode ? [.isSelected] : [])
                    }
                } footer: {
                    // Explains where the mode sits in the decision order.
                    Text("The mode is the last word: your rules, then country policies, then threat feeds and blocklists all get to decide first.")
                }
            }
            .navigationTitle("Mode")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

/// Picks the active profile and shows what each one does and which Wi-Fi
/// networks switch to it.
struct ProfileSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    /// The current Wi-Fi network as read by Settings. nil when protection is off
    /// (no VPN session means no SSID; see `refreshCurrentSSID`).
    let currentSSID: String?

    private var active: Profile? { model.activeProfile }

    /// Wi-Fi rules pointing at a profile.
    private func assignedNetworks(_ kind: Profile.Kind) -> [WiFiProfileAssignment] {
        model.wifiAutoProfiles.filter { $0.profileKind == kind }
    }

    /// The Wi-Fi rule responsible for the active profile. Only shown when the
    /// tunnel reports an automatic switch, the current network is known and a
    /// rule matches it; a manual pick must not be attributed to a Wi-Fi rule.
    private var automationCaption: String? {
        guard model.counters.autoProfileKind != nil,
              let ssid = currentSSID,
              WiFiProfileAssignment.match(ssid, in: model.wifiAutoProfiles) != nil
        else { return nil }
        return "Switched here automatically by your Wi-Fi rule for \(ssid)."
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(model.profiles) { profile in
                        Button {
                            // Unlike the mode sheet, this doesn't dismiss: the section below describes
                            // the active profile, so staying lets the user read what they picked.
                            model.activeProfileID = profile.id
                        } label: {
                            HStack(alignment: .firstTextBaseline) {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(profile.name)
                                        .foregroundStyle(.primary)
                                    // Always prefixed with "In Ask mode": only the `RunMode.ask` branch of the
                                    // engine reads `unmatchedAction`.
                                    Text(Self.consequence(profile))
                                        .font(.footnote)
                                        .foregroundStyle(.secondary)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                                Spacer()
                                if model.activeProfileID == profile.id {
                                    Image(systemName: "checkmark")
                                        .font(.footnote.weight(.semibold))
                                        .foregroundStyle(.tint)
                                }
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityAddTraits(
                            model.activeProfileID == profile.id ? [.isSelected] : [])
                    }
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        if let automationCaption {
                            Text(automationCaption)
                        }
                        if model.mode != .ask {
                            // Only the Ask branch of the engine reads `unmatchedAction`.
                            Text("The mode is \(model.mode.displayName), so the profile default is not in use — only Ask mode reads it.")
                        }
                    }
                }

                if let active {
                    Section {
                        LabeledContent("Name", value: active.name)
                        // The label names Ask mode because only that branch reads this value.
                        LabeledContent("Ask-mode default") {
                            Text(active.unmatchedAction == .allow ? "Allow" : "Block")
                                .foregroundStyle(active.unmatchedAction == .allow ? .green : .red)
                        }
                        let networks = assignedNetworks(active.kind)
                        if networks.isEmpty {
                            Text("No Wi-Fi networks switch to this profile.")
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(networks, id: \.ssid) { assignment in
                                LabeledContent("Wi-Fi", value: assignment.ssid)
                            }
                        }
                    } header: {
                        Text("Active profile")
                    } footer: {
                        Text("In Ask mode this default is applied to a connection no rule and no list matched, and you are notified afterwards so you can turn it into a rule. Wi-Fi networks listed here switch to this profile when you join them.")
                    }
                }
            }
            .navigationTitle("Profile")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    private static func consequence(_ profile: Profile) -> String {
        profile.unmatchedAction == .allow
            ? "In Ask mode, allows unmatched connections while it waits for your answer."
            : "In Ask mode, blocks unmatched connections until you allow them."
    }
}
