import SharedCore
import SwiftUI

// Country policies only block. There is no allow direction for a country;
// see CountryPolicy.derivedAction before adding a control that implies one.

/// Copy shared by the Rules section footer, the policy sheet and the picker.
enum CountryPolicyCopy {
    static let coverage = "Covers targets seen from this country, and new ones as they show up. A target's own rule wins."
}

/// One country policy: what it does, when it was created, and a delete button.
/// Intentionally doesn't list the covered targets; the country is the unit the
/// user manages. Separate from `InsightsCountrySheet`, which is about traffic
/// rather than the policy.
struct CountryPolicySheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    /// Snapshot from when the row was tapped. Reads go through `policy`, which
    /// re-reads from the model by id, so the sheet never shows a stale copy.
    let initial: CountryPolicy

    private var policy: CountryPolicy {
        model.countryPolicies.first { $0.id == initial.id } ?? initial
    }

    private var name: String { RecentTargets.countryName(policy.countryCode) }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    // A policy has one direction, so this is a statement rather than a control.
                    LabeledContent("Policy") {
                        Text("Block").foregroundStyle(.red)
                    }
                    LabeledContent("Created", value: RuleFormat.timestamp(policy.createdAt))
                } footer: {
                    Text(CountryPolicyCopy.coverage)
                }

                Section {
                    // No confirmation, matching "Delete rule" and the row's swipe.
                    Button("Delete policy", role: .destructive) {
                        model.removeCountryPolicies(ids: [policy.id])
                        dismiss()
                    }
                }
            }
            // Flag and name, the way the rest of the app names a country.
            .navigationTitle("\(CountryFlag.emoji(policy.countryCode)) \(name)")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }
}

/// Pick a country to block. Offers every ISO region, not just countries seen
/// in traffic, so users can block a place before connecting to it.
struct CountryPolicyPicker: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var query = ""

    private struct Candidate: Identifiable, Hashable {
        /// ISO alpha-2, uppercased, same as `CountryPolicy.countryCode` and
        /// `TrafficEvent.countryCode`.
        let id: String
        let name: String
    }

    /// Built once per process: ~250 regions through a localization lookup and a
    /// locale-aware sort.
    private static let census: [Candidate] = Locale.Region.isoRegions
        .map(\.identifier)
        // Two A-Z letters only. `isoRegions` also includes UN M.49 groupings
        // ("019" = Americas), and GeoIP only produces alpha-2 codes.
        .filter { $0.count == 2 && $0.allSatisfy { ("A"..."Z").contains($0) } }
        .map { Candidate(id: $0, name: RecentTargets.countryName($0)) }
        .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }

    /// Countries that already have a policy are omitted rather than disabled;
    /// picking one again would be a no-op or reset the existing policy.
    private var listed: [Candidate] {
        let taken = Set(model.countryPolicies.map(\.countryCode))
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        return Self.census.filter { candidate in
            guard !taken.contains(candidate.id) else { return false }
            guard !needle.isEmpty else { return true }
            return candidate.name.lowercased().contains(needle)
                || candidate.id.lowercased().contains(needle)
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(listed) { candidate in
                        Button {
                            model.setCountryPolicy(countryCode: candidate.id, blocked: true)
                            dismiss()
                        } label: {
                            HStack(spacing: 8) {
                                Text(CountryFlag.emoji(candidate.id))
                                Text(candidate.name)
                                Spacer()
                            }
                            .contentShape(Rectangle())
                        }
                        // Plain style so rows don't render as blue links.
                        .buttonStyle(.plain)
                    }
                } footer: {
                    Text(CountryPolicyCopy.coverage)
                }
            }
            .overlay {
                if listed.isEmpty {
                    if query.isEmpty {
                        ContentUnavailableView(
                            "Every country has a policy",
                            systemImage: "flag",
                            description: Text("There is nothing left to add. Existing policies are on the Rules page.")
                        )
                    } else {
                        ContentUnavailableView.search(text: query)
                    }
                }
            }
            .searchable(text: $query, prompt: "Country")
            .navigationTitle("Block a country")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}
