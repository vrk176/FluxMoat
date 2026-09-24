import SharedCore
import SwiftUI
import os

/// Same category as the Rules list. Log booleans only, never a rule's target.
private let ruleDetailLog = Logger(subsystem: "fluxmoat", category: "rules")

/// One rule with all its details, plus Edit and Delete. Follows the same layout
/// as `TargetDetailSheet` and `FlowDetailSheet`: one LabeledContent per fact,
/// inline title, Done in the confirmation slot, detents set by the caller.
struct RuleDetailSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    /// Snapshot from when the row was tapped. Reads go through `rule`, which
    /// re-reads from the model by id, so edits made from this sheet show up here.
    let initial: Rule
    @State private var editing = false
    /// Flows this rule decided, newest first. Empty both while loading and for a
    /// rule with no hits, so the section checks `rollup` to tell them apart.
    @State private var matches: [TrafficEvent] = []

    private var rule: Rule { model.rules.first { $0.id == initial.id } ?? initial }

    /// Read from the same dictionary as the row's caption so the two can't disagree.
    private var rollup: TrafficEventStore.RuleMatchRollup? { model.ruleHits[rule.id] }

    var body: some View {
        NavigationStack {
            List {
                Section {
                    LabeledContent("Target") {
                        Text(rule.target.displayText)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                            // The only row allowed to wrap: the target is the rule's identity and may be long.
                            .multilineTextAlignment(.trailing)
                    }
                    LabeledContent("Action") {
                        Text(rule.action == .allow ? "Allow" : "Block")
                            .foregroundStyle(rule.action == .allow ? .green : .red)
                    }
                    // Show the scope rather than the raw priority number it's derived from.
                    LabeledContent("Scope", value: rule.target.scopeText)
                    LabeledContent("Created", value: RuleFormat.timestamp(rule.createdAt))
                    // Omitted when empty instead of showing "never" or a blank note.
                    if let expiresAt = rule.expiresAt {
                        // Absolute time plus a relative reading. Always future tense: lapsed rules
                        // are deleted, never shown.
                        LabeledContent("Expires") {
                            VStack(alignment: .trailing, spacing: 2) {
                                Text(RuleFormat.timestamp(expiresAt))
                                Text(RuleFormat.expiryCaption(expiresAt))
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    if let note = rule.note, !note.isEmpty {
                        LabeledContent("Note") {
                            Text(note).multilineTextAlignment(.trailing)
                        }
                    }
                    if let override = model.overrideNotice(for: rule) {
                        LabeledContent("Overrides") {
                            Text(override.caption)
                                .foregroundStyle(BrandPalette.threat)
                                .multilineTextAlignment(.trailing)
                        }
                    }
                }

                // Hidden when the store couldn't be read (`AppModel.ruleHitsKnown`), so an
                // unreadable store isn't reported as "no matches".
                if model.ruleHitsKnown {
                    Section {
                        if let rollup {
                            LabeledContent("Matches", value: "\(rollup.hits)")
                            LabeledContent("Last match", value: RuleFormat.timestamp(rollup.lastHit))
                            ForEach(matches) { event in
                                // Time and verdict only; the target is already at the top of the sheet.
                                LabeledContent(RuleFormat.timestamp(event.timestamp)) {
                                    Text(event.verdict == .allow ? "Allowed" : "Blocked")
                                        .foregroundStyle(event.verdict == .allow ? .green : .red)
                                }
                            }
                        } else {
                            Text("No matches in retained history")
                                .foregroundStyle(.secondary)
                        }
                    } header: {
                        Text("Recent matches")
                    } footer: {
                        // Retention deletes old flows, so an empty list can't distinguish a rule that
                        // never fired from one whose last match aged out.
                        Text("History is deleted after the retention period, so a rule that last matched before then shows nothing here.")
                    }
                }

                Section {
                    Button("Edit rule") {
                        ruleDetailLog.notice("✅ app:rules editorOpen VERIFY editing=\(true, privacy: .public)")
                        editing = true
                    }
                }

                Section {
                    Button("Delete rule", role: .destructive) {
                        model.removeRules(ids: [rule.id])
                        dismiss()
                    }
                }
            }
            .navigationTitle("Rule")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            // Skip the query when the rollup says there are no hits: `recentMatches` does
            // a full scan either way, and most rules never match.
            .task {
                guard rollup != nil else { return }
                matches = await model.recentMatches(for: rule.id)
            }
            // The rule can disappear while this is open: it expires and gets purged,
            // another device deletes it via iCloud, or an edit here merges it into
            // another rule (`AppModel.commitRule`). Dismiss instead of showing the stale
            // `initial` copy with a Delete button that does nothing.
            .onChange(of: model.rules.contains { $0.id == initial.id }) { _, present in
                if !present { dismiss() }
            }
            .sheet(isPresented: $editing) {
                RuleEditorView(rule: rule) { model.commitRule($0, replacing: $1) }
            }
        }
    }
}

/// Date formatting for the Rules screens.
enum RuleFormat {
    /// Time only when the date is today, otherwise date and time, so "3:12 PM" on
    /// something expiring tomorrow isn't misread as this afternoon.
    static func timestamp(_ date: Date) -> String {
        Calendar.current.isDateInToday(date)
            ? date.formatted(date: .omitted, time: .shortened)
            : date.formatted(date: .abbreviated, time: .shortened)
    }

    /// Same as `timestamp`, worded for a picker row that keeps the current value.
    static func expiry(_ date: Date) -> String {
        "until \(timestamp(date))"
    }

    /// "Expires in 42 min". Future tense only, since lapsed rules are purged within
    /// a tick (`AppModel.purgeLapsedRules`). Uses the system relative formatter.
    static func expiryCaption(_ date: Date) -> String {
        "Expires \(date.formatted(.relative(presentation: .numeric, unitsStyle: .abbreviated)))"
    }

    /// Whether the rule's expiry has passed. `AppModel` calls this at launch and on
    /// each tick to delete lapsed rules.
    static func hasLapsed(_ rule: Rule, now: Date = Date()) -> Bool {
        guard let expiresAt = rule.expiresAt else { return false }
        return expiresAt <= now
    }
}
