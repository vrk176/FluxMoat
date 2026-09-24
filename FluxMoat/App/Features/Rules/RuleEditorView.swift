import SharedCore
import SwiftUI

// Rule priority is not user-editable. It is derived from the target's shape
// (`RuleTarget.derivedPriority`) by AppModel's writers, which are the only
// code that sets it.

/// Creates a new rule or edits an existing one.
struct RuleEditorView: View {
    enum TargetKind: String, CaseIterable, Identifiable {
        case domain = "Domain"
        case ip = "IP"
        case cidr = "Network range"
        case port = "Port"
        /// Named this way because `protocol` is a keyword; the raw value is the
        /// picker label.
        case protocolKind = "Protocol"

        var id: String { rawValue }
    }

    /// When the rule already has an expiry, "keep it" must be an option. The
    /// durations are relative to now, so otherwise editing only the note would
    /// move the expiry.
    private enum Expiry: Hashable {
        case keep(Date)
        case after(TimeInterval)
    }

    /// The rule being edited, or nil for a new one. Carries fields the editor
    /// doesn't show, including the id.
    private let editing: Rule?
    private let originalExpiry: Date?
    /// The rule to write, and the id of an existing rule it replaces (nil for a
    /// plain add or edit). A replacement happens when the user writes the opposite
    /// action for a target that already has a rule, so the two don't coexist.
    let onSave: (Rule, UUID?) -> Void

    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var action: RuleAction
    @State private var kind: TargetKind
    @State private var value: String
    @State private var portUpper: String
    /// IANA protocol number, as stored in `RuleTarget.network`.
    /// `FlowRow.protocolName` turns it into a name for the picker.
    @State private var protocolNumber: UInt8
    @State private var temporary: Bool
    @State private var expiry: Expiry
    @State private var note: String

    init(rule: Rule? = nil, onSave: @escaping (Rule, UUID?) -> Void) {
        self.editing = rule
        self.onSave = onSave
        self.originalExpiry = rule?.expiresAt

        var seedKind = TargetKind.domain
        var seedValue = ""
        var seedUpper = ""
        var seedProtocol = Self.defaultProtocol
        switch rule?.target {
        case .domain(let raw): seedValue = raw
        case .ip(let raw): seedKind = .ip; seedValue = raw
        case .cidr(let raw): seedKind = .cidr; seedValue = raw
        case .port(let range):
            seedKind = .port
            seedValue = "\(range.lowerBound)"
            seedUpper = range.lowerBound == range.upperBound ? "" : "\(range.upperBound)"
        case .network(let proto, let range):
            // Uses the same port fields as the Port kind; left blank when the rule
            // covers the whole protocol, which is common for imported rules.
            seedKind = .protocolKind
            seedProtocol = proto
            if let range {
                seedValue = "\(range.lowerBound)"
                seedUpper = range.lowerBound == range.upperBound ? "" : "\(range.upperBound)"
            }
        case nil: break
        }

        _action = State(initialValue: rule?.action ?? .deny)
        _kind = State(initialValue: seedKind)
        _value = State(initialValue: seedValue)
        _portUpper = State(initialValue: seedUpper)
        _protocolNumber = State(initialValue: seedProtocol)
        _temporary = State(initialValue: rule?.expiresAt != nil)
        _expiry = State(initialValue: rule?.expiresAt.map(Expiry.keep) ?? .after(3600))
        _note = State(initialValue: rule?.note ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Picker("Action", selection: $action) {
                    Text("Block").tag(RuleAction.deny)
                    Text("Allow").tag(RuleAction.allow)
                }
                .pickerStyle(.segmented)

                Picker("Target type", selection: $kind) {
                    ForEach(TargetKind.allCases) { kind in
                        Text(kind.rawValue).tag(kind)
                    }
                }

                Section {
                    if kind == .protocolKind {
                        Picker("Protocol", selection: $protocolNumber) {
                            ForEach(protocolChoices, id: \.self) { number in
                                Text(FlowRow.protocolName(number)).tag(number)
                            }
                        }
                    }
                    TextField(placeholder, text: $value)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .keyboardType(usesPortFields ? .numberPad : .URL)
                    if usesPortFields {
                        TextField("Upper port (optional, for a range)", text: $portUpper)
                            .keyboardType(.numberPad)
                    }
                } footer: {
                    if kind == .domain {
                        // Target shape decides which rule wins, so say it where the target is typed.
                        Text("Use *.example.com to match subdomains. A rule for an exact name beats a site-wide one.")
                    } else if kind == .protocolKind {
                        VStack(alignment: .leading, spacing: 6) {
                            // Blank usually means "not filled in", so spell out that it's valid here.
                            Text("Leave the ports empty to match every port on this protocol.")
                            if protocolNumber == Self.icmp {
                                // ICMP rules can be saved but don't filter yet; say so in the editor.
                                Text(CapabilityCopy.icmpEditorHint)
                            }
                        }
                    }
                }

                Section {
                    Toggle("Temporary", isOn: $temporary)
                    if temporary {
                        Picker("Expires in", selection: $expiry) {
                            if let originalExpiry {
                                Text("Keep \(RuleFormat.expiry(originalExpiry))")
                                    .tag(Expiry.keep(originalExpiry))
                            }
                            Text("15 minutes").tag(Expiry.after(900))
                            Text("1 hour").tag(Expiry.after(3600))
                            // A flat 86,400 seconds from Save, not "until tomorrow".
                            Text("24 hours").tag(Expiry.after(86_400))
                        }
                    }
                    TextField("Note", text: $note)
                }

                if let validationMessage {
                    Text(validationMessage).foregroundStyle(.red)
                }
                // Red is reserved for blocked and for the error above that prevents saving.
                // The notices below describe saves that will go through, so they stay neutral.
                // Separate rows so an error and a notice can show at the same time.
                if let replacementNotice {
                    Text(replacementNotice)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if let scopeNotice {
                    Text(scopeNotice)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle(editing == nil ? "New Rule" : "Edit Rule")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .disabled(!canSave)
                }
            }
        }
    }

    private var placeholder: String {
        switch kind {
        case .domain: "example.com or *.example.com"
        case .ip: "203.0.113.7 or 2001:db8::1"
        case .cidr: "10.0.0.0/8 or 2001:db8::/32"
        case .port: "Port number, e.g. 443"
        case .protocolKind: "Port number (optional), e.g. 443"
        }
    }

    /// TCP, since most flows use it.
    private static let defaultProtocol: UInt8 = 6

    /// The protocols `FlowRow.protocolName` has names for.
    private static let namedProtocols: [UInt8] = [6, 17, 1]

    /// ICMP is not filtered by the data plane yet, hence the footer note.
    private static let icmp: UInt8 = 1

    /// An imported .lsrules rule can use a protocol number outside the named set.
    /// Give it its own row, or the picker would show an empty selection and the
    /// first tap would silently rewrite the rule to TCP.
    private var protocolChoices: [UInt8] {
        Self.namedProtocols.contains(protocolNumber)
            ? Self.namedProtocols
            : Self.namedProtocols + [protocolNumber]
    }

    /// Port and Protocol both use the same pair of port fields. The only
    /// difference is that ports are optional for a protocol rule.
    private var usesPortFields: Bool {
        kind == .port || kind == .protocolKind
    }

    /// Edits modify the existing rule instead of building a fresh `Rule`, so the
    /// id (see `AppModel.updateRule`), `createdAt`, `enabled` and profile scope
    /// survive. Rebuilding would reset them and could widen a profile-scoped rule
    /// to all profiles.
    ///
    /// Save is already disabled while the form is invalid; the guard is a backstop.
    private func save() {
        guard validationMessage == nil, let target = resolvedTarget else { return }
        onSave(assembled(target: target), replacedRuleID)
        dismiss()
    }

    /// The id this save replaces, if any. Only an opposite-action conflict on the
    /// same target replaces a rule; duplicates block the save, and shadowed rules
    /// have a different target.
    private var replacedRuleID: UUID? {
        if case .opposite(let existing) = conflict { return existing.id }
        return nil
    }

    /// Builds the rule this sheet describes so the notices check the same object
    /// `save` would write. Applies `.leveled` because the notices read the
    /// priority; AppModel re-derives it on write with the same
    /// `RuleTarget.derivedPriority`, so the two agree. For example, retyping a
    /// host as `*.host` moves the rule from exact to site-wide.
    private func assembled(target: RuleTarget) -> Rule {
        let expiresAt: Date? = temporary ? resolvedExpiry : nil
        let trimmedNote = note.isEmpty ? nil : note
        if var edited = editing {
            edited.action = action
            edited.target = target
            edited.expiresAt = expiresAt
            edited.note = trimmedNote
            return edited.leveled
        }
        return Rule(
            action: action,
            target: target,
            expiresAt: expiresAt,
            note: trimmedNote
        ).leveled
    }

    private var resolvedExpiry: Date {
        switch expiry {
        case .keep(let date): date
        case .after(let interval): Date().addingTimeInterval(interval)
        }
    }

    /// Parse result. Not `Result`: the failure is a message for the user, not an
    /// `Error`.
    private enum ParsedTarget {
        case ok(RuleTarget)
        case invalid(String)
    }

    private var resolvedTarget: RuleTarget? {
        if case .ok(let target) = parsedTarget { return target }
        return nil
    }

    private var canSave: Bool {
        resolvedTarget != nil && validationMessage == nil
    }

    /// The current validation error, or nil. Computed from @State, so it updates
    /// on every keystroke and picker change and never goes stale.
    private var validationMessage: String? {
        // An empty, untouched form isn't an error. Save is disabled anyway.
        if !isTargetUntouched, case .invalid(let reason) = parsedTarget {
            return reason
        }
        if let target = resolvedTarget, CountryPolicy.isDerived(assembled(target: target)) {
            return countryPolicyCollision
        }
        // Checked last: the other two concern a rule that would be broken or lost.
        // Kept in this property so there's a single answer to why Save is disabled
        // and `canSave` can't disagree with the message.
        if case .duplicate(let existing) = conflict {
            return duplicateMessage(existing)
        }
        return nil
    }

    /// Nothing typed into any target field yet. Includes the upper port, since a
    /// protocol rule can be valid with only the upper port filled in.
    private var isTargetUntouched: Bool {
        value.isEmpty && (!usesPortFields || portUpper.isEmpty)
    }

    /// The rule `save` would write, or nil while the fields don't describe one.
    /// The checks below judge this rather than the raw form.
    private var candidate: Rule? {
        resolvedTarget.map { assembled(target: $0) }
    }

    /// Computed rather than cached so it never reflects an outdated field value.
    private var conflict: AppModel.RuleConflict? {
        guard let candidate else { return nil }
        return model.ruleConflict(for: candidate, excluding: editing?.id)
    }

    /// Points to the existing rule, including its note, since the fix is to edit
    /// that rule rather than this form.
    private func duplicateMessage(_ existing: Rule) -> String {
        let existingNote = existing.note ?? ""
        let noteSuffix = existingNote.isEmpty ? "" : " — “\(existingNote)”"
        return "A rule already \(verb(for: existing.action)) this target\(noteSuffix). "
            + "Edit that rule instead of adding a second one."
    }

    /// Not an error: the user is changing their mind about a target. Says what
    /// the save will replace so the old rule doesn't silently disappear.
    private var replacementNotice: String? {
        guard case .opposite(let existing) = conflict else { return nil }
        return "Saving replaces the existing rule that \(verb(for: existing.action)) this target."
    }

    /// Other rules that reach this target. Informational only: the narrower rule
    /// always wins, so blocking a site-wide target won't override a host rule
    /// inside it.
    private var scopeNotice: String? {
        guard let candidate,
              let notice = model.scopeNotice(for: candidate, excluding: editing?.id)
        else { return nil }
        switch notice {
        case .narrower(let inner):
            // Names the inner target, since that's the rule to change for a different result.
            return "\(inner.target.displayText) already has its own rule, which wins for that target."
        case .wider(let outer):
            return "Overrides \(outer.target.displayText) for this target."
        }
    }

    /// How to describe an existing rule's action in a sentence.
    private func verb(for action: RuleAction) -> String {
        action == .allow ? "allows" : "blocks"
    }

    /// Rejects rules that look like compiled country-policy rules. At launch those
    /// are stripped from the snapshot by priority and note prefix
    /// (`CountryPolicy.isDerived`), so a user rule matching both would be silently
    /// dropped. The priority ladder currently can't produce that priority, so this
    /// is a safeguard; the message names the note because that's what the user
    /// can change. Calls `isDerived` directly so the check can't drift from the stripper.
    private var countryPolicyCollision: String {
        "A country-policy note is reserved — the app rebuilds those rules at launch, so this one would be dropped. Change the note."
    }

    /// Pure parse of the fields. Writes no @State, so it is safe to call from
    /// the view body.
    private var parsedTarget: ParsedTarget {
        let trimmed = value.trimmingCharacters(in: .whitespaces)
        switch kind {
        case .domain:
            let normalized = DomainName.normalize(trimmed)
            let host = normalized.hasPrefix("*.") ? String(normalized.dropFirst(2)) : normalized
            guard !host.isEmpty, !host.contains(" "), !host.hasPrefix(".") else {
                return .invalid("Enter a valid domain name.")
            }
            return .ok(.domain(normalized))
        case .ip:
            guard IPAddress.parse(trimmed) != nil else {
                return .invalid("Enter a valid IPv4 or IPv6 address.")
            }
            return .ok(.ip(trimmed))
        case .cidr:
            guard CIDRBlock(trimmed) != nil else {
                return .invalid("Enter a valid network range like 10.0.0.0/8.")
            }
            return .ok(.cidr(trimmed))
        case .port:
            guard let lower = UInt16(trimmed) else {
                return .invalid("Enter a port between 0 and 65535.")
            }
            let upper = portUpper.isEmpty ? lower : UInt16(portUpper) ?? lower
            guard upper >= lower else {
                return .invalid("Upper port must be ≥ lower port.")
            }
            return .ok(.port(lower...upper))
        case .protocolKind:
            // No ports means the whole protocol, which is how imported .lsrules protocol
            // rules arrive. Typed ports get the same bounds and messages as the Port kind.
            if trimmed.isEmpty, portUpper.isEmpty {
                return .ok(.network(protocolNumber: protocolNumber, port: nil))
            }
            guard let lower = UInt16(trimmed) else {
                return .invalid("Enter a port between 0 and 65535.")
            }
            let upper = portUpper.isEmpty ? lower : UInt16(portUpper) ?? lower
            guard upper >= lower else {
                return .invalid("Upper port must be ≥ lower port.")
            }
            return .ok(.network(protocolNumber: protocolNumber, port: lower...upper))
        }
    }
}
