import SharedCore
import SwiftUI

// MARK: - Aggregation

/// Rolled-up counts for one node of the Recent targets tree. Every level
/// (country, group, leaf) uses the same shape.
struct TargetStats: Hashable {
    var connections = 0
    var allowed = 0
    /// Every deny, threats included; matches History's SQL count.
    var blocked = 0
    /// The subset of `blocked` with a known threat reason.
    var threats = 0
    /// The subset of `blocked` from the DoH sinkhole, which runs below the rules
    /// (see `ResolverBlock`), so no allow rule can undo it. A count rather than a
    /// flag so `resolverOnlyBlocks` holds however the flows were partitioned.
    var resolverBlocks = 0
    var bytesUp: UInt64 = 0
    var bytesDown: UInt64 = 0
    /// Bytes per direction within the last `MiniTrafficMeter.windowSeconds`, the
    /// input to `MiniTrafficMeter`. Same meaning and window as Live Traffic's
    /// `FlowGroup.recentUp`, since the meter uses one absolute scale everywhere.
    ///
    /// Distinct from `bytesUp`/`bytesDown`, which cover the whole buffer. The
    /// window test happens per event in `absorb`, so these roll up the tree
    /// without re-walking the buffer.
    var recentUp: UInt64 = 0
    var recentDown: UInt64 = 0
    var lastSeen = Date.distantPast
    /// Distinct remote ports seen for this target, listed in the detail sheet.
    /// Flows without a port (`TrafficEvent.remotePort` is nil) are skipped.
    var ports: Set<UInt16> = []
    /// Distinct protocol numbers. Usually just {6}; a set so a target that also
    /// uses UDP shows both.
    var protocols: Set<UInt8> = []

    /// True when every block on this row came from the DNS resolver sinkhole,
    /// so an Allow rule would have no effect. If any block came from a
    /// blocklist or threat feed, Allow still does something, hence "all" not "any".
    var resolverOnlyBlocks: Bool { blocked > 0 && resolverBlocks == blocked }

    /// `meterWindowStart` is fixed once per build so every row is measured
    /// against the same window and a level means the same thing on every row.
    ///
    /// No upper bound, same as Live Traffic: the clock ticks at 1 Hz and drain
    /// batches arrive whenever, so an event can be slightly newer than the clock.
    mutating func absorb(_ event: TrafficEvent, meterWindowStart: Date) {
        connections += 1
        if event.verdict == .deny {
            blocked += 1
            if FlowRow.isThreat(event) { threats += 1 }
            if ResolverBlock.sank(event) { resolverBlocks += 1 }
        } else {
            allowed += 1
        }
        bytesUp += event.bytesUp
        bytesDown += event.bytesDown
        if event.timestamp >= meterWindowStart {
            // Wrapping add: never trap during a body pass.
            recentUp &+= event.bytesUp
            recentDown &+= event.bytesDown
        }
        lastSeen = max(lastSeen, event.timestamp)
        if let port = event.remotePort { ports.insert(port) }
        protocols.insert(event.protocolNumber)
    }
}

/// Level 3: one concrete destination, a full domain or a single IP address.
struct TargetLeaf: Identifiable, Hashable {
    let id: String
    /// Display string, e.g. `metrics.tracker.example` or `8.8.8.8`.
    let identifier: String
    let countryCode: String?
    let stats: TargetStats
}

/// Level 2 within a country: either a registrable domain and its full domains,
/// or the catch-all bucket for flows without a name.
struct TargetGroup: Identifiable, Hashable {
    let id: String
    let title: String
    let isIPBucket: Bool
    let stats: TargetStats
    let leaves: [TargetLeaf]
}

/// Level 1: everything seen from one country.
struct CountryGroup: Identifiable, Hashable {
    let id: String
    let code: String?
    let name: String
    let stats: TargetStats
    let groups: [TargetGroup]
}

/// One visible List row. The tree is flattened against the current expansion
/// state so every level gets a real list row with its own separator and
/// insert/remove animation.
enum RecentTargetRow: Identifiable {
    case country(CountryGroup, expanded: Bool)
    case group(TargetGroup, expanded: Bool)
    case leaf(TargetLeaf)

    var id: String {
        switch self {
        case .country(let c, _): c.id
        case .group(let g, _): g.id
        case .leaf(let l): l.id
        }
    }
}

enum RecentTargets {
    /// Title of the catch-all IP bucket.
    static let ipBucketTitle = "IP addresses"
    /// Used only by the leaf sheet; the tree has no Unknown row (see `groupingCode`).
    static let unknownCountryName = "Unknown"

    /// Localized country name. Falls back to the raw code rather than "Unknown"
    /// so an unlocalizable code isn't merged with GeoIP misses.
    static func countryName(_ code: String?) -> String {
        guard let code else { return unknownCountryName }
        return Locale.current.localizedString(forRegionCode: code) ?? code
    }

    /// The country a flow is grouped under, or nil when GeoIP has no answer.
    /// Unlocated flows (private ranges, documentation blocks, new allocations)
    /// get no row: they have nothing in common, and a single swipe on an
    /// "Unknown" row would act on all of them. They remain visible in Live Traffic.
    static func groupingCode(_ event: TrafficEvent) -> String? {
        guard let code = event.countryCode?.uppercased(), !code.isEmpty else { return nil }
        return code
    }

    /// Builds the tree from the full flow buffer (AppModel caps `recentFlows` at 200).
    ///
    /// `order` is a lookup for level-1 positions (see `seated(_:to:)`), decided by
    /// the caller once a second. Empty means none yet, so the busiest-first seed
    /// is used.
    ///
    /// `clock` is where every meter window ends. The caller freezes this section
    /// while a country is expanded, and frozen events must be measured against the
    /// frozen clock or the meters would drain while the list claims to be still
    /// (see `LiveTrafficView.frozenClock`). The default is for tests and previews.
    ///
    /// `@MainActor` because ranking reads `MiniTrafficMeter.level`, a static on a
    /// View. The only caller is a view body, and it avoids duplicating the level
    /// thresholds somewhere nonisolated.
    @MainActor
    static func build(from flows: [TrafficEvent], order: [String] = [], clock: Date = Date()) -> [CountryGroup] {
        // One sliding window for the whole tree so a country's level reflects the
        // same window as the rows under it. `MiniTrafficMeter` defines its length.
        let meterWindowStart = clock.addingTimeInterval(-MiniTrafficMeter.windowSeconds)
        // Manual grouping so unlocated flows are dropped in the same pass.
        var byCountry: [String: [TrafficEvent]] = [:]
        for flow in flows {
            guard let code = groupingCode(flow) else { continue }
            byCountry[code, default: []].append(flow)
        }
        let countries = byCountry
            .map { code, countryFlows in
                let countryID = "c/\(code)"
                // Partition by observed domain. `inferredDomain` doesn't count: it's our own
                // resolver's guess, not a name seen in the flow.
                var named: [(domain: String, event: TrafficEvent)] = []
                var nameless: [TrafficEvent] = []
                for event in countryFlows {
                    let name = normalizedDomain(event.domain)
                    // Some sources put an IP literal in `domain`. Treat it as nameless so it
                    // lands in the IP bucket instead of its own one-leaf domain group.
                    if !name.isEmpty, IPAddress.parse(name) == nil {
                        named.append((name, event))
                    } else {
                        nameless.append(event)
                    }
                }

                var groups = Dictionary(grouping: named, by: { registrableDomain($0.domain) })
                    .map { registrable, pairs -> TargetGroup in
                        let groupID = "\(countryID)/d/\(registrable)"
                        let leaves = Dictionary(grouping: pairs, by: \.domain)
                            .map { domain, leafPairs in
                                TargetLeaf(
                                    id: "\(groupID)/l/\(domain)",
                                    identifier: domain,
                                    countryCode: code,
                                    stats: stats(of: leafPairs.map(\.event), meterWindowStart: meterWindowStart)
                                )
                            }
                            .sorted(by: leafOrder)
                        return TargetGroup(
                            id: groupID,
                            title: registrable,
                            isIPBucket: false,
                            stats: stats(of: pairs.map(\.event), meterWindowStart: meterWindowStart),
                            leaves: leaves
                        )
                    }
                groups.sort(by: groupOrder)

                if !nameless.isEmpty {
                    let groupID = "\(countryID)/ip"
                    let leaves = Dictionary(grouping: nameless, by: \.remoteIP)
                        .map { ip, leafFlows in
                            TargetLeaf(
                                id: "\(groupID)/l/\(ip)",
                                identifier: ip,
                                countryCode: code,
                                stats: stats(of: leafFlows, meterWindowStart: meterWindowStart)
                            )
                        }
                        .sorted(by: leafOrder)
                    // The IP bucket is always first under a country, regardless of activity: its
                    // contents can't be guessed from its title, so it must be easy to find.
                    groups.insert(TargetGroup(
                        id: groupID,
                        title: ipBucketTitle,
                        isIPBucket: true,
                        stats: stats(of: nameless, meterWindowStart: meterWindowStart),
                        leaves: leaves
                    ), at: 0)
                }

                return CountryGroup(
                    id: countryID,
                    code: code,
                    name: countryName(code),
                    stats: stats(of: countryFlows, meterWindowStart: meterWindowStart),
                    groups: groups
                )
            }
        return seated(countries, to: order)
    }

    /// Level-1 rows in the positions from the last ranking, with newcomers
    /// appended (ranked among themselves). A lookup rather than a live sort so
    /// rows don't swap under the user's finger; positions only change when
    /// `reranked(_:)` sees a country change meter level. Since the caller re-ranks
    /// before storing the order, a newcomer settles at the end of its level.
    @MainActor
    private static func seated(_ countries: [CountryGroup], to order: [String]) -> [CountryGroup] {
        guard !order.isEmpty else { return countries.sorted(by: countryRank) }
        let rank = Dictionary(order.enumerated().map { ($0.element, $0.offset) }) { first, _ in first }
        let known = countries
            .filter { rank[$0.id] != nil }
            .sorted { (rank[$0.id] ?? 0) < (rank[$1.id] ?? 0) }
        let newcomers = countries.filter { rank[$0.id] == nil }.sorted(by: countryRank)
        return known + newcomers
    }

    /// Ranking key: the meter level of both directions summed. Each level is 4×
    /// the previous, so one row only overtakes another when it's clearly busier,
    /// and the change is visible in the meter at the same moment.
    @MainActor
    static func rankLevel(_ stats: TargetStats) -> Int {
        MiniTrafficMeter.level(for: stats.recentUp &+ stats.recentDown)
    }

    /// Busiest level first; ties keep their current order. `sorted(by:)` isn't
    /// stable, so stability is enforced by tie-breaking on the original offset.
    /// That's what keeps rows that didn't change level in place.
    /// Same logic as `LiveTrafficView.reranked` for a different row type.
    @MainActor
    static func reranked(_ countries: [CountryGroup]) -> [CountryGroup] {
        countries.enumerated()
            .sorted { a, b in
                let left = rankLevel(a.element.stats)
                let right = rankLevel(b.element.stats)
                return left == right ? a.offset < b.offset : left > right
            }
            .map(\.element)
    }

    /// Flattens to the rows visible right now.
    static func rows(
        _ countries: [CountryGroup],
        expandedCountries: Set<String>,
        expandedGroups: Set<String>
    ) -> [RecentTargetRow] {
        var rows: [RecentTargetRow] = []
        for country in countries {
            let countryOpen = expandedCountries.contains(country.id)
            rows.append(.country(country, expanded: countryOpen))
            guard countryOpen else { continue }
            for group in country.groups {
                let groupOpen = expandedGroups.contains(group.id)
                rows.append(.group(group, expanded: groupOpen))
                guard groupOpen else { continue }
                rows.append(contentsOf: group.leaves.map(RecentTargetRow.leaf))
            }
        }
        return rows
    }

    /// Approximate registrable domain (eTLD+1), reusing
    /// `AskNotificationThrottle.notificationGroup`: last two labels plus a short
    /// list of two-part suffixes (co.uk, com.cn, co.jp, ...). Not the Public
    /// Suffix List, so some groupings are wrong (e.g. `foo.s3.amazonaws.com`
    /// lands under `amazonaws.com`). That only affects grouping, never filtering.
    static func registrableDomain(_ domain: String) -> String {
        AskNotificationThrottle.notificationGroup(for: domain)
    }

    /// Lowercased, with any trailing root dot removed. `notificationGroup` only
    /// drops the empty last label for names with three or more labels, so
    /// "example.com." would otherwise form its own group.
    static func normalizedDomain(_ domain: String?) -> String {
        guard var name = domain?.lowercased() else { return "" }
        if name.hasSuffix(".") { name.removeLast() }
        return name
    }

    /// Distinct ports as one field, e.g. "443, 853". nil for an empty set so
    /// callers can omit the row. Sorted numerically (a string sort would put 8080
    /// between 443 and 853). Shared by both detail sheets so they format alike.
    static func portField(_ ports: Set<UInt16>) -> String? {
        field(ports.sorted().map(String.init))
    }

    /// Same as `portField`, using the app's protocol names.
    static func protocolField(_ numbers: Set<UInt8>) -> String? {
        field(numbers.sorted().map(FlowRow.protocolName))
    }

    private static func field(_ values: [String]) -> String? {
        values.isEmpty ? nil : values.joined(separator: ", ")
    }

    private static func stats(of flows: [TrafficEvent], meterWindowStart: Date) -> TargetStats {
        var stats = TargetStats()
        for flow in flows { stats.absorb(flow, meterWindowStart: meterWindowStart) }
        return stats
    }

    /// Seed order for level 1 and the tie-break among newcomers. Activity level
    /// first, then connection count, then name, so the comparator is a total order.
    @MainActor
    private static func countryRank(_ a: CountryGroup, _ b: CountryGroup) -> Bool {
        let left = rankLevel(a.stats)
        let right = rankLevel(b.stats)
        if left != right { return left > right }
        if a.stats.connections != b.stats.connections {
            return a.stats.connections > b.stats.connections
        }
        return a.name < b.name
    }

    /// Busiest first, domain groups only (`build` places the IP bucket first).
    /// No hysteresis needed: group rows only exist while their country is expanded,
    /// and expanding freezes both the flows and the meter clock
    /// (`DashboardView.mutateExpansion`), so the input doesn't change. Same for leaves.
    @MainActor
    private static func groupOrder(_ a: TargetGroup, _ b: TargetGroup) -> Bool {
        let left = rankLevel(a.stats)
        let right = rankLevel(b.stats)
        if left != right { return left > right }
        if a.stats.connections != b.stats.connections {
            return a.stats.connections > b.stats.connections
        }
        return a.title < b.title
    }

    @MainActor
    private static func leafOrder(_ a: TargetLeaf, _ b: TargetLeaf) -> Bool {
        let left = rankLevel(a.stats)
        let right = rankLevel(b.stats)
        if left != right { return left > right }
        if a.stats.connections != b.stats.connections {
            return a.stats.connections > b.stats.connections
        }
        return a.identifier < b.identifier
    }
}

// MARK: - Row decisions

/// What a row's swipe, its sheet's button and its VoiceOver value need.
/// Rows differ only in how many rule targets they stand for.
struct TargetRuleSubject {
    /// Targets to write rules for: one for a leaf, the apex plus wildcard for a
    /// domain group, every observed address for the IP bucket.
    let targets: [RuleTarget]
    /// VoiceOver name, e.g. "tracker.example" or "Canada".
    let name: String
    /// Added to every rule's note. Rules search matches notes, so this is how a
    /// user finds a batch later; keep the values few and recognizable.
    let note: String
    /// Every block on this row came from the DNS sinkhole, so an Allow rule
    /// wouldn't do anything. `TargetRuleReading` turns this into hiding Allow.
    let resolverOnlyBlocks: Bool
    /// Set only for a country row. The row then reads and writes a
    /// `CountryPolicy`, and `targets`/`note` are unused. Country policies only
    /// block (`CountryPolicy.derivedAction`), so the swipe is Block or Unblock
    /// and never writes an allow.
    var countryCode: String?
}

/// Shared by the row swipe and the Insights sheets' buttons so both surfaces
/// perform the same write.
@MainActor
extension TargetRuleSubject {
    /// A country gets a policy, anything else gets rules. Both replace existing
    /// decisions rather than appending, so a row can't hold conflicting ones.
    func block(_ model: AppModel) {
        if let countryCode {
            model.setCountryPolicy(countryCode: countryCode, blocked: true)
        } else {
            model.setUserRule(targets: targets, action: .deny, note: note)
        }
    }

    /// A domain or address gets an explicit allow rule, which can carve an
    /// exception out of a wildcard. A country just has its policy removed; there
    /// is no allow policy for a country, since it would exempt a whole country
    /// from blocklists and threat feeds.
    func release(_ model: AppModel) {
        if let countryCode {
            model.setCountryPolicy(countryCode: countryCode, blocked: false)
        } else {
            model.setUserRule(targets: targets, action: .allow, note: note)
        }
    }
}

extension TargetLeaf {
    /// `build` already routed anything that parses as an IP to the nameless path,
    /// so this only reads that decision back. Returns nothing for a blank
    /// identifier: `.domain("")` would match nothing but still show up on the
    /// Rules page. Same guard as `AppModel.addRule(for:)`.
    var ruleTargets: [RuleTarget] {
        guard !identifier.isEmpty else { return [] }
        return IPAddress.parse(identifier) != nil ? [.ip(identifier)] : [.domain(identifier)]
    }

    var ruleSubject: TargetRuleSubject {
        TargetRuleSubject(
            targets: ruleTargets,
            name: identifier,
            note: "From Recent targets",
            resolverOnlyBlocks: stats.resolverOnlyBlocks
        )
    }
}

extension TargetGroup {
    /// A domain group means the whole site, which takes two rules: the bare name
    /// matches only that host and `*.name` only its subdomains. The IP bucket
    /// stands for exactly the addresses currently in it.
    var ruleTargets: [RuleTarget] {
        isIPBucket ? leaves.flatMap(\.ruleTargets) : [.domain(title), .domain("*." + title)]
    }

    var ruleSubject: TargetRuleSubject {
        TargetRuleSubject(
            targets: ruleTargets,
            name: title,
            note: isIPBucket ? "From Recent targets (addresses)" : "From Recent targets",
            resolverOnlyBlocks: stats.resolverOnlyBlocks
        )
    }
}

extension CountryGroup {
    var ruleSubject: TargetRuleSubject {
        TargetRuleSubject(
            // The rule engine has no notion of country (GeoIP is app-side only), so the
            // swipe creates one country policy that the app keeps compiling
            // (`AppModel.derivedCountryRules`) instead of writing a rule per target.
            // The swipe acts on `countryCode`.
            targets: [],
            name: name,
            note: "",
            // Always false: releasing a country removes its block policy rather than
            // writing an allow, which works regardless of what blocked the traffic.
            resolverOnlyBlocks: false,
            countryCode: code
        )
    }
}

extension RecentTargetRow {
    /// What a swipe on this row acts on, at any level.
    var ruleSubject: TargetRuleSubject {
        switch self {
        case .country(let country, _): country.ruleSubject
        case .group(let group, _): group.ruleSubject
        case .leaf(let leaf): leaf.ruleSubject
        }
    }
}

// MARK: - Rule state for a row

/// A row's current decision, computed once and used by the swipe verb, the
/// sheet's button and VoiceOver, so they can't disagree.
@MainActor
struct TargetRuleReading {
    let subject: TargetRuleSubject
    /// What the user's rules say about the row. A row covering several targets
    /// only has a state when all of them agree; otherwise it's neutral.
    let state: RuleAction?
    /// Whether the state comes from the row's own rule rather than a broader
    /// wildcard. A leaf under a blocked `*.site` reads "blocked by a broader rule"
    /// in VoiceOver. Allow on such a leaf still works: an exact allow outranks the
    /// wildcard (`RuleTarget.derivedPriority`).
    ///
    /// True if any of the row's targets has its own rule that agrees with the
    /// shown state, so the row never offers to undo a state it doesn't own.
    let isOwned: Bool
    /// Whether Allow would be a no-op. True only when every block came from the
    /// DNS sinkhole and the row has no rule of its own backing the state. If the
    /// row has its own deny, Allow replaces a rule that applies at connect time,
    /// before the resolver is asked, so it's a real change. When true, the swipe
    /// hides Allow like Live Traffic does; the leaf sheet explains why.
    let allowIsDead: Bool

    init(subject: TargetRuleSubject, model: AppModel) {
        self.subject = subject
        // A country row only needs to know whether a policy exists; a policy can only block.
        if let code = subject.countryCode {
            let policed = model.countryPolicy(for: code) != nil
            state = policed ? .deny : nil
            // A country can't inherit from anything broader, so a policy is always its own.
            isOwned = policed
            allowIsDead = false
            return
        }
        var shared: RuleAction?
        var agreed = true
        for target in subject.targets {
            guard let current = model.userRuleState(for: target) else {
                agreed = false
                break
            }
            if let shared, shared != current {
                agreed = false
                break
            }
            shared = current
        }
        let resolved = agreed ? shared : nil
        state = resolved
        let owned = resolved.map { value in
            subject.targets.contains { model.ownUserRuleAction(for: $0) == value }
        } ?? false
        isOwned = owned
        allowIsDead = subject.resolverOnlyBlocks && !owned
    }

    /// VoiceOver value after the row's name. Rows don't show the decision
    /// visually (it's on the swipe, the sheet and the Rules page), so this is the
    /// only way VoiceOver users hear it. Keep it.
    var spokenState: String {
        // A country is block-only and always owns its state. "Not blocked" rather
        // than "No rule", since no rule is involved either way.
        if subject.countryCode != nil { return state == nil ? "Not blocked" : "Blocked" }
        return switch (state, isOwned) {
        case (.deny, true): "Blocked"
        case (.deny, false): "Blocked by a broader rule"
        case (.allow, true): "Allowed"
        case (.allow, false): "Allowed by a broader rule"
        case (nil, _): "No rule"
        }
    }

    /// "Unblock" for a country, since releasing it writes no allow rule.
    var releaseVerb: String { subject.countryCode == nil ? "Allow" : "Unblock" }
}

// MARK: - Rows

/// Level 1: flag, localized country name, activity meter and block state.
struct CountryTargetRow: View {
    @Environment(AppModel.self) private var model
    let country: CountryGroup
    let isExpanded: Bool
    let onTap: () -> Void

    var body: some View {
        let reading = TargetRuleReading(subject: country.ruleSubject, model: model)
        return HStack(spacing: 0) {
            RowLabelButton(action: onTap, spokenState: reading.spokenState) {
                Text(CountryFlag.emoji(country.code))
                Text(country.name)
                    .font(.body.weight(.medium))
                    .lineLimit(1)
            }
            MiniTrafficMeter(bytesUp: country.stats.recentUp, bytesDown: country.stats.recentDown)
            ChevronButton(isExpanded: isExpanded, action: onTap)
        }
        .padding(.vertical, 2)
    }
}

/// Level 2: a registrable domain or the nameless-flow bucket, indented under
/// its country.
struct TargetGroupRow: View {
    @Environment(AppModel.self) private var model
    let group: TargetGroup
    let isExpanded: Bool
    let onTap: () -> Void

    var body: some View {
        let reading = TargetRuleReading(subject: group.ruleSubject, model: model)
        return HStack(spacing: 0) {
            RowLabelButton(action: onTap, spokenState: reading.spokenState) {
                // The glyph distinguishes name from address. Not "network", which at caption
                // size looks too similar to "globe".
                Image(systemName: group.isIPBucket ? "desktopcomputer" : "globe")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(width: 16)
                Text(group.title)
                    .font(group.isIPBucket ? .subheadline : .subheadline.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            MiniTrafficMeter(bytesUp: group.stats.recentUp, bytesDown: group.stats.recentDown)
            ChevronButton(isExpanded: isExpanded, action: onTap)
        }
        .padding(.vertical, 1)
        .padding(.leading, 18)
    }
}

/// Level 3: the destination itself. No chevron; tapping the label opens the sheet.
struct TargetLeafRow: View {
    @Environment(AppModel.self) private var model
    let leaf: TargetLeaf
    let onTap: () -> Void

    var body: some View {
        let reading = TargetRuleReading(subject: leaf.ruleSubject, model: model)
        return HStack(spacing: 0) {
            RowLabelButton(action: onTap, spokenState: reading.spokenState) {
                Text(leaf.identifier)
                    .font(.footnote.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            MiniTrafficMeter(bytesUp: leaf.stats.recentUp, bytesDown: leaf.stats.recentDown)
        }
        .padding(.vertical, 1)
        .padding(.leading, 40)
    }
}

/// The tappable text half of a row. A real Button, not an `onTapGesture` on the
/// whole row, because the chevron beside it is also a button and a parent tap
/// gesture under it would fire both.
///
/// Also the row's only accessibility element (the meter is decorative), so it
/// carries the decision as its value. Nothing else on the row states it.
private struct RowLabelButton<Content: View>: View {
    let action: () -> Void
    let spokenState: String
    @ViewBuilder let content: Content

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                content
                Spacer(minLength: 6)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityValue(spokenState)
    }
}

/// Hints that the row expands. Hidden from VoiceOver since the label button
/// already carries the action.
private struct ChevronButton: View {
    let isExpanded: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: "chevron.down")
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .rotationEffect(.degrees(isExpanded ? 180 : 0))
                .padding(.leading, 4)
                .padding(.vertical, 12)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityHidden(true)
    }
}

// MARK: - Swipe action

// Rows intentionally have no allowed/blocked marker. The state is on the
// Rules page, in the swipe verb and in the sheet's button; VoiceOver gets it
// from `TargetRuleReading.spokenState`.

/// Trailing swipe with a single verb: a blocked row can only be released, any
/// other row can only be blocked. No confirmation, consistent with other rule
/// gestures in the app; each action is one swipe from being undone.
private struct TargetRuleSwipe: ViewModifier {
    @Environment(AppModel.self) private var model
    let subject: TargetRuleSubject

    func body(content: Content) -> some View {
        let reading = TargetRuleReading(subject: subject, model: model)
        return content.swipeActions(edge: .trailing) {
            if reading.state == .deny {
                // Hidden for resolver-only blocks, same as Live Traffic: the rule would be
                // written but have no effect. The leaf sheet explains why.
                if !reading.allowIsDead {
                    Button { subject.release(model) } label: {
                        // Just the verb; a long domain would be truncated at swipe width. VoiceOver
                        // keeps the name since it can't see which row is open.
                        Text(reading.releaseVerb)
                    }
                    .tint(.green)
                    .accessibilityLabel("\(reading.releaseVerb) \(subject.name)")
                }
            } else {
                Button(role: .destructive) { subject.block(model) } label: {
                    Text("Block")
                }
                .accessibilityLabel("Block \(subject.name)")
            }
        }
    }
}

extension View {
    /// Attaches the row's swipe. Applied by the owning list rather than inside the
    /// row because `swipeActions` belongs on the list cell.
    func targetRuleSwipe(_ subject: TargetRuleSubject) -> some View {
        modifier(TargetRuleSwipe(subject: subject))
    }
}

// MARK: - Leaf detail

/// Details for one destination: byte totals, what it is, where it answered
/// from, and how its connections went. Read-only; the row's swipe is where
/// rules are made, since a rule here would act on an aggregate of many flows.
/// Mirrors Live Traffic's `FlowDetailSheet` layout.
struct TargetDetailSheet: View {
    @Environment(\.dismiss) private var dismiss
    let leaf: TargetLeaf

    var body: some View {
        NavigationStack {
            List {
                // Byte totals first, in the dashboard hero's style.
                Section {
                    TrafficTotalsHeader(sent: leaf.stats.bytesUp, received: leaf.stats.bytesDown)
                        // The two blocks are the row's background, so drop the row's own background
                        // and insets to keep them aligned with the section edges below.
                        .listRowInsets(EdgeInsets())
                        .listRowBackground(Color.clear)
                }

                Section {
                    LabeledContent("Target") {
                        Text(leaf.identifier)
                            .font(.callout.monospaced())
                            .textSelection(.enabled)
                    }
                    LabeledContent("Country") {
                        Text("\(CountryFlag.emoji(leaf.countryCode)) \(RecentTargets.countryName(leaf.countryCode))")
                    }
                    // Aggregated across the buffer, not just the newest flow. Omitted when no
                    // port was seen (see `portField`).
                    if let ports = RecentTargets.portField(leaf.stats.ports) {
                        LabeledContent("Port", value: ports)
                    }
                    if let protocols = RecentTargets.protocolField(leaf.stats.protocols) {
                        LabeledContent("Protocol", value: protocols)
                    }
                    LabeledContent("Connections", value: "\(leaf.stats.connections)")
                    LabeledContent("Allowed", value: "\(leaf.stats.allowed)")
                    LabeledContent("Blocked", value: "\(leaf.stats.blocked)")
                    // Omitted when zero.
                    if leaf.stats.threats > 0 {
                        LabeledContent("Threats", value: "\(leaf.stats.threats)")
                    }
                    LabeledContent("Last seen", value: lastSeenText)
                } footer: {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Totals across every observed connection to this target.")
                        // Explains why the row's swipe offers no Allow. Same text as Live Traffic's
                        // connection sheet.
                        if leaf.stats.resolverOnlyBlocks {
                            Text(ResolverBlock.cannotAllowNote)
                        }
                    }
                }
            }
            .navigationTitle("Target")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
    }

    /// `recentFlows` is capped by count, not age, so it can hold yesterday's flows.
    /// Include the date when it isn't today so a bare time isn't misread as recent.
    private var lastSeenText: String {
        let seen = leaf.stats.lastSeen
        guard Calendar.current.isDateInToday(seen) else {
            return seen.formatted(date: .abbreviated, time: .shortened)
        }
        return seen.formatted(date: .omitted, time: .standard)
    }
}
