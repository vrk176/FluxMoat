import Foundation
import Observation
import UIKit
import WidgetKit
import os
import SharedCore

@MainActor
@Observable
final class AppModel {
    /// A navigation request from outside the UI (a notification tap, a link
    /// from another screen), held until the UI can act on it.
    ///
    /// For the weekly-summary notification: `AppDelegate` sets it,
    /// `RootView` selects the Insights tab without clearing it, and
    /// `InsightsView` reads and clears it on appear. `RootView` must not clear
    /// it because on a cold launch `InsightsView` doesn't exist until the tab
    /// is selected.
    ///
    /// Cases describe the destination in product terms so `MainTab` can stay
    /// private to `RootView`.
    enum PendingDestination: Equatable {
        /// Insights over the last 7 days, the weekly summary's window.
        case insightsWeeklySummary
        /// Settings → Data, where the retention picker lives.
        case settingsHistoryRetention
        /// Settings → DNS, where the encrypted-DNS block switch and its
        /// explanation live.
        case settingsEncryptedDNS
    }

    var pendingDestination: PendingDestination?

    var isProtectionOn = false
    /// Run mode. Changes are persisted to the snapshot for the tunnel.
    /// Switching to .ask also requests notification permission for the
    /// extension's ask notifications.
    var mode: RunMode = .standard {
        didSet {
            guard oldValue != mode else { return }
            persistRules()
            if mode == .ask { Self.requestNotificationPermission() }
        }
    }
    var profiles: [Profile]
    var activeProfileID: UUID? {
        didSet {
            // The active profile's unmatchedAction is part of the snapshot.
            guard oldValue != activeProfileID else { return }
            // Profile scope affects which rules are active, so cached echoes
            // are stale.
            invalidateRuleEcho()
            persistRules()
        }
    }
    var rules: [Rule] {
        didSet { invalidateRuleEcho() }
    }
    /// Cached answers for `ruleEcho(for:)`, keyed by canonical target.
    ///
    /// @ObservationIgnored because these are written during view body
    /// evaluation, and writing an observed property mid-render causes an
    /// update loop.
    @ObservationIgnored private var echoCache: [RuleTarget: RuleEcho] = [:]
    @ObservationIgnored private var echoCacheStamp = Date.distantPast
    /// Blocklist/threat membership sets for `overrideNotice(for:)` and the
    /// generation they were built at. @ObservationIgnored for the same reason
    /// as the echo cache.
    @ObservationIgnored private var overlap: OverlapIndex?
    @ObservationIgnored private var overlapGeneration = -1
    /// Manually imported blocklist domains only (e.g. from .lsrules).
    /// Subscribed lists are stored per source; the snapshot carries the union.
    var blocklistDomains: [String] {
        didSet { bumpBlocklistGeneration() }
    }
    /// DoH upstream for tunnel-side resolution (nil means system DNS). Stored
    /// in the snapshot and restored from it at launch.
    var dohServerURL: String? {
        didSet {
            guard oldValue != dohServerURL else { return }
            persistRules()
        }
    }
    /// Blocks public encrypted-DNS resolvers so DNS falls back to plaintext
    /// and domain rules work again. Must default to off; only the user may
    /// turn it on. The deny rules are built in the extension by
    /// `RuleSnapshot.compile()`; this is only the switch.
    var blockEncryptedDNS: Bool = false {
        didSet {
            guard oldValue != blockEncryptedDNS else { return }
            persistRules()
        }
    }
    /// Flow-history retention. Stored in the snapshot so the extension, which
    /// owns the store, prunes on every tunnel start. Shrinking it also prunes
    /// here immediately.
    var historyRetention: RetentionPeriod = .default {
        didSet {
            guard oldValue != historyRetention else { return }
            persistRules()
            let retention = historyRetention
            // Only a shorter window can delete anything. Skip the prune (a
            // DELETE + VACUUM on the main thread) when the window grows.
            guard retention.days < oldValue.days || retention.maxRows < oldValue.maxRows else {
                log.notice("✅ app:eventStore prune VERIFY retention=\(retention.rawValue, privacy: .public) skipped=widened")
                return
            }
            // Log failures so a prune error isn't mistaken for "nothing to
            // delete".
            do {
                let deleted = try eventStore.sync {
                    try $0.prune(maxAge: retention.maxAge, maxRows: retention.maxRows)
                }
                log.notice("✅ app:eventStore prune VERIFY retention=\(retention.rawValue, privacy: .public) deleted=\(deleted, privacy: .public)")
            } catch {
                noteStoreFailure("prune", error)
            }
        }
    }
    /// Quiet hours for ask notifications (nil = off). Stored in the snapshot.
    /// Asks still queue during quiet hours; only the banner is silenced.
    var askQuietHours: QuietHours? {
        didSet {
            guard oldValue != askQuietHours else { return }
            persistRules()
        }
    }
    /// Wi-Fi to profile automation rules. Stored in the snapshot. The tunnel
    /// enforces them (it keeps running across network changes) and reports the
    /// applied kind in liveCounters so the picker follows.
    var wifiAutoProfiles: [WiFiProfileAssignment] = [] {
        didSet {
            guard oldValue != wifiAutoProfiles else { return }
            persistRules()
        }
    }
    /// iCloud config sync. Opt-in, default off. Syncs configuration only
    /// (rules, settings, Wi-Fi automation, blocklist metadata and manual
    /// domains) to the user's private CloudKit database. Traffic history and
    /// credentials (the abuse.ch key) never sync.
    var iCloudSyncEnabled: Bool = false {
        didSet {
            guard oldValue != iCloudSyncEnabled else { return }
            UserDefaults.standard.set(iCloudSyncEnabled, forKey: Self.iCloudSyncEnabledKey)
            if iCloudSyncEnabled {
                scheduleCloudSync(delay: .zero)
            } else {
                cloudSyncTask?.cancel()
                // Clear the baseline so re-enabling does a conservative first
                // sync instead of diffing against stale state.
                cloudSync.resetBaseline()
                cloudSyncStatus = .idle
            }
        }
    }
    var cloudSyncStatus: CloudSyncService.Status = .idle
    private static let iCloudSyncEnabledKey = "iCloudSyncEnabled"
    /// One-time flag for the resolver threat-intel backfill in `init`. A later
    /// migration should use its own key.
    private static let resolverIntelBackfillKey = "resolverIntelBackfill014"
    /// One-time flag for adding the ThreatFox mirror default (see `init`).
    /// `blocklistCatalogSeeded` is already set on existing installs, so it
    /// can't be reused.
    private static let threatFoxMirrorSeededKey = "threatfoxMirrorSeeded"
    /// Fixed id and URL for the ThreatFox mirror, shared by the fresh-install
    /// seed and the upgrade path so iCloud sees one subscription.
    private static let threatFoxMirrorID = UUID(uuidString: "6B1E5A31-0003-4000-8000-5EEDB10C0003")!
    private static let threatFoxMirrorURL = URL(string: "https://feeds.hominexis.com/threatfox/manifest.json")
    /// Nudge shown when protection is on but an enabled blocklist has never
    /// been downloaded. Lists do nothing until the user taps Update, since
    /// nothing downloads without user action.
    var blocklistNudgeDismissed = false
    var showBlocklistDownloadNudge: Bool {
        isProtectionOn && !blocklistNudgeDismissed &&
            blocklistSources.contains { $0.enabled && $0.lastUpdatedAt == nil }
    }
    /// Set once the tunnel reports an encrypted-DNS bypass while blocking is
    /// off. Lasts for the session.
    var encryptedDNSBypassSeen = false
    var encryptedDNSBypassBannerDismissed = false
    /// Show the bypass banner: bypass seen, blocking still off, not dismissed.
    var showEncryptedDNSBypassBanner: Bool {
        encryptedDNSBypassSeen && !blockEncryptedDNS && !encryptedDNSBypassBannerDismissed
    }
    /// abuse.ch Auth-Key, used for all abuse.ch feeds. Stored in the Keychain,
    /// never the App Group store, and only sent to `*.abuse.ch` hosts (see
    /// `authKey(for:)`).
    var abuseChAuthKey: String = "" {
        didSet {
            guard oldValue != abuseChAuthKey else { return }
            let wrote = KeychainStore.set(abuseChAuthKey, for: Self.abuseChAuthKeyAccount)
            abuseChKeyStored = wrote && !abuseChAuthKey.isEmpty
            // Never log the key or its length, only whether one is stored.
            log.notice("✅ app:threatIntel key VERIFY stored=\(self.abuseChKeyStored, privacy: .public) wrote=\(wrote, privacy: .public)")
        }
    }
    /// Whether the Keychain actually holds a key. A Keychain write can fail,
    /// in which case `abuseChAuthKey` would still look saved while feed
    /// downloads go out unauthenticated.
    private(set) var abuseChKeyStored = false
    private static let abuseChAuthKeyAccount = "abuseChAuthKey"
    /// Blocklist subscriptions. Metadata only; parsed entries are stored on
    /// disk per source.
    var blocklistSources: [BlocklistSource] = [] {
        didSet { bumpBlocklistGeneration() }
    }
    /// Bumped when anything behind `overrideNotice(for:)` changes (a source
    /// toggled, an update, a manual import).
    ///
    /// It's the cache stamp for `overlapIndex()`, and reading it in
    /// `overrideNotice` subscribes the row to blocklist changes. Without that
    /// read, a row answered from the cache would never refresh.
    private(set) var blocklistGeneration = 0
    /// Sources with an update in flight. The UI shows a spinner and ignores a
    /// second tap.
    var updatingBlocklistIDs: Set<UUID> = []
    /// Ask mode: unanswered asks polled from the tunnel once a second.
    var pendingAsks: [PendingAsk] = []
    var counters = ProviderResponse.LiveCounters(
        bytesUpPerSecond: 0, bytesDownPerSecond: 0, activeFlows: 0, blockedToday: 0
    )
    /// Newest first, capped at 200.
    var recentFlows: [TrafficEvent] = []
    /// A history database read has failed this launch (corrupt, locked or
    /// missing file). Lets Trends and the Map say the data is unreadable
    /// instead of showing an empty period.
    ///
    /// Sticky, so the page doesn't flicker between states while several
    /// rollups run. Only a successful `clearHistory()` clears it, since
    /// wiping rebuilds the file.
    private(set) var storeUnavailable = false
    /// Match counts per rule id, built by `refreshRuleHits()` on each Rules
    /// reload. Read by `RuleDetailSheet`.
    ///
    /// A missing key means no matches in retained history, not that the rule
    /// never fired: retention deletes old rows.
    private(set) var ruleHits: [UUID: TrafficEventStore.RuleMatchRollup] = [:]
    /// Whether `ruleHits` holds a real answer. False before the first read and
    /// after a failed one, so an empty dictionary isn't shown as "Never
    /// matched".
    private(set) var ruleHitsKnown = false
    /// Country policies (see CountryPolicy.swift). Compiled into domain/IP
    /// rules at snapshot time and never stored in `rules`. Change them through
    /// the `setCountryPolicy` family, which saves both this file and the
    /// snapshot.
    private(set) var countryPolicies: [CountryPolicy] = []

    private let client: any TunnelClient
    private let cloudSync = CloudSyncService()
    private var cloudSyncTask: Task<Void, Never>?
    /// True while a merged cloud config is being applied, so the didSet →
    /// persistRules cascade doesn't schedule another cloud round.
    private var isApplyingRemoteConfig = false
    /// True while `resetAllConfiguration()` clears everything, so each didSet
    /// doesn't write the snapshot and reload the tunnel.
    private var isResettingAll = false
    /// Whether a bulk rewrite is in progress. didSets skip the snapshot and
    /// cloud writes; the caller does one write at the end.
    private var isCoalescingWrites: Bool { isApplyingRemoteConfig || isResettingAll }
    private var tickTask: Task<Void, Never>?
    private let snapshotStore: RuleSnapshotStore
    private let eventStore: HistoryStoreGate
    private let blocklistStore: BlocklistSourceStore
    private let countryPolicyStore: CountryPolicyStore
    /// Pending debounced save for country-target growth. See
    /// `scheduleDerivedPersist()`.
    private var derivedPersistTask: Task<Void, Never>?
    private let log = Logger(subsystem: "fluxmoat", category: "store")

    var activeProfile: Profile? {
        profiles.first { $0.id == activeProfileID }
    }

    /// Packet tunnels can't run in the simulator, so it uses the mock client.
    static func defaultClient() -> any TunnelClient {
        #if targetEnvironment(simulator)
        MockTunnelClient()
        #else
        TunnelManagerClient()
        #endif
    }

    init(client: (any TunnelClient)? = nil) {
        self.client = client ?? Self.defaultClient()
        // Built-in profiles have constant ids (see `Profile.builtIns`).
        self.profiles = Profile.builtIns
        self.activeProfileID = Profile.builtIn(.home)?.id

        // App Group when entitlements are available; the local fallback keeps
        // simulator and unsigned builds working.
        self.snapshotStore = RuleSnapshotStore.appGroup() ?? RuleSnapshotStore(
            directoryURL: FileManager.default
                .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("FluxMoat/Rules", isDirectory: true)
        )

        // Flow history written by the extension, including while the app was
        // closed. Preloaded so Live Traffic isn't empty; the 1 Hz poll adds new
        // flows on top.
        self.eventStore = HistoryStoreGate(TrafficEventStore.appGroup() ?? TrafficEventStore(
            directoryURL: FileManager.default
                .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("FluxMoat/Events", isDirectory: true)
        ))
        // Not `try?`: if the store won't open, record it instead of looking
        // like a fresh install. `noteStoreFailure` can't be called before init
        // completes, so this does the same two things inline.
        do {
            let history = try eventStore.sync { try $0.recent(limit: 200) }
            if !history.isEmpty {
                self.recentFlows = history.map { event in
                    var event = event
                    event.countryCode = GeoIPService.shared
                        .countryCode(for: event.remoteIP) ?? event.countryCode
                    return event
                }
                log.notice("✅ app:eventStore preload VERIFY count=\(history.count, privacy: .public)")
            }
        } catch {
            self.storeUnavailable = true
            log.error("❌ app:historyRead FAILED op=preload type=\(String(describing: type(of: error)), privacy: .public) detail=\(String(describing: error), privacy: .private)")
        }

        let countryPolicyStore = CountryPolicyStore.appGroup() ?? CountryPolicyStore(
            directoryURL: FileManager.default
                .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("FluxMoat/Countries", isDirectory: true)
        )
        self.countryPolicyStore = countryPolicyStore
        let loadedPolicies = (try? countryPolicyStore.load()) ?? CountryPolicyStore.LoadResult()
        // Country policies are block-only. Allow policies from older versions
        // are dropped, and logged so a vanished policy can be explained.
        if loadedPolicies.droppedAllowPolicies > 0 {
            log.notice("✅ app:countryPolicy migrate VERIFY dropped allow policies=\(loadedPolicies.droppedAllowPolicies, privacy: .public) kept=\(loadedPolicies.policies.count, privacy: .public)")
        }
        // Disabled policies from older versions are purged: nothing in the UI
        // can re-enable them, and `derivedCountryRules()` skips them anyway.
        // Purge rather than re-enable so a blocked country never starts
        // blocking again without a user action.
        let livePolicies = loadedPolicies.policies.filter(\.enabled)
        let purgedPolicies = loadedPolicies.policies.count - livePolicies.count
        self.countryPolicies = livePolicies

        let blocklistStore = BlocklistSourceStore.appGroup() ?? BlocklistSourceStore(
            directoryURL: FileManager.default
                .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("FluxMoat/Blocklists", isDirectory: true)
        )
        self.blocklistStore = blocklistStore
        var sources = (try? blocklistStore.loadSources()) ?? []
        // Default lists, seeded once so deleting one sticks. Nothing is
        // downloaded until the user taps Update.
        if sources.isEmpty,
           !UserDefaults.standard.bool(forKey: "blocklistCatalogSeeded") {
            // One ad/tracker list plus two threat feeds. Feodo Tracker is
            // abuse.ch's botnet C2 IP list and needs no Auth-Key; ThreatFox
            // comes from the project mirror (`threatFoxMirrorURL`), also keyless.
            // Fixed ids: seeded data must be identical across reinstalls or
            // iCloud sync treats the copies as different items.
            sources = [
                BlocklistSource(
                    id: UUID(uuidString: "6B1E5A31-0001-4000-8000-5EEDB10C0001")!,
                    name: "StevenBlack (ads + malware)",
                    sourceURL: URL(string: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
                    format: .hosts,
                    category: .adTracker
                ),
                BlocklistSource(
                    id: UUID(uuidString: "6B1E5A31-0002-4000-8000-5EEDB10C0002")!,
                    name: "Feodo Tracker (botnet C2)",
                    sourceURL: URL(string: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
                    format: .ipList,
                    category: .threat
                ),
                BlocklistSource(
                    id: Self.threatFoxMirrorID,
                    name: "ThreatFox (malware IOCs)",
                    sourceURL: Self.threatFoxMirrorURL,
                    format: .jsonManifest,
                    category: .threat
                ),
            ]
            try? blocklistStore.saveSources(sources)
            UserDefaults.standard.set(true, forKey: "blocklistCatalogSeeded")
        }
        // The seed above only runs on an empty source list, so defaults added
        // later need their own one-time flag to reach existing installs. The
        // flag is set whether or not anything was appended, so deleting the
        // feed sticks.
        //
        // Skip the append if the id is already present (an iCloud merge from
        // a device that upgraded first), or the feed would appear twice.
        //
        // The mirror (GitHub Pages, refreshed every 6 h) serves the format the
        // ThreatFox reader already parses, so no key is needed. Nothing
        // downloads until the user taps Update.
        if !UserDefaults.standard.bool(forKey: Self.threatFoxMirrorSeededKey) {
            let added = !sources.contains { $0.id == Self.threatFoxMirrorID }
            if added {
                sources.append(
                    BlocklistSource(
                        id: Self.threatFoxMirrorID,
                        name: "ThreatFox (malware IOCs)",
                        sourceURL: Self.threatFoxMirrorURL,
                        format: .jsonManifest,
                        category: .threat
                    )
                )
                // Write to the store directly: `self` isn't fully initialized,
                // so `saveBlocklistSources()` can't be called yet.
                try? blocklistStore.saveSources(sources)
            }
            UserDefaults.standard.set(true, forKey: Self.threatFoxMirrorSeededKey)
            log.notice("✅ app:blocklist seed VERIFY source=threatfox added=\(added, privacy: .public) sources=\(sources.count, privacy: .public)")
        }
        self.blocklistSources = sources
        // Assignments in init don't fire didSet, so nothing is written back.
        // `abuseChKeyStored` comes from the same read.
        let storedAuthKey = KeychainStore.string(for: Self.abuseChAuthKeyAccount)
        self.abuseChAuthKey = storedAuthKey ?? ""
        self.abuseChKeyStored = !(storedAuthKey ?? "").isEmpty
        self.iCloudSyncEnabled = UserDefaults.standard.bool(forKey: Self.iCloudSyncEnabledKey)

        // Purge counts for the log line at the end of init. Counts only, never
        // targets.
        var purgedPaused = 0
        var purgedLapsed = 0
        // Whether retired profile kinds were folded forward on load. If so,
        // init writes the result back so the fold isn't redone every launch.
        var foldedRetiredProfile = false
        var foldedWiFiRules = 0
        let stored = try? snapshotStore.load()
        if let (snapshot, source) = stored {
            // The snapshot mixes user rules with rules compiled from country
            // policies. Drop the compiled ones, which are rebuilt on the next
            // persist, or they would end up in the Rules list permanently.
            let carried = snapshot.rules.filter { !CountryPolicy.isDerived($0) }
            // Only rules in force are kept.
            //
            // Paused rules (`enabled == false`) come from older versions and
            // can no longer be re-enabled from the UI. They are purged rather
            // than re-enabled so a paused Block doesn't silently start applying.
            //
            // Lapsed temporary rules are removed here at launch and by
            // `purgeLapsedRules()` while the app runs.
            //
            // A `.lsrules` import with `"disabled": true` or an iCloud merge
            // from an older version can still bring in a paused rule. They're
            // left alone at that point (purging mid-import or mid-merge causes
            // other problems) and get cleaned up on the next launch.
            let live = carried.filter(\.enabled)
            purgedPaused = carried.count - live.count
            let running = live.filter { !RuleFormat.hasLapsed($0) }
            purgedLapsed = live.count - running.count
            self.rules = running
            // Restore the mode; otherwise the next persistRules() would write
            // .standard back and knock the tunnel out of Ask mode.
            //
            // `RunMode.init(from:)` already folds retired modes to Standard;
            // `normalized` covers any path that skips decoding.
            let restoredMode = RunMode.normalized(snapshot.mode ?? .standard)
            self.mode = restoredMode
            // Restore the profile too, or a user on Public would come back as
            // Home and the first persist would send that to the tunnel. Stored
            // by kind because built-in profile ids used to change every launch.
            let storedKind = snapshot.activeProfileKind
            let activeKind = storedKind.map(Profile.normalizedKind) ?? .home
            if let storedKind, storedKind != activeKind { foldedRetiredProfile = true }
            let resolvedProfile = Profile.builtIn(activeKind)
            self.activeProfileID = resolvedProfile?.id
            self.dohServerURL = snapshot.dohServerURL
            self.blockEncryptedDNS = snapshot.blockEncryptedDNS ?? false
            self.historyRetention = snapshot.historyRetention ?? .default
            self.askQuietHours = snapshot.askQuietHours
            // Wi-Fi rules naming the retired Low Data profile are folded to
            // Home, which has the same unmatched action.
            var assignments = snapshot.wifiAutoProfiles ?? []
            for index in assignments.indices {
                let folded = Profile.normalizedKind(assignments[index].profileKind)
                guard folded != assignments[index].profileKind else { continue }
                assignments[index].profileKind = folded
                foldedWiFiRules += 1
            }
            self.wifiAutoProfiles = assignments
            // `stored` is the stored kind, `kind` the profile the lookup
            // actually returned ("-" if none). Uses locals, not `self`:
            // @Observable reads go through `access(keyPath:)`, which isn't
            // allowed before every stored property is initialized. Only enum
            // labels and counts are public; never log an SSID.
            log.notice("✅ app:profile restore VERIFY stored=\(storedKind?.rawValue ?? "-", privacy: .public) kind=\(resolvedProfile?.kind.rawValue ?? "-", privacy: .public) mode=\(restoredMode.rawValue, privacy: .public) wifiFolded=\(foldedWiFiRules, privacy: .public)")
            // The snapshot holds the composed union; manual domains live in
            // their own file so subscription domains don't leak into them.
            let manual = (try? blocklistStore.readDomains(for: BlocklistSourceStore.manualDomainsID)) ?? []
            if !manual.isEmpty {
                self.blocklistDomains = manual
            } else if sources.isEmpty {
                // Migration: older installs kept manual domains only in the
                // snapshot.
                self.blocklistDomains = snapshot.blocklistDomains
                if !snapshot.blocklistDomains.isEmpty {
                    try? blocklistStore.writeDomains(snapshot.blocklistDomains, for: BlocklistSourceStore.manualDomainsID)
                }
            } else {
                self.blocklistDomains = []
            }
            if source == .backup {
                log.warning("⚠️ app:loadSnapshot recovered from backup")
            }
        } else {
            // A fresh install starts with no rules. (Older versions seeded
            // two samples; see `retiredSampleRuleIDs`.)
            self.rules = []
            self.blocklistDomains = []
        }

        // One-time upgrade fix: snapshots written before `resolverThreatIntel`
        // existed decode it as nil, so Quad9 users would keep reporting threat
        // sinks as `.customResolver` until some setting changed. Rewrite once
        // through the normal path (cloud-apply guard, tunnel reload). Fresh
        // installs don't need it.
        if !UserDefaults.standard.bool(forKey: Self.resolverIntelBackfillKey) {
            if stored != nil { persistRules() }
            UserDefaults.standard.set(true, forKey: Self.resolverIntelBackfillKey)
            log.notice("✅ app:resolverIntelBackfill VERIFY: one-shot done rewrote=\(stored != nil, privacy: .public) intel=\(DoHPreset.threatIntelFiltering(forURL: self.dohServerURL), privacy: .public)")
        }

        // Re-derive every rule's priority from its target shape. Rules can
        // arrive with stale priorities (iCloud from older versions, imported
        // files, old backups), which can let an allow on a site outrank a
        // block on one of its hosts. Idempotent, so it only logs and writes
        // when something changed. Counts only in the log.
        let releveled = Rule.relevelAll(&self.rules)
        if releveled > 0 {
            log.notice("✅ app:rules normalize VERIFY changed=\(releveled, privacy: .public) kept=\(self.rules.count, privacy: .public)")
        }

        // Persist purges and fixes right away, or the tunnel keeps enforcing
        // the old snapshot until some unrelated edit. Counts only in the log.
        //
        // Use `commitCountryPolicies()` when a policy was purged so the policy
        // file is written too. Re-leveling and folded settings share the same
        // single write.
        let foldedRetiredSettings = foldedRetiredProfile || foldedWiFiRules > 0
        if purgedPaused > 0 || purgedLapsed > 0 || purgedPolicies > 0 {
            log.notice("✅ app:rules purge VERIFY paused=\(purgedPaused, privacy: .public) lapsed=\(purgedLapsed, privacy: .public) policies=\(purgedPolicies, privacy: .public) kept=\(self.rules.count, privacy: .public)")
            if purgedPolicies > 0 {
                commitCountryPolicies()
            } else {
                persistRules()
            }
        } else if releveled > 0 || foldedRetiredSettings {
            persistRules()
        }

        // Feed the preload through the same path as live batches, so traffic
        // recorded while the app was closed also extends country policies.
        // Called here because it needs `self` fully initialized.
        let preloaded = absorbCountryTargets(from: recentFlows)
        if preloaded > 0 {
            log.notice("✅ app:countryPolicy preload VERIFY absorbed=\(preloaded, privacy: .public) from flows=\(self.recentFlows.count, privacy: .public)")
        }

        // Keep the protection switch in sync with real (asynchronous) VPN
        // status transitions.
        self.client.onRunningChanged = { [weak self] running in
            guard let self else { return }
            self.isProtectionOn = running
            // Mirror state for the widgets and reload them. The tunnel also
            // writes this file (for when the app isn't running); writing the
            // same value twice is harmless.
            try? WidgetStateStore.appGroup()?.write(WidgetState(protectionOn: running))
            WidgetCenter.shared.reloadAllTimelines()
            // Tick off the real running state, not just the toggle: on-demand
            // and launch reconcile can bring the tunnel up without
            // `setProtection`.
            if running {
                self.startTicking()
            } else {
                self.tickTask?.cancel()
                self.tickTask = nil
            }
            self.log.notice("✅ app:isProtection VERIFY: onRunningChanged running=\(running, privacy: .public) → isProtectionOn=\(self.isProtectionOn, privacy: .public)")
        }
    }

    /// Reconciles the protection toggle with the real VPN state at launch. On a
    /// cold launch nothing else reads an already-running VPN, so the toggle
    /// would show off (e.g. after an app upgrade). Goes through
    /// `onRunningChanged`.
    func refreshProtectionState() async {
        await client.refreshStatus()
    }

    /// Writes the snapshot atomically, logs the persisted identity and asks the
    /// tunnel to hot-swap. During a cloud apply every didSet would call this;
    /// the guard collapses those into the single `persistRulesNow()` at the end
    /// of `applyRemoteConfig`.
    private func persistRules() {
        guard !isCoalescingWrites else { return }
        persistRulesNow()
    }

    private func persistRulesNow() {
        do {
            // Country policies are compiled in only here. The tunnel only
            // understands domains and addresses, and keeping derived rules out
            // of `rules` keeps them out of the Rules list.
            let derived = derivedCountryRules()
            let snapshot = RuleSnapshot(
                rules: rules + derived,
                blocklistDomains: composedBlocklistDomains(),
                threatDomains: composedThreatDomains(),
                threatIPs: composedThreatIPs(),
                mode: mode,
                profileDefault: activeProfile?.unmatchedAction,
                // The tunnel reads the action; the app reads the kind on the
                // next launch.
                activeProfileKind: activeProfile?.kind,
                dohServerURL: dohServerURL,
                blockEncryptedDNS: blockEncryptedDNS ? true : nil,
                historyRetention: historyRetention == .default ? nil : historyRetention,
                askQuietHours: askQuietHours,
                wifiAutoProfiles: wifiAutoProfiles.isEmpty ? nil : wifiAutoProfiles,
                // The tunnel can't tell a threat-filtering resolver (Quad9) from
                // an ad-blocking one (NextDNS) since both just sinkhole names,
                // so the classification comes from the preset here.
                resolverThreatIntel: DoHPreset.threatIntelFiltering(forURL: dohServerURL)
            )
            let sha = try snapshotStore.write(snapshot)
            let (reloaded, source) = try snapshotStore.load()
            // .notice rather than .info: `log collect` keeps only the last ~99 s
            // of info on device, and this is the one line that records
            // rules.count on every write.
            log.notice("✅ app:writeSnapshot commit VERIFY: rules \(self.rules.count)+\(derived.count, privacy: .public) derived→\(reloaded.rules.count, privacy: .public) source \(source == .current ? "current" : "backup", privacy: .public) sha \(String(sha.prefix(8)), privacy: .public)")
            Task { [weak self] in
                guard let self else { return }
                do {
                    // The tunnel acks only after loadSnapshot has run, so the ack
                    // confirms the reload from an app-only log capture.
                    _ = try await self.client.send(.reloadRules)
                    self.log.info("✅ app:reloadRules ack VERIFY: tunnel confirmed snapshot reload")
                } catch {
                    self.log.info("⚠️ app:reloadRules not delivered (tunnel off is normal): \(error.localizedDescription, privacy: .public)")
                }
            }
            if !isCoalescingWrites { scheduleCloudSync() }
        } catch {
            log.error("❌ app:writeSnapshot failed: \(error, privacy: .public)")
        }
    }

    /// User-visible reason the last protection toggle failed (e.g. VPN
    /// authorization denied, missing entitlement).
    var protectionError: String?

    /// Set while an app-initiated toggle is in flight (onboarding's waiting
    /// state, the Dashboard spinner). A UI hint only: `isProtectionOn` is the
    /// source of truth, and this never mirrors NEVPNStatus.
    enum ProtectionTransition { case idle, starting, stopping }
    var protectionTransition: ProtectionTransition = .idle

    func setProtection(_ on: Bool) {
        // Ignore a repeat tap in the direction already in flight, which would
        // start a duplicate task (double saveToPreferences). The opposite
        // direction is still allowed so the user can change their mind.
        let dir: ProtectionTransition = on ? .starting : .stopping
        guard protectionTransition != dir else { return }
        protectionTransition = dir
        Task {
            // Always ends on idle. If an opposite-direction task overlapped,
            // one of them clears the hint early, which is harmless.
            defer { protectionTransition = .idle }
            if on {
                do {
                    protectionError = nil
                    try await client.start()
                    startTicking()
                    isProtectionOn = client.isRunning
                    // start() returns once startVPNTunnel is called, while NE may
                    // still be bringing the tunnel up. Keep the .starting hint
                    // until it's running (15 s cap) so onboarding doesn't flash
                    // "Turn On" and invite a second tap. Usually exits on the
                    // first check since .connecting counts as running.
                    var waited = 0.0
                    while !client.isRunning, waited < 15 {
                        try? await Task.sleep(for: .milliseconds(250))
                        waited += 0.25
                    }
                    isProtectionOn = client.isRunning
                } catch {
                    protectionError = error.localizedDescription
                    log.error("❌ app:startTunnel failed: \(error, privacy: .public)")
                    isProtectionOn = client.isRunning
                }
            } else {
                await client.stop()
                tickTask?.cancel()
                tickTask = nil
                // stopVPNTunnel returns while the status is still `connected`,
                // so reading isRunning here would flip the toggle back on.
                // Show the user's intent; onRunningChanged reconciles later.
                isProtectionOn = false
            }
        }
    }

    private func startTicking() {
        tickTask?.cancel()
        tickTask = Task { [weak self] in
            while let self, !Task.isCancelled {
                guard let tick = await self.client.nextTick() else { break }
                // Pick up external changes (VPN turned off in Settings,
                // extension crash).
                self.isProtectionOn = self.client.isRunning
                self.counters = tick.counters
                // Follow the tunnel's Wi-Fi automation in the picker. nil means
                // no override. `normalizedKind` maps labels from a tunnel still
                // running an older snapshot.
                if let raw = tick.counters.autoProfileKind,
                   let reported = Profile.Kind(rawValue: raw) {
                    let kind = Profile.normalizedKind(reported)
                    if self.activeProfile?.kind != kind,
                       let target = self.profiles.first(where: { $0.kind == kind }) {
                        self.activeProfileID = target.id
                    }
                }
                // Latch the bypass signal so the one-shot prompt can still
                // appear after the counter resets.
                if (tick.counters.encryptedDNSBypassToday ?? 0) > 0 {
                    self.encryptedDNSBypassSeen = true
                }
                // On-device GeoIP; the mock's country is only a fallback for
                // addresses missing from the database.
                let annotated = tick.newFlows.map { event in
                    var event = event
                    event.countryCode = GeoIPService.shared
                        .countryCode(for: event.remoteIP) ?? event.countryCode
                    return event
                }
                // Dedupe by id: a duplicate Identifiable id crashes
                // SwiftUI.List's diff. Duplicates come from the extension's
                // live buffer replaying events the store preload already
                // delivered, and from repeated ids within one batch.
                var seen = Set(self.recentFlows.map(\.id))
                let fresh = annotated.filter { seen.insert($0.id).inserted }
                self.recentFlows.insert(contentsOf: fresh, at: 0)
                // Country policies grow from here, the only place a flow and
                // its country meet before the buffer drops old entries.
                self.absorbCountryTargets(from: fresh)
                // Purge expired rules on the tick. This only runs while the
                // tunnel is up; the launch purge in `init` covers the rest.
                if self.purgeLapsedRules() > 0 { self.persistRules() }
                // Ask mode: pending asks have stable ids and aren't drained,
                // so replace the list wholesale each tick.
                if case .pendingAsks(let asks) = try? await self.client.send(.pendingAsks) {
                    self.pendingAsks = asks
                }
                if self.recentFlows.count > 200 {
                    self.recentFlows.removeLast(self.recentFlows.count - 200)
                }
            }
            if let self, !Task.isCancelled {
                self.isProtectionOn = self.client.isRunning
            }
        }
    }

    // MARK: Rules

    /// Ids of the two sample rules earlier versions seeded on first launch.
    /// Reserved permanently.
    ///
    /// Clouds that synced a seeded install still hold these records, possibly
    /// edited by the user, so incoming copies are not filtered. The ids must
    /// never be reused by a seed, fixture or migration, or they would collide
    /// with those records.
    static let retiredSampleRuleIDs: Set<UUID> = [
        UUID(uuidString: "6B1E5A31-0001-4000-8000-5EEDF01E0001")!,
        UUID(uuidString: "6B1E5A31-0002-4000-8000-5EEDF01E0002")!,
    ]

    /// Appends a user rule. This and `updateRule` are the only writers that
    /// set a rule's priority: `leveled` derives it from the target's shape
    /// (`RuleTarget.derivedPriority`), whatever the caller, import file or
    /// other device supplied.
    func addRule(_ rule: Rule) {
        rules.append(rule.leveled)
        rules.sort { $0.priority > $1.priority }
        // Every writer logs its source so a crash log shows which path changed
        // the rules.
        log.notice("✅ app:rules write VERIFY source=add count=\(self.rules.count, privacy: .public)")
        persistRules()
    }

    /// Replaces an edited rule in place, keeping its id.
    ///
    /// iCloud merges rules per id and tombstones ids that disappear locally,
    /// so saving an edit under a new id would be a delete plus an insert. Edit
    /// by id, never delete and re-add.
    ///
    /// A rule removed while its editor was open is not resurrected.
    func updateRule(_ rule: Rule) {
        guard let index = rules.firstIndex(where: { $0.id == rule.id }) else { return }
        rules[index] = rule.leveled
        // Editing the target can change its shape and therefore its priority.
        rules.sort { $0.priority > $1.priority }
        log.notice("✅ app:rules write VERIFY source=update count=\(self.rules.count, privacy: .public)")
        persistRules()
    }

    /// Ask mode: writes a rule for the user's answer and clears the question
    /// locally and in the tunnel. Only future connections use the rule; flows
    /// that ran in the meantime got the profile default.
    func resolveAsk(_ ask: PendingAsk, action: RuleAction) {
        let target: RuleTarget = ask.domain.map { RuleTarget.domain($0) } ?? .ip(ask.remoteIP)
        if !rules.contains(where: { $0.enabled && $0.target == target && $0.action == action }) {
            // No priority: `addRule` derives it from the target.
            addRule(Rule(action: action, target: target, note: "From Ask"))
        }
        pendingAsks.removeAll { $0.id == ask.id }
        Task { [weak self] in
            _ = try? await self?.client.send(.resolveAsk(ask.id))
        }
    }

    /// Ask-mode notifications come from the tunnel extension but permission
    /// belongs to the app, so request it when the user enables Ask mode.
    ///
    /// Goes through `WeeklySummaryNotifier` so the app has a single place that
    /// requests authorization. The result is ignored: Ask mode works without
    /// banners since pending asks still show on the Dashboard.
    private static func requestNotificationPermission() {
        Task { _ = await WeeklySummaryNotifier.requestAuthorization() }
    }

    /// One-tap rule from an observed flow: blocks or allows its domain if it
    /// has one, otherwise its IP. Applies to new connections after the
    /// snapshot reload; open flows keep their verdict.
    func addRule(for event: TrafficEvent, action: RuleAction) {
        let target: RuleTarget
        if let domain = event.domain, !domain.isEmpty {
            target = .domain(domain)
        } else if !event.remoteIP.isEmpty {
            target = .ip(event.remoteIP)
        } else {
            return
        }
        setUserRule(target: target, action: action, note: "From Live Traffic")
    }

    /// Single-target form of `setUserRule`, used by Live Traffic's row swipe and
    /// flow sheet.
    ///
    /// Replaces rather than appends, so Allow then Block on the same flow
    /// can't leave two rules where the tie resolves to allow. Repeating the
    /// current verb is a no-op, since `setUserRule` mints a new id each time
    /// and that would churn the id iCloud merges on.
    func setUserRule(target: RuleTarget, action: RuleAction, note: String) {
        let key = Self.ruleKey(target)
        let now = Date()
        let own = rules.filter {
            $0.isActive(at: now, profileID: activeProfileID) && Self.ruleKey($0.target) == key
        }
        // Already the only in-force rule on this target, with this action.
        if own.count == 1, own[0].action == action { return }
        setUserRule(targets: [target], action: action, note: note)
    }

    func deleteRules(at offsets: IndexSet) {
        rules.remove(atOffsets: offsets)
        log.notice("✅ app:rules write VERIFY source=delete count=\(self.rules.count, privacy: .public)")
        persistRules()
    }

    /// Removal by id for filtered lists, where row offsets don't match
    /// `rules` indices.
    func removeRules(ids: Set<UUID>) {
        guard !ids.isEmpty else { return }
        rules.removeAll { ids.contains($0.id) }
        log.notice("✅ app:rules write VERIFY source=remove count=\(self.rules.count, privacy: .public)")
        persistRules()
    }

    /// Deletes every rule whose expiry has passed and returns how many went.
    ///
    /// Not filtered by profile: `isActive` is also false for a rule scoped to
    /// another profile, but that rule comes back when the profile changes.
    /// Expiry is the only inactive state that never reverses.
    ///
    /// Callers (launch and the tick) persist.
    @discardableResult
    private func purgeLapsedRules(now: Date = Date()) -> Int {
        let before = rules.count
        rules.removeAll { RuleFormat.hasLapsed($0, now: now) }
        let purged = before - rules.count
        if purged > 0 {
            log.notice("✅ app:rules purge VERIFY lapsed=\(purged, privacy: .public) kept=\(self.rules.count, privacy: .public)")
        }
        return purged
    }

    /// Toggles one listed rule between Allow and Block.
    ///
    /// Edits the rule in place instead of going through `setUserRule`, so its
    /// id (which iCloud merges on), note and expiry survive. Other in-force
    /// rules on the same target are removed so the flip can't leave a
    /// contradicting pair.
    func flipRule(_ id: UUID) {
        guard let index = rules.firstIndex(where: { $0.id == id }) else { return }
        let flipped: RuleAction = rules[index].action == .allow ? .deny : .allow
        rules[index].action = flipped
        // Usually a no-op, but a rule synced from an older device or imported
        // this session may still carry a stale priority.
        rules[index] = rules[index].leveled
        // Drop the other in-force rules on this target, keeping this one.
        let key = Self.ruleKey(rules[index].target)
        let keptID = rules[index].id
        let now = Date()
        rules.removeAll {
            $0.id != keptID
                && $0.isActive(at: now, profileID: activeProfileID)
                && Self.ruleKey($0.target) == key
        }
        // Re-leveling can move this rule, and `ruleConflict` relies on the
        // array being sorted by priority.
        rules.sort { $0.priority > $1.priority }
        log.notice("✅ app:rules write VERIFY source=flip count=\(self.rules.count, privacy: .public)")
        persistRules()
    }

    // MARK: Conflicts with existing rules

    /// How an existing rule relates to one the user is about to save.
    ///
    /// A duplicate blocks the save; an opposite saves and retires the existing
    /// rule. The existing `Rule` is carried so the editor can name it.
    enum RuleConflict: Equatable {
        /// Same canonical target, same action. Already written.
        case duplicate(Rule)
        /// Same canonical target, opposite action, and in force right now.
        case opposite(Rule)
    }

    /// The existing rule on `candidate`'s exact target (by `ruleKey`), if any.
    ///
    /// `excluding` is the id of the rule being edited. `candidate.id` is also
    /// skipped so a rule is never reported as conflicting with itself.
    func ruleConflict(for candidate: Rule, excluding: UUID?) -> RuleConflict? {
        let key = Self.ruleKey(candidate.target)
        let now = Date()
        for rule in rules where rule.id != excluding && rule.id != candidate.id {
            guard Self.ruleKey(rule.target) == key else { continue }
            // Every writer keeps `rules` sorted by priority, so the first rule
            // on this key is the one that decides the target.
            if rule.action == candidate.action {
                // Regardless of profile scope: a same-action rule scoped to
                // another profile is still a duplicate.
                return .duplicate(rule)
            }
            if rule.isActive(at: now, profileID: activeProfileID) {
                // Only an in-force opposite counts, the same line `flipRule`
                // draws. A rule scoped to another profile decides nothing now.
                return .opposite(rule)
            }
        }
        return nil
    }

    /// An overlapping rule with the opposite action, shown as information.
    ///
    /// Never blocks a save. An exact target outranks a wildcard above it, so a
    /// narrow rule inside a wide one keeps deciding its own target; the notice
    /// just tells the user that.
    enum RuleScopeNotice: Equatable {
        /// A narrower opposite rule inside this rule's reach. It keeps deciding
        /// its own target.
        case narrower(Rule)
        /// A wider opposite rule covering this one. This rule overrides it for
        /// its own target.
        case wider(Rule)
    }

    /// The overlap worth mentioning for `candidate`, if any.
    ///
    /// Same-key rules are left to `ruleConflict`, and same-action overlaps
    /// aren't reported. A narrower rule is reported ahead of a wider one
    /// because it's the more surprising fact.
    func scopeNotice(for candidate: Rule, excluding: UUID?) -> RuleScopeNotice? {
        let key = Self.ruleKey(candidate.target)
        let now = Date()
        var wider: Rule?
        for rule in rules where rule.id != excluding && rule.id != candidate.id {
            guard rule.action != candidate.action,
                  rule.isActive(at: now, profileID: activeProfileID),
                  Self.ruleKey(rule.target) != key else { continue }
            if Self.ruleCovers(candidate.target, rule.target) {
                return .narrower(rule)
            }
            if wider == nil, Self.ruleCovers(rule.target, candidate.target) {
                wider = rule
            }
        }
        return wider.map(RuleScopeNotice.wider)
    }

    /// Saves from the rule editor: an ordinary add or edit, or a save that
    /// also retires a contradicted rule.
    ///
    /// `replacedID` names a different rule the user just contradicted. That
    /// rule keeps its id and takes the edited fields, since iCloud merges per
    /// id and a delete plus insert would race a tombstone. `createdAt`,
    /// `enabled` and `profileID` aren't in the editor and are left as they are.
    func commitRule(_ rule: Rule, replacing replacedID: UUID?) {
        guard let replacedID, replacedID != rule.id else {
            upsertRule(rule)
            return
        }
        guard var survivor = rules.first(where: { $0.id == replacedID }) else {
            // Deleted on another device, or expired, while the editor was
            // open. Save as an ordinary rule, as `updateRule` does.
            upsertRule(rule)
            return
        }
        survivor.action = rule.action
        survivor.target = rule.target
        // No priority copied: `updateRule` derives it from the new target.
        survivor.expiresAt = rule.expiresAt
        survivor.note = rule.note
        // The edited rule has been merged into the survivor, so remove it.
        //
        // Remove first: each write ships a snapshot to the tunnel, and editing
        // first would briefly ship both the survivor's new target and the old
        // rule's opposite verdict.
        if rules.contains(where: { $0.id == rule.id }) {
            removeRules(ids: [rule.id])
        }
        updateRule(survivor)
    }

    /// Updates the rule if it exists, adds it otherwise. `updateRule` won't
    /// resurrect a removed rule.
    private func upsertRule(_ rule: Rule) {
        if rules.contains(where: { $0.id == rule.id }) {
            updateRule(rule)
        } else {
            addRule(rule)
        }
    }

    // MARK: Allow rules that override lists

    /// Which layer an allow rule is holding open, if any.
    enum RuleOverride {
        case blocklist
        case threatFeed
    }

    /// Whether this allow rule overrides a list that would otherwise block its
    /// target, for the caption on the rule's row.
    ///
    /// `CompiledRuleSet.evaluate` returns on the first matching user rule,
    /// before the threat feed and blocklist are checked, so an allow at any
    /// priority exempts its target from both. Threat is reported first, as
    /// the engine checks it first.
    ///
    /// Known gaps, both under-reporting:
    /// - Wildcards are checked at their host and upward only. `*.example.com`
    ///   over a blocklist entry for `ads.example.com` isn't reported, since
    ///   that would mean scanning the whole blocklist per row.
    /// - Threat IPs match exact addresses only; CIDR entries aren't checked.
    func overrideNotice(for rule: Rule) -> RuleOverride? {
        // Read the generation before any early return: it subscribes the row
        // to blocklist changes and is the cache stamp.
        let generation = blocklistGeneration
        guard rule.action == .allow,
              rule.isActive(at: Date(), profileID: activeProfileID) else { return nil }
        let index = overlapIndex(generation: generation)

        switch rule.target {
        case .domain(let raw):
            let normalized = DomainName.normalize(raw)
            let host = normalized.hasPrefix("*.") ? String(normalized.dropFirst(2)) : normalized
            // Host first, then parents: a list entry also covers its
            // subdomains, as in the engine.
            var names = [host]
            names.append(contentsOf: DomainName.parentDomains(of: host))
            if names.contains(where: index.threatDomains.contains) { return .threatFeed }
            if names.contains(where: index.blocklistDomains.contains) { return .blocklist }
        case .ip(let raw):
            if index.threatIPs.contains(raw.trimmingCharacters(in: .whitespaces)) { return .threatFeed }
        case .cidr, .port, .network:
            // Neither list can match these target types.
            break
        }
        return nil
    }

    /// The three membership sets, built once per blocklist generation.
    ///
    /// Cached because building them reads every source's domain file from
    /// disk (about 55 ms for a 200k-entry list on an M5 Max), too slow for a
    /// `List` body. The lookups themselves are well under a microsecond, so
    /// they run directly.
    ///
    /// Built from the same `composed*` functions as the snapshot, so a caption
    /// never refers to a list the tunnel didn't receive.
    private func overlapIndex(generation: Int) -> OverlapIndex {
        if let overlap, overlapGeneration == generation { return overlap }
        let built = OverlapIndex(
            blocklistDomains: Set(composedBlocklistDomains().map(DomainName.normalize)),
            threatDomains: Set((composedThreatDomains() ?? []).map(DomainName.normalize)),
            // CIDR ranges are skipped; see `overrideNotice`.
            threatIPs: Set((composedThreatIPs() ?? []).filter { !$0.contains("/") })
        )
        overlap = built
        overlapGeneration = generation
        return built
    }

    private struct OverlapIndex {
        let blocklistDomains: Set<String>
        let threatDomains: Set<String>
        let threatIPs: Set<String>
    }

    /// Invalidates the overlap cache. Called from both blocklist properties'
    /// `didSet`.
    private func bumpBlocklistGeneration() {
        blocklistGeneration &+= 1
    }

    // MARK: Recent-targets rule controls

    /// What the user's own rules say about `target` right now, for a Recent
    /// targets row. nil means no user rule matches, so any verdict comes from a
    /// list, a threat feed or the mode default.
    ///
    /// Only rules in force count (`isActive`), and domains check their parents
    /// so a `*.example.com` rule covers its subdomains, as in the engine. Ties
    /// resolve the engine's way, but `.cidr`, `.port` and `.network` rules
    /// aren't considered.
    func userRuleState(for target: RuleTarget) -> RuleAction? {
        ruleEcho(for: target).state
    }

    /// The action of the rule on this exact target (the one `setUserRule`
    /// would replace), ignoring verdicts inherited from a wildcard above it.
    /// nil when there is none.
    ///
    /// Lets a row tell a block it can remove from one inherited from a
    /// `*.site` rule. Callers compare it with `userRuleState` so an own rule
    /// that loses to a broader one isn't offered for clearing.
    func ownUserRuleAction(for target: RuleTarget) -> RuleAction? {
        ruleEcho(for: target).own
    }

    /// Both answers for one target, from a single pass over the rules.
    ///
    /// Cached because the dashboard redraws every second and country rows fan
    /// out over many targets, which gets expensive with thousands of imported
    /// rules. Editing rules clears the cache, and since `isActive` depends on
    /// the clock the cache also expires after one second.
    private func ruleEcho(for target: RuleTarget) -> RuleEcho {
        // Read these before the cache lookup. @Observable tracks a property
        // only when a view reads it, so a row answered from the cache would
        // otherwise never redraw after a rule edit.
        let rules = self.rules
        let profile = activeProfileID

        let now = Date()
        if now.timeIntervalSince(echoCacheStamp) > 1 {
            echoCache.removeAll(keepingCapacity: true)
            echoCacheStamp = now
        }
        let key = Self.ruleKey(target)
        if let hit = echoCache[key] { return hit }

        var winner: Rule?
        var ownWinner: Rule?
        for rule in rules where rule.isActive(at: now, profileID: profile) {
            if Self.ruleKey(rule.target) == key { ownWinner = Self.stronger(rule, than: ownWinner) }
            guard Self.ruleCovers(rule.target, target) else { continue }
            winner = Self.stronger(rule, than: winner)
        }
        let echo = RuleEcho(state: winner?.action, own: ownWinner?.action)
        echoCache[key] = echo
        return echo
    }

    /// Same resolution as the engine: higher priority wins, allow wins ties.
    /// Must stay in sync with `CompiledRuleSet`, which works on compiled
    /// indices and can't be shared here.
    private static func stronger(_ rule: Rule, than current: Rule?) -> Rule {
        guard let current else { return rule }
        if rule.priority > current.priority { return rule }
        if rule.priority == current.priority, rule.action == .allow, current.action == .deny { return rule }
        return current
    }

    struct RuleEcho {
        /// What wins for this target across every rule that covers it.
        let state: RuleAction?
        /// What a rule on this exact target says, if there is one.
        let own: RuleAction?
    }

    /// Resets the stamp to `.distantPast` so the next read restamps it with
    /// its own clock.
    private func invalidateRuleEcho() {
        echoCache.removeAll(keepingCapacity: true)
        echoCacheStamp = .distantPast
    }

    /// Whether `ruleTarget` decides `target`: an exact match or a wildcard
    /// above it. `*.example.com` covers `a.example.com` and `*.a.example.com`
    /// but not the apex `example.com`, which is why a group row writes a pair.
    private static func ruleCovers(_ ruleTarget: RuleTarget, _ target: RuleTarget) -> Bool {
        switch (ruleTarget, target) {
        case (.domain(let rawRule), .domain(let rawWanted)):
            let ruleName = DomainName.normalize(rawRule)
            let wanted = DomainName.normalize(rawWanted)
            if ruleName == wanted { return true }
            guard ruleName.hasPrefix("*.") else { return false }
            let suffix = String(ruleName.dropFirst(2))
            let host = wanted.hasPrefix("*.") ? String(wanted.dropFirst(2)) : wanted
            return DomainName.parentDomains(of: host).contains(suffix)
        case (.ip(let rawRule), .ip(let rawWanted)):
            // Compare parsed addresses so leading zeros and v6 casing don't
            // matter; fall back to raw strings when parsing fails.
            if let ruleIP = IPAddress.parse(rawRule), let wantedIP = IPAddress.parse(rawWanted) {
                return ruleIP == wantedIP
            }
            return rawRule == rawWanted
        default:
            return false
        }
    }

    /// Sets every target in `targets` to `action`, replacing the user's
    /// existing rules on them. `action == nil` clears them.
    ///
    /// Replaces rather than appends: appending let Block then Allow on the
    /// same row leave both rules, and the tie resolves to allow.
    ///
    /// Only rules active now (`isActive`, the same check as
    /// `ownUserRuleAction`) are replaced. A rule scoped to another profile is
    /// left alone. Don't widen this predicate.
    ///
    /// Persists once for the whole batch, since each persist is a snapshot
    /// write plus tunnel IPC and a country fan-out can be dozens of targets.
    ///
    /// `note` is what the Rules page search matches, so pass something
    /// recognizable ("From Recent targets").
    func setUserRule(targets: [RuleTarget], action: RuleAction?, note: String) {
        guard !targets.isEmpty else { return }
        let now = Date()
        let replacing = Set(targets.map(Self.ruleKey))
        rules.removeAll {
            $0.isActive(at: now, profileID: activeProfileID) && replacing.contains(Self.ruleKey($0.target))
        }
        if let action {
            // No priority argument: `Rule.leveled` derives it from each
            // target's shape, so a group row's apex and its `*.` twin land on
            // different levels.
            rules.append(contentsOf: targets.map {
                Rule(action: action, target: $0, note: note).leveled
            })
            rules.sort { $0.priority > $1.priority }
        }
        log.notice("✅ app:rules write VERIFY source=set count=\(self.rules.count, privacy: .public)")
        persistRules()
    }

    /// Key used for replacement and dedup. Domains compare in the engine's
    /// canonical form and addresses by their parsed value, so
    /// `Tracker.Example.` and `2001:DB8::1` match their normalized forms. Raw
    /// string is the fallback when parsing fails.
    private static func ruleKey(_ target: RuleTarget) -> RuleTarget {
        switch target {
        case .domain(let raw): .domain(DomainName.normalize(raw))
        case .ip(let raw): .ip(IPAddress.parse(raw)?.description ?? raw)
        default: target
        }
    }

    // MARK: Country policies

    /// The active policy for `code`, if any. Country policies only block
    /// (`CountryPolicy.derivedAction`), so existence is the whole answer.
    ///
    /// `enabled` is still checked because an older app version on the same
    /// iCloud account can sync a disabled policy; the launch purge removes
    /// those.
    func countryPolicy(for code: String?) -> CountryPolicy? {
        guard let code, !code.isEmpty else { return nil }
        let wanted = code.uppercased()
        return countryPolicies.first { $0.countryCode == wanted && $0.enabled }
    }

    /// Blocks a country, or unblocks it when `blocked` is false (the policy is
    /// removed). There is at most one policy per country.
    ///
    /// A new policy keeps the previous one's targets and adds whatever the
    /// recent-flows buffer holds for the country. Seeding only from the
    /// 200-flow buffer would shrink a long-lived policy to what happens to be
    /// on screen.
    func setCountryPolicy(countryCode: String, blocked: Bool) {
        let code = countryCode.uppercased()
        guard !code.isEmpty else { return }
        // Read before the remove so a re-block keeps the old targets.
        let carried = countryPolicies.first { $0.countryCode == code }?.derivedTargets ?? []
        countryPolicies.removeAll { $0.countryCode == code }
        if blocked {
            countryPolicies.append(CountryPolicy(
                countryCode: code,
                derivedTargets: Self.mergedTargets(carried, observedTargets(forCountry: code))
            ))
            countryPolicies.sort { $0.createdAt < $1.createdAt }
        }
        commitCountryPolicies()
    }

    /// Union in first-seen order, deduped by `ruleKey` so the same address
    /// written two ways appears once.
    private static func mergedTargets(_ existing: [RuleTarget], _ fresh: [RuleTarget]) -> [RuleTarget] {
        var seen = Set<RuleTarget>()
        var union: [RuleTarget] = []
        for target in existing + fresh where seen.insert(ruleKey(target)).inserted {
            union.append(target)
        }
        return union
    }

    /// A policy's rules only exist in `derivedCountryRules()`, so removing it
    /// leaves `rules` untouched; the next snapshot just omits them.
    func removeCountryPolicies(ids: Set<UUID>) {
        guard !ids.isEmpty else { return }
        countryPolicies.removeAll { ids.contains($0.id) }
        commitCountryPolicies()
    }

    /// Saves the policy file, then rebuilds the snapshot and reloads the
    /// tunnel.
    private func commitCountryPolicies() {
        // Any pending debounced flush is covered by this write.
        derivedPersistTask?.cancel()
        derivedPersistTask = nil
        saveCountryPolicies()
        persistRules()
    }

    private func saveCountryPolicies() {
        do {
            try countryPolicyStore.save(countryPolicies)
            let targets = countryPolicies.reduce(0) { $0 + $1.derivedTargets.count }
            log.notice("✅ app:countryPolicy save VERIFY policies=\(self.countryPolicies.count, privacy: .public) targets=\(targets, privacy: .public)")
        } catch {
            log.error("❌ app:countryPolicy save failed: \(error, privacy: .public)")
        }
    }

    /// Every destination in the recent buffer attributed to `code`, used to
    /// seed a new policy.
    private func observedTargets(forCountry code: String) -> [RuleTarget] {
        var seen = Set<RuleTarget>()
        var targets: [RuleTarget] = []
        for event in recentFlows where event.countryCode?.uppercased() == code {
            guard let target = Self.observedTarget(for: event) else { continue }
            guard seen.insert(Self.ruleKey(target)).inserted else { continue }
            targets.append(target)
        }
        return targets
    }

    /// The rule target for a flow: its domain if it had one, otherwise
    /// its address. Matches `addRule(for:action:)`.
    private static func observedTarget(for event: TrafficEvent) -> RuleTarget? {
        if let domain = event.domain, !domain.isEmpty { return .domain(domain) }
        if !event.remoteIP.isEmpty { return .ip(event.remoteIP) }
        return nil
    }

    /// Adds new flows' targets to the policies for their countries and returns
    /// how many were added. Called on every tick and once at launch with the
    /// event-store preload, so a policy keeps covering new destinations.
    ///
    /// The return value is only used for the launch log.
    @discardableResult
    private func absorbCountryTargets(from events: [TrafficEvent]) -> Int {
        guard !countryPolicies.isEmpty, !events.isEmpty else { return 0 }
        var added = 0
        for index in countryPolicies.indices where countryPolicies[index].enabled {
            let code = countryPolicies[index].countryCode
            var known = Set(countryPolicies[index].derivedTargets.map(Self.ruleKey))
            for event in events where event.countryCode?.uppercased() == code {
                guard let target = Self.observedTarget(for: event) else { continue }
                guard known.insert(Self.ruleKey(target)).inserted else { continue }
                countryPolicies[index].derivedTargets.append(target)
                added += 1
            }
        }
        if added > 0 { scheduleDerivedPersist() }
        return added
    }

    /// Batches policy growth, since persisting per tick would mean a snapshot
    /// write plus tunnel IPC several times a second.
    ///
    /// Trailing-only, not restart-on-every-change: under steady traffic a
    /// restarting debounce would never fire. The first change arms a 3 s timer
    /// and later ones ride along.
    private func scheduleDerivedPersist() {
        guard derivedPersistTask == nil else { return }
        derivedPersistTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            guard !Task.isCancelled, let self else { return }
            self.derivedPersistTask = nil
            self.saveCountryPolicies()
            self.persistRules()
        }
    }

    /// Compiles every enabled policy into concrete rules for the snapshot.
    /// Derived rules go into the snapshot only, never into `rules`.
    ///
    /// Only duplicates across policies are skipped. Targets that already have
    /// a user rule are still emitted even though the derived rule loses to it:
    /// the snapshot is static, so if a temporary user rule expired the target
    /// would otherwise have no rule at all until the next persist. The engine
    /// resolves priority per connection, so the user's rule wins while active
    /// and the derived one takes over after.
    private func derivedCountryRules() -> [Rule] {
        guard !countryPolicies.isEmpty else { return [] }
        var seen = Set<RuleTarget>()
        var derived: [Rule] = []
        for policy in countryPolicies where policy.enabled {
            let note = policy.derivedNote(countryName: RecentTargets.countryName(policy.countryCode))
            for target in policy.derivedTargets {
                guard seen.insert(Self.ruleKey(target)).inserted else { continue }
                derived.append(Rule(
                    action: CountryPolicy.derivedAction,
                    target: target,
                    priority: CountryPolicy.derivedPriority,
                    note: note,
                    createdAt: policy.createdAt
                ))
            }
        }
        return derived
    }

    /// Merges a parsed .lsrules report and returns a user-facing summary of the
    /// net additions.
    ///
    /// Rules dedup on (canonical target, action); priority and note are not
    /// part of the key. On a duplicate the incoming copy is dropped, so a
    /// re-import never overwrites a rule the user has since edited.
    func applyImport(_ report: LSRulesImporter.Report) -> String {
        var seenRules = Set(rules.map(Self.importKey))
        // The set also catches a file that lists the same host twice.
        //
        // `.leveled` discards the file's priority and derives it from the target
        // shape. Arbitrary imported priorities could put a host rule below its
        // parent domain's rule, where it would never take effect.
        let addedRules = report.rules.filter { seenRules.insert(Self.importKey($0)).inserted }
        rules.append(contentsOf: addedRules.map(\.leveled))
        rules.sort { $0.priority > $1.priority }
        log.notice("✅ app:rules write VERIFY source=import count=\(self.rules.count, privacy: .public)")
        var seenDomains = Set(blocklistDomains)
        let addedDomains = report.blocklistDomains.filter { seenDomains.insert($0).inserted }
        blocklistDomains.append(contentsOf: addedDomains)
        try? blocklistStore.writeDomains(blocklistDomains, for: BlocklistSourceStore.manualDomainsID)
        persistRules()

        var lines: [String] = []
        if !report.rules.isEmpty {
            lines.append(Self.netAddLine(
                added: addedRules.count, parsed: report.rules.count, noun: "rule", plural: "rules"
            ))
        }
        if !report.blocklistDomains.isEmpty {
            lines.append(Self.netAddLine(
                added: addedDomains.count,
                parsed: report.blocklistDomains.count,
                noun: "blocked domain",
                plural: "blocked domains"
            ))
        }
        lines.append(contentsOf: Self.importDowngradeLines(report))
        return lines.joined(separator: "\n")
    }

    /// What the importer had to drop from this file. Shared with the
    /// confirmation sheet so the preview and the result say the same thing.
    static func importDowngradeLines(_ report: LSRulesImporter.Report) -> [String] {
        var lines: [String] = []
        if report.appScopeDropped > 0 {
            lines.append("\(counted(report.appScopeDropped, "rule", "rules")) had app-specific fields (ignored — iOS has no per-app identity)")
        }
        if report.constraintsDropped > 0 {
            lines.append("\(counted(report.constraintsDropped, "rule", "rules")) lost port/protocol constraints")
        }
        if !report.skipped.isEmpty {
            lines.append("\(counted(report.skipped.count, "entry", "entries")) skipped (ask/incoming/app-only)")
        }
        return lines
    }

    /// "1 rule" / "3 rules". Both forms are passed in because plurals like
    /// "entry/entries" aren't a suffix rule.
    private static func counted(_ count: Int, _ noun: String, _ plural: String) -> String {
        "\(count) \(count == 1 ? noun : plural)"
    }

    /// Summary line for one half of the import. Includes the already-present
    /// count so re-importing the same file doesn't read as a failure.
    private static func netAddLine(added: Int, parsed: Int, noun: String, plural: String) -> String {
        let duplicates = parsed - added
        if added == 0 {
            return "No new \(plural) — all \(parsed) were already here"
        }
        let head = "Added \(counted(added, noun, plural))"
        return duplicates > 0 ? "\(head), \(duplicates) already here" : head
    }

    /// Import identity for a rule: the canonicalized destination plus the
    /// action.
    private struct ImportKey: Hashable {
        let target: RuleTarget
        let action: RuleAction
    }

    private static func importKey(_ rule: Rule) -> ImportKey {
        ImportKey(target: ruleKey(rule.target), action: rule.action)
    }

    // MARK: Wi-Fi automation

    /// Adds a Wi-Fi → profile rule. Duplicate SSIDs are dropped: one network,
    /// one profile.
    func addWifiAssignment(ssid: String, profileKind: Profile.Kind, unmatchedAction: RuleAction) {
        guard !wifiAutoProfiles.contains(where: { $0.ssid == ssid }) else { return }
        wifiAutoProfiles.append(WiFiProfileAssignment(
            ssid: ssid, profileKind: profileKind, unmatchedAction: unmatchedAction
        ))
    }

    // MARK: Blocklist subscriptions

    /// Ad/tracker domains for the snapshot: manual/imported domains plus
    /// enabled ad-category sources. Threat-category domain feeds go to
    /// `composedThreatDomains()` so their hits are counted separately.
    private func composedBlocklistDomains() -> [String] {
        var seen = Set(blocklistDomains)
        var composed = blocklistDomains
        for source in blocklistSources
        where source.enabled && (source.category ?? .adTracker) == .adTracker {
            for domain in (try? blocklistStore.readDomains(for: source.id)) ?? [] where seen.insert(domain).inserted {
                composed.append(domain)
            }
        }
        return composed
    }

    /// Threat-intel domains from enabled threat-category sources. nil when
    /// there are none, so the field is omitted from the snapshot.
    private func composedThreatDomains() -> [String]? {
        var seen = Set<String>()
        var composed: [String] = []
        for source in blocklistSources
        where source.enabled && source.category == .threat {
            for domain in (try? blocklistStore.readDomains(for: source.id)) ?? [] where seen.insert(domain).inserted {
                composed.append(domain)
            }
        }
        return composed.isEmpty ? nil : composed
    }

    /// Union of enabled sources' IP/CIDR indicators. IP feeds are always
    /// treated as threat intel regardless of category. nil when empty.
    private func composedThreatIPs() -> [String]? {
        var seen = Set<String>()
        var composed: [String] = []
        for source in blocklistSources where source.enabled {
            for ip in (try? blocklistStore.readIPs(for: source.id)) ?? [] where seen.insert(ip).inserted {
                composed.append(ip)
            }
        }
        return composed.isEmpty ? nil : composed
    }

    func addBlocklistSource(name: String, url: URL, format: BlocklistSource.Format, category: BlocklistSource.Category) {
        blocklistSources.append(BlocklistSource(name: name, sourceURL: url, format: format, category: category))
        saveBlocklistSources()
    }

    func deleteBlocklistSources(at offsets: IndexSet) {
        for index in offsets {
            blocklistStore.deleteDomains(for: blocklistSources[index].id)
            blocklistStore.deleteIPs(for: blocklistSources[index].id)
        }
        blocklistSources.remove(atOffsets: offsets)
        saveBlocklistSources()
        persistRules()
    }

    /// Removes all manually imported domains. They only come from .lsrules
    /// import and no subscription can re-fetch them, so the UI confirms first.
    /// Subscription domains live in their own files and are unaffected.
    func removeManualDomains() {
        guard !blocklistDomains.isEmpty else { return }
        blocklistDomains = []
        blocklistStore.deleteDomains(for: BlocklistSourceStore.manualDomainsID)
        persistRules()
    }

    func toggleBlocklistSource(_ id: UUID) {
        guard let index = blocklistSources.firstIndex(where: { $0.id == id }) else { return }
        blocklistSources[index].enabled.toggle()
        saveBlocklistSources()
        persistRules()
    }

    /// The abuse.ch Auth-Key, only for sources hosted on abuse.ch, so the
    /// credential is never sent to a third-party blocklist host.
    private func authKey(for source: BlocklistSource) -> String? {
        guard !abuseChAuthKey.isEmpty,
              let host = source.sourceURL?.host?.lowercased(),
              host == "abuse.ch" || host.hasSuffix(".abuse.ch") else { return nil }
        return abuseChAuthKey
    }

    /// Who asked for a download. Automatic rounds stay quiet on failure and
    /// respect Low Data Mode; a manual tap reports errors and fetches now.
    private enum BlocklistUpdateTrigger { case manual, automatic }

    /// Result of one download attempt. Only the automatic round reads it, for
    /// its summary log line.
    private enum BlocklistUpdateResult { case updated, unchanged, failed }

    /// Session for automatic refreshes. Created once because a URLSession that
    /// is never invalidated leaks its queues.
    ///
    /// `allowsConstrainedNetworkAccess = false` respects Low Data Mode for
    /// fetches the user didn't ask for. Manual updates use the default session.
    private static let autoRefreshSession: URLSession = {
        let config = URLSessionConfiguration.default
        config.allowsConstrainedNetworkAccess = false
        return URLSession(configuration: config)
    }()

    func updateBlocklistSource(_ id: UUID) async {
        await updateBlocklistSource(id, trigger: .manual)
    }

    /// Downloads one subscription and rebuilds the snapshot when it changed,
    /// so the tunnel picks up the new list immediately.
    /// - Returns: the outcome, or nil when it didn't run (source gone, or a
    ///   download for it already in flight).
    @discardableResult
    private func updateBlocklistSource(
        _ id: UUID, trigger: BlocklistUpdateTrigger
    ) async -> BlocklistUpdateResult? {
        guard let index = blocklistSources.firstIndex(where: { $0.id == id }),
              !updatingBlocklistIDs.contains(id) else { return nil }
        updatingBlocklistIDs.insert(id)
        defer { updatingBlocklistIDs.remove(id) }

        let source = blocklistSources[index]
        let updater = BlocklistUpdater(
            session: trigger == .automatic ? Self.autoRefreshSession : .shared
        )
        let result: BlocklistUpdateResult
        do {
            switch try await updater.fetch(source, authKey: authKey(for: source)) {
            case .notModified:
                guard let index = blocklistSources.firstIndex(where: { $0.id == id }) else { return nil }
                blocklistSources[index].updateError = nil
                if trigger == .manual {
                    log.notice("✅ app:blocklist update VERIFY: not modified entries=\(source.entryCount, privacy: .public)")
                }
                result = .unchanged
            case .updated(let domains, let ipEntries, let skippedLines, let etag):
                // Look the row up again: the array can be replaced while the
                // download is in flight (a delete, a cloud-sync apply).
                guard let index = blocklistSources.firstIndex(where: { $0.id == id }) else { return nil }
                // A feed is either domains or IP/CIDR. Write both so a format
                // change on the same source clears stale entries.
                try blocklistStore.writeDomains(domains, for: source.id)
                try blocklistStore.writeIPs(ipEntries, for: source.id)
                // Count what actually landed on disk, not the in-memory arrays.
                let persisted = try blocklistStore.readDomains(for: source.id).count
                    + blocklistStore.readIPs(for: source.id).count
                blocklistSources[index].entryCount = persisted
                blocklistSources[index].lastUpdatedAt = Date()
                blocklistSources[index].etag = etag
                blocklistSources[index].updateError = nil
                persistRules()
                if trigger == .manual {
                    log.notice("✅ app:blocklist update VERIFY: entries \(source.entryCount, privacy: .public)→\(persisted, privacy: .public) skipped \(skippedLines, privacy: .public)")
                }
                result = .updated
            }
        // Automatic rounds don't set `updateError`: the user took no action,
        // so there's nothing on the row for them to fix. They log and retry on
        // a later foreground.
        } catch let error as BlocklistUpdater.UpdateError {
            if trigger == .manual {
                if let index = blocklistSources.firstIndex(where: { $0.id == id }) {
                    blocklistSources[index].updateError = error.reason
                }
                log.error("❌ app:blocklist update failed: \(error.reason, privacy: .public)")
            } else {
                log.debug("app:blocklist autoRefresh source failed: \(error.reason, privacy: .public)")
            }
            result = .failed
        } catch {
            if trigger == .manual {
                if let index = blocklistSources.firstIndex(where: { $0.id == id }) {
                    blocklistSources[index].updateError = error.localizedDescription
                }
                // URLError descriptions can include the list URL, so keep it private.
                log.error("❌ app:blocklist update failed: \(error.localizedDescription, privacy: .private)")
            } else {
                log.debug("app:blocklist autoRefresh source failed: \(error.localizedDescription, privacy: .private)")
            }
            result = .failed
        }
        saveBlocklistSources()
        return result
    }

    func updateAllBlocklistSources() async {
        for source in blocklistSources where source.enabled {
            await updateBlocklistSource(source.id)
        }
    }

    // MARK: Foreground auto-refresh

    /// One automatic round at a time. Both foreground hooks can fire on the
    /// same launch (see `FluxMoatApp`).
    private var isAutoRefreshingBlocklists = false

    private static let autoRefreshStampsKey = "blocklistAutoRefreshChecks"

    /// Per-source time of the last automatic check, changed or not, as epoch
    /// seconds.
    ///
    /// Kept in UserDefaults, not on `BlocklistSource`, so this device-local
    /// polling state doesn't go into the source file or the iCloud payload.
    /// `lastUpdatedAt` records content changes and doesn't move on a 304.
    private static func autoRefreshStamps() -> [UUID: Date] {
        let raw = UserDefaults.standard.dictionary(forKey: autoRefreshStampsKey) as? [String: Double] ?? [:]
        return raw.reduce(into: [:]) { stamps, entry in
            if let id = UUID(uuidString: entry.key) {
                stamps[id] = Date(timeIntervalSince1970: entry.value)
            }
        }
    }

    private static func saveAutoRefreshStamps(_ stamps: [UUID: Date]) {
        let raw = stamps.reduce(into: [String: Double]()) { raw, entry in
            raw[entry.key.uuidString] = entry.value.timeIntervalSince1970
        }
        UserDefaults.standard.set(raw, forKey: autoRefreshStampsKey)
    }

    /// Refreshes already-downloaded blocklists that are due, on each foreground.
    /// A subscription's first download is always a user tap; a list must never
    /// appear from a silent fetch. `BlocklistAutoRefresh` decides which are due.
    func refreshBlocklistsOnForeground() async {
        guard !isAutoRefreshingBlocklists else { return }
        isAutoRefreshingBlocklists = true
        defer { isAutoRefreshingBlocklists = false }

        var stamps = Self.autoRefreshStamps()
        // Forget bookkeeping for sources that have since been deleted.
        let live = Set(blocklistSources.map(\.id))
        if stamps.contains(where: { !live.contains($0.key) }) {
            stamps = stamps.filter { live.contains($0.key) }
            Self.saveAutoRefreshStamps(stamps)
        }

        let now = Date()
        let due = blocklistSources
            .filter { BlocklistAutoRefresh.shouldRefresh($0, lastCheckedAt: stamps[$0.id], now: now) }
            .map(\.id)
        // Nothing due is the common case and isn't worth a log line.
        guard !due.isEmpty else { return }

        var updated = 0, unchanged = 0, failed = 0
        for id in due {
            guard let result = await updateBlocklistSource(id, trigger: .automatic) else { continue }
            // Stamp failures too, so a server that's down isn't retried on
            // every foreground.
            stamps[id] = Date()
            Self.saveAutoRefreshStamps(stamps)
            switch result {
            case .updated: updated += 1
            case .unchanged: unchanged += 1
            case .failed: failed += 1
            }
        }

        let checked = updated + unchanged + failed
        guard checked > 0 else { return }
        log.notice("✅ app:blocklist autoRefresh VERIFY checked=\(checked, privacy: .public) updated=\(updated, privacy: .public) unchanged=\(unchanged, privacy: .public) failed=\(failed, privacy: .public)")
    }

    private func saveBlocklistSources() {
        do {
            try blocklistStore.saveSources(blocklistSources)
            if !isCoalescingWrites { scheduleCloudSync() }
        } catch {
            log.error("❌ app:blocklist saveSources failed: \(error, privacy: .public)")
        }
    }

    // MARK: - iCloud sync

    /// The UI's way in to the sync switch.
    func setICloudSync(_ on: Bool) {
        iCloudSyncEnabled = on
    }

    /// Debounced: config edits come in bursts (rule editor, list reorders),
    /// so run one cloud round after they settle.
    private func scheduleCloudSync(delay: Duration = .seconds(3)) {
        guard iCloudSyncEnabled else { return }
        cloudSyncTask?.cancel()
        cloudSyncTask = Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            await self?.runCloudSync()
        }
    }

    /// Foreground hook: pull whatever another device pushed while this app
    /// was suspended.
    func cloudSyncOnForeground() {
        scheduleCloudSync(delay: .zero)
    }

    private func runCloudSync() async {
        guard iCloudSyncEnabled else { return }
        // Set before the await so the status row shows progress. The service's
        // own `.syncing` isn't visible here until the round returns; a failed
        // round still ends on the error state the service sets.
        cloudSyncStatus = .syncing
        // Section stamps are placeholders. `SyncMerge.stampedLocal` in the
        // service derives the real ones from the last-synced baseline.
        let merged = await cloudSync.sync(
            rules: rules,
            settings: SyncedSettings(
                mode: mode,
                dohServerURL: dohServerURL,
                blockEncryptedDNS: blockEncryptedDNS,
                historyRetention: historyRetention,
                askQuietHours: askQuietHours,
                activeProfileKind: activeProfile?.kind,
                updatedAt: .distantPast),
            wifi: SyncedWiFiProfiles(assignments: wifiAutoProfiles, updatedAt: .distantPast),
            blocklist: SyncedBlocklist(
                manualDomains: blocklistDomains,
                sources: blocklistSources.map(SyncedBlocklistSource.init),
                updatedAt: .distantPast))
        cloudSyncStatus = cloudSync.status
        if let merged { applyRemoteConfig(merged) }
    }

    /// Applies a merged cloud config through the same paths as user edits
    /// (didSet, persistRules, tunnel reload), so remote changes reach the tunnel
    /// the same way.
    private func applyRemoteConfig(_ merged: SyncedConfig) {
        isApplyingRemoteConfig = true
        defer { isApplyingRemoteConfig = false }

        let mergedRules = merged.rules.map(\.rule)
        let rulesChanged = mergedRules != rules
        if rulesChanged {
            rules = mergedRules
            log.notice("✅ app:rules write VERIFY source=cloud count=\(self.rules.count, privacy: .public)")
        }

        mode = RunMode.normalized(merged.settings.mode)
        dohServerURL = merged.settings.dohServerURL
        blockEncryptedDNS = merged.settings.blockEncryptedDNS
        historyRetention = merged.settings.historyRetention
        askQuietHours = merged.settings.askQuietHours
        // Missing in configs written by older app versions. Keep the local
        // choice rather than resetting to Home.
        if let syncedKind = merged.settings.activeProfileKind,
           let target = Profile.builtIn(Profile.normalizedKind(syncedKind)) {
            activeProfileID = target.id
        }
        wifiAutoProfiles = merged.wifi.assignments.map {
            var assignment = $0
            assignment.profileKind = Profile.normalizedKind(assignment.profileKind)
            return assignment
        }

        if blocklistDomains != merged.blocklist.manualDomains {
            blocklistDomains = merged.blocklist.manualDomains
            try? blocklistStore.writeDomains(blocklistDomains, for: BlocklistSourceStore.manualDomainsID)
        }
        // Synced source metadata overlays local sources. Device-local fields
        // (etag, counts, errors, downloaded content) are kept for surviving ids;
        // new sources arrive empty until the user taps Update.
        let localByID = Dictionary(uniqueKeysWithValues: blocklistSources.map { ($0.id, $0) })
        let syncedIDs = Set(merged.blocklist.sources.map(\.id))
        let overlaid = merged.blocklist.sources.map { synced -> BlocklistSource in
            var source = localByID[synced.id] ?? BlocklistSource(
                id: synced.id, name: synced.name, sourceURL: synced.sourceURL,
                format: synced.format, category: synced.category, enabled: synced.enabled)
            source.name = synced.name
            source.sourceURL = synced.sourceURL
            source.format = synced.format
            source.category = synced.category
            source.enabled = synced.enabled
            return source
        }
        if overlaid != blocklistSources {
            for removed in blocklistSources where !syncedIDs.contains(removed.id) {
                blocklistStore.deleteDomains(for: removed.id)
                blocklistStore.deleteIPs(for: removed.id)
            }
            blocklistSources = overlaid
            saveBlocklistSources()
        }

        // One write for the whole apply. This is only called when merged
        // differs from local.
        persistRulesNow()
        log.notice("✅ app:cloudSync apply VERIFY rules=\(mergedRules.count, privacy: .public) sources=\(overlaid.count, privacy: .public) rulesChanged=\(rulesChanged, privacy: .public)")
    }

    /// Records a failed history read: sets `storeUnavailable` and logs which
    /// operation failed.
    ///
    /// Only the op and the error type are public. The error text stays private
    /// because `StoreError` can include the database file path.
    ///
    /// Pass `disablesHistory: false` for decorative reads (flags, counts) so a
    /// populated page isn't blanked by a failure that doesn't affect its rows.
    private func noteStoreFailure(_ op: String, _ error: any Error, disablesHistory: Bool = true) {
        if disablesHistory { storeUnavailable = true }
        log.error("❌ app:historyRead FAILED op=\(op, privacy: .public) type=\(String(describing: type(of: error)), privacy: .public) detail=\(String(describing: error), privacy: .private)")
    }

    /// Time-bucketed history for the dashboard's hour chart. Buckets align to
    /// the local time zone so day buckets start at midnight. On failure, returns
    /// an empty array and sets `storeUnavailable`.
    ///
    /// Synchronous on purpose: an hour of minute buckets on a store capped at
    /// 20k rows takes a few milliseconds. The Insights queries below span up to
    /// a month and run async.
    func historyBuckets(bucketSeconds: Int, since: Date?) -> [TrafficEventStore.TimeBucketAggregate] {
        do {
            return try eventStore.sync {
                try $0.bucketAggregates(
                    bucketSeconds: bucketSeconds,
                    offsetSeconds: TimeZone.current.secondsFromGMT(),
                    since: since
                )
            }
        } catch {
            noteStoreFailure("buckets", error)
            return []
        }
    }

    // MARK: - Insights rollups (off the main thread)
    //
    // Named differently from `historyBuckets` so the sync and async variants
    // aren't confused. The SQL runs on the gate's queue; failures set
    // `storeUnavailable` back on the main actor.
    //
    // `until == nil` means no upper bound. A value closes the window, which is
    // how the previous period is queried.

    /// Time-bucketed history for the Trends charts.
    func insightsBuckets(
        bucketSeconds: Int, since: Date?, until: Date? = nil
    ) async -> [TrafficEventStore.TimeBucketAggregate] {
        let offset = TimeZone.current.secondsFromGMT()
        do {
            return try await eventStore.read {
                try $0.bucketAggregates(
                    bucketSeconds: bucketSeconds, offsetSeconds: offset,
                    since: since, until: until
                )
            }
        } catch {
            noteStoreFailure("buckets", error)
            return []
        }
    }

    /// Time rollup for one destination, for the target sheet's sparkline.
    /// Uses the same time zone offset as the page chart so its buckets line up
    /// with the page's. Runs once per sheet opening.
    func insightsTargetBuckets(
        target: String, bucketSeconds: Int, since: Date?, until: Date? = nil
    ) async -> [TrafficEventStore.TimeBucketAggregate] {
        let offset = TimeZone.current.secondsFromGMT()
        do {
            return try await eventStore.read {
                try $0.targetBucketAggregates(
                    target: target, bucketSeconds: bucketSeconds,
                    offsetSeconds: offset, since: since, until: until
                )
            }
        } catch {
            noteStoreFailure("targetBuckets", error)
            return []
        }
    }

    /// Most-contacted destinations for the Trends ranking.
    func insightsTopTargets(
        since: Date?, until: Date? = nil, limit: Int = 10
    ) async -> [TrafficEventStore.TargetAggregate] {
        do {
            return try await eventStore.read {
                try $0.topTargets(since: since, until: until, limit: limit)
            }
        } catch {
            noteStoreFailure("topTargets", error)
            return []
        }
    }

    /// Most-blocked destinations.
    func insightsTopBlocked(
        since: Date?, until: Date? = nil, limit: Int = 5
    ) async -> [TrafficEventStore.TargetAggregate] {
        do {
            return try await eventStore.read {
                try $0.topBlockedTargets(since: since, until: until, limit: limit)
            }
        } catch {
            noteStoreFailure("topBlocked", error)
            return []
        }
    }

    /// Number of distinct destinations in the window, for the share card's
    /// "of N" footnote. Only called from the share sheet because it's a
    /// COUNT(DISTINCT) over the whole window. nil when the store can't answer.
    func insightsDistinctTargets(since: Date?, until: Date? = nil) async -> Int? {
        do {
            return try await eventStore.read {
                try $0.distinctTargets(since: since, until: until)
            }
        } catch {
            // Cosmetic footnote: don't blank the History page over it.
            noteStoreFailure("distinctTargets", error, disablesHistory: false)
            return nil
        }
    }

    /// Destinations first seen inside the window. `since` is required because
    /// "first seen in all of history" is true of everything; the All window
    /// skips this query.
    func insightsNewTargets(
        since: Date, until: Date? = nil, limit: Int = 5
    ) async -> [TrafficEventStore.TargetAggregate] {
        do {
            return try await eventStore.read {
                try $0.newTargets(since: since, until: until, limit: limit)
            }
        } catch {
            noteStoreFailure("newTargets", error)
            return []
        }
    }

    /// Country codes for the Trends ranking rows, keyed by target.
    ///
    /// Rollup rows carry no country (GeoIP never runs in the tunnel), so SQL
    /// finds the address each hostname was last dialed at in the window
    /// (`TrafficEventStore.latestRemoteIPs`) and GeoIP maps it here in the app.
    /// Address targets skip the query since they are their own answer.
    ///
    /// Targets that can't be placed (no stored address, or a private/unlisted
    /// address) are left out of the result, and the row shows the globe.
    ///
    /// Never log the inputs: they are the user's domains and addresses.
    func insightsTargetCountries(
        for targets: [String], since: Date?, until: Date? = nil
    ) async -> [String: String] {
        guard !targets.isEmpty else { return [:] }
        // An address is already the answer; only names need the query.
        var dialed: [String: String] = [:]
        var unplaced: [String] = []
        for target in targets {
            if IPAddress.parse(target) != nil {
                dialed[target] = target
            } else {
                unplaced.append(target)
            }
        }
        // Copied to a `let` because the closure runs on the store's queue.
        let names = unplaced
        if !names.isEmpty {
            do {
                let found = try await eventStore.read {
                    try $0.latestRemoteIPs(for: names, since: since, until: until)
                }
                dialed.merge(found) { current, _ in current }
            } catch {
                // Flags are decoration: keep the rows, drop the flags.
                noteStoreFailure("targetCountries", error, disablesHistory: false)
            }
        }
        return dialed.compactMapValues { GeoIPService.shared.countryCode(for: $0) }
    }

    /// Per-country rollup for the world map. SQL groups by IP and GeoIP maps
    /// each IP here in the app, since the `country` column is NULL for rows the
    /// extension writes. On failure, returns an empty array.
    ///
    /// GeoIP stays on this side of the await: the lookup is in-memory and
    /// `GeoIPService.shared` is main-actor state.
    ///
    /// The share sheet passes `disablesHistory: false` so a failed Countries
    /// card doesn't blank the Trends page.
    func insightsCountries(
        since: Date?, until: Date? = nil, disablesHistory: Bool = true
    ) async -> [TrafficEventStore.CountryAggregate] {
        let ips: [TrafficEventStore.IPAggregate]
        do {
            ips = try await eventStore.read { try $0.ipAggregates(since: since, until: until) }
        } catch {
            noteStoreFailure("countryAggregates", error, disablesHistory: disablesHistory)
            return []
        }
        return TrafficEventStore.CountryAggregate.aggregate(ips) {
            GeoIPService.shared.countryCode(for: $0)
        }
    }

    // MARK: - Rule hit counts
    //
    // Rules come from the snapshot file, not history, so these reads are
    // decoration. Failures pass `disablesHistory: false` to keep the Rules page
    // usable.

    /// Rebuilds hit counts for every rule in one query. The store skips SQLite
    /// entirely for an empty id set.
    func refreshRuleHits() async {
        let ids = Set(rules.map(\.id))
        do {
            ruleHits = try await eventStore.read { try $0.matchedRuleRollup(for: ids) }
            ruleHitsKnown = true
        } catch {
            noteStoreFailure("ruleHits", error, disablesHistory: false)
            ruleHits = [:]
            ruleHitsKnown = false
        }
    }

    /// Flows matched by one rule, newest first, for the detail sheet.
    /// Callers check `ruleHits` first and skip rules with no hits, since the
    /// query costs the same either way.
    func recentMatches(for ruleID: UUID, limit: Int = 20) async -> [TrafficEvent] {
        do {
            return try await eventStore.read { try $0.recentMatches(ruleID: ruleID, limit: limit) }
        } catch {
            noteStoreFailure("recentMatches", error, disablesHistory: false)
            return []
        }
    }

    // MARK: - Rule export

    /// The full rule ledger in the app's own JSON format.
    func exportRulesJSON() throws -> RuleExporter.JSONExport {
        let export = try RuleExporter.writeJSON(
            rules: rules,
            countryPolicies: countryPolicies,
            blocklistDomains: blocklistDomains,
            into: try ruleExportDirectory()
        )
        // Log counts only. The exported file holds the user's domains; the
        // device log must not.
        log.notice("✅ app:ruleExport json VERIFY rules=\(export.rules, privacy: .public) policies=\(export.countryPolicies, privacy: .public) domains=\(export.blocklistDomains, privacy: .public)")
        return export
    }

    /// The ledger in Little Snitch's format. Whatever it can't express is
    /// reported in `loss` so the UI can warn before sharing.
    func exportRulesLSRules() throws -> RuleExporter.LSRulesExport {
        let export = try RuleExporter.writeLSRules(
            rules: rules,
            countryPolicies: countryPolicies,
            blocklistDomains: blocklistDomains,
            into: try ruleExportDirectory()
        )
        log.notice("✅ app:ruleExport lsrules VERIFY rules=\(export.rules, privacy: .public) domains=\(export.blocklistDomains, privacy: .public) lossless=\(export.loss.isLossless, privacy: .public)")
        return export
    }

    /// Separate from the history export directory: `exportHistory` deletes
    /// `FluxMoatExports` on every run and would remove a rules file that is
    /// still open in a share sheet.
    private func ruleExportDirectory() throws -> URL {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("FluxMoatRuleExports", isDirectory: true)
        try? FileManager.default.removeItem(at: dir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Exports the full flow history as CSV to a temp file for the share
    /// sheet. Previous exports are removed first. The app never uploads it.
    func exportHistory() throws -> (url: URL, rows: Int) {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("FluxMoatExports", isDirectory: true)
        try? FileManager.default.removeItem(at: dir)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let stamp = Date().formatted(.iso8601.year().month().day())
        let url = dir.appendingPathComponent("FluxMoat-history-\(stamp).csv")
        let rows = try eventStore.sync { try $0.exportCSV(to: url) }
        log.notice("✅ app:eventStore export VERIFY rows=\(rows, privacy: .public)")
        return (url, rows)
    }

    // MARK: - Reset

    /// Erases all user configuration on this device: rules, list subscriptions,
    /// imported domains, country policies, Wi-Fi automation, the resolver,
    /// quiet hours and the abuse.ch key.
    ///
    /// Not touched: traffic history (`clearHistory()`), mode, profile,
    /// retention, the encrypted-DNS block (only the user may lower protection)
    /// and the iCloud switch.
    ///
    /// With iCloud on, the empty config has to win the next merge.
    /// `SyncMerge.stampedLocal` diffs against the last-synced baseline, so each
    /// removed rule becomes a tombstone stamped now and each changed section is
    /// stamped now, which beats the cloud copy. Don't call
    /// `cloudSync.resetBaseline()` here: without a baseline every section is
    /// stamped `.distantPast` and the cloud copy comes straight back. The sync
    /// runs immediately rather than after the usual debounce.
    ///
    /// With sync off there is no baseline (turning sync off clears it), so
    /// re-enabling sync later adopts whatever the account holds. The reset
    /// sheet warns about this.
    func resetAllConfiguration() {
        let beforeRules = rules.count
        let beforePolicies = countryPolicies.count
        let beforeSources = blocklistSources.count
        let beforeManual = blocklistDomains.count
        let beforeWiFi = wifiAutoProfiles.count

        isResettingAll = true

        // Cancel a pending country-target flush so it can't write after the
        // reset (same as `commitCountryPolicies`).
        derivedPersistTask?.cancel()
        derivedPersistTask = nil

        rules = []
        countryPolicies = []
        // Delete each subscription's downloaded files too, or they're orphaned
        // on disk (same as `deleteBlocklistSources`).
        for source in blocklistSources {
            blocklistStore.deleteDomains(for: source.id)
            blocklistStore.deleteIPs(for: source.id)
        }
        blocklistSources = []
        blocklistDomains = []
        blocklistStore.deleteDomains(for: BlocklistSourceStore.manualDomainsID)
        wifiAutoProfiles = []
        dohServerURL = nil
        askQuietHours = nil
        // `KeychainStore.set` deletes the item when given an empty string.
        abuseChAuthKey = ""

        saveCountryPolicies()
        saveBlocklistSources()

        // Clear the flag before the write so this one persist does the
        // snapshot, tunnel reload and cloud sync.
        isResettingAll = false
        persistRulesNow()
        scheduleCloudSync(delay: .zero)

        log.notice("✅ app:resetAll VERIFY rules=\(beforeRules, privacy: .public)→\(self.rules.count, privacy: .public) policies=\(beforePolicies, privacy: .public)→\(self.countryPolicies.count, privacy: .public) sources=\(beforeSources, privacy: .public)→\(self.blocklistSources.count, privacy: .public) manualDomains=\(beforeManual, privacy: .public)→\(self.blocklistDomains.count, privacy: .public) wifi=\(beforeWiFi, privacy: .public)→\(self.wifiAutoProfiles.count, privacy: .public) doh=\(self.dohServerURL == nil, privacy: .public) quietHours=\(self.askQuietHours == nil, privacy: .public) key=\(!self.abuseChKeyStored, privacy: .public) cloudPush=\(self.iCloudSyncEnabled, privacy: .public)")
    }

    func clearHistory() {
        recentFlows.removeAll()
        // Remove the on-disk history too (DELETE + VACUUM + WAL truncate in
        // `wipe`), not just the in-memory list.
        do {
            try eventStore.sync { try $0.wipe() }
            // A wipe rebuilds the file, so it's the one thing that clears
            // `storeUnavailable`.
            storeUnavailable = false
            log.notice("✅ app:eventStore wipe VERIFY: history erased")
        } catch {
            log.error("❌ app:eventStore wipe failed: \(error, privacy: .public)")
        }
        counters = .init(bytesUpPerSecond: 0, bytesDownPerSecond: 0, activeFlows: 0, blockedToday: 0)
    }
}

/// Serializes all app-side access to `TrafficEventStore`.
///
/// The store holds a raw `sqlite3` handle with no locking and must be used
/// from one queue at a time. Insights reads run off the main actor, so without
/// this a Trends reload and a Settings wipe (VACUUM) could use the handle at
/// once. A second connection would push that contention into SQLite's busy
/// timeout instead, where VACUUM fails rather than waits.
///
/// `@unchecked Sendable`: the store never leaves the queue, only closure
/// results come back.
final class HistoryStoreGate: @unchecked Sendable {
    private let store: TrafficEventStore
    /// Serial. `.utility` because nothing here is interactive; sync callers
    /// block on it and the queue inherits their QoS.
    private let queue = DispatchQueue(
        label: "fluxmoat.history", qos: .utility
    )

    init(_ store: TrafficEventStore) {
        self.store = store
    }

    /// Blocking access for cold-launch preload, prune, export and wipe.
    func sync<T>(_ body: (TrafficEventStore) throws -> T) rethrows -> T {
        try queue.sync { try body(store) }
    }

    /// Runs `body` on the queue without blocking the caller's actor.
    func read<T: Sendable>(
        _ body: @escaping @Sendable (TrafficEventStore) throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try body(self.store) })
            }
        }
    }
}
