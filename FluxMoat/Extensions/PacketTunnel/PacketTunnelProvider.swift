import CryptoKit
import NetworkExtension
import Network
import SharedCore
import LeafKit
import os

/// Packet tunnel provider. Claims both default routes, hands the utun fd to
/// leaf, and relays every connection through the in-process `Socks5Server`,
/// where the gatekeeper decides what is allowed.
///
/// Fail-open: a failed start completes with an error so NetworkExtension tears
/// the tunnel down, and a runtime kill gets system teardown plus on-demand
/// restart. Do not add a "tunnel up but routing nothing" mode (empty routes,
/// dummy match domains, feature flags); it hides data-plane bugs.
///
/// Uses completion-handler overrides because Swift 6 will not pass the
/// non-Sendable options dictionary into the async variants. NE calls provider
/// callbacks serially; the boot-retry timer runs on a global queue, so the
/// state it touches is guarded by `stateLock`.
final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private let log = Logger(subsystem: "fluxmoat", category: "tunnel")
    private let tunnelMTU = 1500
    private var startedAt: Date?

    /// Compiled from the App Group snapshot; drives the gatekeeper.
    private var compiledRules: CompiledRuleSet?
    private var snapshotCreatedAt: Date?
    private var mode: RunMode = .standard
    /// Action for unmatched flows in the active profile (.allow if unset).
    private var profileDefault: RuleAction = .allow
    /// DoH upstream from the snapshot (nil means system resolution). The
    /// resolver is kept across reloads while the URL is unchanged so its TTL
    /// cache survives rule edits.
    private var dohServerURL: String?
    private var dohResolver: DoHResolver?
    /// Whether sinkholed answers from this resolver count as threats. Only
    /// the app knows if the URL is a threat-intel preset or a custom one, so
    /// this defaults to false for snapshots without the field.
    private var dohThreatIntel = false
    /// History retention from the snapshot. Pruning happens here because the
    /// extension owns writes to the store.
    private var historyRetention: RetentionPeriod = .default
    /// Quiet hours for Ask notifications, from the snapshot.
    private var askQuietHours: QuietHours?
    /// Wi-Fi to profile assignments, enforced here because the tunnel outlives
    /// the app across network changes. Non-nil `autoProfileKind` means an
    /// assignment currently overrides the snapshot's default.
    private var wifiAutoProfiles: [WiFiProfileAssignment] = []
    private var autoProfileKind: Profile.Kind?
    /// The app-chosen default, so leaving a mapped Wi-Fi can revert to it.
    private var snapshotProfileDefault: RuleAction = .allow
    /// Log dedup only. Every reload re-applies the assignment (loadSnapshot
    /// overwrites profileDefault), but the log line repeats only when kind,
    /// default or SSID hash changed.
    private var lastLoggedAutoSwap: String?

    // Data-plane components (nil until started).
    private var socksServer: Socks5Server?
    private var leaf: LeafRuntime?

    /// Watches path changes. Logs Wi-Fi/cellular handoffs and drives the Wi-Fi
    /// profile automation; it does not touch routing.
    private var pathMonitor: NWPathMonitor?

    // For per-second rate in liveCounters.
    private var lastSampleAt: Date?
    private var lastBytesUp: UInt64 = 0
    private var lastBytesDown: UInt64 = 0

    // Samples phys_footprint while the data plane runs; it must stay under
    // the NetworkExtension limit of about 50 MB.
    private var memoryTimer: DispatchSourceTimer?
    private var peakFootprintMB: Double = 0
    /// Byte totals at the previous memory sample, so each memory log line can
    /// report up and down throughput at that moment. Kept apart from
    /// `lastSampleAt`/`lastBytes*`, which belong to the app's 1 Hz poll;
    /// sharing them would corrupt both rates. Only the timer handler touches these.
    private var lastMemSampleUp: UInt64 = 0
    private var lastMemSampleDown: UInt64 = 0
    private var lastMemSampleAt: Date?

    /// The footprint can climb from under 30 MB to the 50 MB jetsam limit in
    /// under a second, so the timer ticks 4 times a second. Every 12th tick
    /// logs a 3 s heartbeat; other ticks log only on a spike or near the limit.
    /// Idle cost is one `task_info` call per tick.
    private var lastFastFootprintMB: Double = 0
    private var memTickCount: Int = 0
    /// Log every tick above this, 10 MB below the 50 MB limit.
    private static let memHighWaterMB: Double = 40
    /// Growth within one tick that counts as a spike.
    private static let memSpikeDeltaMB: Double = 4
    /// Bytes to MB for the backlog log line; nil reads as 0.
    private static func mb(_ bytes: Int?) -> Double { Double(bytes ?? 0) / 1_048_576 }

    /// Reload counter for logs, so footprint changes can be tied to a
    /// specific reload. Diagnostics only.
    private var reloadGen = 0

    /// Boot-time snapshot retry. Snapshot files use Class C protection, so
    /// reads fail (error 257) between boot and first unlock, and on-demand can
    /// start the tunnel in that window. Without a retry the tunnel would run
    /// with no rules until the next reload. Runs only until the first
    /// successful load; racing a reloadRules is harmless (same idempotent swap).
    private var snapshotRetryTimer: DispatchSourceTimer?

    /// Guards the snapshot-derived state above, because `snapshotRetryTimer`
    /// fires off NE's callback queue. A torn read of `compiledRules`
    /// (refcounted storage) would crash the extension and drop the tunnel.
    private let stateLock = NSLock()

    // MARK: - Snapshot / gatekeeper

    /// The published SOCKS server, read under `stateLock`. Its own methods
    /// marshal onto its serial queue, so callers use it outside the lock.
    private func activeServer() -> Socks5Server? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return socksServer
    }

    /// Caller must hold `stateLock` (NSLock is not recursive).
    private func makeGatekeeperLocked() -> FlowGatekeeper {
        FlowGatekeeper(
            rules: compiledRules ?? CompiledRuleSet(rules: []),
            mode: mode,
            profileDefault: profileDefault
        )
    }

    /// Loads the current snapshot from the App Group and swaps the compiled
    /// set. On failure the previous set stays; with no set at all, everything
    /// is allowed (fail-open).
    private func loadSnapshot(reason: String) {
        guard let store = RuleSnapshotStore.appGroup() else {
            log.error("❌ tunnel:loadSnapshot(\(reason, privacy: .public)) no App Group container (entitlement missing?)")
            return
        }
        do {
            // Footprint after each stage (decode, compile), logged in one line
            // after the swap. Reloads are a known memory spike.
            let memBefore = MemoryFootprint.currentMB() ?? 0
            let (snapshot, source) = try store.load()
            let memDecode = MemoryFootprint.currentMB() ?? 0

            // Mutate shared state inside the lock. Server calls and logging
            // run after unlocking; Socks5Server uses its own queue.
            stateLock.lock()
            compiledRules = snapshot.compile()
            // Old and new compiled sets both exist at this point.
            let memCompile = MemoryFootprint.currentMB() ?? 0
            reloadGen += 1
            let gen = reloadGen
            snapshotCreatedAt = snapshot.createdAt
            // Older snapshots lack these fields; default to standard/allow.
            mode = snapshot.mode ?? .standard
            profileDefault = snapshot.profileDefault ?? .allow
            // The snapshot's default applies now; the Wi-Fi check below
            // re-applies an assignment if the current network still matches.
            snapshotProfileDefault = profileDefault
            autoProfileKind = nil
            wifiAutoProfiles = snapshot.wifiAutoProfiles ?? []
            historyRetention = snapshot.historyRetention ?? .default
            askQuietHours = snapshot.askQuietHours
            let resolverChanged = snapshot.dohServerURL != dohServerURL
            if resolverChanged {
                dohServerURL = snapshot.dohServerURL
                // The app also enforces https; this is the final check.
                if let raw = snapshot.dohServerURL, let url = URL(string: raw),
                   url.scheme?.lowercased() == "https" {
                    dohResolver = DoHResolver(serverURL: url)
                } else {
                    dohResolver = nil
                }
            }
            // Tracked apart from `resolverChanged`: the flag can change without
            // the URL, and rebuilding the resolver would drop its TTL cache.
            let threatIntel = snapshot.resolverThreatIntel ?? false
            let intelBefore = dohThreatIntel
            let threatIntelChanged = threatIntel != intelBefore
            dohThreatIntel = threatIntel
            // Log from the live fields, not the snapshot, so a missed swap
            // shows up in the log.
            let resolver = dohResolver
            let intelAfter = dohThreatIntel
            let gatekeeper = makeGatekeeperLocked()
            let server = socksServer
            let retryWasRunning = snapshotRetryTimer != nil
            snapshotRetryTimer?.cancel()
            snapshotRetryTimer = nil
            let activeMode = mode
            let activeDefault = profileDefault
            // The count actually enforced, including rules added by
            // blockEncryptedDNS.
            let effectiveRules = compiledRules?.ruleCount ?? 0
            stateLock.unlock()

            if resolverChanged || threatIntelChanged {
                server?.updateResolver(resolver, threatIntel: threatIntel)
            }
            server?.updateAskQuietHours(snapshot.askQuietHours)
            // Re-apply Wi-Fi automation against the new snapshot. Before the
            // monitor starts, its own callback handles this.
            if let path = pathMonitor?.currentPath {
                evaluateWiFiProfile(onWiFi: path.usesInterfaceType(.wifi))
            }
            log.notice("✅ tunnel:loadSnapshot(\(reason, privacy: .public)) swap VERIFY: rules \(snapshot.rules.count, privacy: .public)→\(effectiveRules, privacy: .public) blockDNS=\(snapshot.blockEncryptedDNS == true, privacy: .public) blocklist \(snapshot.blocklistDomains.count, privacy: .public) threatDom=\(snapshot.threatDomains?.count ?? 0, privacy: .public) threatIP=\(snapshot.threatIPs?.count ?? 0, privacy: .public) mode \(activeMode.rawValue, privacy: .public) default \(activeDefault.rawValue, privacy: .public) doh=\(resolver?.serverHost ?? "off", privacy: .public) resolverIntel \(intelBefore, privacy: .public)→\(intelAfter, privacy: .public) snap=\(snapshot.resolverThreatIntel.map { $0 ? "true" : "false" } ?? "nil", privacy: .public) source \(source == .current ? "current" : "backup", privacy: .public)")
            log.notice("🧠 tunnel:loadSnapshot(\(reason, privacy: .public)) mem stages VERIFY gen=\(gen, privacy: .public) before=\(memBefore, format: .fixed(precision: 1), privacy: .public)MB decode=\(memDecode, format: .fixed(precision: 1), privacy: .public)MB compile=\(memCompile, format: .fixed(precision: 1), privacy: .public)MB")
            server?.updateGatekeeper(gatekeeper)
            if retryWasRunning {
                log.notice("✅ tunnel:snapshotRetry recovered VERIFY — timer cancelled")
            }
        } catch {
            log.error("❌ tunnel:loadSnapshot(\(reason, privacy: .public)) failed, keeping previous set: \(error, privacy: .public)")
            // Per-file reason: missing, read denied (257 means data protection
            // is still locked) or decode failure. Paths hold no user data.
            log.error("🔎 tunnel:loadSnapshot(\(reason, privacy: .public)) diag VERIFY \(store.diagnose(), privacy: .public)")
            stateLock.lock()
            let needsRetry = compiledRules == nil && snapshotRetryTimer == nil
            var scheduled: DispatchSourceTimer?
            if needsRetry {
                let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
                timer.schedule(deadline: .now() + 10, repeating: 10)
                timer.setEventHandler { [weak self] in
                    self?.loadSnapshot(reason: "bootRetry")
                }
                snapshotRetryTimer = timer
                scheduled = timer
            }
            stateLock.unlock()
            if let scheduled {
                scheduled.resume()
                log.notice("⏳ tunnel:snapshotRetry scheduled VERIFY interval=10s")
            }
        }
    }

    // MARK: - Start / stop

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // .notice so it always shows in Console.app without Include-Info.
        log.notice("🚦 startTunnel requested")
        // Widgets read protection state from the App Group. The tunnel writes
        // it because on-demand starts happen without the app. Failure only
        // leaves widgets stale.
        try? WidgetStateStore.appGroup()?.write(WidgetState(protectionOn: true))

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.mtu = NSNumber(value: tunnelMTU)

        // Captive portals need no special handling. iOS sends the portal probe
        // and the login sheet as interface-scoped connections that bypass the
        // tunnel. Do not add excluded routes or stop the tunnel for portals,
        // and do not drop the NEDNSSettings below: without it DNS skips
        // fake-DNS and domain rules, blocklists and DoH stop working.
        let ipv4 = NEIPv4Settings(addresses: ["192.0.2.2"], subnetMasks: ["255.255.255.255"])
        let ipv6 = NEIPv6Settings(addresses: ["fd00::2"], networkPrefixLengths: [64])
        // Claim both default routes so nothing bypasses the filter. Fake-DNS
        // answers only with IPv4 (198.18.0.0/15; AAAA gets NODATA), so domain
        // traffic uses the v4 route. The v6 route catches IPv6 literal
        // connections. Real egress, v4 or v6, goes out on the relay's own
        // NWConnection outside the tunnel.
        ipv4.includedRoutes = [NEIPv4Route.default()]
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv4Settings = ipv4
        settings.ipv6Settings = ipv6
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"])

        loadSnapshot(reason: "startTunnel")

        // Route counts read from the settings actually applied, for the log.
        // Counts rather than objects, since NE settings are not Sendable.
        let v4routes = ipv4.includedRoutes?.count ?? 0
        let v6routes = ipv6.includedRoutes?.count ?? 0
        nonisolated(unsafe) let complete = completionHandler
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { complete(error); return }
            if let error {
                self.log.error("setTunnelNetworkSettings failed: \(error, privacy: .public)")
                complete(error)
                return
            }
            self.startedAt = Date()
            self.log.notice("✅ tunnel:settings applied VERIFY v4routes=\(v4routes, privacy: .public) v6routes=\(v6routes, privacy: .public)")
            self.startDataPlane(complete)
        }
    }

    /// Brings up the SOCKS5 server, then leaf pointed at it.
    ///
    /// Any failure must complete `startTunnel` with an error so NE tears the
    /// tunnel down and normal routing returns. Never swallow an error here to
    /// keep the tunnel up; that leaves the device routing into a dead tunnel.
    private func startDataPlane(_ completion: @escaping (Error?) -> Void) {
        // NE's completion handler is not Sendable but is only called from
        // serial callbacks, so it can cross into the @Sendable closures.
        nonisolated(unsafe) let complete = completion
        guard let fd = TunnelInterface.currentUTunFD() else {
            complete(DataPlaneError.tunFDNotFound)
            return
        }
        // Flow history in the App Group, pruned on every start. Nil (missing
        // entitlement) only turns history off; the data plane does not need it.
        let store = TrafficEventStore.appGroup()
        if let store {
            // Retention from the snapshot loaded above (.default if absent).
            stateLock.lock()
            let retention = historyRetention
            stateLock.unlock()
            let pruned = (try? store.prune(maxAge: retention.maxAge, maxRows: retention.maxRows)) ?? 0
            log.notice("💾 tunnel:eventStore prune VERIFY retention=\(retention.rawValue, privacy: .public) deleted=\(pruned, privacy: .public)")
        } else {
            log.notice("💾 tunnel:eventStore unavailable (no App Group) — history off")
        }
        // Publish the server and read snapshot state in one critical section;
        // the boot-retry timer may be swapping the resolver concurrently.
        stateLock.lock()
        let server = Socks5Server(gatekeeper: makeGatekeeperLocked(), eventStore: store)
        let resolver = dohResolver
        let threatIntel = dohThreatIntel
        let quietHours = askQuietHours
        self.socksServer = server
        stateLock.unlock()
        // loadSnapshot ran before the server existed, so pass the resolver
        // and quiet hours now.
        server.updateResolver(resolver, threatIntel: threatIntel)
        server.updateAskQuietHours(quietHours)
        server.start { [weak self] result in
            guard let self else { return }
            switch result {
            case .failure(let error):
                self.log.error("❌ tunnel:dataPlane socks server failed: \(error, privacy: .public)")
                complete(error)
            case .success(let port):
                do {
                    let config = try LeafConfig(tunFD: fd, mtu: self.tunnelMTU, socksPort: port).json()
                    let leaf = LeafRuntime(rtID: 1)
                    self.leaf = leaf
                    leaf.start(configJSON: config, completionQueue: .main) { [weak self] outcome in
                        // Leaf returns only on shutdown or a fatal error;
                        // a non-clean exit means the data plane is gone.
                        if case .failed(let code) = outcome {
                            self?.log.error("❌ tunnel:dataPlane leaf exited abnormally code=\(code, privacy: .public)")
                            self?.cancelTunnelWithError(DataPlaneError.leafExited(code))
                        }
                    }
                    self.log.notice("✅ tunnel:dataPlane up (fd=\(fd, privacy: .public) socksPort=\(port, privacy: .public))")
                    self.startMemorySampler()
                    self.startPathMonitor()
                    complete(nil)
                } catch {
                    self.log.error("❌ tunnel:dataPlane leaf config/start failed: \(error, privacy: .public)")
                    complete(error)
                }
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        log.notice("stopTunnel: \(String(describing: reason), privacy: .public)")
        try? WidgetStateStore.appGroup()?.write(WidgetState(protectionOn: false))
        // Cancel the retry and unpublish the server under the lock so an
        // in-flight retry cannot restore state after teardown.
        stateLock.lock()
        snapshotRetryTimer?.cancel()
        snapshotRetryTimer = nil
        let server = socksServer
        socksServer = nil
        stateLock.unlock()
        stopMemorySampler()
        stopPathMonitor()
        leaf?.shutdown()
        leaf = nil
        server?.stop()
        startedAt = nil
        completionHandler()
    }

    // MARK: - Control channel

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        do {
            let request = try ProviderRequest.decoded(from: messageData)
            let response: ProviderResponse
            switch request {
            case .status:
                // Snapshot-derived fields; the boot-retry timer can rewrite
                // them from its own queue.
                stateLock.lock()
                let status = ProviderResponse.Status(
                    mode: mode,
                    activeProfileID: nil,
                    snapshotCreatedAt: snapshotCreatedAt,
                    lastError: nil
                )
                stateLock.unlock()
                response = .status(status)
            case .liveCounters:
                response = .liveCounters(currentCounters())
            case .recentEvents:
                let drained = activeServer()?.drainEvents() ?? []
                log.notice("📡 recentEvents drained VERIFY count=\(drained.count, privacy: .public)")
                response = .recentEvents(drained)
            case .pendingAsks:
                response = .pendingAsks(activeServer()?.pendingAsks() ?? [])
            case .resolveAsk(let id):
                activeServer()?.resolveAsk(id)
                response = .acknowledged
            case .reloadRules:
                loadSnapshot(reason: "reloadRules")
                response = .acknowledged
            case .switchProfile, .healthCheck:
                response = .acknowledged
            }
            completionHandler?(try response.encoded())
        } catch {
            log.error("bad app message: \(error, privacy: .public)")
            completionHandler?(try? ProviderResponse.failed("bad message").encoded())
        }
    }

    /// Per-second rates from the server's running totals since the last
    /// poll. Zeros when the server is not running.
    private func currentCounters() -> ProviderResponse.LiveCounters {
        guard let counters = activeServer()?.snapshotCounters() else {
            return .init(bytesUpPerSecond: 0, bytesDownPerSecond: 0, activeFlows: 0, blockedToday: 0)
        }
        let now = Date()
        let elapsed = lastSampleAt.map { now.timeIntervalSince($0) } ?? 1
        let dt = max(elapsed, 0.001)
        let upRate = UInt64(Double(counters.totalBytesUp &- lastBytesUp) / dt)
        let downRate = UInt64(Double(counters.totalBytesDown &- lastBytesDown) / dt)
        lastSampleAt = now
        lastBytesUp = counters.totalBytesUp
        lastBytesDown = counters.totalBytesDown
        stateLock.lock()
        let autoKind = autoProfileKind?.rawValue
        stateLock.unlock()
        return .init(
            bytesUpPerSecond: upRate,
            bytesDownPerSecond: downRate,
            activeFlows: counters.activeFlows,
            blockedToday: Int(counters.blockedFlows),
            threatBlockedToday: Int(counters.threatBlockedFlows),
            encryptedDNSBypassToday: Int(counters.encryptedDNSBypassFlows),
            autoProfileKind: autoKind
        )
    }

    // MARK: - Memory sampler

    /// Logs `phys_footprint` every 3 s so the footprint against the ~50 MB
    /// jetsam limit is visible on device under load. Ticks at 4 Hz; see
    /// `lastFastFootprintMB` for the fast-tick logging.
    private func startMemorySampler() {
        // Reset so a restart in the same process does not report a false
        // spike against the previous session.
        lastFastFootprintMB = 0
        memTickCount = 0
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 2, repeating: 0.25)
        timer.setEventHandler { [weak self] in
            guard let self, let mb = MemoryFootprint.currentMB() else { return }
            if mb > self.peakFootprintMB { self.peakFootprintMB = mb }

            let previous = self.lastFastFootprintMB
            self.lastFastFootprintMB = mb
            let tick = self.memTickCount
            self.memTickCount &+= 1
            let isHeartbeat = tick % 12 == 0

            // Read counters only when logging: `snapshotCounters()` does a
            // queue.sync onto the SOCKS queue, which is costly under load.
            let spiked = previous > 0 && mb - previous >= Self.memSpikeDeltaMB
            let high = mb >= Self.memHighWaterMB
            if !isHeartbeat && (spiked || high) {
                let server = self.activeServer()
                let fastFlows = server?.snapshotCounters().activeFlows ?? 0
                let backlog = server?.snapshotUploadBacklog()
                let marker = spiked ? "⚠️ mem SPIKE" : "📈 mem HIGH"
                self.log.notice("\(marker, privacy: .public) VERIFY: \(previous, format: .fixed(precision: 1), privacy: .public)→\(mb, format: .fixed(precision: 1), privacy: .public)MB in 0.25s activeFlows=\(fastFlows, privacy: .public) machineBuf=\(Self.mb(backlog?.machineBuf), format: .fixed(precision: 2), privacy: .public)MB inflight=\(Self.mb(backlog?.inflight), format: .fixed(precision: 2), privacy: .public)MB worstFlow=\(Self.mb(backlog?.worst), format: .fixed(precision: 2), privacy: .public)MB bpPause=\(backlog?.pauses ?? 0, privacy: .public) peak=\(self.peakFootprintMB, format: .fixed(precision: 1), privacy: .public)MB")
            }
            guard isHeartbeat else { return }

            let counters = self.activeServer()?.snapshotCounters()
            let flows = counters?.activeFlows ?? 0

            // Throughput per direction from `snapshotLiveBytes()`, which
            // includes bytes on open flows. `totalBytes*` only update when a
            // flow closes, so a long transfer would read as zero. These are
            // plain byte totals, so logging them as `.public` is fine.
            let live = self.activeServer()?.snapshotLiveBytes()
            let totalUp = live?.up ?? 0
            let totalDown = live?.down ?? 0
            let now = Date()
            var upMbps = 0.0
            var downMbps = 0.0
            if let last = self.lastMemSampleAt {
                let seconds = now.timeIntervalSince(last)
                if seconds > 0 {
                    if totalUp >= self.lastMemSampleUp {
                        upMbps = Double(totalUp - self.lastMemSampleUp) * 8 / 1_000_000 / seconds
                    }
                    if totalDown >= self.lastMemSampleDown {
                        downMbps = Double(totalDown - self.lastMemSampleDown) * 8 / 1_000_000 / seconds
                    }
                }
            }
            self.lastMemSampleUp = totalUp
            self.lastMemSampleDown = totalDown
            self.lastMemSampleAt = now

            let backlog = self.activeServer()?.snapshotUploadBacklog()
            self.log.notice("📊 mem VERIFY: footprint=\(mb, format: .fixed(precision: 1), privacy: .public)MB peak=\(self.peakFootprintMB, format: .fixed(precision: 1), privacy: .public)MB activeFlows=\(flows, privacy: .public) up=\(upMbps, format: .fixed(precision: 1), privacy: .public)Mb/s down=\(downMbps, format: .fixed(precision: 1), privacy: .public)Mb/s machineBuf=\(Self.mb(backlog?.machineBuf), format: .fixed(precision: 2), privacy: .public)MB inflight=\(Self.mb(backlog?.inflight), format: .fixed(precision: 2), privacy: .public)MB bpPause=\(backlog?.pauses ?? 0, privacy: .public)")
        }
        memoryTimer = timer
        timer.resume()
    }

    private func stopMemorySampler() {
        memoryTimer?.cancel()
        memoryTimer = nil
        log.notice("📊 mem final peak=\(self.peakFootprintMB, format: .fixed(precision: 1), privacy: .public)MB")
    }

    /// Logs every path change and re-evaluates Wi-Fi profile automation. It
    /// never touches leaf or routes. Logged fields are interface metadata, not
    /// traffic identifiers, so `.public` is fine.
    private func startPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            let ifaces = [(NWInterface.InterfaceType.wifi, "wifi"),
                          (.cellular, "cellular"),
                          (.wiredEthernet, "wired"),
                          (.loopback, "loopback"),
                          (.other, "other")]
                .filter { path.usesInterfaceType($0.0) }
                .map(\.1)
                .joined(separator: "+")
            self.log.notice("🌐 tunnel:path change VERIFY status=\(String(describing: path.status), privacy: .public) iface=\(ifaces.isEmpty ? "none" : ifaces, privacy: .public) expensive=\(path.isExpensive, privacy: .public) constrained=\(path.isConstrained, privacy: .public)")
            self.evaluateWiFiProfile(onWiFi: path.usesInterfaceType(.wifi))
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        pathMonitor = monitor
    }

    /// Re-evaluates Wi-Fi profile automation. NEHotspotNetwork needs the
    /// wifi-info entitlement and an active VPN; no location permission.
    /// Never log the SSID, only its hash prefix.
    private func evaluateWiFiProfile(onWiFi: Bool) {
        stateLock.lock()
        let assignments = wifiAutoProfiles
        let autoActive = autoProfileKind != nil
        stateLock.unlock()
        guard onWiFi else {
            if autoActive { applyAutoProfile(nil, ssidHash: "off-wifi") }
            return
        }
        guard !assignments.isEmpty || autoActive else { return }
        NEHotspotNetwork.fetchCurrent { [weak self] network in
            guard let self else { return }
            let ssid = network?.ssid
            let assignment = ssid.flatMap { WiFiProfileAssignment.match($0, in: assignments) }
            self.applyAutoProfile(assignment, ssidHash: Self.ssidHashPrefix(ssid))
        }
    }

    /// Applies or clears (nil) the automation override: swaps the gatekeeper's
    /// default action and records the kind for the app via liveCounters.
    private func applyAutoProfile(_ assignment: WiFiProfileAssignment?, ssidHash: String) {
        stateLock.lock()
        let newDefault = assignment?.unmatchedAction ?? snapshotProfileDefault
        let newKind = assignment?.profileKind
        guard newKind != autoProfileKind || newDefault != profileDefault else {
            stateLock.unlock()
            return
        }
        autoProfileKind = newKind
        profileDefault = newDefault
        let gatekeeper = makeGatekeeperLocked()
        let server = socksServer
        let swapKey = "\(newKind?.rawValue ?? "none")|\(newDefault.rawValue)|\(ssidHash)"
        let shouldLog = swapKey != lastLoggedAutoSwap
        lastLoggedAutoSwap = swapKey
        stateLock.unlock()
        server?.updateGatekeeper(gatekeeper)
        if shouldLog {
            log.notice("📶 tunnel:wifiProfile swap VERIFY kind=\(newKind?.rawValue ?? "none", privacy: .public) default=\(newDefault.rawValue, privacy: .public) ssidHash=\(ssidHash, privacy: .public)")
        }
    }

    /// First 8 hex chars of the SSID's SHA-256, to correlate networks in logs
    /// without writing the SSID.
    private static func ssidHashPrefix(_ ssid: String?) -> String {
        guard let ssid else { return "none" }
        let digest = SHA256.hash(data: Data(ssid.utf8))
        return digest.map { String(format: "%02x", $0) }.joined().prefix(8).description
    }

    private func stopPathMonitor() {
        pathMonitor?.cancel()
        pathMonitor = nil
    }

    enum DataPlaneError: Error {
        case tunFDNotFound
        case leafExited(Int32)
    }
}
