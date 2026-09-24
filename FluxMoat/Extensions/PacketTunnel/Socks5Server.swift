import Foundation
import Network
import SharedCore
import UserNotifications
import os

/// In-process SOCKS5 server. Leaf's `socks` outbound connects here on
/// loopback; `FlowGatekeeper` judges each connection and allowed ones are
/// relayed over a direct `NWConnection`. NE keeps provider-initiated
/// connections out of the tunnel, so there is no loop.
///
/// Protocol, decision and accounting logic lives in `SOCKS5ServerConnection`
/// in SharedCore; this class binds it to Network.framework.
///
/// All mutable state is confined to one serial `queue`, which is why
/// `@unchecked Sendable` is safe.
///
/// Privacy: logs use an opaque session id, verdicts, ports and byte counts.
/// Destination hosts and addresses are only ever logged as `.private`.
final class Socks5Server: @unchecked Sendable {
    /// Aggregated counters the provider reads for `liveCounters` and batches
    /// into the shared store. No per-destination data is retained here.
    struct Counters: Sendable {
        var totalBytesUp: UInt64 = 0
        var totalBytesDown: UInt64 = 0
        var activeFlows: Int = 0
        var allowedFlows: UInt64 = 0
        var blockedFlows: UInt64 = 0
        /// Subset of `blockedFlows` sinkholed by a threat-intel DoH resolver.
        var threatBlockedFlows: UInt64 = 0
        /// Allowed flows to a known encrypted-DNS endpoint while
        /// `blockEncryptedDNS` was off. The app uses this to warn that
        /// filtering is being bypassed.
        var encryptedDNSBypassFlows: UInt64 = 0
        /// Times a client read was paused by the upload high-water mark.
        /// Diagnostics only.
        var uploadPauses: UInt64 = 0
    }

    /// Loopback port the server binds and leaf dials. A fixed port is fine
    /// since only leaf connects here. Must equal `LeafConfig.socksPort`.
    static let loopbackPort: UInt16 = 10808

    // MARK: - Upload backpressure

    /// Stop reading from the client once this much upload is queued on a
    /// session; resume only from a send completion once it drains to
    /// `uploadLowWater`.
    ///
    /// Loopback delivers far faster than the uplink drains, so without this
    /// NWConnection's send queue grows without limit. A single upload flow
    /// can queue several MB in under 100 ms and push the extension past its
    /// 50 MB jetsam limit. Pausing the read propagates TCP flow control back
    /// to the app. Capping only the send queue just moves the backlog into
    /// the handshake buffer; strict one-send-per-read lockstep caps
    /// throughput at one buffer per round trip.
    private static let uploadHighWater = 256 * 1024
    private static let uploadLowWater = 64 * 1024

    private let queue = DispatchQueue(label: "fluxmoat.socks5")
    private let log = Logger(subsystem: "fluxmoat", category: "socks5")

    /// Swapped atomically (on `queue`) when the rule snapshot reloads.
    private var gatekeeper: FlowGatekeeper
    /// DoH upstream for domain CONNECTs (nil means system resolution via
    /// NWConnection). Swapped on `queue` when the snapshot reloads.
    private var resolver: DoHResolver?
    /// Whether sinkholed answers from `resolver` count as threats. Set by the
    /// app, which knows if the URL is a threat-intel preset; defaults to false.
    private var resolverThreatIntel = false
    private var listener: NWListener?
    private var counters = Counters()
    private var nextSessionID: UInt64 = 0
    private var sessions: [UInt64: Session] = [:]
    /// Recently closed CONNECT flows, drained by the app for Live Traffic.
    /// Bounded (drops oldest). Connection metadata only, never payload.
    private var events = TrafficEventBuffer()

    /// Ask mode: unanswered per-destination questions (coalesced, bounded,
    /// expiring). The app polls `pendingAsks()` and clears entries with
    /// `resolveAsk`. New questions also post a local notification, but the
    /// app's poll is the path that is always available.
    private var askCenter = AskCenter()

    /// Persistent history (App Group SQLite). Events batch here and flush
    /// every `persistFlushInterval` or `persistBatchLimit` events, so history
    /// stays complete even when the app never polls. Never logged.
    private let eventStore: TrafficEventStore?
    private var pendingPersist: [TrafficEvent] = []
    private var persistTimer: DispatchSourceTimer?
    private static let persistBatchLimit = 32
    private static let persistFlushInterval: TimeInterval = 5

    init(gatekeeper: FlowGatekeeper, eventStore: TrafficEventStore? = nil) {
        self.gatekeeper = gatekeeper
        self.eventStore = eventStore
    }

    // MARK: - Lifecycle

    /// Binds the listener on 127.0.0.1:`loopbackPort`. `onReady` reports the
    /// port for leaf's `socks` outbound, or an error.
    ///
    /// The address is pinned with `requiredLocalEndpoint`.
    /// `requiredInterfaceType = .loopback` does not pin it: on device the
    /// listener bound `::` on cellular and leaf could not reach it.
    func start(onReady: @escaping @Sendable (Result<UInt16, Error>) -> Void) {
        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true // survive restart TIME_WAIT
            let endpoint = NWEndpoint.hostPort(
                host: "127.0.0.1",
                port: NWEndpoint.Port(rawValue: Self.loopbackPort)!
            )
            params.requiredLocalEndpoint = endpoint
            let listener = try NWListener(using: params)
            self.listener = listener

            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    let port = listener.port?.rawValue ?? Self.loopbackPort
                    self.log.notice("✅ socks5:listen ready host=127.0.0.1 port=\(port, privacy: .public)")
                    onReady(.success(Self.loopbackPort))
                case .failed(let error):
                    self.log.error("❌ socks5:listen failed: \(error, privacy: .public)")
                    onReady(.failure(error))
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] conn in
                self?.accept(conn)
            }
            listener.start(queue: queue)
            startPersistTimer()
        } catch {
            log.error("❌ socks5:listen setup failed: \(error, privacy: .public)")
            onReady(.failure(error))
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.listener?.cancel()
            self.listener = nil
            for (_, session) in self.sessions { session.closeAll() }
            self.sessions.removeAll()
            self.persistTimer?.cancel()
            self.persistTimer = nil
            self.flushPersist() // don't lose the tail batch on teardown
            self.log.info("socks5:stop — all sessions closed")
        }
    }

    /// Hot-swaps the gatekeeper after a snapshot reload. Existing sessions
    /// keep the verdict they already got; new connections use the new rules.
    func updateGatekeeper(_ new: FlowGatekeeper) {
        queue.async { [weak self] in
            guard let self else { return }
            self.gatekeeper = new
            // Live UDP relays judge every datagram, so push the new rules to
            // them too. This also frees the old rule set.
            for session in self.sessions.values {
                session.udpRelay?.updateGatekeeper(new)
            }
            // `preVerdictHolders` counts sessions still waiting on decide(),
            // the only place an old rule set can stay alive (for the length of
            // a handshake). Expect about 0.
            var holders = 0
            for session in self.sessions.values where session.machine.holdsRuleSet {
                holders += 1
            }
            let mb = MemoryFootprint.currentMB() ?? 0
            self.log.notice("✅ socks5:gatekeeper swapped VERIFY footprint=\(mb, format: .fixed(precision: 1), privacy: .public)MB preVerdictHolders=\(holders, privacy: .public) liveSessions=\(self.sessions.count, privacy: .public)")
        }
    }

    /// Swaps the DoH resolver (nil means system resolution). In-flight
    /// sessions keep the resolver they started with.
    func updateResolver(_ new: DoHResolver?, threatIntel: Bool) {
        queue.async { [weak self] in
            guard let self else { return }
            self.resolver = new
            self.resolverThreatIntel = threatIntel
            // .notice because .info is not captured by `log collect`. The
            // server host is app config, not user traffic, so it can be
            // public. Values are read back after assignment.
            self.log.notice("✅ socks5:resolver swapped VERIFY doh=\(self.resolver?.serverHost ?? "off", privacy: .public) resolverIntel=\(self.resolverThreatIntel, privacy: .public)")
        }
    }

    /// Snapshot of counters for `liveCounters` (marshalled onto `queue`).
    func snapshotCounters() -> Counters {
        queue.sync { counters }
    }

    /// Byte totals including open sessions. `counters.totalBytes*` only
    /// advance in `finish(_:)`, so a long transfer would not show until it
    /// ends. Active flows number in the tens, so the walk is cheap.
    func snapshotLiveBytes() -> (up: UInt64, down: UInt64) {
        queue.sync {
            var up = counters.totalBytesUp
            var down = counters.totalBytesDown
            for session in sessions.values {
                up &+= session.machine.bytesUp &+ (session.udpRelay?.bytesUp ?? 0)
                down &+= session.machine.bytesDown &+ (session.udpRelay?.bytesDown ?? 0)
            }
            return (up, down)
        }
    }

    /// Upload backlog split by where it sits: the state machine's buffer
    /// (client data held during the outbound handshake) and NWConnection's
    /// send queue. Uploads, not downloads, are what drive the footprint toward
    /// the jetsam limit. `worst` is the largest single-session backlog.
    func snapshotUploadBacklog() -> (machineBuf: Int, inflight: Int, worst: Int, pauses: UInt64) {
        queue.sync {
            var machineBuf = 0
            var inflight = 0
            var worst = 0
            for session in sessions.values {
                let buffered = session.machine.bufferedBytes
                machineBuf += buffered
                inflight += session.inflightUp
                worst = max(worst, session.uploadBacklog)
            }
            return (machineBuf, inflight, worst, counters.uploadPauses)
        }
    }

    /// Returns and clears recently closed flows for Live Traffic. Each event
    /// is delivered once.
    func drainEvents() -> [TrafficEvent] {
        queue.sync { events.drain() }
    }

    // MARK: - Session

    /// One leaf-to-destination relay. Only touched on the server `queue`,
    /// which is why `@unchecked Sendable` is safe.
    private final class Session: @unchecked Sendable {
        let id: UInt64
        let client: NWConnection
        let machine: SOCKS5ServerConnection
        var outbound: NWConnection?
        /// Set when the client issued UDP ASSOCIATE instead of CONNECT; owns
        /// the loopback UDP relay for this control connection's lifetime.
        var udpRelay: UDPRelay?
        var countedActive = false
        var closed = false
        /// Bytes passed to `outbound.send` whose `.contentProcessed` has not
        /// fired yet, i.e. still in NWConnection's send queue.
        var inflightUp = 0
        /// Client read is parked waiting for the upload backlog to drain.
        var clientReadPaused = false
        /// Everything queued on the upload path: bytes held by the state
        /// machine until the handshake finishes plus bytes not yet sent.
        /// Backpressure uses the sum; capping either alone moves the backlog.
        var uploadBacklog: Int { machine.bufferedBytes + inflightUp }
        /// Ask-mode question already recorded for this session (record once).
        var askRecorded = false
        /// The DoH resolver sinkholed this session's name. The gatekeeper's
        /// verdict stays allow; this makes teardown record a block.
        var resolverBlocked = false
        /// Whether that sinkhole counts as a threat. Latched from the lookup
        /// at block time so a reload mid-flow cannot relabel the flow.
        var resolverBlockedIsThreat = false
        /// The address this flow actually dialed, as canonical text, so the
        /// app can run GeoIP on domain flows. Set from the DoH answer, or read
        /// from the connection when the system resolved the name. Nil if
        /// nothing was dialed; never fill it with a guess.
        var resolvedRemoteIP: String?

        init(id: UInt64, client: NWConnection, gatekeeper: FlowGatekeeper) {
            self.id = id
            self.client = client
            self.machine = SOCKS5ServerConnection(gatekeeper: gatekeeper)
        }

        func closeAll() {
            guard !closed else { return }
            closed = true
            client.cancel()
            outbound?.cancel()
            udpRelay?.stop()
        }
    }

    private func accept(_ conn: NWConnection) {
        let id = nextSessionID
        nextSessionID &+= 1
        let session = Session(id: id, client: conn, gatekeeper: gatekeeper)
        sessions[id] = session
        log.debug("socks5:accept sid=\(id, privacy: .public)")

        conn.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                self?.receiveClient(session)
            case .failed, .cancelled:
                self?.finish(session)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    // MARK: - Client → machine

    private func receiveClient(_ session: Session) {
        session.client.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.apply(session.machine.handle(.clientBytes(data)), for: session)
                if session.machine.askedUser, !session.askRecorded {
                    session.askRecorded = true
                    self.recordAsk(for: session)
                }
            }
            if isComplete || error != nil {
                self.finish(session)
                return
            }
            guard !session.closed else { return }
            // Do not re-arm the read while upload is backed up, or one flow
            // can queue megabytes and hit the jetsam limit. A send completion
            // or the post-handshake flush resumes it via
            // `resumeClientReadIfDrained`. Only pause when one of those is
            // pending; pausing before CONNECT would strand the session.
            let wakeupPending = session.outbound != nil || session.inflightUp > 0
            if wakeupPending, session.uploadBacklog >= Self.uploadHighWater {
                session.clientReadPaused = true
                self.counters.uploadPauses &+= 1
                return
            }
            self.receiveClient(session)
        }
    }

    /// Restarts a client read parked by the high-water mark.
    private func resumeClientReadIfDrained(_ session: Session) {
        guard session.clientReadPaused, !session.closed else { return }
        guard session.uploadBacklog <= Self.uploadLowWater else { return }
        session.clientReadPaused = false
        receiveClient(session)
    }

    // MARK: - Outbound → machine

    private func receiveOutbound(_ session: Session) {
        session.outbound?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                self.apply(session.machine.handle(.outboundBytes(data)), for: session)
            }
            if isComplete || error != nil {
                self.apply(session.machine.handle(.outboundClosed), for: session)
                return
            }
            guard !session.closed else { return }
            self.receiveOutbound(session)
        }
    }

    // MARK: - Action interpreter

    private func apply(_ actions: [SOCKS5ServerConnection.Action], for session: Session) {
        for action in actions {
            switch action {
            case .sendToClient(let data):
                session.client.send(content: data, completion: .contentProcessed { _ in })

            case .openOutbound(let host, let port):
                openOutbound(host: host, port: port, for: session)

            case .forwardToOutbound(let data):
                // Every counted send must get a completion, or `inflightUp`
                // sticks high and the read stays paused. Hence `if let`
                // rather than `outbound?.send`. Capture the count, not the
                // Data: NWConnection already holds the bytes, and a second
                // strong reference adds to the footprint.
                if let outbound = session.outbound {
                    let count = data.count
                    session.inflightUp += count
                    outbound.send(content: data, completion: .contentProcessed { [weak self, weak session] _ in
                        guard let self, let session else { return }
                        session.inflightUp -= count
                        self.resumeClientReadIfDrained(session)
                    })
                }

            case .beginUDPAssociate:
                beginUDPAssociate(for: session)

            case .closeAll:
                finish(session)
            }
        }
    }

    /// Sets up UDP ASSOCIATE: binds a loopback UDP socket and replies with
    /// its endpoint so leaf knows where to send datagrams. Filtering and relay
    /// live in `UDPRelay`. A bind failure fails the association.
    private func beginUDPAssociate(for session: Session) {
        counters.activeFlows += 1
        session.countedActive = true
        let relay = UDPRelay(id: session.id, gatekeeper: gatekeeper, queue: queue, log: log)
        session.udpRelay = relay
        log.notice("udp:associate begin VERIFY sid=\(session.id, privacy: .public)")
        relay.start { [weak self] port in
            guard let self, !session.closed else { return }
            guard let port else {
                self.finish(session)
                return
            }
            let bound = (ip: IPAddress.parse("127.0.0.1")!, port: port)
            session.client.send(content: SOCKS5Reply.encode(.succeeded, bound: bound),
                                completion: .contentProcessed { _ in })
        }
    }

    private func openOutbound(host: String, port: UInt16, for session: Session) {
        // Only allowed flows reach this point.
        counters.allowedFlows &+= 1
        counters.activeFlows += 1
        session.countedActive = true

        // Command, port and address family are safe as .public. The host is
        // a traffic identifier and must stay .private.
        let cmd = session.machine.request?.command
        let family: String
        switch session.machine.request?.destination {
        case .ipv4: family = "v4"
        case .ipv6: family = "v6"
        case .domain: family = "domain"
        case .none: family = "?"
        }
        log.notice("socks5:outbound open VERIFY sid=\(session.id, privacy: .public) cmd=\(String(describing: cmd), privacy: .public) family=\(family, privacy: .public) port=\(port, privacy: .public) host=\(host, privacy: .private)")

        // An allowed flow to a known encrypted-DNS endpoint (DoT on 853, or a
        // public resolver IP on 443) means filtering is being bypassed. Only
        // possible with `blockEncryptedDNS` off. Counted, not blocked. Do not
        // log the resolver operator.
        if let encDNS = EncryptedDNSBlocklist.classify(host: host, port: port) {
            counters.encryptedDNSBypassFlows &+= 1
            log.notice("🛰️ socks5:encdns-bypass VERIFY sid=\(session.id, privacy: .public) kind=\(encDNS.rawValue, privacy: .public) family=\(family, privacy: .public) port=\(port, privacy: .public) host=\(host, privacy: .private)")
        }

        // Domain destinations resolve through DoH when configured. Domains
        // only arrive here via leaf's fake-DNS; an IP literal means the client
        // resolved elsewhere (DoT, DoH, its own resolver), so there is no name
        // to check. Blocking port 853 alone does not help: clients fall back to
        // DoH on 443, so the port and resolver-IP lists must be used together.
        if family == "domain", let resolver {
            let sid = session.id
            // Capture the threat flag with the resolver. Reading it later
            // could pair an answer with a different resolver's flag after a
            // reload.
            let threatIntel = resolverThreatIntel
            Task { [weak self] in
                guard let self else { return }
                let outcome: Result<(resolution: DoHResolver.Resolution, fromCache: Bool), Error>
                do {
                    outcome = .success(try await resolver.resolve(host))
                } catch {
                    outcome = .failure(error)
                }
                self.queue.async {
                    self.finishResolve(outcome, host: host, port: port, sid: sid, threatIntel: threatIntel)
                }
            }
            return
        }
        connectOutbound(to: host, port: port, for: session)
    }

    /// Handles the DoH outcome on `queue`. The session may have closed
    /// meanwhile. `threatIntel` comes from the lookup because the resolver may
    /// have been swapped.
    private func finishResolve(
        _ outcome: Result<(resolution: DoHResolver.Resolution, fromCache: Bool), Error>,
        host: String, port: UInt16, sid: UInt64, threatIntel: Bool
    ) {
        guard let session = sessions[sid], !session.closed else { return }
        switch outcome {
        case .success((.addresses(let addresses), let fromCache)):
            log.notice("✅ doh:resolve VERIFY sid=\(sid, privacy: .public) src=\(fromCache ? "cache" : "net", privacy: .public) n=\(addresses.count, privacy: .public)")
            // Remember the answer so later IP-only flows to these addresses
            // can be labeled (display only, see `associations`).
            associations.record(domain: host, addresses: addresses, now: Date())
            connectOutbound(to: addresses[0], port: port, for: session)
        case .success((.blockedByResolver, _)):
            // Set before .outboundFailed so teardown records a block, not a
            // failed allow. Only threat-intel presets count as threats; a
            // custom resolver is usually an ad blocker.
            session.resolverBlocked = true
            session.resolverBlockedIsThreat = threatIntel
            // Log the flag, not the resolver name or URL.
            log.notice("🛡️ doh:blocked VERIFY sid=\(sid, privacy: .public) resolverIntel=\(threatIntel, privacy: .public)")
            apply(session.machine.handle(.outboundFailed), for: session)
        case .success((.noSuchDomain, _)):
            log.notice("doh:nxdomain sid=\(sid, privacy: .public)")
            apply(session.machine.handle(.outboundFailed), for: session)
        case .failure(let error):
            // Fail open: a DoH outage must not break browsing, at the cost of
            // system DNS for this lookup. The error stays .private because
            // URLError text can include the DoH URL.
            log.error("⚠️ doh:fallback VERIFY sid=\(sid, privacy: .public) err=\(String(describing: error), privacy: .private)")
            connectOutbound(to: host, port: port, for: session)
        }
    }

    private func connectOutbound(to host: String, port: UInt16, for session: Session) {
        // Record the dialed address for GeoIP. After DoH `host` is already an
        // address; otherwise it is a name and `.ready` below reads the address
        // back. Only values that parse as an IP are stored.
        session.resolvedRemoteIP = IPAddress.parse(host)?.description
        // hostIsAddress: true if DoH gave an address, false if dialing a name.
        log.notice("✅ socks5:dial VERIFY sid=\(session.id, privacy: .public) hostIsAddress=\(session.resolvedRemoteIP != nil, privacy: .public)")
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any
        )
        let outbound = NWConnection(to: endpoint, using: .tcp)
        session.outbound = outbound
        outbound.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                // For a name, the address is only on the connection's path.
                // Read via `session.outbound` instead of capturing the
                // connection, which would create a retain cycle through its
                // own handler.
                if session.resolvedRemoteIP == nil,
                   let peer = session.outbound?.currentPath?.remoteEndpoint,
                   case .hostPort(let peerHost, _) = peer {
                    session.resolvedRemoteIP = IPAddress.parse("\(peerHost)")?.description
                }
                self.log.notice("✅ socks5:outbound ready VERIFY sid=\(session.id, privacy: .public) port=\(port, privacy: .public) ipCaptured=\(session.resolvedRemoteIP != nil, privacy: .public)")
                self.apply(session.machine.handle(.outboundConnected), for: session)
                self.receiveOutbound(session)
            case .failed(let error):
                self.log.error("❌ socks5:outbound failed VERIFY sid=\(session.id, privacy: .public) port=\(port, privacy: .public) err=\(String(describing: error), privacy: .public)")
                self.apply(session.machine.handle(.outboundFailed), for: session)
            case .cancelled:
                self.apply(session.machine.handle(.outboundFailed), for: session)
            default:
                break
            }
        }
        outbound.start(queue: queue)
    }

    // MARK: - Teardown + accounting

    private func finish(_ session: Session) {
        guard sessions[session.id] != nil else { return }
        sessions[session.id] = nil

        // UDP associations carry their bytes on the relay, not the TCP machine.
        let udpUp = session.udpRelay?.bytesUp ?? 0
        let udpDown = session.udpRelay?.bytesDown ?? 0
        counters.totalBytesUp &+= session.machine.bytesUp &+ udpUp
        counters.totalBytesDown &+= session.machine.bytesDown &+ udpDown
        if session.countedActive { counters.activeFlows -= 1 }
        if session.machine.verdict?.action == .deny || session.resolverBlocked {
            counters.blockedFlows &+= 1
        }
        // Threats: a sinkhole from a threat-intel resolver, or a deny from a
        // local threat feed. Blocklist denies and custom resolver sinks are
        // not counted.
        if (session.resolverBlocked && session.resolverBlockedIsThreat)
            || session.machine.verdict?.source == .threatFeed {
            counters.threatBlockedFlows &+= 1
        }

        // Deny is split by source. The source is an enum name, not traffic
        // content, so .public is fine.
        let verdict: String
        if session.resolverBlocked {
            // Separate threat-intel sinks from custom resolver sinks.
            verdict = session.resolverBlockedIsThreat ? "deny-resolver" : "deny-resolver-custom"
        } else if session.machine.verdict?.action == .deny {
            switch session.machine.verdict?.source {
            case .threatFeed: verdict = "deny-threat"
            case .blocklist: verdict = "deny-blocklist"
            case .userRule: verdict = "deny-rule"
            default: verdict = "deny"
            }
        } else if session.machine.verdict?.action == .allow {
            verdict = "allow"
        } else {
            verdict = "none"
        }
        log.notice("socks5:close sid=\(session.id, privacy: .public) verdict=\(verdict, privacy: .public) up=\(session.machine.bytesUp &+ udpUp, privacy: .public) down=\(session.machine.bytesDown &+ udpDown, privacy: .public)")

        recordEvent(for: session)
        session.closeAll()
    }

    /// Buffers Live Traffic events for a closed flow. UDP ASSOCIATE emits one
    /// per relayed destination (its own request is 0.0.0.0:0); TCP CONNECT
    /// emits one.
    private func recordEvent(for session: Session) {
        if let relay = session.udpRelay {
            for event in relay.drainDestinationEvents() { emit(event) }
            return
        }
        guard let request = session.machine.request, request.command == .connect else { return }
        let ip: String
        let domain: String?
        switch request.destination {
        // Keep both the requested name and the dialed address; GeoIP needs
        // the address. Empty if the flow was never dialed (sinkholed or denied).
        case .domain(let name): ip = session.resolvedRemoteIP ?? ""; domain = name
        case .ipv4(let addr), .ipv6(let addr): ip = addr.description; domain = nil
        }
        // A resolver sinkhole records as a deny, overriding the gatekeeper's
        // allow. History counts `filteringResolver` and `threatFeed` as
        // threats; `customResolver` is a plain block.
        let verdict: RuleAction = session.resolverBlocked
            ? .deny : (session.machine.verdict?.action ?? .allow)
        let source: TrafficEvent.VerdictSource?
        if session.resolverBlocked {
            source = session.resolverBlockedIsThreat ? .filteringResolver : .customResolver
        } else {
            source = session.machine.verdict.map { .init($0.source) }
        }
        // Booleans only. Never log the address.
        log.notice("✅ socks5:event VERIFY sid=\(session.id, privacy: .public) named=\(domain != nil, privacy: .public) ipRecorded=\(!ip.isEmpty, privacy: .public)")
        emit(TrafficEvent(
            remoteIP: ip,
            domain: domain,
            remotePort: request.port,
            protocolNumber: 6,
            bytesUp: session.machine.bytesUp,
            bytesDown: session.machine.bytesDown,
            verdict: verdict,
            verdictSource: source,
            matchedRuleID: session.machine.verdict?.matchedRuleID
        ))
    }

    // MARK: - Ask mode

    /// Snapshot of unanswered questions (marshalled onto `queue`).
    func pendingAsks() -> [PendingAsk] {
        queue.sync {
            askCenter.expire()
            return askCenter.pending
        }
    }

    /// Clears an answered question (the app already wrote the rule).
    func resolveAsk(_ id: UUID) {
        queue.async { [weak self] in
            guard let self else { return }
            let resolved = self.askCenter.resolve(id: id) != nil
            self.log.notice("ask:resolve VERIFY known=\(resolved, privacy: .public) pending=\(self.askCenter.pending.count, privacy: .public)")
        }
    }

    /// Throttle for Ask banners: one aggregate notification, 60 s global
    /// cooldown, 30 min per-eTLD+1 cooldown, optional quiet hours. Suppressed
    /// banners never lose a question; the app's pendingAsks poll still has it.
    private var askThrottle = AskNotificationThrottle()
    /// Rate limit for silent (.passive) refreshes while alerts are in cooldown.
    private var lastPassiveUpdateAt = Date.distantPast
    /// Short-term domain/IP pairs from our own DoH answers, used to fill
    /// `TrafficEvent.inferredDomain` for IP-only flows. Display only; never
    /// use it for verdicts.
    private var associations = DomainIPAssociations()

    /// Swapped when the snapshot reloads (same pattern as `updateResolver`).
    func updateAskQuietHours(_ quietHours: QuietHours?) {
        queue.async { [weak self] in
            guard let self else { return }
            self.askThrottle.quietHours = quietHours
            self.log.notice("✅ socks5:askQuietHours swapped VERIFY set=\(quietHours != nil, privacy: .public)")
        }
    }

    /// Records an Ask-mode question for a flow the profile default just
    /// handled; a new destination also posts a notification. The destination
    /// may appear in the notification but never in os_log.
    private func recordAsk(for session: Session) {
        guard let request = session.machine.request else { return }
        let domain: String?
        let ip: String
        switch request.destination {
        case .domain(let name): domain = name; ip = ""
        case .ipv4(let addr), .ipv6(let addr): domain = nil; ip = addr.description
        }
        let applied = session.machine.verdict?.action ?? .allow
        guard let newAsk = askCenter.record(
            domain: domain, remoteIP: ip, port: request.port, appliedAction: applied
        ) else { return }
        log.notice("❓ ask:new VERIFY pending=\(self.askCenter.pending.count, privacy: .public) applied=\(applied.rawValue, privacy: .public)")
        postAskNotification(for: newAsk)
    }

    /// Posts the Ask notification, subject to `askThrottle`. A fixed
    /// identifier means each post replaces the previous banner, so a burst
    /// shows as one banner with a count. Log suppression reasons, never targets.
    private func postAskNotification(for ask: PendingAsk) {
        let now = Date()
        let minuteOfDay = Calendar.current.component(.hour, from: now) * 60
            + Calendar.current.component(.minute, from: now)
        let verdict = askThrottle.decide(
            group: AskNotificationThrottle.notificationGroup(for: ask.targetKey),
            now: now, minuteOfDay: minuteOfDay
        )
        switch verdict {
        case .post:
            // Also reset the passive clock. A passive replacement right after
            // an alert cancels the banner before it is shown.
            lastPassiveUpdateAt = now
            submitAskNotification(for: ask, alerting: true)
        case .globalCooldown, .groupCooldown:
            // Cooldown limits alerts, not the count. A rate-limited .passive
            // replacement keeps the pending count current in Notification
            // Center without a banner or sound.
            log.notice("🔕 ask:notify suppressed VERIFY reason=\(verdict.rawValue, privacy: .public) pending=\(self.askCenter.pending.count, privacy: .public)")
            if now.timeIntervalSince(lastPassiveUpdateAt) >= 5 {
                lastPassiveUpdateAt = now
                submitAskNotification(for: ask, alerting: false)
            }
        case .quietHours:
            // No updates at all during quiet hours.
            log.notice("🔕 ask:notify suppressed VERIFY reason=\(verdict.rawValue, privacy: .public) pending=\(self.askCenter.pending.count, privacy: .public)")
        }
    }

    /// Submits the aggregate notification, replacing the previous one.
    /// `alerting: false` uses `.passive`: updated content, no banner or sound.
    private func submitAskNotification(for ask: PendingAsk, alerting: Bool) {
        // add() succeeding does not mean a banner shows; that depends on
        // these system settings, so log them. Raw values (auth: 2 authorized,
        // 3 provisional, 1 denied; alert: 2 enabled, 1 disabled).
        UNUserNotificationCenter.current().getNotificationSettings { [log] settings in
            log.notice("🔎 ask:notify settings VERIFY auth=\(settings.authorizationStatus.rawValue, privacy: .public) alert=\(settings.alertSetting.rawValue, privacy: .public) nc=\(settings.notificationCenterSetting.rawValue, privacy: .public) lock=\(settings.lockScreenSetting.rawValue, privacy: .public)")
        }
        let pending = askCenter.pending.count
        let content = UNMutableNotificationContent()
        content.title = pending > 1 ? "Pending decisions (\(pending))" : "New connection"
        let latest = ask.appliedAction == .allow
            ? "\(ask.targetKey) was allowed by default — decide whether to keep allowing it."
            : "\(ask.targetKey) was blocked by default — decide whether to allow it."
        content.body = pending > 1 ? "Latest: \(latest)" : latest
        content.interruptionLevel = alerting ? .active : .passive
        let request = UNNotificationRequest(
            identifier: "fluxmoat-asks", content: content, trigger: nil
        )
        let kind = alerting ? "posted" : "refreshed"
        UNUserNotificationCenter.current().add(request) { [log] error in
            if let error {
                log.error("❌ ask:notify VERIFY failed: \(error, privacy: .public)")
            } else {
                log.notice("✅ ask:notify VERIFY \(kind, privacy: .public) pending=\(pending, privacy: .public)")
            }
        }
    }

    /// Routes one closed-flow event to both consumers: the live drain buffer
    /// (app polling) and the persistent history batch.
    private func emit(_ event: TrafficEvent) {
        var event = event
        // Both TCP and UDP events pass here, so IP-only flows get a
        // display-only name from recent DoH answers. Never log the name.
        if event.domain == nil, !event.remoteIP.isEmpty,
           let inferred = associations.lookup(ip: event.remoteIP, now: Date()) {
            event.inferredDomain = inferred
            log.notice("🔗 socks5:assoc hit VERIFY proto=\(event.protocolNumber, privacy: .public) table=\(self.associations.count, privacy: .public)")
        }
        events.append(event)
        guard eventStore != nil else { return }
        pendingPersist.append(event)
        if pendingPersist.count >= Self.persistBatchLimit {
            flushPersist()
        }
    }

    /// Writes the pending batch to the shared store. Log counts only, never
    /// event contents.
    private func flushPersist() {
        guard let eventStore, !pendingPersist.isEmpty else { return }
        let batch = pendingPersist
        pendingPersist.removeAll(keepingCapacity: true)
        do {
            try eventStore.append(batch)
            log.notice("💾 events persisted VERIFY batch=\(batch.count, privacy: .public)")
        } catch {
            log.error("❌ events persist failed (batch \(batch.count, privacy: .public) dropped): \(error, privacy: .public)")
        }
    }

    private func startPersistTimer() {
        guard eventStore != nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.persistFlushInterval, repeating: Self.persistFlushInterval)
        timer.setEventHandler { [weak self] in self?.flushPersist() }
        persistTimer = timer
        timer.resume()
    }
}
