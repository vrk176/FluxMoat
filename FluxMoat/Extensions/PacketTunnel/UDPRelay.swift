import Foundation
import Network
import SharedCore
import os

/// One SOCKS5 UDP ASSOCIATE relay, living as long as its TCP control
/// connection. Leaf sends datagrams to a loopback UDP listener; each one is
/// unwrapped (RFC 1928 section 7), judged per datagram with
/// `FlowGatekeeper.decideDatagram`, and relayed through a NAT-mapped outbound
/// `NWConnection`. Replies are wrapped and sent back to leaf.
///
/// Only touched on the shared server `queue`, which is why `@unchecked
/// Sendable` is safe.
///
/// Privacy: logs carry only counts and the association id, never the
/// destination.
final class UDPRelay: @unchecked Sendable {
    // The NAT map must stay capped and idle-reclaimed. UDP fan-out (QUIC
    // probes) would otherwise grow the socket table past the extension's
    // ~50 MB jetsam limit. When full, drop new destinations instead of growing.
    /// Per-association cap on concurrent outbound UDP sockets.
    private static let maxDestinations = 32
    /// Outbound UDP sockets idle longer than this are closed on the next sweep.
    private static let idleTimeout: TimeInterval = 60
    private static let sweepInterval: TimeInterval = 30
    /// Cap on destinations tracked for Live Traffic. Beyond it new
    /// destinations are relayed but not recorded.
    private static let maxDestStats = 256

    private let id: UInt64
    private let queue: DispatchQueue
    private let log: Logger
    private var gatekeeper: FlowGatekeeper

    private var listener: NWListener?
    /// Leaf's datagram source (one UDP "connection" on the loopback listener).
    private var inbound: NWConnection?

    /// NAT map entry, keyed by "host:port", with last activity for idle reclaim.
    private struct Outbound {
        let connection: NWConnection
        let destination: SOCKS5.Destination
        let port: UInt16
        var lastActive: Date
    }
    private var outbounds: [String: Outbound] = [:]
    private var sweepTimer: DispatchSourceTimer?
    private var closed = false

    /// Per-destination totals for Live Traffic, kept for the whole association
    /// (unlike `outbounds`, they survive idle reclaim). One `TrafficEvent` per
    /// destination is emitted at close, so QUIC shows the domains it reached.
    private struct DestStat {
        let destination: SOCKS5.Destination
        let port: UInt16
        var bytesUp: UInt64 = 0
        var bytesDown: UInt64 = 0
        var verdict: RuleAction = .allow
        var verdictSource: TrafficEvent.VerdictSource?
    }
    private var destStats: [String: DestStat] = [:]

    // Read by the server at teardown.
    private(set) var bytesUp: UInt64 = 0    // leaf to destination payload
    private(set) var bytesDown: UInt64 = 0  // destination to leaf payload
    private(set) var datagramsAllowed: UInt64 = 0
    private(set) var datagramsDenied: UInt64 = 0

    init(id: UInt64, gatekeeper: FlowGatekeeper, queue: DispatchQueue, log: Logger) {
        self.id = id
        self.gatekeeper = gatekeeper
        self.queue = queue
        self.log = log
    }

    /// Called on reload so long-lived associations judge new datagrams by the
    /// current rules and the old rule set can be freed.
    func updateGatekeeper(_ new: FlowGatekeeper) {
        gatekeeper = new
    }

    // MARK: - Lifecycle

    /// Binds an ephemeral loopback UDP listener; `onBound` reports the port to
    /// put in the ASSOCIATE reply (or nil on failure). Runs on `queue`.
    func start(onBound: @escaping @Sendable (UInt16?) -> Void) {
        do {
            let params = NWParameters.udp
            params.allowLocalEndpointReuse = true
            params.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
            let listener = try NWListener(using: params)
            self.listener = listener

            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    let port = listener.port?.rawValue ?? 0
                    self.log.notice("✅ udp:associate bound VERIFY aid=\(self.id, privacy: .public) port=\(port, privacy: .public)")
                    self.startSweep()
                    onBound(port == 0 ? nil : port)
                case .failed(let error):
                    self.log.error("❌ udp:associate bind failed aid=\(self.id, privacy: .public) err=\(error, privacy: .public)")
                    onBound(nil)
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] conn in
                self?.adoptInbound(conn)
            }
            listener.start(queue: queue)
        } catch {
            log.error("❌ udp:associate listener setup failed aid=\(self.id, privacy: .public) err=\(error, privacy: .public)")
            onBound(nil)
        }
    }

    func stop() {
        guard !closed else { return }
        closed = true
        sweepTimer?.cancel()
        sweepTimer = nil
        inbound?.cancel()
        inbound = nil
        for (_, ob) in outbounds { ob.connection.cancel() }
        outbounds.removeAll()
        listener?.cancel()
        listener = nil
        log.notice("udp:associate close VERIFY aid=\(self.id, privacy: .public) up=\(self.bytesUp, privacy: .public) down=\(self.bytesDown, privacy: .public) allow=\(self.datagramsAllowed, privacy: .public) deny=\(self.datagramsDenied, privacy: .public)")
    }

    /// One Live Traffic event per destination (proto 17). Called at teardown;
    /// clears the stats.
    func drainDestinationEvents() -> [TrafficEvent] {
        let events = destStats.values.map { stat -> TrafficEvent in
            let ip: String
            let domain: String?
            switch stat.destination {
            case .domain(let name): ip = ""; domain = name
            case .ipv4(let addr), .ipv6(let addr): ip = addr.description; domain = nil
            }
            return TrafficEvent(
                remoteIP: ip, domain: domain, remotePort: stat.port,
                protocolNumber: 17, bytesUp: stat.bytesUp, bytesDown: stat.bytesDown,
                verdict: stat.verdict, verdictSource: stat.verdictSource
            )
        }
        destStats.removeAll()
        return events
    }

    // MARK: - Inbound (leaf → us)

    private func adoptInbound(_ conn: NWConnection) {
        // Leaf uses one source endpoint per association. Cancel any second one.
        guard inbound == nil, !closed else { conn.cancel(); return }
        inbound = conn
        conn.stateUpdateHandler = { [weak self] state in
            if case .failed = state { self?.stop() }
            if case .cancelled = state { self?.stop() }
        }
        conn.start(queue: queue)
        receiveInbound(conn)
    }

    private func receiveInbound(_ conn: NWConnection) {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty { self.handleClientDatagram(data) }
            if error != nil { self.stop(); return }
            guard !self.closed else { return }
            self.receiveInbound(conn)
        }
    }

    private func handleClientDatagram(_ data: Data) {
        guard case .parsed(let dg, _) = SOCKS5UDPDatagram.parse(data) else {
            // Drop malformed or fragmented datagrams.
            return
        }
        let key = "\(dg.destination.host):\(dg.port)"
        let verdict = gatekeeper.decideDatagram(destination: dg.destination, port: dg.port)
        guard verdict.action == .allow else {
            datagramsDenied &+= 1
            // Record the blocked destination so Live Traffic shows it (0 bytes).
            if destStats[key] == nil, destStats.count < Self.maxDestStats {
                destStats[key] = DestStat(
                    destination: dg.destination, port: dg.port,
                    verdict: .deny, verdictSource: .init(verdict.source)
                )
            }
            return
        }
        datagramsAllowed &+= 1
        bytesUp &+= UInt64(dg.payload.count)
        if destStats[key] != nil {
            destStats[key]!.bytesUp &+= UInt64(dg.payload.count)
        } else if destStats.count < Self.maxDestStats {
            var stat = DestStat(destination: dg.destination, port: dg.port)
            stat.bytesUp = UInt64(dg.payload.count)
            destStats[key] = stat
        }
        sendOutbound(dg)
    }

    // MARK: - Outbound (us → destination, NAT-mapped)

    private func sendOutbound(_ dg: SOCKS5UDPDatagram) {
        let key = "\(dg.destination.host):\(dg.port)"
        if var existing = outbounds[key] {
            existing.lastActive = Date()
            outbounds[key] = existing
            existing.connection.send(content: dg.payload, completion: .contentProcessed { _ in })
            return
        }
        guard outbounds.count < Self.maxDestinations else {
            // NAT table full: drop rather than grow.
            log.notice("⚠️ udp:natFull drop VERIFY aid=\(self.id, privacy: .public) dsts=\(self.outbounds.count, privacy: .public)")
            return
        }

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(dg.destination.host),
            port: NWEndpoint.Port(rawValue: dg.port) ?? .any
        )
        let conn = NWConnection(to: endpoint, using: .udp)
        outbounds[key] = Outbound(connection: conn, destination: dg.destination, port: dg.port, lastActive: Date())
        conn.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.receiveOutbound(key: key, conn: conn)
            case .failed, .cancelled:
                self.outbounds[key]?.connection.cancel()
                self.outbounds[key] = nil
            default:
                break
            }
        }
        conn.start(queue: queue)
        conn.send(content: dg.payload, completion: .contentProcessed { _ in })
    }

    private func receiveOutbound(key: String, conn: NWConnection) {
        conn.receiveMessage { [weak self] data, _, _, error in
            guard let self else { return }
            if let data, !data.isEmpty, let ob = self.outbounds[key], let inbound = self.inbound {
                self.outbounds[key]?.lastActive = Date()
                self.bytesDown &+= UInt64(data.count)
                self.destStats[key]?.bytesDown &+= UInt64(data.count)
                let reply = SOCKS5UDPDatagram(destination: ob.destination, port: ob.port, payload: data)
                inbound.send(content: reply.encoded(), completion: .contentProcessed { _ in })
            }
            if error != nil {
                self.outbounds[key]?.connection.cancel()
                self.outbounds[key] = nil
                return
            }
            guard !self.closed, self.outbounds[key] != nil else { return }
            self.receiveOutbound(key: key, conn: conn)
        }
    }

    // MARK: - Idle reclaim

    private func startSweep() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + Self.sweepInterval, repeating: Self.sweepInterval)
        timer.setEventHandler { [weak self] in self?.sweepIdle() }
        sweepTimer = timer
        timer.resume()
    }

    private func sweepIdle() {
        let cutoff = Date().addingTimeInterval(-Self.idleTimeout)
        for (key, ob) in outbounds where ob.lastActive < cutoff {
            ob.connection.cancel()
            outbounds[key] = nil
        }
    }
}
