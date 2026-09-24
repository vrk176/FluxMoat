import Foundation
import NetworkExtension
import os
import SharedCore

/// Tunnel control client backed by `NETunnelProviderManager`.
///
/// The first `saveToPreferences()` triggers the system "Add VPN Configurations"
/// alert. Packet tunnels don't run in the simulator, so `AppModel` uses the mock there.
/// State changes, status transitions and errors are all logged so device logs
/// are enough to diagnose tunnel startup problems.
@MainActor
final class TunnelManagerClient: TunnelClient {
    private let log = Logger(subsystem: "fluxmoat", category: "tunnel-manager")
    private var manager: NETunnelProviderManager?
    private var statusObserver: (any NSObjectProtocol)?
    private var lastStatus: NEVPNStatus = .invalid
    private var lastCountersPollFailed = false
    var onRunningChanged: ((Bool) -> Void)?

    var isRunning: Bool {
        switch manager?.connection.status {
        case .connected, .connecting, .reasserting: true
        default: false
        }
    }

    /// Loads the saved configuration at launch, without starting the tunnel, and
    /// reports its real state so the toggle is correct when the VPN is already up.
    func refreshStatus() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            guard let manager = managers.first else {
                // No saved configuration, so nothing is running.
                log.notice("✅ app:refreshStatus VERIFY: 0 existing configuration(s) → off")
                onRunningChanged?(false)
                return
            }
            // NetworkExtension quirk: a manager from `loadAllFromPreferences` can
            // report a stale `connection.status` (e.g. disconnected while the
            // tunnel is up). Reloading it makes the status current.
            try await manager.loadFromPreferences()
            self.manager = manager
            observeStatus(of: manager)
            log.notice("✅ app:refreshStatus VERIFY: \(managers.count, privacy: .public) config(s) status \(Self.describe(manager.connection.status), privacy: .public) running \(self.isRunning, privacy: .public)")
            onRunningChanged?(isRunning)
        } catch {
            log.error("❌ app:refreshStatus failed: \(error, privacy: .public)")
            onRunningChanged?(false)
        }
    }

    func start() async throws {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            log.info("✅ app:startTunnel read prefs: \(managers.count, privacy: .public) existing configuration(s)")

            let manager = managers.first ?? NETunnelProviderManager()
            if manager.protocolConfiguration == nil {
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = AppIdentifiers.packetTunnelBundleID
                // Display only (shown in Settings); there is no remote server.
                proto.serverAddress = "On-Device Filter"
                manager.protocolConfiguration = proto
                manager.localizedDescription = "FluxMoat"
                log.info("app:startTunnel creating new configuration (first run → expect system VPN authorization alert)")
            } else {
                log.info("app:startTunnel reusing existing configuration")
            }
            manager.isEnabled = true
            // On-demand makes iOS bring the tunnel back after reboots, app
            // updates and extension jetsam. `stop()` must clear it, or iOS
            // reconnects immediately.
            let onDemand = NEOnDemandRuleConnect()
            onDemand.interfaceTypeMatch = .any
            manager.onDemandRules = [onDemand]
            manager.isOnDemandEnabled = true

            // First-ever save triggers the system VPN authorization alert.
            try await manager.saveToPreferences()
            // NetworkExtension quirk: a freshly saved configuration must be
            // reloaded before startVPNTunnel, or the start fails.
            try await manager.loadFromPreferences()
            self.manager = manager
            observeStatus(of: manager)
            log.notice("✅ app:saveConfig commit VERIFY: enabled \(manager.isEnabled, privacy: .public) onDemand \(manager.isOnDemandEnabled, privacy: .public) proto \(manager.protocolConfiguration != nil, privacy: .public) status \(Self.describe(manager.connection.status), privacy: .public)")

            try manager.connection.startVPNTunnel()
            log.info("✅ app:startVPNTunnel invoked — status \(Self.describe(manager.connection.status), privacy: .public)")
        } catch {
            log.error("❌ app:startTunnel failed: \(error, privacy: .public)")
            throw error
        }
    }

    func stop() async {
        guard let manager else {
            log.error("❌ app:stopTunnel no manager loaded")
            return
        }
        let before = manager.connection.status
        // Clear and save on-demand first, or iOS reconnects the tunnel right
        // after stopVPNTunnel.
        if manager.isOnDemandEnabled {
            manager.isOnDemandEnabled = false
            do {
                try await manager.saveToPreferences()
                log.notice("✅ app:stopTunnel onDemand cleared VERIFY: onDemand \(manager.isOnDemandEnabled, privacy: .public)")
            } catch {
                log.error("❌ app:stopTunnel failed to clear on-demand: \(error, privacy: .public)")
            }
        }
        manager.connection.stopVPNTunnel()
        log.notice("✅ app:stopVPNTunnel invoked: status \(Self.describe(before), privacy: .public)→\(Self.describe(manager.connection.status), privacy: .public)")
    }

    func send(_ request: ProviderRequest) async throws -> ProviderResponse {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            log.error("❌ app:sendMessage no session (manager \(self.manager != nil, privacy: .public))")
            throw TunnelClientError(reason: "tunnel session unavailable")
        }
        let payload = try request.encoded()
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(payload) { data in
                    guard let data,
                          let response = try? ProviderResponse.decoded(from: data) else {
                        continuation.resume(throwing: TunnelClientError(reason: "empty or undecodable response"))
                        return
                    }
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    /// Polls live counters and recently closed flows once per second while the
    /// tunnel runs. Poll failures are logged on transition only.
    func nextTick() async -> MockTick? {
        try? await Task.sleep(for: .seconds(1))
        // Logged once when polling stops, to line up with the extension's teardown.
        guard isRunning else {
            log.notice("⏸️ app:pollTick VERIFY stop status=\(Self.describe(self.manager?.connection.status ?? .invalid), privacy: .public)")
            return nil
        }
        do {
            guard case .liveCounters(let counters) = try await send(.liveCounters) else {
                throw TunnelClientError(reason: "unexpected response case")
            }
            if lastCountersPollFailed {
                lastCountersPollFailed = false
                log.info("✅ app:pollCounters recovered")
            }
            // Best-effort: a failed events poll must not discard good counters.
            var events: [TrafficEvent] = []
            if case .recentEvents(let e) = try? await send(.recentEvents) { events = e }
            return MockTick(counters: counters, newFlows: events)
        } catch {
            if !lastCountersPollFailed {
                lastCountersPollFailed = true
                log.error("❌ app:pollCounters failed (status \(Self.describe(self.manager?.connection.status ?? .invalid), privacy: .public)): \(error, privacy: .public)")
            }
            return MockTick(
                counters: .init(bytesUpPerSecond: 0, bytesDownPerSecond: 0, activeFlows: 0, blockedToday: 0),
                newFlows: []
            )
        }
    }

    // MARK: - Status transitions

    private func observeStatus(of manager: NETunnelProviderManager) {
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        lastStatus = manager.connection.status
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: manager.connection,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.logStatusTransition()
            }
        }
    }

    private func logStatusTransition() {
        guard let manager else { return }
        let current = manager.connection.status
        let marker = current == .disconnected && lastStatus == .connecting ? "❌" : "✅"
        log.notice("\(marker, privacy: .public) app:vpnStatus change VERIFY: \(Self.describe(self.lastStatus), privacy: .public)→\(Self.describe(current), privacy: .public)")
        lastStatus = current
        // Start and stop are asynchronous, so the toggle follows these
        // transitions rather than the status read right after the call.
        onRunningChanged?(isRunning)
    }

    private static func describe(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: "invalid"
        case .disconnected: "disconnected"
        case .connecting: "connecting"
        case .connected: "connected"
        case .reasserting: "reasserting"
        case .disconnecting: "disconnecting"
        @unknown default: "unknown(\(status.rawValue))"
        }
    }
}

struct TunnelClientError: Error, LocalizedError {
    let reason: String
    var errorDescription: String? { reason }
}
