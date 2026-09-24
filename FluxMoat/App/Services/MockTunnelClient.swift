import Foundation
import SharedCore

/// The app's control channel to the tunnel. `TunnelManagerClient` is the real
/// implementation; `MockTunnelClient` lets the UI run in the simulator.
@MainActor
protocol TunnelClient: AnyObject {
    var isRunning: Bool { get }
    /// Called on every running-state change. VPN status changes are async, so
    /// UI state should follow this rather than read `isRunning` after start/stop.
    var onRunningChanged: ((Bool) -> Void)? { get set }
    /// Loads the saved VPN configuration at launch, without starting the tunnel,
    /// and reports its real state. Otherwise the toggle shows off after a cold
    /// launch while the system VPN is still running.
    func refreshStatus() async
    func start() async throws
    func stop() async
    func send(_ request: ProviderRequest) async throws -> ProviderResponse
    func nextTick() async -> MockTick?
}

struct MockTick: Sendable {
    var counters: ProviderResponse.LiveCounters
    var newFlows: [TrafficEvent]
}

/// Generates plausible-looking traffic so every screen can be built and
/// demoed without a device or entitlements. Clearly fake data only.
@MainActor
final class MockTunnelClient: TunnelClient {
    private(set) var isRunning = false
    var onRunningChanged: ((Bool) -> Void)?
    private var blockedToday = 0

    /// Persists synthesized flows like the real extension does, so History and
    /// the world map have data in the simulator. Same fallback directory as AppModel.
    private let eventStore = TrafficEventStore.appGroup() ?? TrafficEventStore(
        directoryURL: FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("FluxMoat/Events", isDirectory: true)
    )

    /// Domains are fake; IPs are real public resolvers and CDNs so GeoIP resolves
    /// real countries. The two documentation-range IPs cover the unknown-country path.
    private static let sampleTargets: [(domain: String?, ip: String, port: UInt16, proto: UInt8, country: String?)] = [
        ("api.weatherhub.example", "8.8.8.8", 443, 6, nil),
        ("cdn.photos.example", "151.101.1.140", 443, 6, nil),
        ("metrics.tracker.example", "104.16.132.229", 443, 6, nil),
        ("ads.popbanner.example", "9.9.9.9", 443, 6, nil),
        (nil, "2606:4700:4700::1111", 443, 17, nil),
        ("push.chatapp.example", "203.0.113.77", 5223, 6, nil),
        (nil, "198.51.100.9", 123, 17, nil),
    ]

    func refreshStatus() async {
        // No persisted VPN in the mock; just reflect current in-memory state.
        onRunningChanged?(isRunning)
    }

    func start() async throws {
        isRunning = true
        onRunningChanged?(true)
    }

    func stop() async {
        isRunning = false
        onRunningChanged?(false)
    }

    func send(_ request: ProviderRequest) async throws -> ProviderResponse {
        switch request {
        case .status:
            return .status(.init(mode: .standard, activeProfileID: nil, snapshotCreatedAt: Date(), lastError: nil))
        case .liveCounters:
            return .liveCounters(.init(bytesUpPerSecond: 0, bytesDownPerSecond: 0, activeFlows: 0, blockedToday: blockedToday))
        case .recentEvents:
            // Mock synthesizes flows directly in `nextTick`, not via this poll.
            return .recentEvents([])
        case .pendingAsks:
            return .pendingAsks([])
        case .reloadRules, .switchProfile, .healthCheck, .resolveAsk:
            return .acknowledged
        }
    }

    /// One simulated second of traffic; returns nil when stopped.
    func nextTick() async -> MockTick? {
        try? await Task.sleep(for: .seconds(1))
        guard isRunning else { return nil }

        var flows: [TrafficEvent] = []
        for _ in 0..<Int.random(in: 0...2) {
            let target = Self.sampleTargets.randomElement()!
            let blocked = target.domain?.contains("ads.") == true || target.domain?.contains("tracker.") == true
            if blocked { blockedToday += 1 }
            flows.append(
                TrafficEvent(
                    remoteIP: target.ip,
                    domain: target.domain,
                    remotePort: target.port,
                    protocolNumber: target.proto,
                    bytesUp: UInt64.random(in: 200...20_000),
                    bytesDown: UInt64.random(in: 500...400_000),
                    verdict: blocked ? .deny : .allow,
                    countryCode: target.country,
                    networkType: .wifi
                )
            )
        }
        if !flows.isEmpty {
            // countryCode stays nil in the store, as with real rows; GeoIP is
            // applied app-side on read.
            try? eventStore.append(flows)
        }
        return MockTick(
            counters: .init(
                bytesUpPerSecond: UInt64.random(in: 2_000...80_000),
                bytesDownPerSecond: UInt64.random(in: 20_000...2_000_000),
                activeFlows: Int.random(in: 3...14),
                blockedToday: blockedToday
            ),
            newFlows: flows
        )
    }
}
