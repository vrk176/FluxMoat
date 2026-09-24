import Foundation
import leaf
import os

/// Swift wrapper over leaf's C FFI (`leaf.h`). One instance owns one leaf
/// runtime, keyed by `rtID`.
///
/// `leaf_run_with_config_string` blocks until shutdown, so `start` runs it on a
/// dedicated thread. Call `start` and `shutdown` from the provider's serial
/// queue; that confinement is what makes `@unchecked Sendable` safe.
public final class LeafRuntime: @unchecked Sendable {
    /// Outcome of leaf's run loop, from the `leaf.h` ERR_* codes.
    public enum StartOutcome: Sendable, Equatable {
        case ranToCompletion            // ERR_OK after a clean shutdown
        case failed(code: Int32)        // any non-zero startup/runtime error
    }

    private let rtID: UInt16
    private let stackSize: Int
    private let log = Logger(subsystem: "fluxmoat", category: "leaf")

    private var worker: Thread?
    private var didStart = false

    /// - Parameters:
    ///   - rtID: leaf instance id; must be unique per running instance.
    ///   - stackSize: worker thread stack in bytes. Leaf's netstack and tokio
    ///     need headroom; it counts toward the extension's 50 MB limit.
    public init(rtID: UInt16 = 1, stackSize: Int = 2 * 1024 * 1024) {
        self.rtID = rtID
        self.stackSize = stackSize
    }

    /// Starts leaf on its own thread and returns immediately. `onExit` fires on
    /// `completionQueue` when leaf returns, after `shutdown()` or on an error.
    public func start(
        configJSON: String,
        completionQueue: DispatchQueue,
        onExit: @escaping @Sendable (StartOutcome) -> Void
    ) {
        precondition(!didStart, "LeafRuntime.start called twice")
        didStart = true

        let rtID = self.rtID

        let thread = Thread {
            self.log.notice("✅ leaf:run starting rt=\(rtID, privacy: .public) cfgBytes=\(configJSON.utf8.count, privacy: .public)")
            // The C string stays valid for the whole blocking call.
            let code = configJSON.withCString { leaf_run_with_config_string(rtID, $0) }
            let outcome: StartOutcome = (code == ERR_OK) ? .ranToCompletion : .failed(code: code)
            switch outcome {
            case .ranToCompletion:
                self.log.notice("✅ leaf:run exit rt=\(rtID, privacy: .public) code=OK (clean shutdown)")
            case .failed(let c):
                self.log.error("❌ leaf:run exit rt=\(rtID, privacy: .public) code=\(c, privacy: .public) (startup/runtime failure; ERR_CONFIG=2 ⇒ JSON schema mismatch)")
                // The config holds no user data (fd, mtu, port, log level),
                // so it is safe to log and makes schema errors easy to spot.
                self.log.error("leaf:run failed-config VERIFY: \(configJSON, privacy: .public)")
            }
            completionQueue.async { onExit(outcome) }
        }
        thread.name = "fluxmoat.leaf"
        thread.stackSize = stackSize
        worker = thread
        thread.start()
    }

    /// Signals leaf to stop, which unblocks the worker thread. Returns leaf's
    /// success flag.
    @discardableResult
    public func shutdown() -> Bool {
        let ok = leaf_shutdown(rtID)
        log.notice("\(ok ? "✅" : "⚠️", privacy: .public) leaf:shutdown rt=\(self.rtID, privacy: .public) ok=\(ok, privacy: .public)")
        worker = nil
        return ok
    }

    /// Reloads leaf's DNS, outbound and routing config. FluxMoat rule changes do
    /// not go through leaf, so this is only for leaf-side config changes.
    @discardableResult
    public func reload() -> Int32 {
        let code = leaf_reload(rtID)
        log.info("leaf:reload rt=\(self.rtID, privacy: .public) code=\(code, privacy: .public)")
        return code
    }
}
