import Foundation

/// Decides whether an already downloaded subscription may re-check itself
/// when the app comes to the foreground.
///
/// The first download of a list always comes from the user tapping it, so
/// the app never starts blocking a list the user didn't choose. After that,
/// keeping the list fresh happens automatically.
///
/// The caller passes `now` and the stored timestamp, so this is testable
/// without a clock, network or UserDefaults.
public enum BlocklistAutoRefresh {
    /// Minimum time between automatic checks of the same source. Upstream
    /// lists change about once a day, and even an ETag request costs data on
    /// a metered connection.
    public static let minimumInterval: TimeInterval = 6 * 60 * 60

    /// - Parameters:
    ///   - lastCheckedAt: when an automatic check last contacted this source,
    ///     whether or not it changed. nil if it never has.
    ///   - now: current time, injected for tests.
    public static func shouldRefresh(
        _ source: BlocklistSource,
        lastCheckedAt: Date?,
        now: Date
    ) -> Bool {
        // Nothing to fetch, or the user turned it off.
        guard source.enabled, source.sourceURL != nil else { return false }

        // Never downloaded on this device means the user hasn't chosen it here.
        // Cloud sync doesn't copy `lastUpdatedAt`, so a source synced from another
        // device still waits for a tap. `showBlocklistDownloadNudge` uses the same
        // check to prompt for that first download.
        guard let lastUpdatedAt = source.lastUpdatedAt else { return false }

        // Use the last contact, not the last change. A 304 doesn't update
        // `lastUpdatedAt`, so on its own an unchanged list would be re-checked on
        // every foreground. Including `lastUpdatedAt` also means a recent manual
        // update counts.
        let lastContact = max(lastUpdatedAt, lastCheckedAt ?? .distantPast)
        let elapsed = now.timeIntervalSince(lastContact)
        // A timestamp in the future means the clock went backwards. Treat it as
        // due so refreshes don't stall; this check rewrites the timestamp.
        return elapsed < 0 || elapsed >= minimumInterval
    }
}
