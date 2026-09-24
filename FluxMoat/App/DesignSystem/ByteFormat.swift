import Foundation

/// Shared byte formatting for everything shown on screen.
///
/// KB is the smallest unit so rows don't mix bytes and MB, and scaling is
/// binary (1 KB = 1024 bytes) on purpose.
enum ByteFormat {
    /// A transferred total, e.g. "12 KB". Anything under half a KB, including
    /// zero, shows as "0 KB".
    static func volume(_ bytes: UInt64) -> String {
        volume(Int64(clamping: bytes))
    }

    /// Signed variant for chart axis values and FileManager sizes.
    static func volume(_ bytes: Int64) -> String {
        // New formatter per call: ByteCountFormatter isn't Sendable, so a shared
        // static can't cross actors under strict concurrency.
        let formatter = ByteCountFormatter()
        formatter.countStyle = .binary
        // No "bytes" unit; KB is the floor.
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        // Otherwise 0 is spelled "Zero KB".
        formatter.allowsNonnumericFormatting = false
        return formatter.string(fromByteCount: bytes)
    }
}
