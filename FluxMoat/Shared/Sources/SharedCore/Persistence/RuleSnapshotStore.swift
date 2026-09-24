import Foundation

/// Atomic snapshot exchange between the app (writer) and the tunnel
/// (reader) through the App Group container.
///
/// Write order: serialize, write a temp file, copy the current file to the
/// backup, then atomically replace. The reader falls back to the backup when
/// the current file is missing or fails checksum or schema validation, so a
/// crash at any point leaves at least one loadable snapshot.
public struct RuleSnapshotStore: Sendable {
    public static let appGroupID = AppIdentifiers.appGroup

    public enum LoadSource: Sendable, Equatable {
        case current
        case backup
    }

    public struct StoreError: Error, Sendable {
        public let reason: String
    }

    public let directoryURL: URL

    public var currentURL: URL { directoryURL.appendingPathComponent("rules-snapshot.json") }
    public var backupURL: URL { directoryURL.appendingPathComponent("rules-snapshot.previous.json") }

    public init(directoryURL: URL) {
        self.directoryURL = directoryURL
    }

    /// Store inside the App Group container, or nil when the entitlement is
    /// missing (for example unsigned simulator builds). Callers then fall back
    /// to a local directory.
    public static func appGroup() -> RuleSnapshotStore? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
            .map { RuleSnapshotStore(directoryURL: $0.appendingPathComponent("Rules", isDirectory: true)) }
    }

    /// Returns the snapshot's SHA-256 so the caller can log what it wrote.
    @discardableResult
    public func write(_ snapshot: RuleSnapshot) throws -> String {
        let fm = FileManager.default
        let (data, sha256) = try snapshot.serializedWithChecksum()

        try fm.createDirectory(at: directoryURL, withIntermediateDirectories: true)

        let temporaryURL = directoryURL.appendingPathComponent("rules-snapshot.tmp")
        try? fm.removeItem(at: temporaryURL)
        try data.write(to: temporaryURL, options: writingOptions)

        if fm.fileExists(atPath: currentURL.path) {
            // Keep the last good version before swapping in the new one.
            try? fm.removeItem(at: backupURL)
            try fm.copyItem(at: currentURL, to: backupURL)
            _ = try fm.replaceItemAt(currentURL, withItemAt: temporaryURL)
        } else {
            try fm.moveItem(at: temporaryURL, to: currentURL)
        }
        return sha256
    }

    /// Loads the current snapshot, falling back to the backup when the current
    /// file is missing or corrupt. Throws only when neither loads.
    public func load() throws -> (snapshot: RuleSnapshot, source: LoadSource) {
        if let snapshot = Self.read(at: currentURL) {
            return (snapshot, .current)
        }
        if let snapshot = Self.read(at: backupURL) {
            return (snapshot, .backup)
        }
        throw StoreError(reason: "no valid snapshot at \(directoryURL.path)")
    }

    private static func read(at url: URL) -> RuleSnapshot? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? RuleSnapshot.deserialize(data)
    }

    /// Debug helper for load failures, since `read(at:)` discards the error.
    /// Re-reads both files and reports existence, size, and the read error code
    /// (257 usually means the device hasn't been unlocked yet) or decode error.
    /// Read-only.
    public func diagnose() -> String {
        [("current", currentURL), ("backup", backupURL)].map { name, url in
            let exists = FileManager.default.fileExists(atPath: url.path)
            do {
                let data = try Data(contentsOf: url)
                do {
                    _ = try RuleSnapshot.deserialize(data)
                    return "\(name)[exists=\(exists) bytes=\(data.count) decode=ok]"
                } catch {
                    return "\(name)[exists=\(exists) bytes=\(data.count) decode=\(error)]"
                }
            } catch {
                return "\(name)[exists=\(exists) read=err\((error as NSError).code)]"
            }
        }.joined(separator: " ")
    }

    /// Complete-until-first-user-authentication protection. These files can't be
    /// read between boot and first unlock, so the tunnel retries the load when
    /// it starts on demand in that window.
    private var writingOptions: Data.WritingOptions {
        #if os(iOS)
        return [.completeFileProtectionUntilFirstUserAuthentication]
        #else
        return []
        #endif
    }
}
