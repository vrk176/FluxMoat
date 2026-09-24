import Foundation
import Testing
@testable import SharedCore

@Suite struct RuleSnapshotStoreTests {
    private func makeStore() throws -> RuleSnapshotStore {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("snapshot-store-tests-\(UUID().uuidString)", isDirectory: true)
        return RuleSnapshotStore(directoryURL: dir)
    }

    private func snapshot(marker: String) -> RuleSnapshot {
        RuleSnapshot(
            rules: [Rule(action: .deny, target: .domain(marker))],
            blocklistDomains: []
        )
    }

    @Test func writeThenLoadRoundTrip() throws {
        let store = try makeStore()
        let sha = try store.write(snapshot(marker: "v1.example"))
        #expect(sha.count == 64)

        let (loaded, source) = try store.load()
        #expect(source == .current)
        #expect(loaded.rules.first?.target == .domain("v1.example"))
    }

    @Test func secondWriteKeepsBackupAndCorruptCurrentFallsBack() throws {
        let store = try makeStore()
        try store.write(snapshot(marker: "v1.example"))
        try store.write(snapshot(marker: "v2.example"))

        // Both generations on disk.
        #expect(FileManager.default.fileExists(atPath: store.currentURL.path))
        #expect(FileManager.default.fileExists(atPath: store.backupURL.path))

        // Corrupt the current file → load falls back to v1.
        var data = try Data(contentsOf: store.currentURL)
        data[data.count / 2] ^= 0xFF
        try data.write(to: store.currentURL)

        let (loaded, source) = try store.load()
        #expect(source == .backup)
        #expect(loaded.rules.first?.target == .domain("v1.example"))
    }

    @Test func truncatedCurrentFallsBack() throws {
        let store = try makeStore()
        try store.write(snapshot(marker: "v1.example"))
        try store.write(snapshot(marker: "v2.example"))

        let data = try Data(contentsOf: store.currentURL)
        try data.prefix(10).write(to: store.currentURL)

        let (loaded, source) = try store.load()
        #expect(source == .backup)
        #expect(loaded.rules.first?.target == .domain("v1.example"))
    }

    @Test func missingEverythingThrows() throws {
        let store = try makeStore()
        #expect(throws: (any Error).self) {
            _ = try store.load()
        }
    }

    @Test func corruptBothThrows() throws {
        let store = try makeStore()
        try store.write(snapshot(marker: "v1.example"))
        try store.write(snapshot(marker: "v2.example"))
        try Data("junk".utf8).write(to: store.currentURL)
        try Data("junk".utf8).write(to: store.backupURL)
        #expect(throws: (any Error).self) {
            _ = try store.load()
        }
    }

    @Test func firstWriteHasNoBackup() throws {
        let store = try makeStore()
        try store.write(snapshot(marker: "v1.example"))
        #expect(!FileManager.default.fileExists(atPath: store.backupURL.path))
    }
}
