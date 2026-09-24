import CloudKit
import CryptoKit
import Foundation
import os
import SharedCore

/// iCloud sync of user configuration. Merge logic lives in SharedCore's
/// `SyncMerge`; this class moves a single record and keeps this device's
/// last-synced baseline.
///
/// The record (`current`) lives in the private CloudKit database and holds
/// `SyncedConfig` JSON. Conflicts are resolved with CloudKit's change-tag check
/// (`.serverRecordChanged`), a merge, and one retry.
///
/// Only configuration is synced. Traffic history, events and credentials must
/// never be sent through here.
@MainActor
final class CloudSyncService {
    enum Status: Equatable {
        case idle
        case syncing
        case synced(Date)
        case accountUnavailable
        case error(String)
    }

    private(set) var status: Status = .idle

    private let log = Logger(subsystem: "fluxmoat", category: "sync")
    /// Lazy because CKContainer(identifier:) throws an NSException without the
    /// CloudKit entitlement (e.g. unsigned builds). Only users who enable sync
    /// touch CloudKit.
    private lazy var container = CKContainer(identifier: AppIdentifiers.iCloudContainer)
    private static let recordType = "FluxMoatConfig"
    private static let recordName = "current"
    private static let payloadKey = "payload"

    /// Last state this device synced; the baseline for `SyncMerge.stampedLocal`.
    /// CKRecord system fields aren't stored because each round fetches the record fresh.
    private struct PersistedState: Codable {
        var config: SyncedConfig
    }

    private let stateURL: URL
    private var isSyncing = false

    init() {
        let base = FileManager.default
            .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("FluxMoat/Sync", isDirectory: true)
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        stateURL = base.appendingPathComponent("lastSynced.json")
    }

    /// Runs one sync round. Returns the merged config for the caller to apply
    /// when it differs from local state, or nil when local is already up to date.
    func sync(
        rules: [Rule],
        settings: SyncedSettings,
        wifi: SyncedWiFiProfiles,
        blocklist: SyncedBlocklist
    ) async -> SyncedConfig? {
        guard !isSyncing else { return nil }
        isSyncing = true
        status = .syncing
        defer { isSyncing = false }

        do {
            guard try await container.accountStatus() == .available else {
                status = .accountUnavailable
                log.info("⚠️ app:cloudSync account unavailable — skipping")
                return nil
            }

            let previous = loadState()
            let stamped = SyncMerge.stampedLocal(
                rules: rules, settings: settings, wifi: wifi, blocklist: blocklist,
                previous: previous?.config)

            let database = container.privateCloudDatabase
            let recordID = CKRecord.ID(recordName: Self.recordName)
            var serverRecord: CKRecord?
            do {
                serverRecord = try await database.record(for: recordID)
            } catch let error as CKError where error.code == .unknownItem {
                serverRecord = nil  // First device to ever sync.
            }

            var remote: SyncedConfig?
            if let data = serverRecord?[Self.payloadKey] as? Data {
                remote = try SyncedConfig.deserialized(data)
            }
            log.info("☁️ app:cloudSync fetch VERIFY remote=\(remote != nil, privacy: .public) remoteRules=\(remote?.rules.count ?? -1, privacy: .public) localRules=\(stamped.rules.count, privacy: .public)")

            var merged = remote.map { SyncMerge.merge(stamped, $0) } ?? stamped

            if merged != remote {
                let record = serverRecord ?? CKRecord(recordType: Self.recordType, recordID: recordID)
                merged = try await save(merged, into: record, database: database)
            }

            saveState(PersistedState(config: merged))
            status = .synced(Date())
            return merged == stamped ? nil : merged
        } catch let error as SyncError {
            if case .newerSchema(let v) = error {
                status = .error("Cloud data is from a newer app version (v\(v)). Update FluxMoat on this device.")
                log.error("❌ app:cloudSync newer schema \(v, privacy: .public) — refusing lossy merge")
            }
            return nil
        } catch {
            status = .error(error.localizedDescription)
            log.error("❌ app:cloudSync failed: \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    /// Saves with one retry: on `.serverRecordChanged`, merges onto the server's
    /// record and saves again. Returns the config that was stored.
    private func save(
        _ config: SyncedConfig, into record: CKRecord, database: CKDatabase
    ) async throws -> SyncedConfig {
        let payload = try config.serialized()
        record[Self.payloadKey] = payload
        do {
            _ = try await database.save(record)
            log.info("☁️ app:cloudSync save VERIFY rules=\(config.rules.count, privacy: .public) tombstones=\(config.tombstones.count, privacy: .public) sha=\(Self.shaPrefix(payload), privacy: .public)")
            return config
        } catch let error as CKError where error.code == .serverRecordChanged {
            guard let winner = error.serverRecord,
                  let winnerData = winner[Self.payloadKey] as? Data else { throw error }
            let winnerConfig = try SyncedConfig.deserialized(winnerData)
            let remerged = SyncMerge.merge(config, winnerConfig)
            log.info("⚠️ app:cloudSync conflict — re-merging onto server record and retrying once")
            if remerged == winnerConfig { return winnerConfig }
            winner[Self.payloadKey] = try remerged.serialized()
            _ = try await database.save(winner)
            log.info("☁️ app:cloudSync save VERIFY (retry) rules=\(remerged.rules.count, privacy: .public) tombstones=\(remerged.tombstones.count, privacy: .public)")
            return remerged
        }
    }

    // MARK: baseline persistence

    private func loadState() -> PersistedState? {
        guard let data = try? Data(contentsOf: stateURL) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(PersistedState.self, from: data)
    }

    private func saveState(_ state: PersistedState) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(state) else { return }
        try? data.write(to: stateURL, options: .atomic)
    }

    /// Called when sync is turned off, so re-enabling does a fresh first sync
    /// instead of diffing against a stale baseline.
    func resetBaseline() {
        try? FileManager.default.removeItem(at: stateURL)
    }

    private static func shaPrefix(_ data: Data) -> String {
        SHA256.hash(data: data).prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}
