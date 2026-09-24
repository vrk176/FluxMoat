import Foundation
import Testing
@testable import SharedCore

/// Covers two retirements, the Learning/Pause modes and the Low Data
/// profile, plus the thing that made the profile worth persisting: a
/// built-in id that survives a cold launch.

@Suite struct RunModeRetirementTests {
    /// The one that would have taken the whole settings section down.
    /// `SyncedSettings.mode` is non-optional, so an older device pushing
    /// "learning" through iCloud used to throw out the DoH upstream, the
    /// retention period and the quiet hours along with it.
    @Test func retiredAndUnknownRawValuesDecodeToStandard() throws {
        let decoder = JSONDecoder()
        for raw in ["learning", "pause", "garbage", ""] {
            let decoded = try decoder.decode(RunMode.self, from: Data("\"\(raw)\"".utf8))
            #expect(decoded == .standard, "raw \(raw) should fold to .standard")
        }
    }

    @Test func liveRawValuesStillDecodeToThemselves() throws {
        let decoder = JSONDecoder()
        for mode in [RunMode.standard, .ask, .strict] {
            let decoded = try decoder.decode(RunMode.self, from: Data("\"\(mode.rawValue)\"".utf8))
            #expect(decoded == mode)
        }
    }

    @Test func normalizedFoldsOnlyTheRetiredPair() {
        #expect(RunMode.normalized(.learning) == .standard)
        #expect(RunMode.normalized(.pause) == .standard)
        #expect(RunMode.normalized(.standard) == .standard)
        #expect(RunMode.normalized(.ask) == .ask)
        #expect(RunMode.normalized(.strict) == .strict)
    }

    /// A whole synced document written by a device still on the old build.
    /// Encoding a retired mode is what that device does; decoding it without
    /// throwing is what this one has to do.
    @Test func syncedConfigCarryingARetiredModeStillDecodes() throws {
        let config = SyncedConfig(
            rules: [],
            tombstones: [],
            settings: SyncedSettings(
                mode: .pause,
                dohServerURL: "https://dns.quad9.net/dns-query",
                blockEncryptedDNS: true,
                historyRetention: .days90,
                askQuietHours: QuietHours(startMinute: 60, endMinute: 120),
                updatedAt: Date(timeIntervalSince1970: 1_000)),
            wifi: SyncedWiFiProfiles(assignments: [], updatedAt: .distantPast),
            blocklist: SyncedBlocklist(manualDomains: [], sources: [], updatedAt: .distantPast))

        let restored = try SyncedConfig.deserialized(try config.serialized())
        #expect(restored.settings.mode == .standard)
        // The rest of the section survives untouched.
        #expect(restored.settings.dohServerURL == "https://dns.quad9.net/dns-query")
        #expect(restored.settings.blockEncryptedDNS == true)
        #expect(restored.settings.historyRetention == .days90)
        #expect(restored.settings.askQuietHours?.startMinute == 60)
    }

    /// Same story one layer down: a snapshot on disk from before the
    /// retirement is read by the tunnel as well as by the app.
    @Test func snapshotCarryingARetiredModeStillDecodes() throws {
        for retired in [RunMode.learning, .pause] {
            let snapshot = RuleSnapshot(rules: [], mode: retired)
            let restored = try RuleSnapshot.deserialize(try snapshot.serialize())
            #expect(restored.mode == .standard)
        }
    }
}

@Suite struct BuiltInProfileTests {
    /// Regression: these ids used to come from `UUID()` inside
    /// `AppModel.init`, so "the id of the Home profile" changed every launch.
    @Test func builtInIDsAreFixedConstants() {
        #expect(Profile.builtIn(.home)?.id
            == UUID(uuidString: "F10C0A70-0001-4000-8000-50524F464C01"))
        #expect(Profile.builtIn(.publicNetwork)?.id
            == UUID(uuidString: "F10C0A70-0002-4000-8000-50524F464C02"))
    }

    @Test func builtInRosterIsHomeAndPublicOnly() {
        #expect(Profile.builtIns.map(\.kind) == [.home, .publicNetwork])
        #expect(Profile.builtIns.map(\.isBuiltIn) == [true, true])
        #expect(Profile.builtIn(.lowData) == nil)
        #expect(Profile.builtIn(.custom) == nil)
        // Public is the one that blocks what Ask mode never got an answer for.
        #expect(Profile.builtIn(.home)?.unmatchedAction == .allow)
        #expect(Profile.builtIn(.publicNetwork)?.unmatchedAction == .deny)
    }

    @Test func retiredKindsFoldIntoHome() {
        #expect(Profile.normalizedKind(.lowData) == .home)
        #expect(Profile.normalizedKind(.custom) == .home)
        #expect(Profile.normalizedKind(.home) == .home)
        #expect(Profile.normalizedKind(.publicNetwork) == .publicNetwork)
    }
}

@Suite struct ActiveProfileKindPersistenceTests {
    @Test func snapshotRoundTripsTheActiveProfileKind() throws {
        let snapshot = RuleSnapshot(
            rules: [],
            mode: .ask,
            profileDefault: .deny,
            activeProfileKind: .publicNetwork)
        let restored = try RuleSnapshot.deserialize(try snapshot.serialize())
        #expect(restored.activeProfileKind == .publicNetwork)
        #expect(restored.profileDefault == .deny)
        #expect(restored.mode == .ask)
    }

    /// Backward compatible both directions: the key is omitted when nil,
    /// so an old build reads the new file unchanged, and a file without
    /// the key decodes here without throwing.
    @Test func snapshotWithoutTheKeyDecodesAndOmitsIt() throws {
        let snapshot = RuleSnapshot(rules: [], mode: .strict)
        let data = try snapshot.serialize()
        let json = String(decoding: data, as: UTF8.self)
        #expect(!json.contains("activeProfileKind"))

        let restored = try RuleSnapshot.deserialize(data)
        #expect(restored.activeProfileKind == nil)
        #expect(restored.mode == .strict)
        // The field is additive only, so schemaVersion must not have moved.
        #expect(restored.schemaVersion == RuleSnapshot.currentSchemaVersion)
        #expect(RuleSnapshot.currentSchemaVersion == 1)
    }

    @Test func syncedSettingsCarryTheKindAndTolerateItsAbsence() throws {
        let withKind = SyncedConfig(
            rules: [],
            tombstones: [],
            settings: SyncedSettings(
                mode: .ask,
                dohServerURL: nil,
                blockEncryptedDNS: false,
                historyRetention: .default,
                askQuietHours: nil,
                activeProfileKind: .publicNetwork,
                updatedAt: Date(timeIntervalSince1970: 10)),
            wifi: SyncedWiFiProfiles(assignments: [], updatedAt: .distantPast),
            blocklist: SyncedBlocklist(manualDomains: [], sources: [], updatedAt: .distantPast))
        let restoredWithKind = try SyncedConfig.deserialized(try withKind.serialized())
        #expect(restoredWithKind.settings.activeProfileKind == .publicNetwork)

        var withoutKind = withKind
        withoutKind.settings.activeProfileKind = nil
        let data = try withoutKind.serialized()
        #expect(!String(decoding: data, as: UTF8.self).contains("activeProfileKind"))
        let restoredWithoutKind = try SyncedConfig.deserialized(data)
        #expect(restoredWithoutKind.settings.activeProfileKind == nil)
        #expect(restoredWithoutKind.settings.mode == .ask)
    }

    /// A Wi-Fi rule written before the retirement still names Low Data; the
    /// assignment itself has to survive the read so the app can fold it.
    @Test func wifiAssignmentsKeepDecodingARetiredKind() throws {
        let snapshot = RuleSnapshot(
            rules: [],
            wifiAutoProfiles: [
                WiFiProfileAssignment(ssid: "n", profileKind: .lowData, unmatchedAction: .allow)
            ])
        let restored = try RuleSnapshot.deserialize(try snapshot.serialize())
        #expect(restored.wifiAutoProfiles?.first?.profileKind == .lowData)
        #expect(Profile.normalizedKind(restored.wifiAutoProfiles![0].profileKind) == .home)
    }
}
