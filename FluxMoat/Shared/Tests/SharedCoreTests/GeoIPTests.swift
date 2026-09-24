import Foundation
import Testing
@testable import SharedCore

/// Tests run against the real DB-IP Lite database bundled with the app.
/// They are skipped (not failed) if the file has not been downloaded.
private let databaseURL: URL = {
    // …/Shared/Tests/SharedCoreTests/GeoIPTests.swift → repo root is 3 up.
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // GeoIPTests.swift
        .deletingLastPathComponent() // SharedCoreTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // Shared
        .appendingPathComponent("App/Resources/GeoIP/dbip-country-lite.mmdb")
}()

private let databaseAvailable = FileManager.default.fileExists(atPath: databaseURL.path)

@Suite(.enabled(if: databaseAvailable, "dbip-country-lite.mmdb not downloaded"))
struct GeoIPTests {
    private func load() throws -> GeoIPDatabase {
        try GeoIPDatabase(contentsOf: databaseURL)
    }

    @Test func knownAnchorsResolve() throws {
        let db = try load()
        // Long-term stable allocation; safe anchor for a country DB.
        #expect(db.countryCode(for: IPAddress.parse("8.8.8.8")!) == "US")
        // v6 attribution varies by data source; only require a valid code.
        let v6 = db.countryCode(for: IPAddress.parse("2001:4860:4860::8888")!)
        #expect(v6?.count == 2, "v6 anchor → \(v6 ?? "nil")")
    }

    @Test func publicAddressesReturnPlausibleCodes() throws {
        let db = try load()
        for ip in ["1.1.1.1", "9.9.9.9", "208.67.222.222", "2606:4700:4700::1111"] {
            let code = db.countryCode(for: IPAddress.parse(ip)!)
            #expect(code?.count == 2, "\(ip) → \(code ?? "nil")")
        }
    }

    @Test func documentationRangesReturnNilOrReserved() throws {
        let db = try load()
        // TEST-NET-3 and loopback must never map to a real country.
        for ip in ["203.0.113.7", "127.0.0.1"] {
            let code = db.countryCode(for: IPAddress.parse(ip)!)
            #expect(code == nil || code == "ZZ", "\(ip) → \(code ?? "nil")")
        }
    }

    @Test func lookupThroughputIsAcceptable() throws {
        let db = try load()
        var hits = 0
        let start = ContinuousClock.now
        for i in 0..<10_000 {
            let ip = IPAddress.v4(UInt32(0x0800_0000) &+ UInt32(i) &* 7919)
            if db.countryCode(for: ip) != nil { hits += 1 }
        }
        let elapsed = ContinuousClock.now - start
        #expect(hits > 0)
        #expect(elapsed < .seconds(2), "10k lookups took \(elapsed)")
    }
}
