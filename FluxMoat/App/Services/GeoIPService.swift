import Foundation
import SharedCore

/// On-device country lookups from the bundled DB-IP Lite database.
/// The database is CC BY 4.0; the required attribution is in Settings > About.
final class GeoIPService: Sendable {
    static let shared = GeoIPService()

    private let database: GeoIPDatabase?

    private init() {
        database = Bundle.main
            .url(forResource: "dbip-country-lite", withExtension: "mmdb")
            .flatMap { try? GeoIPDatabase(contentsOf: $0) }
    }

    var isAvailable: Bool { database != nil }

    /// Build date from the MMDB metadata (`build_epoch`), so it stays correct
    /// when the database is refreshed. nil if the file is missing or has no epoch.
    var databaseBuildDate: Date? { database?.buildDate }

    func countryCode(for ipString: String) -> String? {
        guard let database, let ip = IPAddress.parse(ipString) else { return nil }
        return database.countryCode(for: ip)
    }
}
