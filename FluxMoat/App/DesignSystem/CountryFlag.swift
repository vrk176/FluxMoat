import Foundation

/// Regional-indicator flag emoji for an ISO 3166-1 alpha-2 code.
enum CountryFlag {
    /// Fallback when GeoIP has no answer (private ranges, new IPs). Keeps the
    /// leading glyph slot filled so row text stays aligned.
    static let unknown = "🌐"

    static func emoji(_ code: String?) -> String {
        guard let code else { return unknown }
        let scalars = code.uppercased().unicodeScalars
        // Check the count after uppercasing: some characters expand (ß becomes
        // SS). Anything other than exactly two A-Z letters would render as tofu.
        guard scalars.count == 2,
              scalars.allSatisfy({ ("A"..."Z").contains(Character($0)) }) else { return unknown }
        return String(scalars.compactMap {
            UnicodeScalar(0x1F1E6 + $0.value - UnicodeScalar("A").value).map(Character.init)
        })
    }
}
