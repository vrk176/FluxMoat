import Foundation

/// Math for the Countries share card, kept here so `swift test` covers it:
/// shaping the Map tab's country rollup for the card, glow sizes, placement
/// of the numbered markers when centroids overlap, and the country nearest
/// a location fix.
///
/// Doesn't depend on GeoIP, CoreLocation or SwiftUI. The app passes in
/// `CountryAggregate` rows and plain lat/lon pairs.
public enum CountriesCardMath {
    /// How many countries the card lists and numbers on the map.
    public static let topCount = 5

    /// One placed country: all blocks in `blocked`, and the threat-list subset
    /// in `threat` (the same split as a Trends bar).
    public struct Country: Equatable, Sendable {
        public let code: String
        public let flows: Int
        public let blocked: Int
        public let threat: Int

        public init(code: String, flows: Int, blocked: Int, threat: Int) {
            self.code = code
            self.flows = flows
            self.blocked = blocked
            self.threat = threat
        }
    }

    /// The Map tab's rollup, shaped for the card. Built from the same
    /// `CountryAggregate` rows as the map so the counts always match.
    public struct Rollup: Equatable, Sendable {
        /// Every country the lookup could place, most connections first. Ties are
        /// sorted by code so the order is stable.
        public let placed: [Country]
        /// Connections whose address had no country. Shown in the footnote so the
        /// totals add up.
        public let unplacedFlows: Int

        public init(_ aggregates: [TrafficEventStore.CountryAggregate]) {
            var placed: [Country] = []
            var unplaced = 0
            for row in aggregates {
                if let code = row.countryCode?.uppercased(), !code.isEmpty {
                    placed.append(Country(code: code, flows: row.flows, blocked: row.blockedFlows, threat: row.threatFlows))
                } else {
                    unplaced += row.flows
                }
            }
            self.placed = placed.sorted { a, b in
                a.flows != b.flows ? a.flows > b.flows : a.code < b.code
            }
            unplacedFlows = unplaced
        }

        /// The hero number.
        public var distinctCountries: Int { placed.count }

        /// The ledger's rows, and the countries that get a numbered marker.
        public var top: [Country] { Array(placed.prefix(CountriesCardMath.topCount)) }

        /// Countries beyond the top list, for the "+N more countries" label.
        public var restCountries: Int { max(0, placed.count - top.count) }

        /// Connections that did get a country.
        public var placedFlows: Int { placed.reduce(0) { $0 + $1.flows } }
    }

    /// Radius in degrees of a country's glow on the map: 1.25 times the cube
    /// root of its connections. Cube root keeps large and small counts both
    /// visible; exact counts are printed in the list. Zero or fewer connections
    /// gets no glow.
    public static func haloRadius(flows: Int) -> Double {
        guard flows > 0 else { return 0 }
        return 1.25 * cbrt(Double(flows))
    }

    /// Brightness of a dot `distance` degrees from the center of a glow with
    /// `radius`: 1 at the center, 0 at the edge and beyond, with a 1.6 power
    /// falloff so the middle stays bright and the edge fades out.
    public static func glowLevel(distance: Double, radius: Double) -> Double {
        guard radius > 0, distance < radius else { return 0 }
        return 1 - pow(distance / radius, 1.6)
    }

    /// A point on the card, in points.
    public struct Point: Equatable, Sendable {
        public var x: Double
        public var y: Double
        public init(x: Double, y: Double) {
            self.x = x
            self.y = y
        }
        func distance(to other: Point) -> Double {
            ((x - other.x) * (x - other.x) + (y - other.y) * (y - other.y)).squareRoot()
        }
    }

    /// Positions for the numbered markers. A marker sits on its centroid
    /// unless it would overlap another one (European countries are close
    /// together). Then it moves to the first offset in `offsets` that clears
    /// every placed marker and every other anchor, drawn with a leader line.
    /// Offsets are tried in order so the result is deterministic, and markers
    /// are kept inside `size`.
    ///
    /// Returns one point per anchor in the same order. A marker that didn't
    /// move returns its anchor exactly, meaning no leader line is needed.
    public static func placeMarkers(
        anchors: [Point], radius: Double, size: Point, gap: Double = 2
    ) -> [Point] {
        let offsets: [Point] = [
            Point(x: -15, y: -13), Point(x: 3, y: -16), Point(x: 15, y: 9), Point(x: 12, y: -9),
            Point(x: -15, y: 9), Point(x: 0, y: -18), Point(x: 0, y: 18), Point(x: 18, y: 0),
            Point(x: -18, y: 0), Point(x: -12, y: 20), Point(x: 12, y: 20), Point(x: -24, y: -6),
        ]
        let minGap = 2 * radius + gap
        var placed: [Point] = []
        func clamp(_ p: Point) -> Point {
            Point(
                x: min(max(p.x, radius + 1), size.x - radius - 1),
                y: min(max(p.y, radius + 1), size.y - radius - 1)
            )
        }
        func clear(_ p: Point, own: Int) -> Bool {
            for other in placed where other.distance(to: p) < minGap { return false }
            for (i, anchor) in anchors.enumerated() where i != own && anchor.distance(to: p) < radius + 3 {
                return false
            }
            return true
        }
        for (i, anchor) in anchors.enumerated() {
            let home = clamp(anchor)
            // Only move when staying would collide with a placed marker or cover
            // another top-five centroid's dot.
            if home == anchor, clear(home, own: i) {
                placed.append(home)
                continue
            }
            var chosen = home
            for offset in offsets {
                let candidate = clamp(Point(x: anchor.x + offset.x, y: anchor.y + offset.y))
                if clear(candidate, own: i) {
                    chosen = candidate
                    break
                }
            }
            placed.append(chosen)
        }
        return placed
    }

    /// A centroid the nearest-country lookup can choose from.
    public struct Centroid: Equatable, Sendable {
        public let code: String
        public let latitude: Double
        public let longitude: Double
        public init(code: String, latitude: Double, longitude: Double) {
            self.code = code
            self.latitude = latitude
            self.longitude = longitude
        }
    }

    /// The country whose centroid is nearest a location fix, or nil when none
    /// is within `within` degrees (for example in mid-ocean). Longitude is
    /// scaled by cos(latitude), which is accurate enough at this scale.
    /// Privacy: this is the only use of the device location, and only the
    /// resulting country code is kept, in memory.
    public static func nearestCountry(
        latitude: Double, longitude: Double, among centroids: [Centroid], within: Double = 30
    ) -> String? {
        var best: (code: String, distance: Double)?
        let scale = cos(latitude * .pi / 180)
        for centroid in centroids {
            var dLon = abs(longitude - centroid.longitude)
            if dLon > 180 { dLon = 360 - dLon }
            let dLat = latitude - centroid.latitude
            let distance = ((dLon * scale) * (dLon * scale) + dLat * dLat).squareRoot()
            if distance <= within, best == nil || distance < best!.distance {
                best = (centroid.code, distance)
            }
        }
        return best?.code
    }
}
