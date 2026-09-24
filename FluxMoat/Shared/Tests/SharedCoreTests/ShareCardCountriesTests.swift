import Foundation
import Testing
@testable import SharedCore

/// The Countries share card's numbers: the per-country rollup it prints,
/// the glow it draws, where its markers land and which country a fix is in.
/// Companion to `ShareCardDataTests` for the third card.
@Suite struct ShareCardCountriesTests {
    private typealias IP = TrafficEventStore.IPAggregate
    private typealias Country = TrafficEventStore.CountryAggregate

    private func ip(_ address: String, flows: Int, blocked: Int = 0, threat: Int = 0) -> IP {
        IP(remoteIP: address, flows: flows, blockedFlows: blocked, threatFlows: threat, bytesUp: 1, bytesDown: 2)
    }

    // MARK: - CountryAggregate.aggregate

    /// Threat blocks merge per country like the other counts, unplaced IPs
    /// land in one nil bucket, and the per-country sums add back up to the
    /// per-IP input.
    @Test func aggregateMergesThreatAndKeepsOneUnplacedBucket() {
        let rows = Country.aggregate([
            ip("198.51.100.1", flows: 10, blocked: 4, threat: 1),
            ip("198.51.100.2", flows: 5, blocked: 2, threat: 2),
            ip("203.0.113.9", flows: 7, blocked: 0),
            ip("10.0.0.1", flows: 3, blocked: 1, threat: 1),
            ip("192.168.1.1", flows: 2),
        ]) { address in
            switch address {
            case "198.51.100.1", "198.51.100.2": "US"
            case "203.0.113.9": "DE"
            default: nil
            }
        }
        let us = rows.first { $0.countryCode == "US" }
        #expect(us?.flows == 15)
        #expect(us?.blockedFlows == 6)
        #expect(us?.threatFlows == 3)
        #expect(rows.first { $0.countryCode == "DE" }?.threatFlows == 0)
        let unplaced = rows.filter { $0.countryCode == nil }
        #expect(unplaced.count == 1)
        #expect(unplaced.first?.flows == 5)
        #expect(unplaced.first?.blockedFlows == 1 && unplaced.first?.threatFlows == 1)
        #expect(rows.reduce(0) { $0 + $1.flows } == 27)
        #expect(rows.reduce(0) { $0 + $1.threatFlows } == 4)
        // Most flows first.
        #expect(rows.map(\.countryCode) == ["US", "DE", nil])
    }

    // MARK: - Rollup

    private func country(_ code: String?, _ flows: Int, blocked: Int = 0, threat: Int = 0) -> Country {
        Country(countryCode: code, flows: flows, blockedFlows: blocked, threatFlows: threat, bytesUp: 0, bytesDown: 0)
    }

    /// The spec's sample: 14 placed countries, 38 unplaced, the top five in
    /// order, and "+9 more".
    @Test func rollupShapesTheSpecSample() {
        let lit: [(String, Int)] = [
            ("US", 612), ("GB", 231), ("NL", 143), ("DE", 118), ("JP", 97),
            ("IE", 18), ("FR", 9), ("SE", 4), ("FI", 3), ("SG", 3), ("AU", 2), ("BR", 2), ("IN", 2), ("CA", 2),
        ]
        var rows = lit.shuffled().map { country($0.0, $0.1) }
        rows.append(country(nil, 38))
        let rollup = CountriesCardMath.Rollup(rows)
        #expect(rollup.distinctCountries == 14)
        #expect(rollup.unplacedFlows == 38)
        #expect(rollup.top.map(\.code) == ["US", "GB", "NL", "DE", "JP"])
        #expect(rollup.restCountries == 9)
        #expect(rollup.placedFlows + rollup.unplacedFlows == 1284)
    }

    /// Ties rank by code so the ledger is stable; codes are normalised to
    /// upper case; an empty code is an unplaced row, not a country called "".
    @Test func rollupOrdersTiesByCodeAndTreatsEmptyCodeAsUnplaced() {
        let rollup = CountriesCardMath.Rollup([
            country("sg", 3), country("AU", 3), country("", 4), country(nil, 6), country("BR", 3),
        ])
        #expect(rollup.placed.map(\.code) == ["AU", "BR", "SG"])
        #expect(rollup.unplacedFlows == 10)
        #expect(rollup.restCountries == 0)
    }

    /// Fewer than five countries is fewer rows and fewer markers, and none
    /// at all is zero everywhere: the card prints "0 countries" then.
    @Test func rollupHandlesSparseAndEmptyWindows() {
        let two = CountriesCardMath.Rollup([country("US", 9, blocked: 2, threat: 1), country("JP", 1)])
        #expect(two.top.count == 2)
        #expect(two.top.first?.blocked == 2 && two.top.first?.threat == 1)
        let none = CountriesCardMath.Rollup([country(nil, 40)])
        #expect(none.distinctCountries == 0)
        #expect(none.top.isEmpty)
        #expect(none.unplacedFlows == 40)
        #expect(CountriesCardMath.Rollup([]).unplacedFlows == 0)
    }

    // MARK: - Glow

    /// 1.25 × cube root: 612 connections is a 10.6° glow, 1 connection
    /// 1.25°, and the scale stays monotonic. Nothing has no glow.
    @Test func haloRadiusIsCubeRootScaled() {
        #expect(abs(CountriesCardMath.haloRadius(flows: 612) - 10.613) < 0.01)
        #expect(abs(CountriesCardMath.haloRadius(flows: 1) - 1.25) < 0.0001)
        #expect(abs(CountriesCardMath.haloRadius(flows: 8) - 2.5) < 0.0001)
        #expect(CountriesCardMath.haloRadius(flows: 0) == 0)
        #expect(CountriesCardMath.haloRadius(flows: -5) == 0)
        #expect(CountriesCardMath.haloRadius(flows: 231) < CountriesCardMath.haloRadius(flows: 612))
    }

    @Test func glowLevelFallsFromCentreToEdge() {
        #expect(CountriesCardMath.glowLevel(distance: 0, radius: 4) == 1)
        #expect(CountriesCardMath.glowLevel(distance: 4, radius: 4) == 0)
        #expect(CountriesCardMath.glowLevel(distance: 5, radius: 4) == 0)
        #expect(CountriesCardMath.glowLevel(distance: 1, radius: 0) == 0)
        let mid = CountriesCardMath.glowLevel(distance: 2, radius: 4)
        #expect(mid > 0 && mid < 1)
    }

    // MARK: - Markers

    private typealias P = CountriesCardMath.Point
    private let mapSize = P(x: 360, y: 131)

    /// Far-apart anchors keep their markers at home.
    @Test func markersStayOnIsolatedAnchors() {
        let anchors = [P(x: 81.4, y: 36.2), P(x: 318.3, y: 39.8)]
        let placed = CountriesCardMath.placeMarkers(anchors: anchors, radius: 5.4, size: mapSize)
        #expect(placed == anchors)
    }

    /// The spec's European cluster (GB / NL / DE, a few points apart) comes
    /// apart: no two markers overlap, every displaced one is still near its
    /// anchor, and the first-ranked anchor that is clear stays put.
    @Test func markersInAClusterAreSpreadWithoutOverlap() {
        let us = P(x: 81.4, y: 36.2)
        let gb = P(x: 177.5, y: 22.0)
        let nl = P(x: 185.3, y: 23.8)
        let de = P(x: 190.4, y: 24.8)
        let jp = P(x: 318.3, y: 39.8)
        let radius = 5.4
        let placed = CountriesCardMath.placeMarkers(anchors: [us, gb, nl, de, jp], radius: radius, size: mapSize)
        #expect(placed.count == 5)
        #expect(placed[0] == us)
        #expect(placed[4] == jp)
        for i in placed.indices {
            for j in placed.indices where j > i {
                #expect(placed[i].distance(to: placed[j]) >= 2 * radius + 2 - 0.001)
            }
        }
        // Displaced markers hang within one offset's reach of their anchor.
        for (anchor, marker) in zip([gb, nl, de], placed[1...3]) {
            #expect(anchor.distance(to: marker) <= 26)
        }
        // Same input, same picture.
        #expect(CountriesCardMath.placeMarkers(anchors: [us, gb, nl, de, jp], radius: radius, size: mapSize) == placed)
    }

    /// A marker on the top edge is pulled inside the map, and that counts
    /// as displaced (a leader line is drawn to the true anchor).
    @Test func markersAreKeptInsideTheMap() {
        let north = P(x: 200, y: 2)
        let placed = CountriesCardMath.placeMarkers(anchors: [north], radius: 5.4, size: mapSize)
        #expect(placed[0].y >= 5.4 + 1)
        #expect(placed[0] != north)
        #expect(CountriesCardMath.placeMarkers(anchors: [], radius: 5.4, size: mapSize).isEmpty)
    }

    // MARK: - Origin

    private let centroids = [
        CountriesCardMath.Centroid(code: "NL", latitude: 52.2, longitude: 5.3),
        CountriesCardMath.Centroid(code: "DE", latitude: 51.2, longitude: 10.4),
        CountriesCardMath.Centroid(code: "BE", latitude: 50.6, longitude: 4.5),
        CountriesCardMath.Centroid(code: "US", latitude: 39.8, longitude: -98.6),
        CountriesCardMath.Centroid(code: "NZ", latitude: -41.8, longitude: 172.8),
    ]

    @Test func nearestCountryPicksTheClosestCentroid() {
        #expect(CountriesCardMath.nearestCountry(latitude: 52.4, longitude: 4.9, among: centroids) == "NL")
        #expect(CountriesCardMath.nearestCountry(latitude: 52.5, longitude: 13.4, among: centroids) == "DE")
        #expect(CountriesCardMath.nearestCountry(latitude: 40.7, longitude: -74.0, among: centroids) == "US")
    }

    /// Mid-ocean is nobody's country, and the date line is not 340° wide.
    @Test func nearestCountryRefusesTheOpenOceanAndWrapsTheDateLine() {
        #expect(CountriesCardMath.nearestCountry(latitude: 0, longitude: -30, among: centroids) == nil)
        #expect(CountriesCardMath.nearestCountry(latitude: -41, longitude: -179, among: centroids) == "NZ")
        #expect(CountriesCardMath.nearestCountry(latitude: 0, longitude: 0, among: []) == nil)
    }

    /// A single-point-per-country table is approximate: a coastal city far
    /// from its own huge country's centroid can read as its smaller
    /// neighbor's. This is why `CountryRow` labels the reader's own row
    /// "· you (approx.)" instead of asserting it outright.
    @Test func nearestCountryCanMisplaceACoastalCityInABigCountry() {
        let americas = [
            CountriesCardMath.Centroid(code: "US", latitude: 39.8, longitude: -98.6),
            CountriesCardMath.Centroid(code: "CA", latitude: 56.1, longitude: -106.3),
            CountriesCardMath.Centroid(code: "BS", latitude: 25.0, longitude: -77.4),
        ]
        // Seattle: nearer to Canada's centroid than the US's own.
        #expect(CountriesCardMath.nearestCountry(latitude: 47.6, longitude: -122.3, among: americas) == "CA")
        // Miami: nearer to the Bahamas' centroid than the US's own.
        #expect(CountriesCardMath.nearestCountry(latitude: 25.8, longitude: -80.2, among: americas) == "BS")
    }
}
