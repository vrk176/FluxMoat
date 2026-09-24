import CoreLocation
import Observation

/// Approximate device location, used only as the origin of the map's connection arcs.
/// Requests reduced accuracy. The coordinate stays in memory: never logged, persisted
/// or sent anywhere. If permission is denied the map just draws no arcs.
@Observable
final class MapOriginLocator: NSObject, CLLocationManagerDelegate {
    private let manager = CLLocationManager()
    private(set) var coordinate: CLLocationCoordinate2D?

    /// Latest fix from any locator. The Insights share sheet only shows "Show my country"
    /// when this is set and never requests location itself. Memory only, never logged
    /// or persisted; the card reduces it to a country code before drawing.
    @MainActor private(set) static var latestFix: CLLocationCoordinate2D?

    /// Idempotent: prompts only when undetermined, fetches one fix when authorized,
    /// does nothing when denied.
    func request() {
        manager.delegate = self
        manager.desiredAccuracy = kCLLocationAccuracyReduced
        switch manager.authorizationStatus {
        case .notDetermined:
            manager.requestWhenInUseAuthorization()
        case .authorizedWhenInUse, .authorizedAlways:
            manager.requestLocation()
        default:
            break
        }
    }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        switch manager.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways:
            manager.requestLocation()
        default:
            break
        }
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        coordinate = locations.last?.coordinate
        if let fix = locations.last?.coordinate {
            Task { @MainActor in Self.latestFix = fix }
        }
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        // Fail silently. Don't log the error, it can contain location details.
    }
}
