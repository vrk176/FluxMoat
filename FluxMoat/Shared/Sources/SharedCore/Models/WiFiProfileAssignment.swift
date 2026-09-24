import Foundation

/// Wi-Fi to profile automation rule: joining `ssid` switches the active
/// profile. Carries the profile's unmatched action so the tunnel can enforce
/// it without the app's full profile list, and the kind so the app can show
/// the switch in its UI.
///
/// The SSID is read with `NEHotspotNetwork`, which requires the Access Wi-Fi
/// Information entitlement on both app and tunnel plus an active VPN of our
/// own, so no location permission is requested. SSIDs are user config but
/// never appear in logs; log a hash prefix instead.
public struct WiFiProfileAssignment: Codable, Sendable, Equatable {
    public var ssid: String
    public var profileKind: Profile.Kind
    public var unmatchedAction: RuleAction

    public init(ssid: String, profileKind: Profile.Kind, unmatchedAction: RuleAction) {
        self.ssid = ssid
        self.profileKind = profileKind
        self.unmatchedAction = unmatchedAction
    }

    /// Exact-match lookup (SSIDs are byte-exact identifiers, not patterns).
    public static func match(_ ssid: String, in assignments: [WiFiProfileAssignment]) -> WiFiProfileAssignment? {
        assignments.first { $0.ssid == ssid }
    }
}
