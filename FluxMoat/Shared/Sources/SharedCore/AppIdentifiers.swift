import Foundation

/// Identifiers that depend on who signs the build. They're set once in
/// Config/Signing.xcconfig and reach the code through each target's
/// Info.plist, so a fork only has to change them in one place.
public enum AppIdentifiers {
    /// The App Group the app, the tunnel and the widget share. Every target
    /// carries the `FluxMoatAppGroup` key, so this works in all three.
    public static let appGroup = infoValue(
        "FluxMoatAppGroup", fallback: "group.com.example.fluxmoat"
    )

    /// CloudKit container for config sync. Only the app carries this key,
    /// which is fine since only the app talks to CloudKit.
    public static let iCloudContainer = infoValue(
        "FluxMoatICloudContainer", fallback: "iCloud.com.example.fluxmoat"
    )

    /// The tunnel extension's bundle id. The xcconfig names it
    /// `<app bundle id>.packettunnel`, so the app can derive it from its own
    /// id. Only meaningful when called from the app.
    public static var packetTunnelBundleID: String {
        (Bundle.main.bundleIdentifier ?? "com.example.fluxmoat") + ".packettunnel"
    }

    /// The fallbacks only kick in outside a built target (e.g. `swift test`),
    /// where there's no Info.plist and no App Group anyway. An unexpanded
    /// `$(...)` means the build setting was missing, so treat it the same way.
    private static func infoValue(_ key: String, fallback: String) -> String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String,
              !value.isEmpty, !value.contains("$(")
        else { return fallback }
        return value
    }
}
