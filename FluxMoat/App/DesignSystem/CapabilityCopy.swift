import Foundation

/// User-facing statements of what the app cannot do. Kept in one place so
/// onboarding, the Dashboard and Settings use identical wording.
enum CapabilityCopy {
    /// Shown by onboarding at first launch as required disclosures. Editing one
    /// changes that disclosure.
    static let deviceWide =
        "Network activity is shown for the whole device. iOS doesn't identify the originating app."
    static let encryptedStaysEncrypted = "Encrypted content stays encrypted."
    static let alertsDoNotPause = "Alerts don't pause a connection while waiting for your response."
    static let locationsAreEstimates = "Locations are estimates and may be inaccurate."
    static let singleVPN = "iOS allows one VPN of this kind at a time."

    /// The five disclosures in onboarding order, most important first.
    static let boundaries: [String] = [
        deviceWide,
        encryptedStaysEncrypted,
        alertsDoNotPause,
        locationsAreEstimates,
        singleVPN,
    ]

    /// Must stay on Settings' Limitations list even with the "Block other
    /// encrypted DNS" switch: an app using its own private DoH/DoT endpoint
    /// can't be caught by any list of public resolvers.
    static let encryptedDNSBypass =
        "Apps using their own encrypted DNS may bypass domain-based filtering; IP rules still apply."

    /// Long form for the Settings Limitations list.
    static let icmpUnfiltered = "Ping (ICMP) traffic isn't filtered yet, so ICMP rules have no effect."

    /// Short form shown in the rule editor when ICMP is picked.
    static let icmpEditorHint = "ICMP isn't filtered yet — this rule won't take effect."
}
