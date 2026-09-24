import SwiftUI

/// The five onboarding stages. All copy the flow shows lives here so it can be
/// changed in one place. `boundaries` is the exception: it comes from
/// `CapabilityCopy` because Settings and the Dashboard show the same sentences.
enum OnboardingStage: Int, CaseIterable, Identifiable {
    case awake, flow, understand, privacy, ready

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .awake: "This is your device"
        case .flow: "See where your network goes"
        case .understand: "Understand what deserves attention"
        case .privacy: "Analyzed on your device"
        case .ready: "Ready to see your network?"
        }
    }

    var body: String {
        switch self {
        case .awake:
            "Throughout the day, it may connect to services around the world — mostly out of sight."
        case .flow:
            "Invisible connections become clear destinations and activity."
        case .understand:
            "See what looks routine, what deserves attention, and what was blocked.\nLocations are estimated from IP addresses."
        case .privacy:
            "FluxMoat observes and filters network activity locally. Your traffic never passes through servers operated by FluxMoat."
        case .ready:
            "iOS will ask for permission to set up a local VPN. Analysis and filtering happen on your device."
        }
    }

    /// Capability limits shown on the privacy stage: device-wide, no HTTPS
    /// decryption, asynchronous decisions, IP-based estimates, one VPN at a time.
    static let boundaries: [String] = CapabilityCopy.boundaries

    // Ready-stage strings for every state.
    /// Replaces the ready body once protection is on.
    static let readyBodyOn = "Your network activity is now visible and processed locally."
    static let ctaTurnOn = "Turn On Protection"
    static let ctaNotNow = "Not Now"
    static let ctaRetry = "Try Again"
    static let ctaEnter = "Enter FluxMoat"
    static let waitingForIOS = "Waiting for iOS…"
    static let protectionOn = "Protection is on"
    static let notStartedSummary = "Protection isn't on yet. Try again, or turn it on later from the Dashboard."
    static let settingsHint = "You can also check the VPN configuration in the Settings app."
    static let technicalDetails = "Technical details"
}

/// Ready-screen phase, derived from AppModel so onboarding can't disagree with
/// the Dashboard. Denied and failed aren't told apart: `protectionError` is a
/// raw `localizedDescription` and guessing intent from it isn't reliable, so
/// there is one "not started" state with the raw text behind a disclosure.
enum OnboardingVPNPhase: Equatable {
    case idle
    case requesting
    case on
    case notStarted(detail: String)

    @MainActor
    static func derive(from model: AppModel) -> OnboardingVPNPhase {
        if model.isProtectionOn { return .on }
        if model.protectionTransition == .starting { return .requesting }
        if let error = model.protectionError { return .notStarted(detail: error) }
        return .idle
    }
}
