import AppIntents
import SharedCore

/// Shortcuts actions: protection on/off, profile, and mode. They run in the app
/// process against the shared AppModel (injected via AppDependencyManager), so
/// changes go through the same persistence and tunnel-reload path as the UI.

// MARK: - Parameter enums (app-side wrappers so SharedCore has no AppIntents dependency)

/// Keep these in sync with what Settings offers; any extra case here would let a
/// shortcut set a value the UI can no longer show or change.
enum ProfileChoice: String, AppEnum {
    case home, publicNetwork

    static let typeDisplayRepresentation = TypeDisplayRepresentation(name: "Profile")
    static let caseDisplayRepresentations: [ProfileChoice: DisplayRepresentation] = [
        .home: "Home",
        .publicNetwork: "Public",
    ]

    var kind: Profile.Kind {
        switch self {
        case .home: .home
        case .publicNetwork: .publicNetwork
        }
    }
}

enum ModeChoice: String, AppEnum {
    case standard, ask, strict

    static let typeDisplayRepresentation = TypeDisplayRepresentation(name: "Mode")
    static let caseDisplayRepresentations: [ModeChoice: DisplayRepresentation] = [
        .standard: "Standard",
        .ask: "Ask",
        .strict: "Strict",
    ]

    var runMode: RunMode {
        switch self {
        case .standard: .standard
        case .ask: .ask
        case .strict: .strict
        }
    }
}

// MARK: - Actions

struct StartProtectionIntent: AppIntent {
    static let title: LocalizedStringResource = "Turn Protection On"
    static let description = IntentDescription(
        "Starts FluxMoat's on-device traffic filtering (VPN).")

    @Dependency private var model: AppModel

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        model.setProtection(true)
        return .result(dialog: "FluxMoat protection is turning on.")
    }
}

struct StopProtectionIntent: AppIntent {
    static let title: LocalizedStringResource = "Turn Protection Off"
    static let description = IntentDescription(
        "Stops FluxMoat's on-device traffic filtering (VPN).")

    @Dependency private var model: AppModel

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        model.setProtection(false)
        return .result(dialog: "FluxMoat protection is turning off.")
    }
}

struct SetProfileIntent: AppIntent {
    static let title: LocalizedStringResource = "Set Profile"
    static let description = IntentDescription(
        "Switches the active FluxMoat profile (Home or Public).")

    @Parameter(title: "Profile") var profile: ProfileChoice
    @Dependency private var model: AppModel

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        guard let target = model.profiles.first(where: { $0.kind == profile.kind }) else {
            // Unreachable while ProfileChoice mirrors the built-in profiles.
            throw IntentError.profileUnavailable
        }
        model.activeProfileID = target.id
        return .result(dialog: "FluxMoat profile set to \(target.name).")
    }
}

struct SetModeIntent: AppIntent {
    static let title: LocalizedStringResource = "Set Mode"
    static let description = IntentDescription(
        "Switches FluxMoat's run mode (Standard, Ask or Strict).")

    @Parameter(title: "Mode") var mode: ModeChoice
    @Dependency private var model: AppModel

    @MainActor
    func perform() async throws -> some IntentResult & ProvidesDialog {
        model.mode = mode.runMode
        return .result(dialog: "FluxMoat mode set to \(mode.runMode.displayName).")
    }
}

enum IntentError: Error, CustomLocalizedStringResourceConvertible {
    case profileUnavailable

    var localizedStringResource: LocalizedStringResource {
        switch self {
        case .profileUnavailable: "That profile is not available."
        }
    }
}

// MARK: - Siri phrases

struct FluxMoatShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: StartProtectionIntent(),
            phrases: [
                "Turn on \(.applicationName)",
                "Start \(.applicationName) protection",
            ],
            shortTitle: "Protection On",
            systemImageName: "shield.lefthalf.filled"
        )
        AppShortcut(
            intent: StopProtectionIntent(),
            phrases: [
                "Turn off \(.applicationName)",
                "Stop \(.applicationName) protection",
            ],
            shortTitle: "Protection Off",
            systemImageName: "shield.slash"
        )
        AppShortcut(
            intent: SetProfileIntent(),
            phrases: [
                "Set \(.applicationName) profile",
                "Switch \(.applicationName) profile",
            ],
            shortTitle: "Set Profile",
            systemImageName: "person.crop.circle"
        )
        AppShortcut(
            intent: SetModeIntent(),
            phrases: [
                "Set \(.applicationName) mode",
                "Switch \(.applicationName) mode",
            ],
            shortTitle: "Set Mode",
            systemImageName: "dial.medium"
        )
    }
}
