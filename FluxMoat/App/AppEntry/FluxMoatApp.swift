import AppIntents
import os
import SwiftUI
import UIKit
import UserNotifications

// Logs trait and scene-phase changes at the root, to tell whether the OS
// flipped the color scheme or the UI rendered dark under a light trait.
private let appearanceLog = Logger(subsystem: "fluxmoat", category: "appearance")

private func schemeName(_ scheme: ColorScheme) -> String {
    scheme == .dark ? "dark" : "light"
}

/// Owns the orientation mask and receives notification taps.
///
/// The app is portrait-only except for the world map's full-screen mode.
/// Info.plist advertises landscape so the scene may rotate at all; this mask is
/// the actual gate, raised by the map while its cover is shown.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    @MainActor static var supportedOrientations: UIInterfaceOrientationMask = .portrait

    /// The `AppModel` the UI is bound to, so notification taps can route into it.
    /// Static because UIKit creates this object; weak because `FluxMoatApp` owns the model.
    @MainActor static weak var model: AppModel?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        // Must be set before launch finishes, or the tap that cold-launched
        // the app is delivered to no delegate.
        UNUserNotificationCenter.current().delegate = self
        return true
    }

    func application(
        _ application: UIApplication,
        supportedInterfaceOrientationsFor window: UIWindow?
    ) -> UIInterfaceOrientationMask {
        MainActor.assumeIsolated { AppDelegate.supportedOrientations }
    }

    // MARK: - Notification taps

    // Nonisolated: UserNotifications calls these off the main actor with
    // non-Sendable arguments, so read out the String first, then hop.
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse
    ) async {
        let destination = response.notification.request.content
            .userInfo[WeeklySummaryNotifier.destinationKey] as? String
        guard destination == WeeklySummaryNotifier.weeklySummaryDestination else { return }
        await MainActor.run {
            AppDelegate.model?.pendingDestination = .insightsWeeklySummary
            appearanceLog.notice("✅ app:notification tap VERIFY destination=weeklySummary delivered=\(AppDelegate.model != nil, privacy: .public)")
        }
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification
    ) async -> UNNotificationPresentationOptions {
        // Only the weekly summary shows in the foreground. Other notifications
        // (such as the tunnel's ask-mode banners) keep the default of not
        // presenting while the app is open.
        let destination = notification.request.content
            .userInfo[WeeklySummaryNotifier.destinationKey] as? String
        return destination == WeeklySummaryNotifier.weeklySummaryDestination
            ? [.banner, .sound]
            : []
    }
}

@main
struct FluxMoatApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    init() {
        // App Intents run in this process and resolve AppModel through the
        // dependency manager, so register the same instance the UI uses.
        let model = AppModel()
        _model = State(initialValue: model)
        AppDependencyManager.shared.add(dependency: model)
        AppDelegate.model = model
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            // No-op unless iCloud sync is on.
            model.cloudSyncOnForeground()
            // Refreshes only blocklists the user already downloaded; the first
            // download is always user-initiated. Debounced per source (6h) in
            // the model, so calling this on every foreground is cheap.
            Task { await model.refreshBlocklistsOnForeground() }
        }
    }
}

struct RootView: View {
    @AppStorage("onboardingComplete") private var onboardingComplete = false
    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.scenePhase) private var scenePhase

    private enum MainTab: Hashable { case dashboard, insights, rules, settings }
    @State private var selection: MainTab = .dashboard
    /// Re-selecting the current tab bumps its token, which rebuilds the tab
    /// (pops its navigation stack and scrolls to top).
    @State private var resetTokens: [MainTab: Int] = [:]

    /// Tab identity includes the color scheme so an appearance change rebuilds
    /// every tab. Otherwise a tab that was off-screen or suspended during the
    /// change keeps cells drawn in the old scheme. Pickers and filters survive
    /// the rebuild because they live in SceneStorage.
    private func token(_ tab: MainTab) -> String {
        "\(resetTokens[tab, default: 0])-\(schemeName(colorScheme))"
    }

    var body: some View {
        TabView(selection: .init(
            get: { selection },
            set: { tapped in
                if tapped == selection { resetTokens[tapped, default: 0] += 1 }
                selection = tapped
            }
        )) {
            Tab("Dashboard", systemImage: "shield.lefthalf.filled", value: MainTab.dashboard) {
                DashboardView().id(token(.dashboard))
            }
            Tab("Insights", systemImage: "chart.bar.xaxis", value: MainTab.insights) {
                InsightsView().id(token(.insights))
            }
            Tab("Rules", systemImage: "list.bullet.rectangle", value: MainTab.rules) {
                RulesView().id(token(.rules))
            }
            Tab("Settings", systemImage: "gearshape", value: MainTab.settings) {
                SettingsView().id(token(.settings))
            }
        }
        // Full-screen cover rather than a sheet: onboarding is a dark scene and
        // must not be interactively dismissed.
        .fullScreenCover(isPresented: .init(
            get: { !onboardingComplete },
            set: { onboardingComplete = !$0 }
        )) {
            OnboardingView(onFinish: { onboardingComplete = true })
                .environment(model)
        }
        // Sync the toggle with the real VPN state on launch.
        .task { await model.refreshProtectionState() }
        // On cold launch the scene may already be active before the scenePhase
        // onChange above is installed, so refresh here too. The refresh is
        // single-flight and debounced, so running twice is harmless.
        .task { await model.refreshBlocklistsOnForeground() }
        // Covers both a tap while running (onChange) and a cold launch (onAppear).
        // Use the new value from the change rather than re-reading the model: a
        // tab that is already built may consume and clear it first.
        .onChange(of: model.pendingDestination) { _, new in selectPendingTab(new) }
        .onAppear {
            selectPendingTab(model.pendingDestination)
            appearanceLog.notice("✅ app:appearance baseline VERIFY scheme=\(schemeName(colorScheme), privacy: .public) phase=\(String(describing: scenePhase), privacy: .public) onboardingCover=\(!onboardingComplete, privacy: .public)")
        }
        .onChange(of: colorScheme) { old, new in
            appearanceLog.notice("✅ app:appearance trait VERIFY \(schemeName(old), privacy: .public)→\(schemeName(new), privacy: .public) phase=\(String(describing: scenePhase), privacy: .public) onboardingCover=\(!onboardingComplete, privacy: .public)")
        }
        .onChange(of: scenePhase) { old, new in
            appearanceLog.notice("✅ app:appearance phase VERIFY \(String(describing: old), privacy: .public)→\(String(describing: new), privacy: .public) scheme=\(schemeName(colorScheme), privacy: .public)")
        }
    }

    /// Selects the tab for a pending destination. Does not clear it: the target
    /// view may not exist yet on cold launch, and it clears the destination
    /// itself once it has acted on it.
    private func selectPendingTab(_ destination: AppModel.PendingDestination?) {
        switch destination {
        case .insightsWeeklySummary: selection = .insights
        case .settingsHistoryRetention, .settingsEncryptedDNS: selection = .settings
        case nil: break
        }
    }
}
