import UserNotifications
import os

private let notifyLog = Logger(subsystem: "fluxmoat", category: "notifications")

/// Schedules the weekly summary notification. Also the only place in the app
/// that requests notification permission.
///
/// The copy contains no numbers on purpose. The request repeats weekly, and its
/// content is fixed at scheduling time, so any figure would be repeated every
/// week. Real figures would need a background refresh that reschedules a
/// one-shot notification each week.
///
/// `@MainActor` because every caller is on the main actor, and with the Swift 6.2
/// compiler a nonisolated `async -> Bool` awaited from a main-actor view crashes
/// IRGen (it needs an `@isolated(any)` reabstraction thunk).
@MainActor
enum WeeklySummaryNotifier {
    /// Fixed identifier so rescheduling replaces the pending request instead of adding one.
    static let requestIdentifier = "fluxmoat.weekly-summary"

    /// userInfo key and value used to route a notification tap. Routing uses the
    /// payload rather than the request identifier, which is only a scheduling handle.
    /// Nonisolated because the notification delegate reads them off the main actor.
    nonisolated static let destinationKey = "fluxmoat.destination"
    nonisolated static let weeklySummaryDestination = "insights.weekly-summary"

    /// Monday 09:00 local time, after the week being summarized has ended and
    /// outside the default quiet hours (22:00 to 07:00).
    /// `weekday` uses Gregorian numbering (1 = Sunday); other calendars may land
    /// on a different day, which the copy never names.
    static let weekday = 2
    static let hour = 9

    /// The app's only `requestAuthorization` call; Ask mode goes through here too.
    /// Returns the user's decision so the toggle can turn itself back off on denial.
    static func requestAuthorization() async -> Bool {
        do {
            let granted = try await UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert, .sound, .badge])
            notifyLog.notice("✅ app:notifications authorize VERIFY granted=\(granted, privacy: .public)")
            return granted
        } catch {
            // The prompt never reached the user; treat it as a decline.
            notifyLog.error("❌ app:notifications authorize FAILED type=\(String(describing: type(of: error)), privacy: .public)")
            return false
        }
    }

    /// Installs the repeating request, replacing whatever was pending under the
    /// same identifier.
    static func schedule() async {
        var components = DateComponents()
        components.weekday = weekday
        components.hour = hour
        components.minute = 0

        let content = UNMutableNotificationContent()
        content.title = summaryTitle
        content.body = summaryBody
        content.sound = .default
        content.userInfo = [destinationKey: weeklySummaryDestination]

        let request = UNNotificationRequest(
            identifier: requestIdentifier,
            content: content,
            trigger: UNCalendarNotificationTrigger(dateMatching: components, repeats: true)
        )
        let center = UNUserNotificationCenter.current()
        // `add` replaces by identifier anyway; removing first means a failed
        // add leaves no stale request behind.
        center.removePendingNotificationRequests(withIdentifiers: [requestIdentifier])
        do {
            try await center.add(request)
            notifyLog.notice("✅ app:notifications weekly VERIFY scheduled weekday=\(weekday, privacy: .public) hour=\(hour, privacy: .public)")
        } catch {
            notifyLog.error("❌ app:notifications weekly FAILED op=add type=\(String(describing: type(of: error)), privacy: .public)")
        }
    }

    static func cancel() {
        UNUserNotificationCenter.current()
            .removePendingNotificationRequests(withIdentifiers: [requestIdentifier])
        notifyLog.notice("✅ app:notifications weekly VERIFY cancelled")
    }

    /// The user can revoke permission in system Settings without the app being
    /// told, so the toggle checks this each time it appears.
    static func isAuthorized() async -> Bool {
        let status = await UNUserNotificationCenter.current().notificationSettings()
            .authorizationStatus
        return status == .authorized || status == .provisional || status == .ephemeral
    }

    // MARK: - Copy
    //
    // Neither string may state a quantity, a comparison, or anything else that
    // could be true at scheduling time and false at delivery time.

    static let summaryTitle = "Your week in traffic"

    static let summaryBody = "See what your phone talked to this week."
}
