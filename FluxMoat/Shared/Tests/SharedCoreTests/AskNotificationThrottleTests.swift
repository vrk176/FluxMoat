import Foundation
import Testing
@testable import SharedCore

@Suite struct QuietHoursTests {
    @Test func normalRangeContainsInsideOnly() {
        let quiet = QuietHours(startMinute: 9 * 60, endMinute: 17 * 60)
        #expect(quiet.contains(minuteOfDay: 9 * 60))
        #expect(quiet.contains(minuteOfDay: 12 * 60))
        #expect(!quiet.contains(minuteOfDay: 17 * 60)) // end exclusive
        #expect(!quiet.contains(minuteOfDay: 8 * 60))
    }

    /// The overnight case: 22:00 to 07:00 crosses midnight.
    @Test func midnightCrossingRangeWraps() {
        let quiet = QuietHours(startMinute: 22 * 60, endMinute: 7 * 60)
        #expect(quiet.contains(minuteOfDay: 23 * 60))
        #expect(quiet.contains(minuteOfDay: 0))
        #expect(quiet.contains(minuteOfDay: 6 * 60 + 59))
        #expect(!quiet.contains(minuteOfDay: 7 * 60))
        #expect(!quiet.contains(minuteOfDay: 12 * 60))
    }

    /// start == end is a zero-length window, not all-day silence.
    @Test func zeroLengthWindowNeverQuiet() {
        let quiet = QuietHours(startMinute: 600, endMinute: 600)
        #expect(!quiet.contains(minuteOfDay: 600))
        #expect(!quiet.contains(minuteOfDay: 0))
    }
}

@Suite struct AskNotificationThrottleTests {
    private let t0 = Date(timeIntervalSince1970: 1_700_000_000)

    /// First post goes through; the same eTLD+1 group is muted for its TTL
    /// even after the global cooldown has elapsed.
    @Test func groupCooldownOutlivesGlobalCooldown() {
        var throttle = AskNotificationThrottle(cooldown: 60, groupTTL: 1800)
        #expect(throttle.decide(group: "example.com", now: t0, minuteOfDay: 600) == .post)
        #expect(throttle.decide(group: "example.com", now: t0.addingTimeInterval(120), minuteOfDay: 600) == .groupCooldown)
        #expect(throttle.decide(group: "example.com", now: t0.addingTimeInterval(1801), minuteOfDay: 600) == .post)
    }

    /// A different group inside the global cooldown is still suppressed
    /// (one banner per minute overall), then posts once the window clears.
    @Test func globalCooldownAppliesAcrossGroups() {
        var throttle = AskNotificationThrottle(cooldown: 60, groupTTL: 1800)
        #expect(throttle.decide(group: "a.com", now: t0, minuteOfDay: 600) == .post)
        #expect(throttle.decide(group: "b.com", now: t0.addingTimeInterval(30), minuteOfDay: 600) == .globalCooldown)
        #expect(throttle.decide(group: "b.com", now: t0.addingTimeInterval(61), minuteOfDay: 600) == .post)
    }

    /// Quiet hours win over everything and mutate nothing, so the first
    /// post after the window still goes through immediately.
    @Test func quietHoursSuppressWithoutConsumingState() {
        var throttle = AskNotificationThrottle(
            quietHours: QuietHours(startMinute: 1320, endMinute: 420), cooldown: 60, groupTTL: 1800)
        #expect(throttle.decide(group: "a.com", now: t0, minuteOfDay: 1380) == .quietHours)
        #expect(throttle.decide(group: "a.com", now: t0.addingTimeInterval(10), minuteOfDay: 500) == .post)
    }

    /// Group memory is bounded: old entries are evicted, not grown forever.
    @Test func groupMemoryIsBounded() {
        var throttle = AskNotificationThrottle(cooldown: 0, groupTTL: 100_000, maxGroups: 4)
        for i in 0..<8 {
            _ = throttle.decide(group: "g\(i).com", now: t0.addingTimeInterval(Double(i)), minuteOfDay: 600)
        }
        // The oldest group has been evicted → posting it again succeeds.
        #expect(throttle.decide(group: "g0.com", now: t0.addingTimeInterval(10), minuteOfDay: 600) == .post)
        // The newest is still remembered → suppressed.
        #expect(throttle.decide(group: "g7.com", now: t0.addingTimeInterval(11), minuteOfDay: 600) == .groupCooldown)
    }

    // MARK: - notificationGroup (eTLD+1 approximation)

    @Test func groupsSubdomainsToRegistrableDomain() {
        #expect(AskNotificationThrottle.notificationGroup(for: "Sub1.Example.com") == "example.com")
        #expect(AskNotificationThrottle.notificationGroup(for: "a.b.c.example.com") == "example.com")
        #expect(AskNotificationThrottle.notificationGroup(for: "example.com") == "example.com")
    }

    @Test func multiPartSuffixesKeepThreeLabels() {
        #expect(AskNotificationThrottle.notificationGroup(for: "www.bbc.co.uk") == "bbc.co.uk")
        #expect(AskNotificationThrottle.notificationGroup(for: "cdn.shop.example.com.cn") == "example.com.cn")
    }

    /// IPs and single labels group as themselves, no fake domains.
    @Test func nonDomainsGroupAsThemselves() {
        #expect(AskNotificationThrottle.notificationGroup(for: "192.168.1.1") == "192.168.1.1")
        #expect(AskNotificationThrottle.notificationGroup(for: "2606:4700:4700::1111") == "2606:4700:4700::1111")
        #expect(AskNotificationThrottle.notificationGroup(for: "localhost") == "localhost")
    }
}