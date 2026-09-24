import Foundation
import Testing
@testable import SharedCore

@Suite struct BlocklistAutoRefreshTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let url = URL(string: "https://example.test/list.txt")!

    private func source(
        enabled: Bool = true,
        url: URL?,
        lastUpdatedAt: Date?
    ) -> BlocklistSource {
        BlocklistSource(
            name: "list", sourceURL: url, format: .hosts,
            enabled: enabled, lastUpdatedAt: lastUpdatedAt, entryCount: 100
        )
    }

    @Test func neverDownloadedIsLeftForTheUsersOwnTap() {
        let fresh = source(url: url, lastUpdatedAt: nil)
        #expect(!BlocklistAutoRefresh.shouldRefresh(fresh, lastCheckedAt: nil, now: now))
        // Even a stale auto-check stamp can't promote it: the first download
        // is a knowing action, full stop.
        #expect(!BlocklistAutoRefresh.shouldRefresh(
            fresh, lastCheckedAt: now.addingTimeInterval(-86_400), now: now))
    }

    @Test func disabledOrURLlessSourcesAreNeverFetched() {
        let old = now.addingTimeInterval(-86_400)
        #expect(!BlocklistAutoRefresh.shouldRefresh(
            source(enabled: false, url: url, lastUpdatedAt: old), lastCheckedAt: nil, now: now))
        // The imported-domains pseudo source has nowhere to fetch from.
        #expect(!BlocklistAutoRefresh.shouldRefresh(
            source(url: nil, lastUpdatedAt: old), lastCheckedAt: nil, now: now))
    }

    @Test func downloadedAndStaleIsDue() {
        let old = now.addingTimeInterval(-BlocklistAutoRefresh.minimumInterval - 1)
        #expect(BlocklistAutoRefresh.shouldRefresh(
            source(url: url, lastUpdatedAt: old), lastCheckedAt: nil, now: now))
    }

    @Test func windowIsExactlySixHoursAndInclusiveAtTheBoundary() {
        #expect(BlocklistAutoRefresh.minimumInterval == 6 * 60 * 60)
        let downloaded = now.addingTimeInterval(-30 * 86_400)
        let atBoundary = now.addingTimeInterval(-BlocklistAutoRefresh.minimumInterval)
        #expect(BlocklistAutoRefresh.shouldRefresh(
            source(url: url, lastUpdatedAt: downloaded), lastCheckedAt: atBoundary, now: now))
        #expect(!BlocklistAutoRefresh.shouldRefresh(
            source(url: url, lastUpdatedAt: downloaded),
            lastCheckedAt: atBoundary.addingTimeInterval(1), now: now))
    }

    @Test func aCheckThatFound304StillBuysTheQuietWindow() {
        // The 304 case: content unchanged for a month, but we talked to the
        // server ten minutes ago. Without the check stamp this would refetch
        // on every single foreground.
        let source = source(url: url, lastUpdatedAt: now.addingTimeInterval(-30 * 86_400))
        #expect(!BlocklistAutoRefresh.shouldRefresh(
            source, lastCheckedAt: now.addingTimeInterval(-600), now: now))
    }

    @Test func aManualUpdateJustNowSuppressesTheNextAutoRound() {
        // No check stamp at all (auto has never run), but the user tapped
        // Update a minute ago, which counts as contact.
        let justUpdated = source(url: url, lastUpdatedAt: now.addingTimeInterval(-60))
        #expect(!BlocklistAutoRefresh.shouldRefresh(justUpdated, lastCheckedAt: nil, now: now))
    }

    @Test func aStampFromTheFutureDoesNotFreezeRefreshesForever() {
        // Clock moved backwards; without the guard this source would be stuck
        // until real time caught up with the bogus stamp.
        let source = source(url: url, lastUpdatedAt: now.addingTimeInterval(-30 * 86_400))
        #expect(BlocklistAutoRefresh.shouldRefresh(
            source, lastCheckedAt: now.addingTimeInterval(30 * 86_400), now: now))
    }
}
