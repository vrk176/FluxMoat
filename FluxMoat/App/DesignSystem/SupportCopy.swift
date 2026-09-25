import Foundation

/// External links and contact info shown in Settings. Each value is optional:
/// the matching row is hidden when it's nil, so a missing address never shows
/// up as a broken link.
enum SupportCopy {
    /// Help page (the project README). nil hides Settings' "Help & FAQ" row.
    static let helpURL: URL? = URL(string: "https://github.com/vrk176/FluxMoat#readme")

    /// Support mailbox. nil hides Settings' "Contact support" row.
    static let supportEmail: String? = "connect@hominexis.com"

    /// Privacy section of the project README. nil hides the About row.
    static let privacyPolicyURL: URL? = URL(string: "https://github.com/vrk176/FluxMoat#privacy")

    /// Discord invite. nil hides Settings' "Community" section. Invites can be
    /// revoked or expire, so set this to nil rather than ship a dead link.
    static let communityURL: URL? = URL(string: "https://discord.gg/Y6CahCf4eF")

    /// App Store page for the developer's other app. nil hides Settings'
    /// "Also from the developer" section. Opened by the system; nothing is
    /// fetched in-app.
    static let siblingAppURL: URL? = URL(
        string: "https://apps.apple.com/us/app/timeback-take-back-your-time/id6759700323"
    )

    /// Name as shown on the App Store.
    static let siblingAppName = "TimeBack"

    /// TimeBack's App Store subtitle, verbatim.
    static let siblingAppTagline = "Take back your time"

    /// `mailto:` link with the app version in the subject. nil if `supportEmail`
    /// is nil.
    static func supportMailto(version: String) -> URL? {
        guard let supportEmail else { return nil }
        // Also encode query delimiters so an odd version string can't break the subject.
        let allowed = CharacterSet.urlQueryAllowed
            .subtracting(CharacterSet(charactersIn: "&=?#"))
        guard let subject = "FluxMoat \(version)"
            .addingPercentEncoding(withAllowedCharacters: allowed)
        else { return nil }
        return URL(string: "mailto:\(supportEmail)?subject=\(subject)")
    }
}
