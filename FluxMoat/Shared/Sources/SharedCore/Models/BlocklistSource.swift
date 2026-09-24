import Foundation

/// A subscribed blocklist.
public struct BlocklistSource: Codable, Identifiable, Sendable, Hashable {
    public enum Format: String, Codable, Sendable, CaseIterable {
        case hosts
        case domainList
        case ipList
        case cidrList
        case jsonManifest
        /// Little Snitch rule group subscription. App-scoped fields
        /// (process, via) are ignored on import and surfaced to the user.
        case lsrules
    }

    /// How a source's hits are counted and shown: ad/tracker lists vs threat-intel
    /// feeds (malware, C2, botnet). Threat hits get their own verdict source and
    /// a separate Dashboard tally.
    public enum Category: String, Codable, Sendable, CaseIterable {
        case adTracker
        case threat
    }

    public var id: UUID
    public var name: String
    public var sourceURL: URL?
    public var format: Format
    /// Optional so sources saved before this field existed still decode.
    /// nil means `.adTracker`.
    public var category: Category?
    public var enabled: Bool
    public var lastUpdatedAt: Date?
    public var etag: String?
    public var signaturePublicKeyID: String?
    public var entryCount: Int
    public var hitCount: Int
    public var updateError: String?

    public init(
        id: UUID = UUID(),
        name: String,
        sourceURL: URL? = nil,
        format: Format,
        category: Category? = nil,
        enabled: Bool = true,
        lastUpdatedAt: Date? = nil,
        etag: String? = nil,
        signaturePublicKeyID: String? = nil,
        entryCount: Int = 0,
        hitCount: Int = 0,
        updateError: String? = nil
    ) {
        self.id = id
        self.name = name
        self.sourceURL = sourceURL
        self.format = format
        self.category = category
        self.enabled = enabled
        self.lastUpdatedAt = lastUpdatedAt
        self.etag = etag
        self.signaturePublicKeyID = signaturePublicKeyID
        self.entryCount = entryCount
        self.hitCount = hitCount
        self.updateError = updateError
    }
}
