import Foundation

/// App-side storage for blocklist subscriptions: metadata in `sources.json`
/// plus one parsed-domains file per source. The tunnel never reads this
/// store; enabled sources are merged into the rule snapshot instead.
///
/// Writes use a temp file, atomic replace and iOS file protection. Domain
/// files have no backup: on failure the source keeps its previous file,
/// and re-downloading is always safe.
public struct BlocklistSourceStore: Sendable {
    public struct StoreError: Error, Sendable {
        public let reason: String
    }

    /// Reserved domains-file slot for the user's manual or imported blocklist
    /// domains (for example from .lsrules). Keeping them next to subscription
    /// files lets the snapshot's union be rebuilt from disk without mixing them
    /// up with subscription entries.
    public static let manualDomainsID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    public let directoryURL: URL

    public var sourcesURL: URL { directoryURL.appendingPathComponent("sources.json") }

    public init(directoryURL: URL) {
        self.directoryURL = directoryURL
    }

    public static func appGroup() -> BlocklistSourceStore? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: RuleSnapshotStore.appGroupID)
            .map { BlocklistSourceStore(directoryURL: $0.appendingPathComponent("Blocklists", isDirectory: true)) }
    }

    // MARK: Source metadata

    /// Missing file decodes as no sources (fresh install).
    public func loadSources() throws -> [BlocklistSource] {
        guard FileManager.default.fileExists(atPath: sourcesURL.path) else { return [] }
        let data = try Data(contentsOf: sourcesURL)
        return try JSONDecoder().decode([BlocklistSource].self, from: data)
    }

    public func saveSources(_ sources: [BlocklistSource]) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try atomicWrite(try encoder.encode(sources), to: sourcesURL)
    }

    // MARK: Parsed domains

    public func domainsURL(for id: UUID) -> URL {
        directoryURL.appendingPathComponent("\(id.uuidString).domains.txt")
    }

    /// One normalized domain per line, as produced by BlocklistParser.
    public func writeDomains(_ domains: [String], for id: UUID) throws {
        try atomicWrite(Data(domains.joined(separator: "\n").utf8), to: domainsURL(for: id))
    }

    /// Missing file (never updated, or removed) reads as empty.
    public func readDomains(for id: UUID) throws -> [String] {
        let url = domainsURL(for: id)
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        guard let text = String(data: try Data(contentsOf: url), encoding: .utf8) else {
            throw StoreError(reason: "domains file for \(id.uuidString) is not UTF-8")
        }
        return text.split(whereSeparator: \.isNewline).map(String.init)
    }

    public func deleteDomains(for id: UUID) {
        try? FileManager.default.removeItem(at: domainsURL(for: id))
    }

    // MARK: Parsed IP / CIDR indicators

    public func ipsURL(for id: UUID) -> URL {
        directoryURL.appendingPathComponent("\(id.uuidString).ips.txt")
    }

    /// One canonical IP/CIDR per line, as produced by BlocklistParser.
    public func writeIPs(_ ips: [String], for id: UUID) throws {
        try atomicWrite(Data(ips.joined(separator: "\n").utf8), to: ipsURL(for: id))
    }

    public func readIPs(for id: UUID) throws -> [String] {
        let url = ipsURL(for: id)
        guard FileManager.default.fileExists(atPath: url.path) else { return [] }
        guard let text = String(data: try Data(contentsOf: url), encoding: .utf8) else {
            throw StoreError(reason: "ips file for \(id.uuidString) is not UTF-8")
        }
        return text.split(whereSeparator: \.isNewline).map(String.init)
    }

    public func deleteIPs(for id: UUID) {
        try? FileManager.default.removeItem(at: ipsURL(for: id))
    }

    // MARK: -

    private func atomicWrite(_ data: Data, to url: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        let temporaryURL = directoryURL.appendingPathComponent(url.lastPathComponent + ".tmp")
        try? fm.removeItem(at: temporaryURL)
        try data.write(to: temporaryURL, options: writingOptions)
        if fm.fileExists(atPath: url.path) {
            _ = try fm.replaceItemAt(url, withItemAt: temporaryURL)
        } else {
            try fm.moveItem(at: temporaryURL, to: url)
        }
    }

    private var writingOptions: Data.WritingOptions {
        #if os(iOS)
        return [.completeFileProtectionUntilFirstUserAuthentication]
        #else
        return []
        #endif
    }
}
