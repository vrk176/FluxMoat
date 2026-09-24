import Foundation

/// Small App Group JSON file the widgets read for protection state.
/// The tunnel writes it on start and stop (this works even when the app isn't
/// running), and the app writes it when it sees a status change so it can
/// reload widget timelines right away. Widgets only read it.
///
/// Counters are not stored here. The widget reads today's stats directly from
/// the shared event store, so there is only one source for them.
public struct WidgetState: Codable, Sendable, Equatable {
    public var protectionOn: Bool
    public var updatedAt: Date

    public init(protectionOn: Bool, updatedAt: Date = Date()) {
        self.protectionOn = protectionOn
        self.updatedAt = updatedAt
    }
}

public struct WidgetStateStore: Sendable {
    public static let appGroupID = AppIdentifiers.appGroup

    /// Store inside the App Group container, or nil when the entitlement is
    /// missing (unsigned simulator builds). Callers skip writing in that case.
    public static func appGroup() -> WidgetStateStore? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroupID)
            .map { WidgetStateStore(directoryURL: $0) }
    }

    private let fileURL: URL

    public init(directoryURL: URL) {
        self.fileURL = directoryURL.appendingPathComponent("widget-state.json")
    }

    /// Atomic replace, like the other App Group stores.
    public func write(_ state: WidgetState) throws {
        let data = try JSONEncoder().encode(state)
        let temporaryURL = fileURL.deletingLastPathComponent()
            .appendingPathComponent("widget-state-\(UUID().uuidString).tmp")
        try data.write(to: temporaryURL, options: .atomic)
        _ = try FileManager.default.replaceItemAt(fileURL, withItemAt: temporaryURL)
    }

    /// nil when never written or unreadable (for example before first unlock).
    /// The widget shows a placeholder in that case.
    public func read() -> WidgetState? {
        guard let data = try? Data(contentsOf: fileURL) else { return nil }
        return try? JSONDecoder().decode(WidgetState.self, from: data)
    }
}
