import Foundation

/// Bounded FIFO of recently closed flows, held by the tunnel until the app
/// polls them for the Live Traffic view. Events are added once per closed
/// flow (never per packet) and the app polls about once a second.
///
/// On overflow the oldest events are dropped, which keeps extension memory
/// bounded during connection bursts. `drain` returns and clears the buffer,
/// so each event reaches the app at most once. Holds connection metadata
/// only. Not thread-safe; confine it to the owner's serial queue.
public struct TrafficEventBuffer: Sendable {
    public private(set) var events: [TrafficEvent] = []
    public let capacity: Int

    public init(capacity: Int = 256) {
        self.capacity = max(1, capacity)
    }

    /// Appends one closed-flow event, dropping the oldest if at capacity.
    public mutating func append(_ event: TrafficEvent) {
        events.append(event)
        if events.count > capacity {
            events.removeFirst(events.count - capacity)
        }
    }

    /// Returns all buffered events and clears the buffer (delivered once).
    public mutating func drain() -> [TrafficEvent] {
        defer { events.removeAll(keepingCapacity: true) }
        return events
    }
}
