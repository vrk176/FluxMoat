import Foundation

/// Event-driven state machine for one client connection to the in-process
/// SOCKS5 server. The tunnel extension feeds it bytes and events from an
/// `NWConnection` and performs the returned `Action`s. Protocol logic, the
/// rule decision and byte counting live here so they are testable. One
/// instance per client connection; not thread-safe, so drive it serially
/// on the connection's queue.
public final class SOCKS5ServerConnection {
    public enum Input: Sendable {
        case clientBytes(Data)
        case outboundConnected
        case outboundFailed
        case outboundBytes(Data)
        case outboundClosed
    }

    public enum Action: Sendable, Equatable {
        case sendToClient(Data)
        /// Open a direct outbound connection to this destination.
        case openOutbound(host: String, port: UInt16)
        case forwardToOutbound(Data)
        /// Set up a UDP ASSOCIATE relay for this control connection. The caller
        /// binds the UDP socket, sends the success reply (only it knows the bound
        /// port), and relays datagrams, checking each one's destination with
        /// `FlowGatekeeper.decideDatagram`. Closing the TCP control connection ends
        /// the association.
        case beginUDPAssociate
        case closeAll
    }

    private enum State {
        case awaitingGreeting
        case awaitingRequest
        case connecting
        case relaying
        /// UDP ASSOCIATE established. The TCP control connection is now idle; data
        /// goes over the UDP relay socket.
        case udpAssociated
        case closed
    }

    /// Released right after the verdict. Each connection gets its own copy of
    /// the compiled rule set and only needs it once, and long-lived connections
    /// would otherwise keep old rule sets in memory after reloads, pushing the
    /// extension toward its memory limit.
    private var gatekeeper: FlowGatekeeper?
    private var state: State = .awaitingGreeting
    private var buffer = Data()

    /// Populated once the request is parsed; the extension reads these to
    /// record a `TrafficEvent` when the connection closes.
    public private(set) var request: SOCKS5Request?
    public private(set) var verdict: Verdict?
    /// True when Ask mode handled this flow with the profile default. The
    /// caller records a `PendingAsk` for the user.
    public private(set) var askedUser = false
    /// True only between accept and verdict (a few milliseconds). Used in
    /// diagnostics to check that connections aren't holding old rule sets.
    public var holdsRuleSet: Bool { gatekeeper != nil }
    public private(set) var bytesUp: UInt64 = 0 // client -> outbound
    public private(set) var bytesDown: UInt64 = 0 // outbound -> client

    /// Bytes waiting in `buffer`. Diagnostics only: client data queues here
    /// uncapped while the outbound connection is still being set up.
    public var bufferedBytes: Int { buffer.count }

    public init(gatekeeper: FlowGatekeeper) {
        self.gatekeeper = gatekeeper
    }

    public func handle(_ input: Input) -> [Action] {
        switch (state, input) {
        case (.awaitingGreeting, .clientBytes(let data)):
            buffer.append(data)
            return parseGreeting()

        case (.awaitingRequest, .clientBytes(let data)):
            buffer.append(data)
            return parseRequest()

        case (.connecting, .outboundConnected):
            state = .relaying
            var actions: [Action] = [.sendToClient(SOCKS5Reply.encode(.succeeded))]
            // Any client bytes that arrived while connecting are forwarded.
            if !buffer.isEmpty {
                bytesUp += UInt64(buffer.count)
                actions.append(.forwardToOutbound(buffer))
                buffer.removeAll()
            }
            return actions

        case (.connecting, .outboundFailed):
            state = .closed
            return [.sendToClient(SOCKS5Reply.encode(.hostUnreachable)), .closeAll]

        case (.connecting, .clientBytes(let data)):
            // Buffer early data until the outbound handshake completes.
            buffer.append(data)
            return []

        case (.udpAssociated, .clientBytes):
            // In normal UDP ASSOCIATE use the TCP control connection carries no data.
            // Ignore stray bytes and keep the association open; closing it ends the
            // relay.
            return []

        case (.relaying, .clientBytes(let data)):
            bytesUp += UInt64(data.count)
            return [.forwardToOutbound(data)]

        case (.relaying, .outboundBytes(let data)):
            bytesDown += UInt64(data.count)
            return [.sendToClient(data)]

        case (_, .outboundClosed), (_, .outboundFailed):
            state = .closed
            return [.closeAll]

        default:
            return []
        }
    }

    // MARK: - Parsing steps

    private func parseGreeting() -> [Action] {
        switch SOCKS5Greeting.parse(buffer) {
        case .needMore:
            return []
        case .invalid:
            state = .closed
            return [.closeAll]
        case .parsed(let greeting, let consumed):
            buffer.removeFirst(consumed)
            guard greeting.methods.contains(SOCKS5Greeting.noAuth) else {
                state = .closed
                return [.sendToClient(SOCKS5Greeting.methodSelection(SOCKS5Greeting.noAcceptable)), .closeAll]
            }
            state = .awaitingRequest
            var actions: [Action] = [.sendToClient(SOCKS5Greeting.methodSelection(SOCKS5Greeting.noAuth))]
            // A pipelined request may already be in the buffer.
            if !buffer.isEmpty {
                actions.append(contentsOf: parseRequest())
            }
            return actions
        }
    }

    private func parseRequest() -> [Action] {
        switch SOCKS5Request.parse(buffer) {
        case .needMore:
            return []
        case .invalid:
            state = .closed
            return [.sendToClient(SOCKS5Reply.encode(.generalFailure)), .closeAll]
        case .parsed(let request, let consumed):
            buffer.removeFirst(consumed)
            self.request = request
            // UDP ASSOCIATE sets up a real relay. This runs before `decide`, which only
            // handles CONNECT; the relay judges each datagram with `decideDatagram`.
            // Don't send UDP ASSOCIATE through `decide`/`openOutbound`: that loops back
            // to the SOCKS listener.
            if request.command == .udpAssociate {
                // The ASSOCIATE request has no useful destination (leaf sends 0.0.0.0:0),
                // so the association is always allowed and the relay judges each datagram.
                // The caller binds the UDP socket and sends the reply once it knows the
                // port. The relay has its own gatekeeper, so drop this one.
                gatekeeper = nil
                self.verdict = Verdict(action: .allow, matchedRuleID: nil, source: .modeDefault)
                state = .udpAssociated
                return [.beginUDPAssociate]
            }
            guard let gatekeeper else {
                // Shouldn't happen: the gatekeeper is only cleared after a verdict and a
                // SOCKS connection carries one request. Close instead of crashing.
                state = .closed
                return [.closeAll]
            }
            let decision = gatekeeper.decide(request)
            // Verdict is done; release the rule set copy.
            self.gatekeeper = nil
            self.verdict = decision.verdict
            self.askedUser = decision.asksUser
            guard decision.allowed else {
                state = .closed
                return [.sendToClient(SOCKS5Reply.encode(decision.reply)), .closeAll]
            }
            state = .connecting
            return [.openOutbound(host: request.destination.host, port: request.port)]
        }
    }
}
