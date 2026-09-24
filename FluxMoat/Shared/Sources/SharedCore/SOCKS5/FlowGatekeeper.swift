import Foundation

/// Turns a parsed SOCKS5 request into an accept or reject decision using the
/// compiled rules. Every flow passes through here before the extension opens
/// an outbound connection. Synchronous so it can run inline on accept.
public struct FlowGatekeeper: Sendable {
    public struct Decision: Sendable, Equatable {
        public let allowed: Bool
        public let verdict: Verdict
        /// SOCKS5 reply to send back to the tun2socks client.
        public let reply: SOCKS5.Reply
        /// True when Ask mode handled an unmatched flow with the profile default.
        /// The caller records a `PendingAsk` so the user can answer later; the flow
        /// itself isn't held.
        public let asksUser: Bool
    }

    private let rules: CompiledRuleSet
    private let mode: RunMode
    private let profileDefault: RuleAction
    private let profileID: UUID?

    public init(
        rules: CompiledRuleSet,
        mode: RunMode,
        profileDefault: RuleAction = .allow,
        profileID: UUID? = nil
    ) {
        self.rules = rules
        self.mode = mode
        self.profileDefault = profileDefault
        self.profileID = profileID
    }

    // TCP CONNECT path, judged once per connection. UDP ASSOCIATE never gets
    // here: the state machine branches to `.beginUDPAssociate` first, and UDP is
    // judged per datagram in `decideDatagram`.
    public func decide(_ request: SOCKS5Request, at timestamp: Date = Date()) -> Decision {
        // Only CONNECT is relayed here. BIND isn't used by tun2socks and is
        // rejected. UDP ASSOCIATE is handled by the state machine, so it never
        // falls through to a TCP connection.
        guard request.command == .connect else {
            return Decision(
                allowed: false,
                verdict: Verdict(action: .deny, matchedRuleID: nil, source: .modeDefault),
                reply: .commandNotSupported,
                asksUser: false
            )
        }
        let flow = request.flowDescriptor(profileID: profileID, timestamp: timestamp)
        let verdict = rules.evaluate(flow, mode: mode, profileDefault: profileDefault)
        let allowed = verdict.action == .allow
        return Decision(
            allowed: allowed,
            verdict: verdict,
            reply: allowed ? .succeeded : .notAllowed,
            // Unmatched in Ask mode: the profile default just handled it, and
            // the destination becomes a pending question for the user.
            asksUser: mode == .ask && verdict.source == .modeDefault
        )
    }

    /// Per-datagram verdict for a UDP ASSOCIATE relay. There is no SOCKS reply:
    /// the caller relays the payload on `.allow` and drops it on `.deny`.
    ///
    /// Call this for every datagram, not once per association. The ASSOCIATE
    /// request's destination is usually `0.0.0.0:0`, so judging once would leave
    /// UDP unfiltered.
    public func decideDatagram(
        destination: SOCKS5.Destination,
        port: UInt16,
        at timestamp: Date = Date()
    ) -> Verdict {
        let proto: UInt8 = 17 // UDP
        let flow: FlowDescriptor
        switch destination {
        case .ipv4(let ip), .ipv6(let ip):
            flow = FlowDescriptor(ip: ip, port: port, protocolNumber: proto, profileID: profileID, timestamp: timestamp)
        case .domain(let name):
            flow = FlowDescriptor(domain: name, port: port, protocolNumber: proto, profileID: profileID, timestamp: timestamp)
        }
        return rules.evaluate(flow, mode: mode, profileDefault: profileDefault)
    }
}
