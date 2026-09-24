import Foundation
import Testing
@testable import SharedCore

/// Hand-built wire responses (RFC 1035) for codec + resolver tests.
private enum Wire {
    static func header(rcode: UInt8, qdcount: UInt16 = 1, ancount: UInt16) -> Data {
        var d = Data()
        d.append(contentsOf: [0, 0, 0x81, 0x80 | rcode]) // id, QR|RD|RA + rcode
        for count in [qdcount, ancount, 0, 0] {
            d.append(UInt8(count >> 8)); d.append(UInt8(count & 0xFF))
        }
        return d
    }

    static func name(_ host: String) -> Data {
        var d = Data()
        for label in host.split(separator: ".") {
            d.append(UInt8(label.utf8.count))
            d.append(contentsOf: label.utf8)
        }
        d.append(0)
        return d
    }

    static func question(_ host: String, type: UInt16 = 1) -> Data {
        var d = name(host)
        d.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xFF), 0, 1])
        return d
    }

    /// Answer whose name is a compression pointer to offset 12 (the
    /// question name), the shape every real resolver emits.
    static func answer(type: UInt16, ttl: UInt32, rdata: [UInt8]) -> Data {
        var d = Data([0xC0, 0x0C])
        d.append(contentsOf: [UInt8(type >> 8), UInt8(type & 0xFF), 0, 1])
        d.append(contentsOf: [UInt8(ttl >> 24), UInt8((ttl >> 16) & 0xFF), UInt8((ttl >> 8) & 0xFF), UInt8(ttl & 0xFF)])
        d.append(contentsOf: [UInt8(rdata.count >> 8), UInt8(rdata.count & 0xFF)])
        d.append(contentsOf: rdata)
        return d
    }

    static func response(rcode: UInt8 = 0, host: String = "ads.example", answers: [Data]) -> Data {
        header(rcode: rcode, ancount: UInt16(answers.count)) + question(host) + answers.joined()
    }
}

private extension [Data] {
    func joined() -> Data { reduce(Data(), +) }
}

@Suite struct DNSMessageTests {
    @Test func queryEncodesCanonicalWireFormat() throws {
        let q = try DNSMessage.query(host: "ads.example", type: .a)
        #expect([UInt8](q.prefix(12)) == [0, 0, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        #expect([UInt8](q.dropFirst(12)) == [3] + Array("ads".utf8) + [7] + Array("example".utf8) + [0, 0, 1, 0, 1])
    }

    @Test func parsesARecordsThroughCompressionPointersSkippingCNAME() throws {
        let data = Wire.response(answers: [
            Wire.answer(type: 5, ttl: 60, rdata: [3] + Array("cdn".utf8) + [0]), // CNAME
            Wire.answer(type: 1, ttl: 300, rdata: [93, 184, 216, 34]),
            Wire.answer(type: 1, ttl: 120, rdata: [93, 184, 216, 35]),
        ])
        let response = try DNSMessage.parseResponse(data)
        #expect(response.rcode == 0)
        #expect(response.addresses == ["93.184.216.34", "93.184.216.35"])
        #expect(response.minTTL == 120)
    }

    @Test func parsesAAAARecord() throws {
        let rdata: [UInt8] = [0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11]
        let response = try DNSMessage.parseResponse(Wire.response(answers: [
            Wire.answer(type: 28, ttl: 60, rdata: rdata),
        ]))
        #expect(response.addresses == ["2606:4700:4700:0:0:0:0:1111"])
    }

    @Test func surfacesNXDOMAINRcode() throws {
        let response = try DNSMessage.parseResponse(Wire.response(rcode: 3, answers: []))
        #expect(response.rcode == 3)
        #expect(response.addresses.isEmpty)
    }

    @Test func rejectsTruncatedMessages() {
        let full = Wire.response(answers: [Wire.answer(type: 1, ttl: 60, rdata: [1, 2, 3, 4])])
        #expect(throws: DNSMessage.ParseError.self) {
            _ = try DNSMessage.parseResponse(full.prefix(full.count - 3))
        }
        #expect(throws: DNSMessage.ParseError.self) {
            _ = try DNSMessage.parseResponse(Data([0, 0, 0x81, 0x80]))
        }
    }
}

/// Serves canned DNS responses; counts round-trips so cache behavior is
/// observable.
final class DoHStubProtocol: URLProtocol {
    nonisolated(unsafe) static var responses: [Data] = []
    nonisolated(unsafe) static var callCount = 0

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let client else { return }
        let body = Self.callCount < Self.responses.count ? Self.responses[Self.callCount] : Data()
        Self.callCount += 1
        let response = HTTPURLResponse(
            url: request.url!, statusCode: 200, httpVersion: nil,
            headerFields: ["Content-Type": "application/dns-message"]
        )!
        client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client.urlProtocol(self, didLoad: body)
        client.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@Suite(.serialized) struct DoHResolverTests {
    private func makeResolver(
        responses: [Data],
        now: @escaping @Sendable () -> Date = Date.init
    ) -> DoHResolver {
        DoHStubProtocol.responses = responses
        DoHStubProtocol.callCount = 0
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [DoHStubProtocol.self]
        return DoHResolver(
            serverURL: URL(string: "https://doh.example/dns-query")!,
            session: URLSession(configuration: config),
            now: now
        )
    }

    @Test func resolvesAndServesSecondLookupFromCache() async throws {
        let resolver = makeResolver(responses: [
            Wire.response(answers: [Wire.answer(type: 1, ttl: 300, rdata: [1, 2, 3, 4])]),
        ])
        let first = try await resolver.resolve("ads.example")
        #expect(first.resolution == .addresses(["1.2.3.4"]))
        #expect(!first.fromCache)
        let second = try await resolver.resolve("ADS.example.")
        #expect(second.resolution == .addresses(["1.2.3.4"]))
        #expect(second.fromCache)
        #expect(DoHStubProtocol.callCount == 1)
    }

    @Test func cacheExpiresByTTL() async throws {
        let answer = Wire.response(answers: [Wire.answer(type: 1, ttl: 300, rdata: [1, 2, 3, 4])])
        nonisolated(unsafe) var clock = Date(timeIntervalSince1970: 1_000)
        let resolver = makeResolver(responses: [answer, answer], now: { clock })
        _ = try await resolver.resolve("ads.example")
        clock = clock.addingTimeInterval(301)
        let again = try await resolver.resolve("ads.example")
        #expect(!again.fromCache)
        #expect(DoHStubProtocol.callCount == 2)
    }

    @Test func sinkOnlyAnswersReportBlockedByResolver() async throws {
        let resolver = makeResolver(responses: [
            Wire.response(answers: [Wire.answer(type: 1, ttl: 60, rdata: [0, 0, 0, 0])]),
        ])
        let outcome = try await resolver.resolve("malware.example")
        #expect(outcome.resolution == .blockedByResolver)
    }

    @Test func nxdomainReportsNoSuchDomain() async throws {
        let resolver = makeResolver(responses: [Wire.response(rcode: 3, answers: [])])
        let outcome = try await resolver.resolve("gone.example")
        #expect(outcome.resolution == .noSuchDomain)
    }

    @Test func emptyAAnswerFallsBackToAAAAQuery() async throws {
        let rdata: [UInt8] = [0x26, 0x06] + [UInt8](repeating: 0, count: 13) + [0x11]
        let resolver = makeResolver(responses: [
            Wire.response(answers: []),
            Wire.response(answers: [Wire.answer(type: 28, ttl: 60, rdata: rdata)]),
        ])
        let outcome = try await resolver.resolve("v6only.example")
        #expect(DoHStubProtocol.callCount == 2)
        #expect(outcome.resolution == .addresses(["2606:0:0:0:0:0:0:11"]))
    }
}

@Suite struct DoHSnapshotFieldTests {
    @Test func dohURLRoundTripsAndNilMatchesLegacyFormat() throws {
        let snapshot = RuleSnapshot(rules: [], dohServerURL: "https://dns.quad9.net/dns-query")
        let back = try RuleSnapshot.deserialize(try snapshot.serialize())
        #expect(back.dohServerURL == "https://dns.quad9.net/dns-query")

        let (data, _) = try RuleSnapshot(rules: []).serializedWithChecksum()
        #expect(!String(decoding: data, as: UTF8.self).contains("dohServerURL"))
    }
}
