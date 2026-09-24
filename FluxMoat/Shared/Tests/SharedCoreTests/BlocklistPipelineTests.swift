import Foundation
import Testing
@testable import SharedCore

@Suite struct BlocklistParserTests {
    @Test func hostsFormatExtractsHostsAndSkipsBoilerplate() throws {
        let payload = """
        # Title: some list
        127.0.0.1 localhost
        ::1 ip6-localhost ip6-loopback
        0.0.0.0 Ads.Example. tracker.example # inline comment
        0.0.0.0 metrics.example
        255.255.255.255 broadcasthost

        not-a-hosts-line
        """
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .hosts)
        #expect(report.domains == ["ads.example", "tracker.example", "metrics.example"])
        // localhost, the two ip6-* names, broadcasthost, and the bare line.
        #expect(report.skippedCount == 5)
    }

    @Test func domainListNormalizesWildcardsAndDedupes() throws {
        let payload = """
        ads.example
        *.ads.example
        .TRACKER.example.
        xn--fiq228c.example
        """
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .domainList)
        #expect(report.domains == ["ads.example", "tracker.example", "xn--fiq228c.example"])
        #expect(report.skippedCount == 0)
    }

    @Test func implausibleEntriesAreSkippedNotFatal() throws {
        let long = String(repeating: "a", count: 64)
        let payload = """
        singlelabel
        192.168.1.1
        bad domain.example
        -bad.example
        a..b.example
        \(long).example
        good.example
        """
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .domainList)
        #expect(report.domains == ["good.example"])
        #expect(report.skippedCount == 6)
    }

    @Test func entryCapThrowsInsteadOfTruncating() {
        let payload = (0..<20).map { "d\($0).example" }.joined(separator: "\n")
        #expect(throws: BlocklistParser.ParseError.self) {
            _ = try BlocklistParser.parse(Data(payload.utf8), format: .domainList, maxEntries: 10)
        }
    }

    @Test func rejectsNonUTF8AndUnsupportedFormats() {
        #expect(throws: BlocklistParser.ParseError.self) {
            _ = try BlocklistParser.parse(Data([0xFF, 0xFE, 0x00, 0xD8]), format: .domainList)
        }
        // lsrules parsing is not implemented, so it must reject rather than silently pass.
        #expect(throws: BlocklistParser.ParseError.self) {
            _ = try BlocklistParser.parse(Data("{}".utf8), format: .lsrules)
        }
    }
}

@Suite struct BlocklistJSONManifestParserTests {
    /// ThreatFox `export/json/recent/` shape: `{ "<id>": [ {ioc…} ], … }`.
    /// One feed mixes IP and domain IOCs; file hashes are counted skipped.
    @Test func exportShapeExtractsIPsDomainsAndSkipsHashes() throws {
        let payload = """
        {
          "800001": [ { "ioc_value": "93.184.216.34:443", "ioc_type": "ip:port" } ],
          "800002": [
            { "ioc_value": "bad.example", "ioc_type": "domain" },
            { "ioc_value": "https://evil.example/path?q=1", "ioc_type": "url" }
          ],
          "800003": [ { "ioc_value": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash" } ]
        }
        """
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .jsonManifest)
        #expect(report.ipEntries == ["93.184.216.34"])
        #expect(report.domains == ["bad.example", "evil.example"])
        #expect(report.skippedCount == 1) // the md5 hash, not flow-matchable
    }

    /// `api/v1` query result shape: IOCs under a top-level `data` array.
    @Test func apiDataShapeUsesDataArray() throws {
        let payload = """
        { "query_status": "ok", "data": [
            { "ioc_value": "198.51.100.7:8080", "ioc_type": "ip:port" },
            { "ioc_value": "c2.example", "ioc_type": "domain" }
        ] }
        """
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .jsonManifest)
        #expect(report.ipEntries == ["198.51.100.7"])
        #expect(report.domains == ["c2.example"])
    }

    /// Plain top-level array, bracketed IPv6 `[v6]:port`, and a record
    /// missing `ioc_value` (skipped, not fatal).
    @Test func plainArrayHandlesIPv6AndSkipsMalformedRecords() throws {
        let payload = """
        [
            { "ioc_value": "[2001:db8::1]:443", "ioc_type": "ip:port" },
            { "ioc_type": "domain" },
            { "ioc_value": "192.0.2.5:80", "ioc_type": "ip:port" }
        ]
        """
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .jsonManifest)
        #expect(report.ipEntries == ["2001:db8::1", "192.0.2.5"])
        #expect(report.skippedCount == 1) // record with no ioc_value
    }

    /// Malformed JSON must throw; a broken download must never be mistaken
    /// for an empty (i.e. "cleared") feed.
    @Test func malformedJSONThrows() {
        #expect(throws: BlocklistParser.ParseError.self) {
            _ = try BlocklistParser.parse(Data("{not json".utf8), format: .jsonManifest)
        }
    }

    /// Valid but empty JSON is a legitimate empty feed, not an error.
    @Test func emptyObjectYieldsEmptyReport() throws {
        let report = try BlocklistParser.parse(Data("{}".utf8), format: .jsonManifest)
        #expect(report.domains.isEmpty && report.ipEntries.isEmpty)
    }
}

@Suite struct BlocklistIPParserTests {
    /// Feodo-class: one IP per line, `#` comments, blank lines.
    @Test func ipListExtractsAddressesAndSkipsComments() throws {
        let payload = """
        # Feodo Tracker Botnet C2 IP Blocklist
        93.184.216.34
        198.51.100.7

        2001:db8::1
        """
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .ipList)
        #expect(report.ipEntries == ["93.184.216.34", "198.51.100.7", "2001:db8::1"])
        #expect(report.domains.isEmpty)
    }

    /// Spamhaus DROP-class: `network/prefix ; SBL comment`, `;` comments.
    @Test func cidrListHandlesDROPFormatAndMasksHostBits() throws {
        let payload = """
        ; Spamhaus DROP List
        192.0.2.0/24 ; SBL123456
        198.51.100.128/25 ; SBL234567
        2001:db8::/32 ; SBL345678
        """
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .cidrList)
        #expect(report.ipEntries == ["192.0.2.0/24", "198.51.100.128/25", "2001:db8::/32"])
    }

    /// Host bits set in the source must be masked so equivalent networks
    /// dedupe.
    @Test func cidrNetworkMaskingDedupes() throws {
        let payload = "192.0.2.5/24\n192.0.2.99/24\n"
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .cidrList)
        #expect(report.ipEntries == ["192.0.2.0/24"])
    }

    /// Malformed lines are skipped and counted, never fatal; one bad line
    /// must not take down a feed.
    @Test func malformedIPEntriesSkippedNotFatal() throws {
        let payload = """
        93.184.216.34
        not-an-ip
        999.999.999.999
        10.0.0.0/33
        """
        let report = try BlocklistParser.parse(Data(payload.utf8), format: .ipList)
        #expect(report.ipEntries == ["93.184.216.34"])
        #expect(report.skippedCount == 3)
    }

    /// A bare IP in a cidrList stays a plain host indicator (not forced to /32).
    @Test func bareIPInCIDRListStaysPlain() throws {
        let report = try BlocklistParser.parse(Data("93.184.216.34".utf8), format: .cidrList)
        #expect(report.ipEntries == ["93.184.216.34"])
    }

    @Test func ipEntryCapThrows() {
        let payload = (0..<20).map { "10.0.0.\($0)" }.joined(separator: "\n")
        #expect(throws: BlocklistParser.ParseError.self) {
            _ = try BlocklistParser.parse(Data(payload.utf8), format: .ipList, maxEntries: 10)
        }
    }
}

@Suite struct BlocklistSourceStoreTests {
    private func temporaryStore() -> BlocklistSourceStore {
        BlocklistSourceStore(directoryURL: FileManager.default.temporaryDirectory
            .appendingPathComponent("blocklist-store-\(UUID().uuidString)", isDirectory: true))
    }

    @Test func sourcesRoundTripAndMissingFileReadsEmpty() throws {
        let store = temporaryStore()
        #expect(try store.loadSources().isEmpty)
        let source = BlocklistSource(name: "L", sourceURL: URL(string: "https://l.example/hosts"), format: .hosts, entryCount: 3)
        try store.saveSources([source])
        let loaded = try store.loadSources()
        #expect(loaded == [source])
    }

    @Test func domainsRoundTripDeleteAndMissingReadEmpty() throws {
        let store = temporaryStore()
        let id = UUID()
        #expect(try store.readDomains(for: id).isEmpty)
        try store.writeDomains(["a.example", "b.example"], for: id)
        #expect(try store.readDomains(for: id) == ["a.example", "b.example"])
        // Overwrite is atomic-replace, not append.
        try store.writeDomains(["c.example"], for: id)
        #expect(try store.readDomains(for: id) == ["c.example"])
        store.deleteDomains(for: id)
        #expect(try store.readDomains(for: id).isEmpty)
    }

    @Test func ipsRoundTripDeleteAndMissingReadEmpty() throws {
        let store = temporaryStore()
        let id = UUID()
        #expect(try store.readIPs(for: id).isEmpty)
        try store.writeIPs(["93.184.216.34", "192.0.2.0/24"], for: id)
        #expect(try store.readIPs(for: id) == ["93.184.216.34", "192.0.2.0/24"])
        store.deleteIPs(for: id)
        #expect(try store.readIPs(for: id).isEmpty)
    }

    @Test func sourceCategoryRoundTripsAndDefaultsNilForLegacyData() throws {
        let store = temporaryStore()
        let threat = BlocklistSource(
            name: "Feodo", sourceURL: URL(string: "https://f.example/ips"),
            format: .ipList, category: .threat
        )
        try store.saveSources([threat])
        #expect(try store.loadSources().first?.category == .threat)

        // A source encoded before `category` existed must decode with nil
        // (→ treated as .adTracker by the composer).
        let legacy = Data(#"[{"id":"\#(UUID().uuidString)","name":"Old","format":"hosts","enabled":true,"entryCount":0,"hitCount":0}]"#.utf8)
        let decoded = try JSONDecoder().decode([BlocklistSource].self, from: legacy)
        #expect(decoded.first?.category == nil)
    }
}

/// Serves canned responses so updater policy (HTTPS-only, 304, size cap)
/// is tested without the network.
final class BlocklistStubProtocol: URLProtocol {
    nonisolated(unsafe) static var handler: ((URLRequest) -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        guard let handler = Self.handler,
              let client else { return }
        let (response, data) = handler(request)
        client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client.urlProtocol(self, didLoad: data)
        client.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

@Suite(.serialized) struct BlocklistUpdaterTests {
    private func stubbedSession() -> URLSession {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [BlocklistStubProtocol.self]
        return URLSession(configuration: config)
    }

    private func source(_ url: String, format: BlocklistSource.Format = .domainList, etag: String? = nil) -> BlocklistSource {
        BlocklistSource(name: "T", sourceURL: URL(string: url), format: format, etag: etag)
    }

    @Test func rejectsNonHTTPSSources() async {
        await #expect(throws: BlocklistUpdater.UpdateError.self) {
            _ = try await BlocklistUpdater(session: stubbedSession())
                .fetch(source("http://insecure.example/list"))
        }
    }

    @Test func matchedETagShortCircuitsTo304() async throws {
        BlocklistStubProtocol.handler = { request in
            #expect(request.value(forHTTPHeaderField: "If-None-Match") == "\"v1\"")
            return (HTTPURLResponse(url: request.url!, statusCode: 304, httpVersion: nil, headerFields: nil)!, Data())
        }
        let outcome = try await BlocklistUpdater(session: stubbedSession())
            .fetch(source("https://list.example/domains", etag: "\"v1\""))
        guard case .notModified = outcome else {
            Issue.record("expected notModified, got \(outcome)")
            return
        }
    }

    @Test func freshPayloadParsesAndCarriesETag() async throws {
        BlocklistStubProtocol.handler = { request in
            (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil,
                             headerFields: ["ETag": "\"v2\""])!,
             Data("ads.example\ntracker.example\n".utf8))
        }
        let outcome = try await BlocklistUpdater(session: stubbedSession())
            .fetch(source("https://list.example/domains"))
        guard case .updated(let domains, let ipEntries, let skipped, let etag) = outcome else {
            Issue.record("expected updated, got \(outcome)")
            return
        }
        #expect(domains == ["ads.example", "tracker.example"])
        #expect(ipEntries.isEmpty)
        #expect(skipped == 0)
        #expect(etag == "\"v2\"")
    }

    @Test func ipFeedFetchCarriesIPEntries() async throws {
        BlocklistStubProtocol.handler = { request in
            (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
             Data("; Feodo\n93.184.216.34\n198.51.100.0/24\n".utf8))
        }
        let outcome = try await BlocklistUpdater(session: stubbedSession())
            .fetch(source("https://list.example/ips", format: .cidrList))
        guard case .updated(let domains, let ipEntries, _, _) = outcome else {
            Issue.record("expected updated, got \(outcome)"); return
        }
        #expect(domains.isEmpty)
        #expect(ipEntries == ["93.184.216.34", "198.51.100.0/24"])
    }

    @Test func authKeyIsSentAsHeaderWhenProvided() async throws {
        BlocklistStubProtocol.handler = { request in
            #expect(request.value(forHTTPHeaderField: "Auth-Key") == "secret-key")
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                    Data("ads.example\n".utf8))
        }
        _ = try await BlocklistUpdater(session: stubbedSession())
            .fetch(source("https://threatfox.abuse.ch/export"), authKey: "secret-key")
    }

    @Test func noAuthKeyHeaderWhenAbsent() async throws {
        BlocklistStubProtocol.handler = { request in
            #expect(request.value(forHTTPHeaderField: "Auth-Key") == nil)
            return (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
                    Data("ads.example\n".utf8))
        }
        _ = try await BlocklistUpdater(session: stubbedSession())
            .fetch(source("https://list.example/domains"))
    }

    /// 401 gets a sentence instead of a number: the only credential this
    /// fetcher sends is the abuse.ch key, so it has exactly one cause and
    /// fix. Everything else keeps its status code.
    @Test func unauthorizedReportsTheKeyRatherThanTheStatusCode() async throws {
        BlocklistStubProtocol.handler = { request in
            (HTTPURLResponse(url: request.url!, statusCode: 401, httpVersion: nil, headerFields: nil)!, Data())
        }
        do {
            _ = try await BlocklistUpdater(session: stubbedSession())
                .fetch(source("https://threatfox.abuse.ch/export", format: .jsonManifest))
            Issue.record("expected an UpdateError")
        } catch let error as BlocklistUpdater.UpdateError {
            #expect(error.reason == "Key rejected — check it in Settings → Threat intelligence.")
        }
    }

    @Test func otherStatusCodesKeepTheirNumber() async throws {
        BlocklistStubProtocol.handler = { request in
            (HTTPURLResponse(url: request.url!, statusCode: 503, httpVersion: nil, headerFields: nil)!, Data())
        }
        do {
            _ = try await BlocklistUpdater(session: stubbedSession())
                .fetch(source("https://list.example/domains"))
            Issue.record("expected an UpdateError")
        } catch let error as BlocklistUpdater.UpdateError {
            #expect(error.reason == "HTTP 503")
        }
    }

    @Test func oversizedBodyIsRejectedMidStream() async {
        BlocklistStubProtocol.handler = { request in
            (HTTPURLResponse(url: request.url!, statusCode: 200, httpVersion: nil, headerFields: nil)!,
             Data(count: BlocklistUpdater.maxDownloadBytes + 1))
        }
        await #expect(throws: BlocklistUpdater.UpdateError.self) {
            _ = try await BlocklistUpdater(session: stubbedSession())
                .fetch(source("https://list.example/domains"))
        }
    }
}
