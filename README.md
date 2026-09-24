# FluxMoat

**English** | [简体中文](README.zh-CN.md)

FluxMoat is an iPhone app that shows every network connection your phone makes
and lets you block the ones you don't want. It works by running a packet tunnel
on the device itself. There is no VPN server, no account and no backend, and
nothing the tunnel records is sent anywhere.

<p align="center">
  <img src="docs/screenshots/dashboard.jpg" width="64%" alt="Dashboard with protection on, the last hour of traffic and recent targets">
  <img src="docs/screenshots/map.jpg" width="32%" alt="World map of destinations">
</p>
<p align="center">
  <img src="docs/screenshots/live-traffic.jpg" width="32%" alt="Live Traffic list">
  <img src="docs/screenshots/insights.jpg" width="32%" alt="Insights trends">
  <img src="docs/screenshots/rules.jpg" width="32%" alt="Rules list with blocklists">
</p>

## Contents

- [Features](#features)
- [How it works](#how-it-works)
- [How a connection is decided](#how-a-connection-is-decided)
- [Privacy](#privacy)
- [Limitations](#limitations)
- [Building](#building)
- [Project layout](#project-layout)
- [Maintenance tasks](#maintenance-tasks)
- [Contributing](#contributing)
- [License](#license)

## Features

### Dashboard

A single switch turns protection on or off. Below it, a chart shows the last
hour of traffic with bytes sent and received, and a list of recent targets
grouped by country. Tap a country to see the hosts behind it.

### Live Traffic

Every connection as it happens: domain (when known) or IP address, port,
protocol, bytes in each direction, the country estimate and whether it was
allowed or blocked. Filter by All, Blocked or Allowed, pause the list to read
it, and tap a row to see details or create a rule from it.

### Rules

Rules allow or block one of the following:

| Target | Example |
| --- | --- |
| Exact domain | `api.example.com` |
| Whole site | `*.example.com` |
| IP address | `203.0.113.7` |
| Network range | `203.0.113.0/24` |
| Port or protocol | TCP port 853, or protocol 17 |
| Country | every destination estimated to be in that country (block only) |

A rule can expire after a set time, carry a note, apply to one profile only, or
be switched off without deleting it. Rules can be exported and imported as
FluxMoat JSON, which keeps everything. They can also be exported to and
imported from Little Snitch rule files (`.lsrules`); that format has no place
for expiry dates or country policies, so those are left out.

### Blocklists and threat feeds

Three sources are listed by default:

- **StevenBlack hosts**: ads, trackers and known malware domains.
- **Feodo Tracker** (abuse.ch): botnet command-and-control servers.
- **ThreatFox** (abuse.ch): recent malware indicators (domains and IPs).

Nothing is downloaded until you tap Update. After the first download, lists you
have enabled are re-checked at most every six hours while the app is open, and
an unchanged list costs a single conditional request. You can add your own list
by URL as a hosts file, domain list, IP list, CIDR list or ThreatFox-style JSON
manifest, and file it under ads and trackers or under threats.

ThreatFox is fetched from a public mirror, so no abuse.ch account is needed. If
you paste your own abuse.ch Auth-Key, the app sends it to abuse.ch hosts only.

### Modes and profiles

The mode decides what happens to a connection that no rule and no list matched:

- **Standard** allows it.
- **Strict** blocks it.
- **Ask** applies the current profile's default and notifies you afterwards, so
  you can turn the connection into a rule. Alerts are grouped and rate-limited,
  and quiet hours can silence them.

There are two profiles, **Home** and **Public**. You can switch them by hand,
with a Shortcut, or automatically by Wi-Fi network (the app remembers which
profile each network should use).

### Insights

Connection counts (allowed, blocked, threat) and data volume over 24 hours,
7 days, 30 days or all time, compared with the previous period. Lists of top
targets, most blocked targets and targets seen for the first time. A map view
places destinations by country. Any view can be shared as an image card with
the numbers, not the hostnames, unless you choose to include them.

### Encrypted DNS

Off by default, in which case the system resolver is used. You can choose Quad9,
Cloudflare Security (1.1.1.2), Cloudflare (no filtering) or a custom DNS over
HTTPS endpoint such as NextDNS. A separate switch blocks other apps from using
well-known public DoH and DoT resolvers, which would otherwise bypass domain
rules.

### Also included

- **History retention** of 7 days, 30 days, 90 days, 6 months or 12 months,
  CSV export of the full history, and a one-tap clear.
- **iCloud sync** of rules, settings, Wi-Fi automation and blocklist
  subscriptions between your devices, through your own private CloudKit
  database. Traffic history and the abuse.ch key never sync.
- **Shortcuts actions**: Turn Protection On, Turn Protection Off, Set Profile,
  Set Mode.
- **Home Screen widget** with protection state and today's blocked count.
- **Weekly summary** notification (optional), which opens the last 7 days in
  Insights.
- **Report a problem** builds a diagnostic summary that contains settings and
  counts only, shows it to you in full, and lets you decide whether to share it.

## How it works

```
iOS network stack
  │  all IPv4 / IPv6 traffic (default routes)
  ▼
Packet Tunnel extension
  ├─ leaf (tun2socks)
  │    reassembles TCP / UDP connections from raw packets
  │    answers DNS with placeholder addresses, so each connection
  │    arrives carrying the hostname it was opened for
  │
  │  SOCKS5 to 127.0.0.1, inside the same process
  ▼
  └─ SOCKS5 server + rule engine
       decides allow or block for each connection
       opens allowed connections directly to their destination
       writes one row per connection to events.sqlite

App Group container, shared by the app and the extension
  rules-snapshot.json   written by the app, read by the tunnel
  events.sqlite         written by the tunnel, read by the app

FluxMoat app
  builds the rule snapshot, reads the history, draws the UI
```

- The tunnel's remote address is `127.0.0.1`. Packets never leave the device
  through the tunnel; allowed connections are opened directly to their real
  destination.
- The app and the extension share an App Group container. The app compiles
  rules, lists and the current profile into `rules-snapshot.json`; the tunnel
  loads it and swaps it in when asked to reload. A snapshot with a bad checksum
  or an unknown schema is rejected and the last good one stays active.
- Flow history is written by the tunnel to a SQLite database in the same
  container and read by the app.
- iOS reports `1.1.1.1` as the DNS server while the tunnel is on. That address
  only points DNS queries into the tunnel so they can be answered locally.
- The extension has to fit in the Network Extension memory limit (about 50 MB),
  so buffers are bounded, the UDP table is capped and idle entries are dropped.
- If the tunnel can't start, it reports the error and iOS removes it, so the
  device falls back to its normal network instead of losing connectivity.
- Country estimates come from the DB-IP Lite database bundled with the app.
  Lookups happen in the app, never in the tunnel.

## How a connection is decided

1. A rule for an exact target beats a site-wide rule, a site-wide rule beats a
   country policy, and a port or protocol rule sits under all three.
2. When two rules are equally specific and disagree, Allow wins.
3. Rules, including country policies, are checked before threat feeds and
   blocklists. An Allow rule is how you make an exception to a list.
4. If nothing matched, the mode decides: Standard allows, Strict blocks, Ask
   applies the profile default and tells you.

## Privacy

What is stored, on the device only: time, destination IP, hostname (from the
device's own DNS lookups), port, protocol, bytes sent and received, the verdict
and the rule that decided it, the active profile, the country estimate and the
network type. Payloads, page contents, URLs and credentials are never stored.
HTTPS is not decrypted and no certificate is installed.

There are no analytics, crash reporting or advertising SDKs, and no server run
by the project receives data from the app. The app talks to the network only in
these cases:

| Destination | When | What is sent |
| --- | --- | --- |
| `feeds.hominexis.com` | You enabled ThreatFox and tapped Update, then every 6 h while open | A plain HTTPS GET |
| `raw.githubusercontent.com` | Same, for StevenBlack hosts | A plain HTTPS GET |
| `feodotracker.abuse.ch` | Same, for Feodo Tracker | A plain HTTPS GET |
| abuse.ch hosts | Only if you added your own Auth-Key | The GET plus your key |
| Your DoH resolver | Only if you turned encrypted DNS on | Your DNS queries |
| Your custom list URL | Only if you added one | A plain HTTPS GET |
| Apple iCloud (CloudKit) | Only if you turned iCloud sync on | Your rules and settings, to your private database |

Location is optional and used only to draw the near end of the lines on the
Insights map. It is requested at reduced accuracy the first time you open the
map, kept in memory and never stored or sent.

## Limitations

- iOS does not tell a packet tunnel which app opened a connection, so traffic is
  shown for the whole device.
- Only connection metadata is visible. HTTPS content is not.
- Ask mode acts after the fact: an alert does not hold a connection open.
- Countries are estimated from IP addresses and can be wrong, especially for
  CDNs that answer from many places.
- Apps that use their own encrypted DNS can bypass domain rules. IP rules still
  apply, and the "Block other encrypted DNS" switch closes the common cases.
- ICMP (ping) is not filtered yet, so ICMP rules have no effect.
- iOS runs one VPN of this kind at a time. Turning another VPN on turns
  FluxMoat off.

## Building

### Requirements

- A Mac with Xcode 26 or later (the project is developed with Xcode 27).
- An iPhone running iOS 18 or later.
- A **paid** Apple Developer Program membership. The packet tunnel needs the
  Network Extension entitlement, which free personal teams don't get.

### Steps

1. Clone the repository.

   ```
   git clone https://github.com/<you>/fluxmoat.git
   cd fluxmoat
   ```

2. Create `FluxMoat/Config/Signing.local.xcconfig` with your team ID and a
   bundle prefix you own. The file is ignored by git.

   ```
   DEVELOPMENT_TEAM = ABCDE12345
   FLUXMOAT_BUNDLE_PREFIX = com.yourname.fluxmoat
   ```

   Everything else follows from the prefix:

   | Item | Value |
   | --- | --- |
   | App | `com.yourname.fluxmoat` |
   | Packet tunnel | `com.yourname.fluxmoat.packettunnel` |
   | Widget | `com.yourname.fluxmoat.widgets` |
   | App Group | `group.com.yourname.fluxmoat` |
   | iCloud container | `iCloud.com.yourname.fluxmoat` |

3. Open `FluxMoat/FluxMoat.xcodeproj`. Swift Package Manager downloads the leaf
   framework (checksum-pinned) the first time.
4. Choose the `FluxMoatApp` scheme and your iPhone, then Run. With automatic
   signing, Xcode registers the bundle IDs, the App Group and the iCloud
   container on your team. If it asks, let it.
5. On the phone, open FluxMoat, turn Protection on and allow the VPN
   configuration when iOS asks.

### Notes

- **Simulator.** The Network Extension does not run in the simulator. Simulator
  builds use a mock tunnel that produces sample traffic, which is enough for UI
  work.
- **iCloud sync.** Debug builds use the CloudKit development environment, where
  the schema is created on first write. For a TestFlight or App Store build,
  deploy the schema (one record type, `FluxMoatConfig`) to production in the
  CloudKit Console first.
- **Signing errors about the App Group or iCloud container** usually mean the
  identifier is already taken by another team. Pick a different
  `FLUXMOAT_BUNDLE_PREFIX`.

### Tests

The rule engine, parsers, snapshot format and stores live in a Swift package
with its own tests:

```
swift test --package-path FluxMoat/Shared
```

## Project layout

```
FluxMoat/
├── App/                    SwiftUI app
│   ├── Features/           Dashboard, Live Traffic, Insights, Rules, Settings, Onboarding
│   ├── Services/           App model, tunnel control, iCloud sync, notifications
│   ├── DesignSystem/       Shared views, colors, copy
│   ├── Intents/            Shortcuts actions
│   └── Resources/GeoIP/    DB-IP country database
├── Extensions/
│   ├── PacketTunnel/       NEPacketTunnelProvider, SOCKS5 server, UDP relay
│   └── Widgets/            Home Screen widget
├── Shared/                 SharedCore package: rule engine, snapshot, stores, parsers (+ tests)
├── LeafKit/                Swift wrapper around the leaf tun2socks engine
├── Config/                 Signing and identifier settings
└── Scripts/                Data generators
```

## Maintenance tasks

**Updating the country database.** DB-IP publishes a new Lite file every month:

```
curl -sfL "https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz" \
  | gunzip > FluxMoat/App/Resources/GeoIP/dbip-country-lite.mmdb
```

Update the date in `FluxMoat/App/Resources/GeoIP/ATTRIBUTION.md` at the same
time.

**Regenerating the world map dots** used by the share cards (needs Pillow and
the Natural Earth 1:110m land GeoJSON):

```
python3 FluxMoat/Scripts/gen-world-dots.py path/to/ne_110m_land.geojson
```

**Hosting your own ThreatFox mirror.** Change `threatFoxMirrorURL` in
`FluxMoat/App/Services/AppModel.swift` to a URL serving the same manifest
format.

## Contributing

Bug reports and pull requests are welcome. A few things help:

- Run the package tests before opening a pull request.
- Never log domains, IP addresses, network names or keys at public level. Use
  counts and labels, and mark anything else `.private`.
- Keep work that uses GeoIP out of the tunnel extension; it has little memory
  to spare.
- For UI changes, include a screenshot.

Questions and discussion: [Discord](https://discord.gg/Y6CahCf4eF).

## License

MIT, see [LICENSE](LICENSE). Third-party components (leaf, DB-IP, Natural
Earth and the blocklist sources) and their licenses are listed in
[NOTICE.md](NOTICE.md).
