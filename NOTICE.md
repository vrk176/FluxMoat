# Third-party components

FluxMoat's own code is MIT licensed (see `LICENSE`). It ships or downloads the
following, each under its own terms.

**leaf** (https://github.com/eycorsican/leaf), Apache License 2.0.
The packet tunnel links leaf's prebuilt `leaf.xcframework` (v0.14.2), which
Swift Package Manager downloads and checksum-verifies at build time. It is not
stored in this repository.

**DB-IP IP to Country Lite** (https://db-ip.com), CC BY 4.0.
Bundled as `FluxMoat/App/Resources/GeoIP/dbip-country-lite.mmdb`. The app shows
"IP Geolocation by DB-IP" with a link in Settings > About, and the Countries
share card carries the same credit. Keep both if you ship a build.

**Natural Earth** (https://www.naturalearthdata.com), public domain.
The land outline used to generate `WorldDots.swift`.

**Blocklists and threat feeds** are not bundled. The app downloads them only
after the user taps Update:
- StevenBlack hosts (https://github.com/StevenBlack/hosts), MIT.
- abuse.ch Feodo Tracker and ThreatFox (https://abuse.ch), CC0.
