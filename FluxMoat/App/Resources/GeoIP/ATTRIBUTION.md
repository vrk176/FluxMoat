# GeoIP data attribution

`dbip-country-lite.mmdb` is the **DB-IP IP to Country Lite** database,
© [DB-IP](https://db-ip.com), licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

License obligations honored by this app:

- Attribution "IP Geolocation by DB-IP" with a link to https://db-ip.com
  is shown in Settings → About and must remain visible in any release.

Update procedure (monthly releases):

```
curl -sfL "https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz" \
  | gunzip > App/Resources/GeoIP/dbip-country-lite.mmdb
```

Current file: 2026-08 release (build date 2026-08-01).
