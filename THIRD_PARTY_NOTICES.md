# Third-party software

The Gatewyn image bundles the following programs. Each keeps its own license; the full texts are in the linked repositories.

| Component | License | Source |
|---|---|---|
| Caddy | Apache-2.0 | https://github.com/caddyserver/caddy |
| caddy-crowdsec-bouncer | Apache-2.0 | https://github.com/hslatman/caddy-crowdsec-bouncer |
| caddy-dns/cloudflare | Apache-2.0 | https://github.com/caddy-dns/cloudflare |
| caddy-dns/ovh, gandi, route53, hetzner, infomaniak, ionos | MIT | https://github.com/caddy-dns |
| caddy-dns/digitalocean | wrapper without a license file (checked 4 November 2026); the libdns/digitalocean package it wraps is MIT | https://github.com/caddy-dns/digitalocean |
| modernc.org/sqlite | BSD-3-Clause | https://gitlab.com/cznic/sqlite |
| htmx (embedded) | 0BSD | https://github.com/bigskysoftware/htmx |
| golang.org/x/net, x/crypto, x/sys, x/text, google/uuid, modernc.org/* (libc, mathutil, memory), remyoudompheng/bigfft | BSD-3-Clause | https://pkg.go.dev |
| dustin/go-humanize | MIT | https://github.com/dustin/go-humanize |
| libdns/libdns and its provider packages (cloudflare, ovh, gandi, route53, digitalocean, hetzner, infomaniak, ionos) | MIT | https://github.com/libdns |

The exact dependency versions are pinned in `go.mod` and in the `Dockerfile`.
