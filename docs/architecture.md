# Gatewyn — architecture and decisions

What exists, and why. Outdated decisions are replaced, not kept as history.

## Proxy

- Caddy only. No nginx or Traefik adapter: each costs almost as much as a project, and proxies differ on certificates, logs and advanced options.
- Custom Caddy image (xcaddy) with modules shipped in advance: the CrowdSec bouncer and eight DNS challenge providers (catalog in `internal/dnsprov`). Caddy loads no module at runtime: adding one means a new image version.
- One container: Caddy ships in the same image as Gatewyn, which starts it (`GATEWYN_CADDY_BIN`), watches it, restarts it if it stops (`internal/caddyproc`) and republishes the hosts at every start. Gatewyn drives Caddy through its admin API, which stays inside the container (127.0.0.1:2019, published nowhere). Without `GATEWYN_CADDY_BIN`, Gatewyn drives an external Caddy (tests, development). Ports 80 and 443 are allowed to the unprivileged user by a sysctl in the compose file. The database, certificates and Caddy configuration live in the `/data` volume.
- Accepted trade-off: the admin interface and the Internet-facing proxy share a container. Compiling Caddy into the Gatewyn binary was rejected: bigger image and less validation of a new Caddy version before switching.
- Gatewyn replaces only its own servers in Caddy's configuration (`PUT`, then `PATCH` if present), never the whole configuration: `POST /load` would also overwrite administration settings. The configuration is produced by local Go structs that reproduce the admin API's JSON without importing Caddy (importing its types added 36 MB). Three safeguards replace the compiler's check: a reference file of 270 scenarios (`internal/caddyconf/testdata/golden.json`), a test that re-reads every output in Caddy's real types rejecting unknown fields, and tests against a real Caddy.

## CrowdSec

- The bouncer runs inside the proxy (`caddy-crowdsec-bouncer`) rather than as a firewall bouncer: the firewall one depends on the host (nftables, host network, extended rights) and does not suit a simple install.
- The CrowdSec engine and its UI are optional companion applications. In the compose file, CrowdSec creates two random secrets at startup and registers them itself, so nothing is copied by hand: the password of its web UI (`AGENT_USERNAME`/`AGENT_PASSWORD`) and the key of Gatewyn's bouncer (`BOUNCER_KEY_gatewyn`). The bouncer key is written to a volume that Gatewyn reads read-only (`GATEWYN_CROWDSEC_KEY_FILE`); the connection form then asks for no key. With an existing CrowdSec, the key is still entered by hand.
- AppSec (WAF) is supported: its address is entered with the CrowdSec connection, an outage lets requests through or refuses them depending on a setting (let through by default), and a "WAF" switch appears in a service's form when AppSec is connected. Checked on a real Caddy with a real CrowdSec: `/.env` refused with the WAF, accepted without. Not covered by the default rules: generic SQL injections. Known limit, open upstream (`caddy-crowdsec-bouncer` issue #149, still present in v0.14.1 and v0.15.0, not fixed as of 2026-11-06): over HTTP/2 and HTTP/3, a request with no `Content-Length` has its body left out of the AppSec call, so body-based rules (forms, JSON, XML) can be bypassed; URL and header rules and IP bans still apply. A related CrowdSec flaw (CVE-2026-44982) is fixed from 1.7.8 and does not affect the pinned version. The form shows a note under the WAF switch.
- CrowdSec is read-only: status, number of active decisions, triggered AppSec rules. Blocked addresses and their country are viewed in CrowdSec's own interface. Gatewyn embeds no GeoIP database. No unban button.

## Certificates

- Automatic by default (HTTP challenge). A DNS challenge account (eight providers) is chosen per host; credentials are encrypted in the database (AES-256-GCM, key `secret.key` next to the database, never displayed again): back the key up with the database. Gatewyn publishes one certificate rule per account in Caddy.
- Also per host: Caddy's self-signed certificate, or HTTP only. Caddy's internal authority can be downloaded for devices.
- Certificate failures are read from Caddy's logs (`internal/acmelog`) and shown in plain language on the Hosts page and the overview.

## Companion applications

- Gatewyn has no Docker access: a socket grants administrator access to the host, so a compromised interface would control the machine.
- A companion application is an optional compose service (profile, exact image version) tied to one feature: CrowdSec and its UI under Security, GoAccess under Statistics. No "Applications" menu, no generic catalog or manifest.
- Traffic statistics: Caddy's JSON access log contains every visitor's address; it is on by default with a 30-day retention, and can be turned off or its retention changed in Settings (retentions: 7 days, 30 days, 90 days or 1 year; a setting never touched means the default, an explicit "off" is kept). CrowdSec reads the same file (the log lives in its own volume, `gatewyn_logs`, mounted read-only in CrowdSec and GoAccess so they never see the database or the encryption key; `acquis.d/caddy.yaml` in the compose file) for its scan scenarios; Caddy deletes older files itself. Requests are kept out of Caddy's main log (stderr, so the container logs) by an `exclude` on `logging.logs.default`, published and removed together with the access log: in a JSON configuration Caddy sends to the main log everything that no log excludes, and only the Caddyfile adds that exclusion by itself. The Statistics page shows a summary and the latest requests read from the log by Gatewyn. GoAccess (profile `stats`, nothing installed by default) reads the log read-only and serves its report on the local machine (`http://127.0.0.1:8091`, address editable in Settings). No report embedded in Gatewyn.

## Updates

- Companion applications: exact versions pinned in the compose file, never `latest`; updated by the user.
- No Versions page: Gatewyn does not look for new versions and calls no outside service on its own.
- Caddy upgrades are manual (see [AGENTS.md](../AGENTS.md)).
- Container health: the image carries a `HEALTHCHECK` (`gatewyn healthcheck`, which reads `/healthz`: database and Caddy's admin API answer), so a stack manager shows the real state.
- Gatewyn is updated from outside (`docker compose pull`). SQLite migrations are versioned, with a copy of the database before each one (`<db>.avant-vN-<date>`).

## Security

- Administrator account (username and password chosen by the user) created on first launch, no default credentials. The first visitor creates the account, with no setup code: create the account right after deploying. Passwords use argon2id, sessions are stored hashed, login attempts are rate-limited (`X-Forwarded-For` is not trusted for it). Audit log of actions.
- The compose file publishes the admin port 8088 on all addresses: it must stay on a private network (firewall), never on the Internet.
- Invalid input can never be forced; a DNS or target problem asks for explicit confirmation. If Caddy rejects the configuration, nothing is kept: the database change is rolled back.
- Access lists by IP address, per host and per path. "Trusted proxies" setting: behind them, the visitor's address comes from `X-Forwarded-For` read right to left, and a forged address is refused.
- Not done: two-factor authentication.

## Language and interface

- Go: same ecosystem as Caddy and CrowdSec, single binary, interface embedded with `embed`, SQLite without CGO. The image holds about 77 MB (Caddy 62, Gatewyn 15).
- Interface: server-side HTML templates and embedded htmx (2.0.4), no CDN, no JavaScript build step, no external resource at display time (fonts and scripts are embedded).
- Pages: Overview, Hosts (Services, Redirects, 404 pages), Security (CrowdSec protection, Network access, Trusted proxies), TLS (Certificates, DNS accounts), Statistics, Settings. Light and dark theme, usable on a phone.
- Principles: plain title and action button on the right, no introductory paragraph, an empty state that says what to do, a flat form with no collapsed block, a "Save" bar stuck at the bottom, delete at the top right. An optional application that is not installed shows a card and a page explaining how to install it.
- Two fields for a first service (domain, target); options sit below, grouped by theme. DNS and target are checked on input; a failure is shown plainly with the cause and the action to take, never a raw ACME code.

### Languages

- French is the reference language: templates and code messages are written in French and do not change. English is produced after rendering by a translation catalog (`internal/i18n/en.go`, `en_messages.go`), which translates the visible text and attributes of the HTML page. A key may contain `%s`, `%d` or `%q` for a variable value, or be a plain fragment of a sentence.
- Why after rendering: no template to rewrite, no risk for French (a test checks the French page is identical whatever the browser's language), and error messages coming from several packages are translated in one place.
- Choice of language: "Automatic / Français / English" in Settings; automatic follows the browser's `Accept-Language` (French without a header, English for any other language).
- Safeguards: tests fail if a template text or a French Go message has no entry, if an English page rendered with real data still contains French (pages, htmx fragments, invalid-input messages, setup and login), or if a translation has a different number of values than its key.
- Operational logs are in English whatever the interface language.

## Verified state

"Real Caddy": throwaway container, `scripts/test-caddy.sh` (and `scripts/test-crowdsec.sh` for CrowdSec).

| Feature | Verification |
|---|---|
| Caddy configuration (hosts, 301/302 redirects, 404 pages, aliases, HSTS, HTTP only, self-signed, compression, streaming responses, `X-Frame-Options`, `noindex`, gRPC `h2c://` target, accented names in punycode) | Unit tests and real Caddy |
| Per-path rules (other target, prefix stripping, access list) | Unit tests and real Caddy |
| IP access lists, trusted proxies | Unit tests and real Caddy (forged address refused) |
| DNS and target checks, translation of certificate issuance errors | Simulated resolver and local servers. A real Let's Encrypt certificate (HTTP/TLS challenge) was obtained by the maintainer on one domain; no automated test against Let's Encrypt |
| DNS challenge, 8 providers | Real Caddy accepts the configuration; **obtaining a real certificate by DNS is not verified** |
| CrowdSec: bouncer, decisions, AppSec | Real throwaway CrowdSec and real Caddy (blocking, then access restored; WAF) |
| Access log and rotation | Real Caddy (JSON written, stops when removed, requests absent from the container logs) |
| Statistics and GoAccess | Real GoAccess image on a sample log; **not under real traffic** |
| SQLite: versioned migrations, copy before migration, audit log; authentication | Unit tests |
| Single container: start, Caddy restart, clean stop, recovery after restart | Checked by hand on a real Caddy |
| Compose: CrowdSec creates and registers the web UI password and Gatewyn's bouncer key; access log in its own volume; `HEALTHCHECK` | Real containers on a locally built image (machine and bouncer registered, key accepted by the API, log written as the unprivileged user, container `healthy`); the same compose was then deployed by the maintainer |
| NPM database reader (read-only) | Hand-built fictional database following NPM v2.16.0's schema; **never on a real NPM database** |

Known limits:
- The NPM reader counts redirects, 404 hosts, streams and access lists without importing them; it has no screen.
- No option to ignore the target's certificate (a NAS with a self-signed HTTPS certificate is flagged but cannot be used). 307 and 308 redirects are not handled.
- No test of port 443 from outside. The public address (used for the DNS check) is set with `GATEWYN_PUBLIC_IP`, with no automatic detection.
- A single administrator account, no multiple users. The password can be changed in Settings (current password required, other sessions are signed out); if it is lost, `docker exec <container> /gatewyn reset-password` sets a random one, prints it and closes all sessions.
- No two-factor authentication, no TCP/UDP streams (would need the `caddy-l4` module).

## Out of scope

nginx and Traefik adapters, a generic plugin system, container installation by Gatewyn (Docker socket), embedded GoAccess, firewall bouncer, single sign-on for all applications.
