# Gatewyn — working rules

A simple web interface to publish services over HTTPS, driving Caddy. Everything in this repository must be fit to be public. Overview: [README.md](README.md). Design and verified state: [docs/architecture.md](docs/architecture.md).

## Goals

- Publish a service over HTTPS in under five minutes, with no prior knowledge of reverse proxies.
- Installation: one Docker image, a compose file of a few lines, SQLite, no external dependency.
- Sober interface, usable on a phone, in French and English. Explicit error messages (for example "the domain does not point to your IP"), never a raw ACME code.
- A first service needs two fields only (domain, target). Any feature that complicates this is dropped, or placed below those fields and grouped by theme.

## Scope

- Proxy: Caddy only, in a custom image (xcaddy) with the needed modules: CrowdSec bouncer (`caddy-crowdsec-bouncer`) and DNS challenge providers (catalog in `internal/dnsprov`). Caddy loads no module at runtime: adding a module means a new image version.
- Core: hosts (services, redirects, 404 pages), access lists by IP, status, certificates and DNS accounts. NPM import: read-only reader, no screen yet.
- Companion applications: the tool does not install them and has no Docker access. Each is an optional compose service (profile, pinned image version) tied to one feature: CrowdSec and its UI under Security, GoAccess under Statistics. No "Applications" menu, no generic catalog.
- Read-only integrations: CrowdSec (status, decisions, AppSec WAF), traffic statistics read from Caddy's JSON access log (on by default for 30 days, can be turned off; it holds visitors' IP addresses). Each is isolated from the core.
- Out of scope: nginx and Traefik adapters, a generic plugin system, container installation by the tool (Docker socket), embedded GoAccess, CrowdSec firewall bouncer.
- The core contains no domain name, IP address or service specific to one installation; everything goes through configuration.

## Security

- Administrator account (username and password chosen by the user) created on the first visit to the interface, no default credentials, no setup code (the first visitor is the owner: create the account right after deploying, and keep port 8088 off the Internet). Audit log. Two-factor authentication: not done.
- No access to the Docker socket. Integrations are read-only; any action (ban an IP, create a DNS record) needs explicit activation.
- The admin interface is for the private network only: never expose port 8088 to the Internet.
- No secret, token, password or private URL in code, tests, logs or examples. Sample data is fictional: `example.com`, `192.0.2.x`.

## Versions and updates

- Compose images use exact versions, never `latest`.
- No automatic update. Companion applications are updated by the user.
- No Versions page and no outside call to look for new versions: Gatewyn calls no outside service on its own. Updates are decided by the user, from the project's releases and the compose file.
- Caddy upgrades are manual: validate the existing configuration with the new version before switching, and keep the old image for rollback.
- SQLite: versioned migrations, automatic copy of the database before each migration. Application data lives in volumes separate from images.

## Development

- Language: Go, single binary with the interface embedded (`embed`). Server-side HTML templates and htmx, no JavaScript framework to build. SQLite through a pure Go driver (`modernc.org/sqlite`), no CGO. Caddy's configuration is produced by local Go structs (`internal/caddyconf/model.go`) that depend on no Caddy package, to keep the binary small; tests re-read every output in Caddy's real types in strict mode (`types_caddy_test.go`), and it is checked against a real Caddy. Never import `github.com/caddyserver/caddy` in shipped code.
- Tests are mandatory for Caddy configuration generation and for authentication. Say what is unit-tested and what is verified on a real Caddy.
- Never test against a production NPM, Caddy or CrowdSec. Use a throwaway instance (container or dedicated VM), read-only on NPM first. Back up before any test on a real service.
- Installation-specific deployment notes (VM, IPs, hosts) never go in this repository.
- Replace outdated decisions instead of piling up history.
- Translations: templates and code messages stay written in French (the reference language); English comes from the catalog in `internal/i18n` (`en.go` for the interface, `en_messages.go` for code messages), applied after rendering. Every new visible text needs its entry there: the tests (`internal/web/i18n_test.go`) fail otherwise. Write messages as one complete sentence with `fmt.Sprintf`, never by concatenating pieces. Operational logs (slog) are in English.
- KISS, no over-engineering: the simplest solution that meets today's need. No abstraction, option or layer "for later"; three repeated lines beat a premature abstraction. A new dependency, table or page must be justified by a real need. When in doubt between simple and complete, choose simple and say so.

## License

MIT ([LICENSE](LICENSE)). Components bundled in the image (Caddy under Apache-2.0, modules, libraries) are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), which is copied into the image: update it whenever a module is added.
