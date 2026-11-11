# Gatewyn

English · [Français](README.fr.md)

A simple web interface to publish services over HTTPS, on top of Caddy.

Website and demo video: <https://jogit.github.io/gatewyn/>

Status: released and in use. The image is published on GitHub Container Registry (`ghcr.io/jogit/gatewyn`, one tag per release, never `latest`). Working rules are in [AGENTS.md](AGENTS.md) and design decisions with their reasons in [docs/architecture.md](docs/architecture.md).

## Idea

Web interfaces for reverse proxies already exist, many of them very complete. Gatewyn chooses simplicity instead: two fields for a first service, checks before anything is published, and error messages that tell you what to do.

Simplicity goal: someone who has never used a reverse proxy publishes a service over HTTPS in under five minutes.

## What Gatewyn does

- **Hosts**: services (reverse proxy), redirects and 404 pages. Several names per host, per-path rules, HSTS, access lists by IP address. The domain's DNS and the service's response are checked before publishing.
- **HTTPS**: automatic certificate (Let's Encrypt), DNS challenge (Cloudflare, OVH, Gandi, Route 53, DigitalOcean, Hetzner, Infomaniak, IONOS), Caddy's self-signed certificate, or HTTP only.
- **Certificate problems in plain language**: when Let's Encrypt refuses a certificate, the Hosts page and the overview give the cause and what to do (read from Caddy's logs), never a raw ACME code.
- **Protection**: CrowdSec (status, number of active decisions, which services are protected, link to its interface) and its AppSec WAF (rules triggered), both optional.
- **Statistics**: Caddy's access log, on by default for 30 days (retention of your choice, can be turned off in Settings), latest requests and a summary in the interface, optional GoAccess report. With CrowdSec, the log is also read to spot scans.
- **English and French interface**: the language follows the browser, or is chosen in Settings.
- **Interface security**: administrator account created on the first visit (no default credentials), login rate limiting, audit log. Keep the interface on a private network: never expose its port to the Internet.
- **Installation**: one Docker image (Gatewyn and Caddy), SQLite, no other dependency. Gatewyn does not access Docker.

## Try it

```sh
docker compose -f deploy/compose.yml up -d
```

Then open `http://<server address>:8088`. Ports 80 and 443 on the machine must be free. Never expose port 8088 to the Internet (firewall), and create the administrator account right away.

CrowdSec and GoAccess are optional compose services, enabled by profile (add the variable to your `.env` file or to your stack, then redeploy):

```sh
COMPOSE_PROFILES=crowdsec,stats
```

The interface explains each step (Protection and Statistics pages). With the `crowdsec` profile, CrowdSec creates the secrets it shares with Gatewyn and with its web UI by itself: there is nothing to copy by hand.

## Update

Gatewyn never updates itself and does not look for new versions. To update, change the image tag in your compose file (see the [releases](https://github.com/jogit/gatewyn/releases)) and redeploy. Your data stays in the volumes, and the database is copied before each migration. To roll back, redeploy the previous tag. Settings keeps a daily backup copy (at the hour you choose, server time: set `TZ` in the compose file; 7 days by default, on the same disk) and offers a download (database and encryption key, keep it private) and a restore. Back the data volume up elsewhere with your own tool.

## Develop

```sh
go test ./...                    # unit tests
sh scripts/test-caddy.sh         # against a real Caddy, in throwaway containers
sh scripts/test-crowdsec.sh      # with a throwaway CrowdSec (blocking, WAF)
```

Both scripts create their own containers on 127.0.0.1 and remove them on exit; they do not touch any existing installation. The first one needs the `gatewyn-caddy:dev` image (`docker build --target caddy -t gatewyn-caddy:dev .`).

### Translations

French is the reference language: templates and messages in the code are written in French, and the English interface is produced by a catalog (`internal/i18n/en.go` for interface text, `internal/i18n/en_messages.go` for messages produced by the Go code). Nothing needs to be marked in the code. Tests fail when a French text has no English entry, or when French remains in an English page, so a new message cannot be forgotten. Operator logs are always in English.

## Roadmap

Two-factor authentication and an import screen for Nginx Proxy Manager (the database reader exists, read-only, without an interface). No date.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Bundled components keep their own licenses: see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Credits

- Built on [Caddy](https://caddyserver.com), [CrowdSec](https://www.crowdsec.net), [GoAccess](https://goaccess.io) and [htmx](https://htmx.org).
