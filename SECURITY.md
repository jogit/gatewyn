# Security policy

Gatewyn drives a reverse proxy that is usually exposed to the Internet, so security reports are taken seriously.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private reporting: on the repository page, **Security → Report a vulnerability**. Include the version (the image tag, for example `1.0.0`), what you did, and what you expected.

You will get an answer as soon as possible. A fix is released first, then the report is made public.

## Supported versions

Only the latest release is supported. Gatewyn does not update itself: pull the new image to get fixes.

## Good to know when you report

- The administration port (8088) is published on all addresses by the compose file: keep it on a private network (firewall), never on the Internet.
- The first administrator account is created by whoever opens the interface first, so create it right after deploying. There are no default credentials.
- Gatewyn has no access to the Docker socket, and its integrations (CrowdSec, statistics) are read-only.
- The access log contains visitors' IP addresses. It is on by default for 30 days and can be turned off in Settings. Requests are written only to that file, never to the container's own logs (stderr), so turning the log off or letting it expire removes the addresses.
- Two-factor authentication is not available yet.

Problems in Caddy, CrowdSec or GoAccess themselves should be reported to those projects.
