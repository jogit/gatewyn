# Image de Gatewyn : un seul conteneur avec Caddy et Gatewyn, comme NPM.
# Gatewyn lance Caddy et le relance s'il s'arrête (GATEWYN_CADDY_BIN).
# Versions épinglées ; ajouter un module Caddy = nouvelle version de l'image.
ARG GO_VERSION=1.27.3
ARG CADDY_VERSION=2.11.9

# Caddy avec le bouncer CrowdSec et les fournisseurs DNS du défi ACME (internal/dnsprov).
# Un fournisseur de plus = une ligne ici et une entrée dans internal/dnsprov.
FROM caddy:${CADDY_VERSION}-builder AS caddy
RUN CGO_ENABLED=0 xcaddy build \
    --with github.com/hslatman/caddy-crowdsec-bouncer/http@v0.15.0 \
    --with github.com/caddy-dns/cloudflare@v0.2.4 \
    --with github.com/caddy-dns/ovh@v1.1.0 \
    --with github.com/caddy-dns/gandi@v1.2.1 \
    --with github.com/caddy-dns/route53@v1.6.2 \
    --with github.com/caddy-dns/digitalocean@v0.0.0-20250606074528-04bde2867106 \
    --with github.com/caddy-dns/hetzner/v2@v2.0.1 \
    --with github.com/caddy-dns/infomaniak@v1.0.2 \
    --with github.com/caddy-dns/ionos@v1.3.0

# Gatewyn : un binaire statique (interface intégrée), sans CGO.
FROM golang:${GO_VERSION} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG GATEWYN_VERSION=0.1.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${GATEWYN_VERSION}" -o /gatewyn ./cmd/gatewyn \
 && mkdir -p /rootfs/data/logs /rootfs/tmp && chmod 1777 /rootfs/tmp

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=caddy /usr/bin/caddy /caddy
COPY --from=build /gatewyn /gatewyn
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/
# /tmp doit être accessible en écriture à l'utilisateur sans privilèges (Caddy y écrit des fichiers temporaires).
COPY --from=build --chown=65532:65532 /rootfs/tmp /tmp
# /data et /data/logs créés dans l'image : un volume nommé en hérite des droits au premier usage
# (/data/logs est un volume à part dans le compose, que CrowdSec et GoAccess lisent seulement).
COPY --from=build --chown=65532:65532 /rootfs/data /data
# Utilisateur sans privilèges. Les ports 80 et 443 sont autorisés par le compose (sysctl).
USER 65532:65532
# Base de Gatewyn, certificats de Caddy et sa configuration : tout dans le volume /data.
ENV GATEWYN_LISTEN=:8080 GATEWYN_DB=/data/gatewyn.db GATEWYN_CADDY_BIN=/caddy \
    XDG_DATA_HOME=/data/caddy XDG_CONFIG_HOME=/data/caddy-config \
    GATEWYN_CERT_DIR=/data/caddy/caddy/certificates
EXPOSE 80 443 8080
# Sonde de santé : l'image n'a ni shell ni curl, c'est Gatewyn lui-même qui interroge /healthz
# (base de données et API d'administration de Caddy).
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 CMD ["/gatewyn", "healthcheck"]
ENTRYPOINT ["/gatewyn"]
