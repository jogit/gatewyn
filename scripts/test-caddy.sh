#!/bin/sh
# Test d'intégration sur un Caddy réel, dans des conteneurs jetables.
# Prérequis : image gatewyn-caddy:dev (docker build --target caddy -t gatewyn-caddy:dev .),
# Go dans le PATH. N'utilise que 127.0.0.1 (ports 12019 et 12443) et supprime
# tout en sortant. Ne touche à aucun Caddy existant.
set -eu

NET=gw-test
ADMIN_PORT=12019
HTTPS_PORT=12443
HTTP_PORT=12080
TMP=$(mktemp -d)
trap 'docker rm -f gw-caddy gw-up gw-echo >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

# Réglage d'administration initial : il doit survivre aux publications de Gatewyn.
cat > "$TMP/boot.json" <<EOF
{"admin":{"listen":"0.0.0.0:2019","origins":["127.0.0.1:$ADMIN_PORT"]}}
EOF

docker network create $NET >/dev/null
docker run -d --name gw-up --network $NET gatewyn-caddy:dev \
  caddy respond --listen :8080 "hello from upstream" >/dev/null
# Service qui répond le chemin demandé suivi d'un long texte (assez long pour être compressé).
ECHO_BODY="{http.request.uri.path} $(head -c 1200 /dev/zero | tr '\0' x)"
docker run -d --name gw-echo --network $NET gatewyn-caddy:dev \
  caddy respond --listen :8080 "$ECHO_BODY" >/dev/null
docker run -d --name gw-caddy --network $NET \
  -p 127.0.0.1:$ADMIN_PORT:2019 -p 127.0.0.1:$HTTPS_PORT:443 -p 127.0.0.1:$HTTP_PORT:80 \
  -v "$TMP/boot.json:/boot.json:ro" gatewyn-caddy:dev caddy run --config /boot.json >/dev/null

i=0
until curl -fs -m 2 "http://127.0.0.1:$ADMIN_PORT/config/" >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -gt 30 ] && { echo "Caddy ne répond pas" >&2; exit 1; }
  sleep 1
done

GATEWYN_TEST_CADDY_ADMIN=http://127.0.0.1:$ADMIN_PORT \
GATEWYN_TEST_CADDY_HTTPS=127.0.0.1:$HTTPS_PORT \
GATEWYN_TEST_CADDY_HTTP=127.0.0.1:$HTTP_PORT \
GATEWYN_TEST_UPSTREAM=http://gw-up:8080 \
GATEWYN_TEST_ECHO=http://gw-echo:8080 \
GATEWYN_TEST_CADDY_IMAGE=gatewyn-caddy:dev \
GATEWYN_TEST_CADDY_CONTAINER=gw-caddy \
  go test -count=1 -v -run TestRealCaddy ./internal/caddyadmin
