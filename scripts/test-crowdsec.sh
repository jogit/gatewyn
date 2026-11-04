#!/bin/sh
# Test d'intégration CrowdSec sur un Caddy réel : un CrowdSec jetable (API locale seule)
# et le Caddy de l'image, dans des conteneurs isolés. N'utilise que 127.0.0.1
# (ports 12019, 12443, 17422 et 18080) et supprime tout en sortant. Ne touche à aucun
# CrowdSec ni Caddy existant.
# Prérequis : image gatewyn-caddy:dev (docker build --target caddy -t gatewyn-caddy:dev .),
# image crowdsecurity/crowdsec (version épinglée ci-dessous), Go dans le PATH.
set -eu

CROWDSEC_IMAGE=crowdsecurity/crowdsec:v1.8.2
NET=gw-cs-test
TMP=$(mktemp -d)
trap 'docker rm -f gw-cs-caddy gw-crowdsec gw-cs-up >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT

docker network create $NET >/dev/null
# AppSec (WAF) : collections de règles et fichier d'acquisition, comme dans la documentation de CrowdSec.
cat > "$TMP/appsec.yaml" <<YAML
appsec_configs:
  - crowdsecurity/appsec-default
labels:
  type: appsec
listen_addr: 0.0.0.0:7422
source: appsec
YAML
docker run -d --name gw-crowdsec --network $NET -p 127.0.0.1:18080:8080 -p 127.0.0.1:17422:7422 \
  -e DISABLE_ONLINE_API=true -e CROWDSEC_BYPASS_DB_VOLUME_CHECK=true \
  -e COLLECTIONS="crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules" \
  -v "$TMP/appsec.yaml:/etc/crowdsec/acquis.d/appsec.yaml:ro" $CROWDSEC_IMAGE >/dev/null
docker run -d --name gw-cs-up --network $NET gatewyn-caddy:dev caddy respond --listen :8080 "hello from upstream" >/dev/null

i=0
until docker exec gw-crowdsec cscli lapi status >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -gt 60 ] && { echo "CrowdSec ne répond pas" >&2; docker logs gw-crowdsec 2>&1 | tail -5 >&2; exit 1; }
  sleep 2
done
KEY=$(docker exec gw-crowdsec cscli bouncers add gatewyn-test -o raw)

cat > "$TMP/boot.json" <<JSON
{"admin":{"listen":"0.0.0.0:2019","origins":["127.0.0.1:12019"]}}
JSON
docker run -d --name gw-cs-caddy --network $NET \
  -p 127.0.0.1:12019:2019 -p 127.0.0.1:12443:443 \
  -v "$TMP/boot.json:/boot.json:ro" gatewyn-caddy:dev caddy run --config /boot.json >/dev/null
i=0
until curl -fs -m 2 "http://127.0.0.1:12019/config/" >/dev/null 2>&1; do
  i=$((i + 1)); [ $i -gt 30 ] && { echo "Caddy ne répond pas" >&2; exit 1; }
  sleep 1
done

GATEWYN_TEST_CADDY_ADMIN=http://127.0.0.1:12019 \
GATEWYN_TEST_CADDY_HTTPS=127.0.0.1:12443 \
GATEWYN_TEST_CROWDSEC_URL=http://gw-crowdsec:8080 \
GATEWYN_TEST_APPSEC_URL=http://gw-crowdsec:7422 \
GATEWYN_TEST_APPSEC_HOSTURL=http://127.0.0.1:17422 \
GATEWYN_TEST_UPSTREAM=http://gw-cs-up:8080 \
GATEWYN_TEST_CROWDSEC_HOSTURL=http://127.0.0.1:18080 \
GATEWYN_TEST_CROWDSEC_KEY="$KEY" \
GATEWYN_TEST_CROWDSEC_CONTAINER=gw-crowdsec \
  go test -count=1 -v -run TestRealCrowdSec ./internal/caddyadmin
