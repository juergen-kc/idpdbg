#!/bin/sh
# Start the Keycloak used by the interop tests (interop_test.go) and wait
# until it is ready. The realm comes from testdata/keycloak.
#
#   scripts/keycloak.sh          start it (stops an earlier copy first)
#   scripts/keycloak.sh stop     remove the container
#
# Then: go test -tags interop -run Keycloak -v .
set -eu

IMAGE="quay.io/keycloak/keycloak:26.8.1@sha256:3f3c5f8e03c614774b4bd9173b88391fefa4153bfc010d8012d59ad825377332"
NAME="idpdbg-keycloak"
cd "$(dirname "$0")/.."

docker rm -f "$NAME" >/dev/null 2>&1 || true
[ "${1:-}" = stop ] && exit 0

docker run -d --name "$NAME" -p 127.0.0.1:8080:8080 -p 127.0.0.1:9000:9000 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HEALTH_ENABLED=true \
  -v "$PWD/testdata/keycloak:/opt/keycloak/data/import:ro" \
  -v "$PWD/testdata/keycloak/realm-files:/opt/keycloak/data/idpdbg:ro" \
  "$IMAGE" start-dev --import-realm --features=oid4vc-vci >/dev/null

i=0
until curl -sf http://localhost:9000/health/ready >/dev/null; do
  i=$((i + 1))
  if [ "$i" -gt 90 ]; then
    docker logs "$NAME" 2>&1 | tail -50
    echo "Keycloak did not become ready" >&2
    exit 1
  fi
  sleep 2
done
echo "Keycloak is ready at http://localhost:8080 (realm idpdbg; admin console login admin/admin)"
