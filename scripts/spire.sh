#!/bin/sh
# Start the SPIRE server (and one agent) used by the interop tests
# (interop_spire_test.go), and copy what the tests need to testdata/spire/run:
# an admin X509-SVID and key for the server's TCP API, and the trust bundle.
#
#   scripts/spire.sh          start (replacing earlier copies) and wait
#   scripts/spire.sh stop     remove the containers
#
# The server API is published on localhost port 18081 (mTLS). On Linux the
# admin socket is testdata/spire/run/admin/api.sock too (Docker Desktop
# cannot share Unix sockets with the host). Then:
#   go test -tags interop -run SPIRE -v .
set -eu

VERSION="1.16.0"
SERVER="idpdbg-spire-server"
AGENT="idpdbg-spire-agent"
NET="idpdbg-spire"
SOCK="/run/spire/admin/api.sock"
cd "$(dirname "$0")/.."
RUN="$PWD/testdata/spire/run"

docker rm -f "$AGENT" "$SERVER" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
[ "${1:-}" = stop ] && exit 0

rm -rf "$RUN"
mkdir -p "$RUN/admin"
docker network create "$NET" >/dev/null
admin="--tmpfs /run/spire/admin:uid=$(id -u),gid=$(id -g)"
[ "$(uname -s)" = Linux ] && admin="-v $RUN/admin:/run/spire/admin"
# As the caller's user, so the admin socket in the shared directory is theirs.
docker run -d --name "$SERVER" --network "$NET" --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:18081:8081 \
  -v "$PWD/testdata/spire/server.conf:/etc/spire/server.conf:ro" \
  $admin \
  --tmpfs "/run/spire/data:uid=$(id -u),gid=$(id -g)" \
  "ghcr.io/spiffe/spire-server:$VERSION" -config /etc/spire/server.conf >/dev/null

server() { docker exec "$SERVER" /opt/spire/bin/spire-server "$@" -socketPath "$SOCK"; }

i=0
until server healthcheck >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ] || [ "$(docker inspect -f '{{.State.Running}}' "$SERVER")" != true ]; then
    docker logs "$SERVER" 2>&1 | tail -50
    echo "the SPIRE server did not become ready" >&2
    exit 1
  fi
  sleep 1
done

# The admin identity (admin_ids in server.conf) and the bundle to verify the
# server with.
server x509 mint -spiffeID spiffe://spire.test/idpdbg-admin -ttl 6h -output json 2>/dev/null | python3 -c '
import json, sys, textwrap
d = json.load(sys.stdin)
pem = lambda kind, b: "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (kind, "\n".join(textwrap.wrap(b, 64)), kind)
open(sys.argv[1] + "/admin-svid.pem", "w").write("".join(pem("CERTIFICATE", c) for c in d["x509_svid"]))
open(sys.argv[1] + "/admin-key.pem", "w").write(pem("PRIVATE KEY", d["private_key"]))
' "$RUN"
server bundle show -format pem >"$RUN/bundle.pem"

# One agent, attested with a join token.
token=$(server token generate -spiffeID spiffe://spire.test/agent/ci -ttl 600 | sed -n 's/^Token: //p')
docker run -d --name "$AGENT" --network "$NET" \
  -v "$PWD/testdata/spire/agent.conf:/etc/spire/agent.conf:ro" \
  "ghcr.io/spiffe/spire-agent:$VERSION" -config /etc/spire/agent.conf -joinToken "$token" >/dev/null
i=0
until server agent list 2>/dev/null | grep -q 'spiffe://spire.test/spire/agent/join_token/'; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    docker logs "$AGENT" 2>&1 | tail -50
    echo "the SPIRE agent did not attest" >&2
    exit 1
  fi
  sleep 1
done
echo "SPIRE $VERSION is ready: trust domain spire.test, server API localhost:18081, admin SVID in $RUN"
