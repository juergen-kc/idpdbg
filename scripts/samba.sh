#!/bin/sh
# Start the Samba AD domain controller used by the interop tests
# (interop_samba_test.go) and copy its keytabs and CA certificate to
# testdata/samba/run.
#
#   scripts/samba.sh          build, start (replacing an earlier copy) and wait
#   scripts/samba.sh stop     remove the container
#
# The KDC, LDAP and LDAPS are published on localhost ports 10088, 10389 and
# 10636 (macOS runs its own KDC on port 88). Then:
#   go test -tags interop -run Samba -v .
set -eu

NAME="idpdbg-samba"
IMAGE="idpdbg-samba-dc"
cd "$(dirname "$0")/.."

docker rm -f "$NAME" >/dev/null 2>&1 || true
[ "${1:-}" = stop ] && exit 0

docker build -q -t "$IMAGE" testdata/samba >/dev/null
docker run -d --name "$NAME" --privileged --hostname dc1 \
  -p 127.0.0.1:10088:88/tcp -p 127.0.0.1:10088:88/udp -p 127.0.0.1:10389:389 -p 127.0.0.1:10636:636 \
  "$IMAGE" >/dev/null

i=0
until docker exec "$NAME" test -f /export/ready 2>/dev/null && nc -z localhost 10636 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -gt 90 ] || [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != true ]; then
    docker logs "$NAME" 2>&1 | tail -50
    echo "the Samba DC did not become ready" >&2
    exit 1
  fi
  sleep 2
done
rm -rf testdata/samba/run
docker cp "$NAME:/export" testdata/samba/run
echo "Samba AD DC is ready: realm SAMBA.TEST, KDC localhost:10088, LDAPS localhost:10636 ($(cat testdata/samba/run/version))"
