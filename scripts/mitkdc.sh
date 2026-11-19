#!/bin/sh
# Start the MIT Kerberos KDC used by the interop tests (interop_mit_test.go)
# and copy its keytabs and PKINIT certificates to testdata/mitkdc/run.
#
#   scripts/mitkdc.sh          build, start (replacing an earlier copy) and wait
#   scripts/mitkdc.sh stop     remove the container
#
# The KDC is published on localhost port 11088 (TCP and UDP). Then:
#   go test -tags interop -run MIT -v .
set -eu

NAME="idpdbg-mitkdc"
IMAGE="idpdbg-mitkdc"
cd "$(dirname "$0")/.."

docker rm -f "$NAME" >/dev/null 2>&1 || true
[ "${1:-}" = stop ] && exit 0

docker build -q -t "$IMAGE" testdata/mitkdc >/dev/null
docker run -d --name "$NAME" -p 127.0.0.1:11088:88/tcp -p 127.0.0.1:11088:88/udp "$IMAGE" >/dev/null

i=0
until docker exec "$NAME" test -f /export/ready 2>/dev/null && nc -z localhost 11088 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -gt 60 ] || [ "$(docker inspect -f '{{.State.Running}}' "$NAME")" != true ]; then
    docker logs "$NAME" 2>&1 | tail -50
    echo "the MIT KDC did not become ready" >&2
    exit 1
  fi
  sleep 1
done
rm -rf testdata/mitkdc/run
docker cp "$NAME:/export" testdata/mitkdc/run
echo "MIT KDC is ready: realm MIT.TEST, KDC localhost:11088 ($(cat testdata/mitkdc/run/version))"
