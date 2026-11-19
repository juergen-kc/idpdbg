#!/bin/sh
# Start the SCIM 2.0 server used by the interop tests (interop_scim_test.go):
# i2scim with its in-memory backend, on http://localhost:8090, with the root
# user admin / idpdbg-interop (a fixture for this throwaway server only).
#
#   scripts/scim.sh          start it (replacing an earlier copy) and wait
#   scripts/scim.sh stop     remove the container
#
# Then: go test -tags interop -run SCIM -v .
set -eu

IMAGE="independentid/i2scim-universal:0.10.6@sha256:4bc5322341fcd3a3527bafa69f6b8dd06cbac1d374160cbec16e4ba539f61b3b"
NAME="idpdbg-scim"

docker rm -f "$NAME" >/dev/null 2>&1 || true
[ "${1:-}" = stop ] && exit 0

docker run -d --name "$NAME" -p 127.0.0.1:8090:8080 \
  -e SCIM_SECURITY_ROOT_PASSWORD=idpdbg-interop \
  "$IMAGE" >/dev/null

i=0
until curl -sf -u admin:idpdbg-interop http://localhost:8090/ServiceProviderConfig >/dev/null; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    docker logs "$NAME" 2>&1 | tail -50
    echo "i2scim did not become ready" >&2
    exit 1
  fi
  sleep 2
done
echo "i2scim is ready at http://localhost:8090 (root user admin)"
