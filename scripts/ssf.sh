#!/bin/sh
# Start the Shared Signals transmitter the interop tests use
# (interop_ssf_test.go): SSFgo's conformance transmitter, an independent
# SSF 1.0 / CAEP implementation, pinned in testdata/ssf/go.mod. It keeps
# everything in memory, generates its signing keys at startup, and emits a
# session-revoked, a credential-change and a device-compliance-change event
# two seconds after a verification request.
#
#   scripts/ssf.sh          build, start (replacing an earlier copy) and wait
#   scripts/ssf.sh stop     stop it
#
# It listens on https://localhost:18443 with issuer
# https://localhost:18443/ssfgo, a certificate from idpdbg's test CA
# (testdata/ssf/run/ca.pem) and the bearer token in testdata/ssf/run/token.
# It skips TLS verification when pushing, as it cannot know idpdbg's
# throwaway push certificate. Then:
#   go test -tags interop -run SSF -v .
set -eu

cd "$(dirname "$0")/.."
RUN="$PWD/testdata/ssf/run"
PIDFILE="$RUN/transmitter.pid"

if [ -f "$PIDFILE" ]; then
  kill "$(cat "$PIDFILE")" 2>/dev/null || true
  rm -f "$PIDFILE"
fi
[ "${1:-}" = stop ] && exit 0

rm -rf "$RUN"
mkdir -p "$RUN"
(cd testdata/ssf && go build -o "$RUN/transmitter" github.com/idfoundry/ssfgo/cmd/conformance-transmitter)

go run . pki ca --levels 1 --dns-names localhost --ip-addresses 127.0.0.1 >"$RUN/ca.json"
python3 - "$RUN" <<'EOF'
import json, sys
d = sys.argv[1]
ca = json.load(open(d + "/ca.json"))
open(d + "/ca.pem", "w").write(ca["root"]["cert_pem"])
open(d + "/tls.pem", "w").write(ca["leaf"]["chain_pem"])
open(d + "/tls.key", "w").write(ca["leaf"]["key_pem"])
EOF
echo "idpdbg-interop-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" >"$RUN/token"

"$RUN/transmitter" -addr 127.0.0.1:18443 -issuer https://localhost:18443/ssfgo \
  -tls-cert "$RUN/tls.pem" -tls-key "$RUN/tls.key" -static-token "$(cat "$RUN/token")" \
  -insecure-push-tls >"$RUN/transmitter.log" 2>&1 &
echo $! >"$PIDFILE"

i=0
until curl -fsS --cacert "$RUN/ca.pem" https://localhost:18443/.well-known/ssf-configuration/ssfgo >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 30 ] || ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    tail -30 "$RUN/transmitter.log"
    echo "the SSF transmitter did not become ready" >&2
    exit 1
  fi
  sleep 1
done
echo "SSFgo transmitter is ready: issuer https://localhost:18443/ssfgo, CA and token in $RUN"
