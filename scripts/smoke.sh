#!/usr/bin/env bash
# Smoke test of what CI cannot reach, before a release or a new phase.
#
#   scripts/smoke.sh [section ...]
#
# Sections (default: public binary containers, plus adlab when its env
# file exists):
#   public      read-only checks against public services: OIDC discovery and
#               JWKS at Google and Microsoft, a TLS site's OCSP and CRL, the
#               FIDO Metadata Service. No credentials.
#   binary      the binary itself: version, the MCP handshake and tool list,
#               an HTML report.
#   containers  the CI interop suites (Keycloak, Samba AD, MIT KDC, SCIM)
#               in Docker, as CI runs them.
#   adlab       an Active Directory domain controller with AD CS (see below).
#               Run it from a terminal that may reach the lab's network.
#   hw          a security key and a PIV card; asks for a touch and the PIN.
#
# IDPDBG=path tests that binary (default: one built from this tree).
#
# adlab reads IDPDBG_ADLAB_ENV (default ~/.config/idpdbg/ad-lab.env), which
# sets AD_REALM, AD_DOMAIN, AD_KDC and AD_ALICE_PASSWORD (and optionally
# AD_DC, the domain controller's name, default dc1.<domain>), and the
# directory IDPDBG_ADLAB_DIR (default ad-lab next to the env file) with
# ca.pem (the AD CS root), alice.keytab, svc-web.keytab, svc-rbcd.keytab
# and alice's PKINIT certificate and key (alice-pkinit.crt, .key). The
# domain is expected to have: alice; svc-web with SPN HTTP/web.<domain>,
# constrained delegation with protocol transition to HTTP/app.<domain>;
# svc-rbcd, allowed by the account with SPN HTTP/res.<domain> to delegate
# to it; bob marked sensitive; IIS with Windows authentication on the DC;
# KDC support for armoring. Passwords stay in the environment of the
# commands that need them and are never printed.
set -uo pipefail
cd "$(dirname "$0")/.."

OUT=$(mktemp -d)
pass=0
fail=0
failed=()
BIN=${IDPDBG:-}
if [ -z "$BIN" ]; then
  go build -o "$OUT/idpdbg" . || exit 1
  BIN=$OUT/idpdbg
fi

ok() { pass=$((pass + 1)); printf 'PASS  %s\n' "$1"; }
bad() { fail=$((fail + 1)); failed+=("$1"); printf 'FAIL  %s%s\n' "$1" "${2:+ — $2}"; }

# run NAME ARGS...: run the binary and keep its JSON result as NAME. Exit
# status 2 means some checks failed, which the caller judges.
run() {
  local n=$1 rc
  shift
  "$BIN" "$@" >"$OUT/$n.json" 2>"$OUT/$n.err"
  rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
    bad "$n" "exit status $rc: $(grep -v '^$' "$OUT/$n.err" | tail -1)"
    echo '{}' >"$OUT/$n.json"
    return 1
  fi
}

# checks NAME: every check in the result, wherever it is nested.
checks() { jq -c '[.. | objects | select(has("check") and has("status")) | {name: .check, status, detail}]' "$OUT/$1.json"; }

# want NAME CHECK STATUS: the first check whose name starts with CHECK has
# STATUS.
want() {
  local s
  s=$(checks "$1" | jq -r --arg p "$2" '[.[] | select(.name | startswith($p)) | .status] | first // "missing"')
  if [ "$s" = "$3" ]; then ok "$1: $2 ($3)"; else bad "$1: $2" "$s, want $3"; fi
}

# clean NAME: no check failed.
clean() {
  local f
  f=$(checks "$1" | jq -r '[.[] | select(.status == "fail") | .name + ": " + (.detail // "")] | join("; ")')
  if [ -z "$f" ]; then ok "$1: no failed checks"; else bad "$1: failed checks" "$f"; fi
}

# field NAME JQ WANT: a value in the result.
field() {
  local v
  v=$(jq -r "$2" "$OUT/$1.json")
  if [ "$v" = "$3" ]; then ok "$1: $2 = $3"; else bad "$1: $2" "$v, want $3"; fi
}

section_public() {
  echo "== public services"
  run google oidc discover --issuer https://accounts.google.com && want google "jwks_uri is reachable" pass
  # Google's keys are on another host than its issuer: a server-supplied
  # URL, which must pass the public-address rule.
  run google-jwks jwks fetch --issuer https://accounts.google.com && field google-jwks '.keys | length > 0' true
  # The multi-tenant endpoint names the template {tenantid} as its issuer,
  # which is not the URL used for discovery: idpdbg must say so.
  run microsoft oidc discover --issuer https://login.microsoftonline.com/common/v2.0 &&
    want microsoft "issuer matches the URL used for discovery" fail
  run microsoft-jwks jwks fetch --issuer https://login.microsoftonline.com/common/v2.0 && field microsoft-jwks '.keys | length > 0' true
  run tls-ocsp tls probe --host www.microsoft.com --ocsp --versions=false && want tls-ocsp "live certificate status" pass
  run tls-crl tls probe --host www.google.com --crl --versions=false && want tls-crl "leaf certificate status" pass
  run mds fido metadata --search "YubiKey 5" && want mds "metadata BLOB signature and chain" pass
}

section_binary() {
  echo "== the binary"
  if "$BIN" version | grep -q '^idpdbg v'; then ok "version: $("$BIN" version)"; else bad "version"; fi
  local n
  n=$(printf '%s\n' \
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}' \
    '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' |
    "$BIN" mcp 2>/dev/null | jq -s '[.[] | select(.id == 2) | .result.tools | length] | first // 0')
  if [ "$n" -gt 100 ]; then ok "mcp: $n tools listed"; else bad "mcp: tools/list" "$n tools"; fi
  local tok=eyJhbGciOiJub25lIn0.eyJzdWIiOiJzbW9rZSJ9.
  "$BIN" jwt decode --token "$tok" --report "$OUT/report.html" >/dev/null 2>&1 # exit 2: alg none fails a check
  if grep -q '<html' "$OUT/report.html" 2>/dev/null; then
    local mode
    mode=$(stat -f %Lp "$OUT/report.html" 2>/dev/null || stat -c %a "$OUT/report.html")
    if [ "$mode" = 600 ]; then ok "report: written, mode 600"; else bad "report: mode" "$mode, want 600"; fi
  else
    bad "report: not written"
  fi
}

section_containers() {
  echo "== interop suites (Docker)"
  local s suite
  for s in keycloak:Keycloak samba:Samba mitkdc:MIT scim:SCIM; do
    suite=${s#*:}
    if ! scripts/"${s%%:*}".sh >"$OUT/$suite.start" 2>&1; then
      bad "$suite: container" "$(tail -1 "$OUT/$suite.start")"
      continue
    fi
    if go test -count=1 -tags interop -run "$suite" . >"$OUT/$suite.test" 2>&1; then
      ok "$suite interop suite"
    else
      bad "$suite interop suite" "$(grep -E -- '--- FAIL|_test.go' "$OUT/$suite.test" | head -3 | tr '\n' ' ')"
    fi
    scripts/"${s%%:*}".sh stop >/dev/null 2>&1
  done
}

section_adlab() {
  echo "== Active Directory lab"
  local envf=${IDPDBG_ADLAB_ENV:-$HOME/.config/idpdbg/ad-lab.env}
  if [ ! -r "$envf" ]; then
    bad "adlab: no env file" "$envf"
    return
  fi
  # Only the variables this section uses, never echoed.
  local AD_REALM AD_DOMAIN AD_KDC AD_ALICE_PASSWORD AD_DC
  eval "$(grep -E '^(AD_REALM|AD_DOMAIN|AD_KDC|AD_ALICE_PASSWORD|AD_DC)=' "$envf")"
  local dir=${IDPDBG_ADLAB_DIR:-$(dirname "$envf")/ad-lab}
  local r=$AD_REALM dom
  dom=$(printf '%s' "$AD_DOMAIN" | tr '[:upper:]' '[:lower:]')
  case $dom in *.*) ;; *) dom=$(printf '%s' "$AD_REALM" | tr '[:upper:]' '[:lower:]') ;; esac
  local dc=${AD_DC:-dc1.$dom} ca=$dir/ca.pem k=(--kdc "$AD_KDC")

  # Kerberos.
  IDPDBG_PASSWORD=$AD_ALICE_PASSWORD run ad-kinit krb kinit --principal "alice@$r" "${k[@]}" && clean ad-kinit
  run ad-ticket krb service_ticket --principal "alice@$r" --keytab "$dir/alice.keytab" "${k[@]}" \
    --spn "HTTP/web.$dom" --service-keytab "$dir/svc-web.keytab" && clean ad-ticket && want ad-ticket "PAC" pass
  run ad-s4u krb s4u --principal "svc-web@$r" --keytab "$dir/svc-web.keytab" "${k[@]}" --impersonate alice \
    --target-spn "HTTP/app.$dom" && want ad-s4u "S4U2Proxy" pass
  run ad-rbcd krb s4u --principal "svc-rbcd@$r" --keytab "$dir/svc-rbcd.keytab" "${k[@]}" --impersonate alice \
    --target-spn "HTTP/res.$dom" && want ad-rbcd "S4U2Proxy" pass
  run ad-s4u-sensitive krb s4u --principal "svc-web@$r" --keytab "$dir/svc-web.keytab" "${k[@]}" --impersonate bob \
    --target-spn "HTTP/app.$dom" && want ad-s4u-sensitive "S4U2Proxy" fail
  run ad-fast krb fast --principal "alice@$r" --keytab "$dir/alice.keytab" "${k[@]}" --armor-principal "svc-web@$r" \
    --armor-keytab "$dir/svc-web.keytab" --target-spn "HTTP/web.$dom" && clean ad-fast &&
    want ad-fast "KDC encrypted challenge verifies" pass
  # Active Directory has no anonymous PKINIT; the refusal must say so.
  run ad-fast-anon krb fast --principal "alice@$r" --keytab "$dir/alice.keytab" "${k[@]}" --armor-anonymous --ca-cert "$ca" &&
    want ad-fast-anon "anonymous PKINIT: PKINIT accepted" fail
  run ad-pkinit krb pkinit --principal "alice@$r" "${k[@]}" --pkinit-cert "$dir/alice-pkinit.crt" \
    --pkinit-key "$dir/alice-pkinit.key" --ca-cert "$ca" --mode dh && want ad-pkinit "DH: PKINIT accepted" pass &&
    want ad-pkinit "DH: KDC certificate chain verifies" pass

  # LDAP.
  local lp=$AD_ALICE_PASSWORD
  IDPDBG_LDAP_PASSWORD=$lp run ad-ldaps ldap bind --url "ldaps://$dc" --bind-dn "alice@$dom" --ca-cert "$ca" && clean ad-ldaps
  IDPDBG_LDAP_PASSWORD=$lp run ad-starttls ldap bind --url "ldap://$dc" --starttls --bind-dn "alice@$dom" --ca-cert "$ca" && clean ad-starttls
  IDPDBG_LDAP_PASSWORD=$lp run ad-search ldap search --url "ldaps://$dc" --bind-dn "alice@$dom" --ca-cert "$ca" \
    --base-dn "DC=${dom//./,DC=}" --filter "(sAMAccountName=alice)" && field ad-search '.count' 1

  # Certificates: AD CS publishes its CRLs, base and delta, in the
  # directory (ldap:///CN=…,CN=CDP,…), readable after a bind.
  IDPDBG_LDAP_PASSWORD=$lp run ad-crl pki crl --cert "$dir/alice-pkinit.crt" --issuer "$ca" --ldap-url "ldaps://$dc" \
    --bind-dn "alice@$dom" --ca-cert "$ca" --allow-private-urls &&
    clean ad-crl && field ad-crl '.cert_status' good && want ad-crl "delta CRL: applies to this base CRL" pass
  # tls probe reads the same location anonymously, which AD refuses.
  run ad-tls tls probe --host "ldaps://$dc" --ca-cert "$ca" --crl --allow-private-urls --versions=false &&
    want ad-tls "leaf CRL download" fail &&
    { checks ad-tls | jq -e '.[] | select(.name == "leaf CRL download") | .detail | test("anonymous read")' >/dev/null &&
      ok "ad-tls: the anonymous refusal says how to read it" || bad "ad-tls: no hint for the anonymous refusal"; }

  # HTTP Negotiate against IIS.
  run ad-spnego spnego http --url "http://$dc/" --principal "alice@$r" --keytab "$dir/alice.keytab" "${k[@]}" && clean ad-spnego
}

# run_tty NAME ARGS...: like run, but prompts (touch, PIN) reach the
# terminal; idpdbg asks for a PIN itself, without echo.
run_tty() {
  local n=$1 rc
  shift
  "$BIN" "$@" >"$OUT/$n.json"
  rc=$?
  if [ $rc -ne 0 ] && [ $rc -ne 2 ]; then
    bad "$n" "exit status $rc"
    echo '{}' >"$OUT/$n.json"
    return 1
  fi
}

section_hw() {
  echo "== security key and PIV card (needs touches, and the PIV PIN for PKINIT)"
  run hw-devices fido devices && field hw-devices '.count >= 1' true
  run hw-info fido info --metadata && clean hw-info
  run hw-piv card read --applet piv && clean hw-piv
  echo ">>> WebAuthn with the key against a test relying party: touch it when asked (4 times)"
  if IDPDBG_HW_TEST=1 go test -count=1 -run TestWebAuthnSecurityKey -v . 2>&1 | tee "$OUT/hw-webauthn.test" | grep '>>>'; [ "${PIPESTATUS[0]}" -eq 0 ]; then
    ok "WebAuthn register and sign-in with the key"
  else
    bad "WebAuthn with the key" "$(grep -E -- '--- FAIL|_test.go' "$OUT/hw-webauthn.test" | head -3 | tr '\n' ' ')"
  fi
  # PKINIT with the key's PIV slot 9a, against the AD lab when it is there.
  local envf=${IDPDBG_ADLAB_ENV:-$HOME/.config/idpdbg/ad-lab.env}
  if [ -r "$envf" ]; then
    local AD_REALM AD_KDC
    eval "$(grep -E '^(AD_REALM|AD_KDC)=' "$envf")"
    local dir=${IDPDBG_ADLAB_DIR:-$(dirname "$envf")/ad-lab}
    echo ">>> PKINIT with PIV slot 9a: enter the PIV PIN when asked"
    run_tty hw-pkinit krb pkinit --principal "alice@$AD_REALM" --kdc "$AD_KDC" --pkinit-piv-slot 9a --ca-cert "$dir/ca.pem" --mode dh &&
      want hw-pkinit "DH: PKINIT accepted" pass
  fi
}

sections=("$@")
if [ ${#sections[@]} -eq 0 ]; then
  sections=(public binary containers)
  [ -r "${IDPDBG_ADLAB_ENV:-$HOME/.config/idpdbg/ad-lab.env}" ] && sections+=(adlab)
fi
for s in "${sections[@]}"; do
  case $s in
  public | binary | containers | adlab | hw) "section_$s" ;;
  *) echo "unknown section $s" >&2; exit 2 ;;
  esac
done

echo
echo "$pass passed, $fail failed (results in $OUT)"
for f in ${failed[@]+"${failed[@]}"}; do echo "  failed: $f"; done
[ "$fail" -eq 0 ]
