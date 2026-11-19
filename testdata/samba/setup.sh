#!/bin/sh
# Provision SAMBA.TEST with the accounts the interop tests use, export
# their keytabs and the CA certificate to /export, then run the DC.
# Every password here belongs to this throwaway test domain only.
set -eu

REALM=SAMBA.TEST
DOMAIN=SAMBA
BASE="DC=samba,DC=test"
PW='Idpdbg-Interop-1'
OUT=/export
mkdir -p "$OUT"

rm -f /etc/samba/smb.conf
samba-tool domain provision --realm="$REALM" --domain="$DOMAIN" --server-role=dc \
  --dns-backend=SAMBA_INTERNAL --adminpass="$PW" --host-name=dc1 \
  --function-level=2016 --option="ad dc functional level = 2016" \
  --option="dns forwarder = 127.0.0.1" >/tmp/provision.log

# TLS for LDAPS and StartTLS: a CA and a server certificate that also names
# localhost, since the tests reach the DC through a mapped port.
TLS=/var/lib/samba/private/idpdbg-tls
mkdir -p "$TLS"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=idpdbg Samba test CA" \
  -keyout "$TLS/ca.key" -out "$TLS/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=dc1.samba.test" \
  -keyout "$TLS/key.pem" -out "$TLS/dc.csr" 2>/dev/null
printf 'subjectAltName=DNS:dc1.samba.test,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > "$TLS/ext.cnf"
openssl x509 -req -in "$TLS/dc.csr" -CA "$TLS/ca.pem" -CAkey "$TLS/ca.key" -CAcreateserial \
  -days 30 -extfile "$TLS/ext.cnf" -out "$TLS/cert.pem" 2>/dev/null
chmod 600 "$TLS/key.pem"
sed -i "/^\[global\]/a \\
\ttls enabled = yes\\
\ttls keyfile = $TLS/key.pem\\
\ttls certfile = $TLS/cert.pem\\
\ttls cafile = $TLS/ca.pem" /etc/samba/smb.conf
cp "$TLS/ca.pem" "$OUT/ca.pem"

samba-tool domain passwordsettings set --min-pwd-age=0 >/dev/null

user() { samba-tool user create "$1" "$PW" >/dev/null; }
user alice
user bob
user pwtest
user svc-web
user svc-app
user svc-rbcd
user svc-res
user svc-legacy
user asrep
samba-tool spn add HTTP/web.samba.test svc-web
samba-tool spn add HTTP/app.samba.test svc-app
samba-tool spn add HTTP/rbcd.samba.test svc-rbcd
samba-tool spn add HTTP/res.samba.test svc-res
# svc-legacy keeps the default encryption types, so its tickets are RC4
# (Kerberoastable); the other services get AES only, as in the AD lab.
samba-tool spn add HTTP/legacy.samba.test svc-legacy

# Classic constrained delegation with protocol transition: svc-web -> app.
samba-tool delegation for-any-protocol svc-web on
samba-tool delegation add-service svc-web HTTP/app.samba.test
# Resource-based: svc-res lets svc-rbcd act for users. Unlike Active
# Directory, Samba makes S4U2Self evidence forwardable only for accounts
# trusted for protocol transition, so svc-rbcd needs that too.
samba-tool delegation add-principal svc-res svc-rbcd
samba-tool delegation for-any-protocol svc-rbcd on
# bob is sensitive and cannot be delegated (NORMAL_ACCOUNT | NOT_DELEGATED).
ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<LDIF
dn: CN=bob,CN=Users,$BASE
changetype: modify
replace: userAccountControl
userAccountControl: 1049088
LDIF
# asrep does not require pre-authentication (AS-REP roastable):
# NORMAL_ACCOUNT | DONT_REQ_PREAUTH.
ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<LDIF
dn: CN=asrep,CN=Users,$BASE
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
LDIF
for svc in svc-web svc-app svc-rbcd svc-res; do
  ldbmodify -H /var/lib/samba/private/sam.ldb >/dev/null <<LDIF
dn: CN=$svc,CN=Users,$BASE
changetype: modify
replace: msDS-SupportedEncryptionTypes
msDS-SupportedEncryptionTypes: 24
LDIF
done

for p in alice svc-web svc-app svc-rbcd svc-res; do
  samba-tool domain exportkeytab "$OUT/$p.keytab" --principal="$p@$REALM" >/dev/null
done
for spn in web app rbcd res; do
  samba-tool domain exportkeytab "$OUT/svc-$spn.keytab" --principal="HTTP/$spn.samba.test@$REALM" >/dev/null
done
chmod -R a+r "$OUT"
samba --version > "$OUT/version"
touch "$OUT/ready"
exec samba -i --no-process-group
