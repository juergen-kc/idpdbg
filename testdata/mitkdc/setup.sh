#!/bin/sh
# Create MIT.TEST with the principals the interop tests use, export keytabs
# and the PKINIT certificates to /export, then run the KDC in the foreground.
# Every password and key here belongs to this throwaway test realm only.
set -eu

REALM=MIT.TEST
PW='Idpdbg-Interop-1'
OUT=/export
KDB=/var/lib/krb5kdc
mkdir -p "$OUT" /etc/krb5kdc

cat > /etc/krb5.conf <<CONF
[libdefaults]
  default_realm = $REALM
[realms]
  $REALM = {
    kdc = localhost
  }
CONF

# PKINIT: a CA, the KDC's certificate (id-pkinit-KPKdc, krbtgt SAN) and
# alice's (id-pkinit-KPClientAuth, alice@MIT.TEST SAN), as in the MIT docs.
cat > "$KDB/pkinit.cnf" <<'CNF'
[kdc_cert]
basicConstraints=CA:FALSE
keyUsage=nonRepudiation,digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.5
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:kdc_princ_name
[kdc_princ_name]
realm=EXP:0,GeneralString:MIT.TEST
principal_name=EXP:1,SEQUENCE:kdc_principal_seq
[kdc_principal_seq]
name_type=EXP:0,INTEGER:2
name_string=EXP:1,SEQUENCE:kdc_principals
[kdc_principals]
princ1=GeneralString:krbtgt
princ2=GeneralString:MIT.TEST
[client_cert]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment,keyAgreement
extendedKeyUsage=1.3.6.1.5.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=otherName:1.3.6.1.5.2.2;SEQUENCE:client_princ_name
[client_princ_name]
realm=EXP:0,GeneralString:MIT.TEST
principal_name=EXP:1,SEQUENCE:client_principal_seq
[client_principal_seq]
name_type=EXP:0,INTEGER:1
name_string=EXP:1,SEQUENCE:client_principals
[client_principals]
princ1=GeneralString:alice
CNF
cd "$KDB"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=idpdbg MIT test CA" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=kdc.mit.test" -keyout kdc.key -out kdc.csr 2>/dev/null
openssl x509 -req -in kdc.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -extfile pkinit.cnf -extensions kdc_cert -out kdc.pem 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=alice" -keyout alice.key -out alice.csr 2>/dev/null
openssl x509 -req -in alice.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -extfile pkinit.cnf -extensions client_cert -out alice.pem 2>/dev/null
cp ca.pem "$OUT/ca.pem"; cp alice.pem "$OUT/alice-pkinit.crt"; cp alice.key "$OUT/alice-pkinit.key"

cat > /etc/krb5kdc/kdc.conf <<CONF
[kdcdefaults]
  kdc_ports = 88
  kdc_tcp_ports = 88
[realms]
  $REALM = {
    database_name = $KDB/principal
    key_stash_file = $KDB/stash
    acl_file = /etc/krb5kdc/kadm5.acl
    supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal aes256-cts-hmac-sha384-192:normal
    pkinit_identity = FILE:$KDB/kdc.pem,$KDB/kdc.key
    pkinit_anchors = FILE:$KDB/ca.pem
  }
CONF
touch /etc/krb5kdc/kadm5.acl

kdb5_util create -s -r "$REALM" -P "$PW-master" >/dev/null
k() { kadmin.local -q "$1" >/dev/null; }
k "addprinc +requires_preauth -pw $PW alice"
# asrep does not require pre-authentication: AS-REP roastable.
k "addprinc -pw $PW asrep"
k "addprinc +requires_preauth -randkey HTTP/web.mit.test"
# A service with only an RFC 8009 (SHA-2) key: its PAC signatures use
# checksum type 20, which gokrb5 cannot parse on its own.
k "addprinc +requires_preauth -e aes256-cts-hmac-sha384-192:normal -randkey HTTP/sha2.mit.test"
# svc-web may use protocol transition (S4U2Self).
k "addprinc +requires_preauth +ok_to_auth_as_delegate -randkey svc-web"
# Anonymous PKINIT (RFC 8062), e.g. to armor FAST without a machine account.
k "addprinc -randkey WELLKNOWN/ANONYMOUS"
k "ktadd -k $OUT/alice.keytab -norandkey alice"
k "ktadd -k $OUT/web.keytab HTTP/web.mit.test"
k "ktadd -k $OUT/sha2.keytab -e aes256-cts-hmac-sha384-192:normal HTTP/sha2.mit.test"
k "ktadd -k $OUT/svc-web.keytab svc-web"
chmod -R a+r "$OUT"
krb5kdc -V 2>/dev/null > "$OUT/version" || dpkg-query -W -f='${Version}' krb5-kdc > "$OUT/version"
touch "$OUT/ready"
exec krb5kdc -n
