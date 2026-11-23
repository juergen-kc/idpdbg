//go:build interop

// Interop tests against an MIT Kerberos KDC, run by the "interop" CI jobs.
// Locally:
//
//	scripts/mitkdc.sh
//	go test -tags interop -run MIT -v .
//
// The realm (MIT.TEST) and its principals come from testdata/mitkdc/setup.sh;
// scripts/mitkdc.sh copies their keytabs and PKINIT certificates to
// testdata/mitkdc/run.
package main

import (
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	mitKDC = smbEnv("IDPDBG_MIT_KDC", "localhost:11088")
	mitDir = smbEnv("IDPDBG_MIT_DIR", "testdata/mitkdc/run")
)

func mitFile(t *testing.T, name string) []byte {
	b, err := os.ReadFile(filepath.Join(mitDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mitKeytab(t *testing.T, name string) string {
	return base64.StdEncoding.EncodeToString(mitFile(t, name+".keytab"))
}

func mitArgs(principal string, extra ...M) M {
	return merge(M{"principal": principal + "@MIT.TEST", "kdc": []any{mitKDC}}, extra...)
}

func TestMITInterop(t *testing.T) {
	if c, err := net.DialTimeout("tcp", mitKDC, 3*time.Second); err != nil {
		t.Fatalf("MIT KDC not reachable at %s: %v (run scripts/mitkdc.sh)", mitKDC, err)
	} else {
		c.Close()
	}
	const pw = "Idpdbg-Interop-1" // fixture from testdata/mitkdc/setup.sh

	t.Run("krb kinit", func(t *testing.T) {
		res := kcRun(t, "krb.kinit", mitArgs("alice", M{"password": pw}), nil)
		kcClean(t, res)
		kcWant(t, res, "pre-authentication enforced", "pass")
	})

	t.Run("krb kinit: AS-REP roastable principal detected", func(t *testing.T) {
		// asrep lacks +requires_preauth, so MIT answers without
		// pre-authentication; idpdbg must flag it.
		res := kcRun(t, "krb.kinit", mitArgs("asrep", M{"password": pw}), nil)
		kcWant(t, res, "pre-authentication enforced", "warn")
		kcWant(t, res, "AS exchange (TGT issued)", "pass")
	})

	t.Run("krb keytab", func(t *testing.T) {
		kcClean(t, kcRun(t, "krb.keytab", M{"keytab": mitKeytab(t, "alice")}, nil))
	})

	t.Run("krb service_ticket with MIT's PAC", func(t *testing.T) {
		// MIT 1.20+ issues PACs without the Windows logon-info buffer.
		res := kcRun(t, "krb.service_ticket", mitArgs("alice", M{"keytab": mitKeytab(t, "alice"),
			"spn": "HTTP/web.mit.test", "service_keytab": mitKeytab(t, "web"), "spnego_token": true}), nil)
		kcClean(t, res)
		kcWant(t, res, "service ticket decrypts with the service keytab", "pass")
		kcWant(t, res, "PAC signatures", "pass")
	})

	t.Run("krb service_ticket: PAC signed with an RFC 8009 checksum", func(t *testing.T) {
		res := kcRun(t, "krb.service_ticket", mitArgs("alice", M{"keytab": mitKeytab(t, "alice"),
			"spn": "HTTP/sha2.mit.test", "service_keytab": mitKeytab(t, "sha2")}), nil)
		kcClean(t, res)
		kcWant(t, res, "service ticket: encryption type", "pass")
		kcWant(t, res, "PAC signatures", "pass")
	})

	t.Run("krb s4u: S4U2Self works, S4U2Proxy explained", func(t *testing.T) {
		res := kcRun(t, "krb.s4u", mitArgs("svc-web", M{"keytab": mitKeytab(t, "svc-web"), "impersonate": "alice",
			"target_spn": "HTTP/web.mit.test"}), nil)
		kcWant(t, res, "S4U2Self ticket names the impersonated user", "pass")
		kcWant(t, res, "S4U2Self ticket forwardable", "pass")
		// MIT's PAC has no logon info: no claim either way.
		kcWant(t, res, "user can be delegated", "info")
		c := checkOf(res, "S4U2Proxy (constrained delegation)")
		if c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "MIT krb5") {
			t.Errorf("want MIT's db2 refusal explained, got %+v", c)
		}
	})

	t.Run("krb fast", func(t *testing.T) {
		res := kcRun(t, "krb.fast", mitArgs("alice", M{"keytab": mitKeytab(t, "alice"), "armor_principal": "svc-web@MIT.TEST",
			"armor_keytab": mitKeytab(t, "svc-web"), "target_spn": "HTTP/web.mit.test"}), nil)
		kcClean(t, res)
		kcWant(t, res, "KDC advertises FAST", "pass")
		kcWant(t, res, "KDC encrypted challenge verifies", "pass")
		kcWant(t, res, "FAST TGS exchange (service ticket issued)", "pass")
	})

	t.Run("krb fast armored by anonymous PKINIT", func(t *testing.T) {
		res := kcRun(t, "krb.fast", mitArgs("alice", M{"keytab": mitKeytab(t, "alice"), "armor_anonymous": true,
			"ca_cert": string(mitFile(t, "ca.pem")), "target_spn": "HTTP/web.mit.test"}), nil)
		kcClean(t, res)
		kcWant(t, res, "anonymous PKINIT: session key = KRB-FX-CF2", "pass")
		kcWant(t, res, "anonymous PKINIT: KDC certificate names the realm's KDC", "pass")
		kcWant(t, res, "armor TGT issued", "pass")
		kcWant(t, res, "KDC encrypted challenge verifies", "pass")
		kcWant(t, res, "FAST TGS exchange (service ticket issued)", "pass")
		// Without the KDC's CA the armor authenticates no one, and says so.
		res = kcRun(t, "krb.fast", mitArgs("alice", M{"keytab": mitKeytab(t, "alice"), "armor_anonymous": true}), nil)
		kcWant(t, res, "anonymous PKINIT: KDC certificate chain verifies", "fail")
		kcWant(t, res, "armor authenticates the KDC", "warn")
	})

	t.Run("krb pkinit: anonymous", func(t *testing.T) {
		res := kcRun(t, "krb.pkinit", M{"realm": "MIT.TEST", "kdc": []any{mitKDC}, "anonymous": true, "ca_cert": string(mitFile(t, "ca.pem"))}, nil)
		kcClean(t, res)
		kcWant(t, res, "anonymous PKINIT: the ticket is flagged anonymous", "pass")
		kcWant(t, res, "anonymous PKINIT: the KDC contributes to the session key", "pass")
	})

	t.Run("krb pkinit: Diffie-Hellman and public-key encryption", func(t *testing.T) {
		res := kcRun(t, "krb.pkinit", mitArgs("alice", M{"pkinit_cert": string(mitFile(t, "alice-pkinit.crt")),
			"pkinit_key": string(mitFile(t, "alice-pkinit.key")), "ca_cert": string(mitFile(t, "ca.pem"))}), nil)
		kcClean(t, res)
		kcWant(t, res, "DH: PKINIT accepted (TGT issued)", "pass")
		kcWant(t, res, "DH: KDC certificate chain verifies", "pass")
		kcWant(t, res, "DH: the KDC contributes to the session key", "info") // MIT sends PA_PKINIT_KX only for anonymous PKINIT
		kcWant(t, res, "RSA: PKINIT accepted (TGT issued)", "pass")
		// MIT signs the request's nonce in KDCDHKeyInfo, and encrypts the
		// public-key reply with 3DES although AES was offered first.
		kcWant(t, res, "DH: KDCDHKeyInfo nonce matches the PKAuthenticator", "warn")
		kcWant(t, res, "RSA: content encryption", "warn")
	})
}
