//go:build interop

// Interop tests against a Samba AD domain controller, run by the "interop"
// CI job. Locally:
//
//	scripts/samba.sh
//	go test -tags interop -run Samba -v .
//
// The domain (SAMBA.TEST) and its accounts come from testdata/samba/setup.sh;
// scripts/samba.sh copies their keytabs and the CA certificate to
// testdata/samba/run.
package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	smbRealm = "SAMBA.TEST"
	smbPass  = "Idpdbg-Interop-1" // test fixture from testdata/samba/setup.sh
	smbBase  = "DC=samba,DC=test"
)

func smbEnv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

var (
	smbKDC   = smbEnv("IDPDBG_SAMBA_KDC", "localhost:10088")
	smbLDAP  = smbEnv("IDPDBG_SAMBA_LDAP", "ldap://localhost:10389")
	smbLDAPS = smbEnv("IDPDBG_SAMBA_LDAPS", "ldaps://localhost:10636")
	smbDir   = smbEnv("IDPDBG_SAMBA_DIR", "testdata/samba/run")
)

// smbKeytab returns a keytab exported by setup.sh, base64-encoded as an MCP
// caller would pass it.
func smbKeytab(t *testing.T, name string) string {
	b, err := os.ReadFile(filepath.Join(smbDir, name+".keytab"))
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func smbCA(t *testing.T) string {
	b, err := os.ReadFile(filepath.Join(smbDir, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func krbArgs(principal string, extra ...M) M {
	return merge(M{"principal": principal + "@" + smbRealm, "kdc": []any{smbKDC}}, extra...)
}

func ldapArgs(t *testing.T, url, user string, extra ...M) M {
	return merge(M{"url": url, "ca_cert": smbCA(t), "bind_dn": user + "@samba.test", "ldap_password": smbPass}, extra...)
}

func TestSambaInterop(t *testing.T) {
	if c, err := net.DialTimeout("tcp", strings.TrimPrefix(smbKDC, "tcp://"), 3*time.Second); err != nil {
		t.Fatalf("Samba KDC not reachable at %s: %v (run scripts/samba.sh)", smbKDC, err)
	} else {
		c.Close()
	}

	t.Run("krb kinit with a password", func(t *testing.T) {
		res := kcRun(t, "krb.kinit", krbArgs("alice", M{"password": smbPass}), nil)
		kcClean(t, res)
		kcWant(t, res, "pre-authentication enforced", "pass")
		kcWant(t, res, "TGT: encryption type", "pass")
	})

	t.Run("krb kinit: account without pre-authentication", func(t *testing.T) {
		// asrep has DONT_REQ_PREAUTH, but Samba 4.22 demands
		// pre-authentication anyway, so it cannot be AS-REP roasted.
		res := kcRun(t, "krb.kinit", krbArgs("asrep", M{"password": smbPass}), nil)
		kcWant(t, res, "pre-authentication enforced", "pass")
	})

	t.Run("krb keytab", func(t *testing.T) {
		kcClean(t, kcRun(t, "krb.keytab", M{"keytab": smbKeytab(t, "alice")}, nil))
	})

	t.Run("krb service_ticket with PAC", func(t *testing.T) {
		res := kcRun(t, "krb.service_ticket", krbArgs("alice", M{"keytab": smbKeytab(t, "alice"),
			"spn": "HTTP/web.samba.test", "service_keytab": smbKeytab(t, "svc-web"), "spnego_token": true}), nil)
		kcClean(t, res)
		kcWant(t, res, "service ticket: encryption type", "pass")
		kcWant(t, res, "service ticket decrypts with the service keytab", "pass")
		kcWant(t, res, "PAC signatures", "pass")
		if find(res, "logon_info") == nil {
			t.Errorf("no logon info decoded from the PAC")
		}
	})

	t.Run("krb service_ticket: Kerberoastable RC4 service", func(t *testing.T) {
		res := kcRun(t, "krb.service_ticket", krbArgs("alice", M{"keytab": smbKeytab(t, "alice"), "spn": "HTTP/legacy.samba.test"}), nil)
		kcWant(t, res, "service ticket: encryption type", "warn")
		kcWant(t, res, "service account exposure", "warn")
	})

	t.Run("krb s4u: classic constrained delegation", func(t *testing.T) {
		res := kcRun(t, "krb.s4u", krbArgs("svc-web", M{"keytab": smbKeytab(t, "svc-web"), "impersonate": "alice",
			"target_spn": "HTTP/app.samba.test", "target_keytab": smbKeytab(t, "svc-app")}), nil)
		kcClean(t, res)
		kcWant(t, res, "S4U2Self ticket forwardable", "pass")
		kcWant(t, res, "PAC records the delegating service", "pass")
	})

	t.Run("krb s4u: resource-based delegation", func(t *testing.T) {
		res := kcRun(t, "krb.s4u", krbArgs("svc-rbcd", M{"keytab": smbKeytab(t, "svc-rbcd"), "impersonate": "alice",
			"target_spn": "HTTP/res.samba.test", "rbcd": true, "target_keytab": smbKeytab(t, "svc-res")}), nil)
		kcClean(t, res)
		kcWant(t, res, "S4U2Proxy (constrained delegation)", "pass")
		kcWant(t, res, "delegated ticket PAC signatures", "pass")
	})

	t.Run("krb s4u: sensitive user is not delegated", func(t *testing.T) {
		res := kcRun(t, "krb.s4u", krbArgs("svc-web", M{"keytab": smbKeytab(t, "svc-web"), "impersonate": "bob",
			"target_spn": "HTTP/app.samba.test"}), nil)
		kcWant(t, res, "user can be delegated", "warn")
		kcWant(t, res, "S4U2Proxy (constrained delegation)", "fail")
	})

	t.Run("krb fast", func(t *testing.T) {
		res := kcRun(t, "krb.fast", krbArgs("alice", M{"keytab": smbKeytab(t, "alice"), "armor_principal": "svc-web@" + smbRealm,
			"armor_keytab": smbKeytab(t, "svc-web"), "target_spn": "HTTP/app.samba.test"}), nil)
		kcClean(t, res)
		// Unlike Active Directory, Samba advertises FAST by default.
		kcWant(t, res, "KDC advertises FAST", "pass")
		kcWant(t, res, "KDC encrypted challenge verifies", "pass")
		kcWant(t, res, "FAST TGS exchange (service ticket issued)", "pass")
	})

	t.Run("tls probe on LDAPS", func(t *testing.T) {
		host, port, _ := net.SplitHostPort(strings.TrimPrefix(smbLDAPS, "ldaps://"))
		res := kcRun(t, "tls.probe", M{"host": host, "port": port, "roots": smbCA(t)}, nil)
		kcClean(t, res)
	})

	t.Run("ldap rootdse and binds", func(t *testing.T) {
		kcClean(t, kcRun(t, "ldap.rootdse", ldapArgs(t, smbLDAPS, "alice"), nil))
		res := kcRun(t, "ldap.bind", ldapArgs(t, smbLDAPS, "alice"), nil)
		kcClean(t, res)
		kcWant(t, res, "Who am I?", "pass")
		res = kcRun(t, "ldap.bind", ldapArgs(t, smbLDAP, "alice", M{"starttls": true}), nil)
		kcClean(t, res)
		kcWant(t, res, "transport is encrypted", "pass")
	})

	t.Run("ldap search: AD attributes decoded", func(t *testing.T) {
		res := kcRun(t, "ldap.search", ldapArgs(t, smbLDAPS, "alice", M{"base_dn": "CN=Users," + smbBase,
			"filter": "(sAMAccountName=bob)", "attributes": []any{"userAccountControl", "objectSid", "pwdLastSet"}}), nil)
		kcClean(t, res)
		uac := fmt.Sprint(find(res, "decoded", "userAccountControl"))
		if !strings.Contains(uac, "NOT_DELEGATED") {
			t.Errorf("userAccountControl decoded as %s", uac)
		}
		if sid := fmt.Sprint(find(res, "objectSid")); !strings.Contains(sid, "S-1-5-21-") {
			t.Errorf("objectSid shown as %s", sid)
		}
	})

	t.Run("ldap passwd: change, wrong old password, reset", func(t *testing.T) {
		user := "CN=pwtest,CN=Users," + smbBase
		fresh := fmt.Sprintf("%s-%d", smbPass, time.Now().UnixNano()) // never in the history
		res := kcRun(t, "ldap.passwd", ldapArgs(t, smbLDAPS, "pwtest", M{"user_dn": user, "old_password": smbPass, "new_password": fresh}), nil)
		kcClean(t, res)
		kcWant(t, res, "password change (unicodePwd)", "pass")

		res = kcRun(t, "ldap.passwd", ldapArgs(t, smbLDAPS, "Administrator", M{"user_dn": user, "old_password": "not-the-password", "new_password": fresh + "x"}), nil)
		if ch := checkOf(res, "password change"); ch == nil || ch.Status != "fail" || !strings.Contains(ch.Detail, "old_password") {
			t.Errorf("wrong old password: want a refusal explained by the old password, got %+v", ch)
		}

		// The administrator resets it, so the test can run again.
		res = kcRun(t, "ldap.passwd", ldapArgs(t, smbLDAPS, "Administrator", M{"user_dn": user, "new_password": smbPass}), nil)
		kcClean(t, res)
		if ch := checkOf(res, "password"); ch == nil || !strings.Contains(ch.Detail, "reset") {
			t.Errorf("want a reset, got %+v", ch)
		}
	})

	t.Run("ldap add, modify, compare, rename, delete", func(t *testing.T) {
		name := fmt.Sprintf("idpdbg-%d", time.Now().UnixNano())
		dn := "OU=" + name + "," + smbBase
		admin := func(extra M) M { return ldapArgs(t, smbLDAPS, "Administrator", extra) }
		kcClean(t, kcRun(t, "ldap.add", admin(M{"dn": dn, "attributes": M{"objectClass": []any{"organizationalUnit"}, "description": "created by idpdbg"}}), nil))
		kcClean(t, kcRun(t, "ldap.modify", admin(M{"dn": dn, "changes": []any{M{"op": "replace", "attr": "description", "values": []any{"changed"}}}}), nil))
		res := kcRun(t, "ldap.compare", admin(M{"dn": dn, "attribute": "description", "value": "changed"}), nil)
		kcClean(t, res)
		renamed := "OU=" + name + "-renamed," + smbBase
		kcClean(t, kcRun(t, "ldap.rename", admin(M{"dn": dn, "new_rdn": "OU=" + name + "-renamed"}), nil))
		kcClean(t, kcRun(t, "ldap.delete", admin(M{"dn": renamed}), nil))
	})
}
