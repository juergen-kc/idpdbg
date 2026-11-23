//go:build interop

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// TestSambaCRL publishes a base and a delta CRL where Active Directory
// Certificate Services would (a cRLDistributionPoint object under
// CN=CDP,CN=Public Key Services in the configuration partition), then has
// pki.crl find them through a host-less ldap:/// location, bound as alice.
func TestSambaCRL(t *testing.T) {
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caName := fmt.Sprintf("idpdbg CRL CA %d", now.UnixNano())
	ca := mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: caName}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, nil, &caKey.PublicKey, caKey)

	cdp := "CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration," + smbBase
	dn := "CN=" + caName + ",CN=dc1," + cdp
	loc := func(attr string) string {
		return "ldap:///" + url.PathEscape(dn) + "?" + attr + "?base?objectClass=cRLDistributionPoint"
	}
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := func(serial int64) *x509.Certificate {
		return mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "ws1.samba.test"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(12 * time.Hour), CRLDistributionPoints: []string{loc("certificateRevocationList")}}, ca, &leafKey.PublicKey, caKey)
	}
	good, onBase, onDelta := leaf(100), leaf(101), leaf(102)
	crl := func(number, base int64, serials ...int64) []byte {
		tpl := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(24 * time.Hour)}
		for _, s := range serials {
			tpl.RevokedCertificateEntries = append(tpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(s), RevocationTime: now.Add(-time.Minute), ReasonCode: 1})
		}
		if base > 0 {
			v, _ := asn1.Marshal(big.NewInt(base))
			tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: oidDeltaCRLIndicator, Critical: true, Value: v})
		} else {
			tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: oidFreshestCRL, Value: freshestCRLDER(loc("deltaRevocationList"))})
		}
		der, err := x509.CreateRevocationList(rand.Reader, tpl, ca, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}

	// Publish as Administrator, as the CA would.
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM([]byte(smbCA(t)))
	u, _ := url.Parse(smbLDAPS)
	conn, err := ldap.DialURL(smbLDAPS, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: u.Hostname()}))
	if err != nil {
		t.Fatalf("Samba LDAPS not reachable at %s: %v (run scripts/samba.sh)", smbLDAPS, err)
	}
	defer conn.Close()
	if err := conn.Bind("Administrator@samba.test", smbPass); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"CN=dc1," + cdp} {
		a := ldap.NewAddRequest(c, nil)
		a.Attribute("objectClass", []string{"container"})
		if err := conn.Add(a); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			t.Fatalf("add %s: %v", c, err)
		}
	}
	a := ldap.NewAddRequest(dn, nil)
	a.Attribute("objectClass", []string{"cRLDistributionPoint"})
	a.Attribute("certificateRevocationList", []string{string(crl(7, 0, 101))})
	a.Attribute("deltaRevocationList", []string{string(crl(8, 7, 102))})
	if err := conn.Add(a); err != nil {
		t.Fatalf("publish the CRLs: %v", err)
	}
	t.Cleanup(func() { conn.Del(ldap.NewDelRequest(dn, nil)) })

	args := func(cert *x509.Certificate) M {
		return M{"cert": pemOf(cert, ca), "ldap_url": smbLDAPS, "ca_cert": smbCA(t), "bind_dn": "alice@samba.test", "ldap_password": smbPass, "allow_private_urls": true}
	}
	for _, tc := range []struct {
		name   string
		cert   *x509.Certificate
		status string
	}{{"good", good, "good"}, {"revoked on the base CRL", onBase, "revoked"}, {"revoked on the delta CRL", onDelta, "revoked"}} {
		t.Run(tc.name, func(t *testing.T) {
			res := kcRun(t, "pki.crl", args(tc.cert), nil)
			if res["cert_status"] != tc.status {
				t.Fatalf("status %v, want %s: %v", res["cert_status"], tc.status, res["checks"])
			}
			if d := checkOf(res, "CRL download"); d == nil || d.Status != "pass" || !strings.Contains(d.Detail, "LDAP") {
				t.Errorf("download: %v", d)
			}
			if tc.cert != onBase {
				wantStatus(t, res, "delta CRL: signature", "pass")
				wantStatus(t, res, "delta CRL: applies to this base CRL", "pass")
			}
		})
	}
}
