package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// AD CS-style CRL locations: host-less ldap:/// URLs into the
// configuration partition.
const (
	testCDPDN   = "CN=Test CA,CN=CA1,CN=CDP,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com"
	testBaseCDP = "ldap:///" + testCDPDN + "?certificateRevocationList?base?objectClass=cRLDistributionPoint"
	testDeltaDP = "ldap:///" + testCDPDN + "?deltaRevocationList?base?objectClass=cRLDistributionPoint"
)

// freshestCRLDER builds a freshestCRL (CRLDistributionPoints syntax) value.
func freshestCRLDER(uri string) []byte {
	b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: idpDER(uri, false, false)})
	if err != nil {
		panic(err)
	}
	return b
}

func mkTestCRL(t *testing.T, p *crlPKI, number, baseNumber int64, entries []x509.RevocationListEntry, freshest string) []byte {
	t.Helper()
	now := time.Now()
	tpl := &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(24 * time.Hour), RevokedCertificateEntries: entries}
	if baseNumber > 0 {
		v, _ := asn1.Marshal(big.NewInt(baseNumber))
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: oidDeltaCRLIndicator, Critical: true, Value: v})
	}
	if freshest != "" {
		tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: oidFreshestCRL, Value: freshestCRLDER(freshest)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tpl, p.ca, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCRLFromLDAPWithDelta(t *testing.T) {
	p := newCRLPKI(t)
	d := newMockDirectory(t)
	now := time.Now()
	leaf := mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(0x7777), Subject: pkix.Name{CommonName: "ws1.example.com"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), CRLDistributionPoints: []string{testBaseCDP}}, p.ca, &p.leafKey.PublicKey, p.caKey)
	chain := pemOf(leaf, p.ca)
	other := x509.RevocationListEntry{SerialNumber: big.NewInt(99), RevocationTime: now.Add(-48 * time.Hour)}
	mine := func(reason int) x509.RevocationListEntry {
		return x509.RevocationListEntry{SerialNumber: big.NewInt(0x7777), RevocationTime: now.Add(-2 * time.Hour), ReasonCode: reason}
	}
	publish := func(base, delta []byte) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.put(testCDPDN, map[string][]string{"objectClass": {"cRLDistributionPoint"}, "cn": {"Test CA"},
			"certificateRevocationList": {string(base)}, "deltaRevocationList": {string(delta)}})
	}
	args := func(extra M) M {
		m := M{"cert": chain, "ldap_url": d.addr, "allow_private_urls": true}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	// Not revoked anywhere.
	publish(mkTestCRL(t, p, 12, 0, []x509.RevocationListEntry{other}, testDeltaDP), mkTestCRL(t, p, 13, 12, nil, ""))
	r := run(t, "pki.crl", args(nil), nil)
	noFailures(t, r)
	if r["cert_status"] != "good" {
		t.Fatalf("good: %v", r)
	}
	if !strings.Contains(checkOf(r, "CRL download").Detail, "LDAP "+d.addr) {
		t.Errorf("download: %v", checkOf(r, "CRL download"))
	}
	wantStatus(t, r, "delta CRL: signature", "pass")
	wantStatus(t, r, "certificate status with delta CRL", "pass")
	if dc, _ := r["crls"].([]M)[0]["delta_crl"].(M); dc == nil || dc["base_crl_number"] != "12" {
		t.Errorf("delta in output: %v", r["crls"])
	}

	// Revoked since the base CRL: only the delta lists it.
	publish(mkTestCRL(t, p, 12, 0, []x509.RevocationListEntry{other}, testDeltaDP), mkTestCRL(t, p, 13, 12, []x509.RevocationListEntry{mine(1)}, ""))
	r = run(t, "pki.crl", args(nil), nil)
	wantStatus(t, r, "certificate status", "pass")
	wantStatus(t, r, "certificate status with delta CRL", "fail")
	if r["cert_status"] != "revoked" || r["crls"].([]M)[0]["revocation_reason"] != "keyCompromise" {
		t.Errorf("revoked by delta: %v", r)
	}

	// On hold in the base, released by the delta.
	publish(mkTestCRL(t, p, 12, 0, []x509.RevocationListEntry{mine(6)}, testDeltaDP), mkTestCRL(t, p, 13, 12, []x509.RevocationListEntry{mine(8)}, ""))
	r = run(t, "pki.crl", args(nil), nil)
	wantStatus(t, r, "certificate status with delta CRL", "pass")
	if r["cert_status"] != "good" {
		t.Errorf("released from hold: %v", r)
	}

	// A delta for a newer base does not apply.
	publish(mkTestCRL(t, p, 12, 0, nil, testDeltaDP), mkTestCRL(t, p, 15, 14, []x509.RevocationListEntry{mine(1)}, ""))
	r = run(t, "pki.crl", args(nil), nil)
	wantStatus(t, r, "delta CRL: applies to this base CRL", "fail")
	if r["cert_status"] != "good" {
		t.Errorf("foreign delta applied: %v", r)
	}

	// A base CRL in place of a delta.
	delta := mkTestCRL(t, p, 13, 0, []x509.RevocationListEntry{mine(1)}, "")
	publish(mkTestCRL(t, p, 12, 0, nil, testDeltaDP), delta)
	wantStatus(t, run(t, "pki.crl", args(nil), nil), "delta CRL: is a delta CRL (deltaCRLIndicator)", "fail")

	// A supplied delta CRL is used instead of the published one.
	sup := mkTestCRL(t, p, 14, 12, []x509.RevocationListEntry{mine(4)}, "")
	r = run(t, "pki.crl", args(M{"delta_crl": string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: sup}))}), nil)
	if r["cert_status"] != "revoked" || r["crls"].([]M)[0]["revocation_reason"] != "superseded" {
		t.Errorf("supplied delta: %v", r)
	}

	// The delta location is unreachable: the base answer stands, with a warning.
	d.mu.Lock()
	d.put(testCDPDN, map[string][]string{"objectClass": {"cRLDistributionPoint"}, "certificateRevocationList": {string(mkTestCRL(t, p, 12, 0, nil, testDeltaDP))}})
	d.mu.Unlock()
	r = run(t, "pki.crl", args(nil), nil)
	wantStatus(t, r, "delta CRL download", "warn")
	if r["cert_status"] != "good" {
		t.Errorf("no delta: %v", r)
	}

	// Directory addresses from certificates are public-only unless allowed.
	r = run(t, "pki.crl", M{"cert": chain, "ldap_url": d.addr}, nil)
	if c := checkOf(r, "CRL download"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "non-public") {
		t.Errorf("loopback directory used: %v", c)
	}

	// No bind password over a plain connection.
	r = run(t, "pki.crl", args(M{"bind_dn": "cn=admin,dc=example,dc=com", "ldap_password": "adminpw"}), nil)
	if c := checkOf(r, "CRL download"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "unencrypted") {
		t.Errorf("plaintext bind: %v", c)
	}
}

// A directory chosen by the certificate gets no credentials, a delta that
// is not newer than its base is not applied, and a directory cannot send
// more than an HTTP response may.
func TestLDAPCRLHardening(t *testing.T) {
	p := newCRLPKI(t)
	d := newMockDirectory(t)
	host := strings.TrimPrefix(d.addr, "ldap://")
	now := time.Now()
	dn := "cn=crl,dc=example,dc=com"
	leaf := mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(0x7777), Subject: pkix.Name{CommonName: "x"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), CRLDistributionPoints: []string{"ldap://" + host + "/" + dn}}, p.ca, &p.leafKey.PublicKey, p.caKey)
	hold := x509.RevocationListEntry{SerialNumber: big.NewInt(0x7777), RevocationTime: now.Add(-time.Hour), ReasonCode: 6}
	release := hold
	release.ReasonCode = 8
	d.mu.Lock()
	d.put(dn, map[string][]string{"objectClass": {"cRLDistributionPoint"},
		"certificateRevocationList": {string(mkTestCRL(t, p, 12, 0, []x509.RevocationListEntry{hold}, "ldap://"+host+"/"+dn+"?deltaRevocationList"))},
		"deltaRevocationList":       {string(mkTestCRL(t, p, 12, 11, []x509.RevocationListEntry{release}, ""))}})
	d.mu.Unlock()

	// bind_dn with ldap_url elsewhere: the certificate's directory is read anonymously.
	r := run(t, "pki.crl", M{"cert": pemOf(leaf, p.ca), "ldap_url": "ldaps://dc1.corp.example", "bind_dn": "cn=admin,dc=example,dc=com",
		"ldap_password": "adminpw", "allow_private_urls": true}, nil)
	if c := checkOf(r, "CRL download"); c == nil || c.Status != "pass" || !strings.Contains(c.Detail, "anonymous") {
		t.Errorf("certificate-chosen directory: %v", c)
	}
	// The delta is numbered like its base: refused, so the hold stands.
	wantStatus(t, r, "delta CRL: newer than the base CRL", "fail")
	if r["cert_status"] != "revoked" {
		t.Errorf("stale delta released the hold: %v", r)
	}

	old := maxResponseBody
	maxResponseBody = 64
	defer func() { maxResponseBody = old }()
	r = run(t, "pki.crl", M{"cert": pemOf(leaf, p.ca), "allow_private_urls": true}, nil)
	if c := checkOf(r, "CRL download"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "more than 64 bytes") {
		t.Errorf("oversized directory answer: %v", c)
	}
}

func TestLDAPCRLURL(t *testing.T) {
	l, err := parseLDAPCRLURL(testBaseCDP)
	if err != nil {
		t.Fatal(err)
	}
	if l.Host != "" || l.DN != testCDPDN || l.Attr != "certificateRevocationList" || l.Filter != "(objectClass=cRLDistributionPoint)" {
		t.Errorf("parsed: %+v", l)
	}
	if got := domainOfDN(l.DN); got != "example.com" {
		t.Errorf("domain: %q", got)
	}
	l, err = parseLDAPCRLURL("ldap://dir.example:3389/cn=Root%20CA,o=Example?certificateRevocationList;binary")
	if err != nil || l.Host != "dir.example" || l.Port != "3389" || l.DN != "cn=Root CA,o=Example" || l.Attr != "certificateRevocationList;binary" {
		t.Errorf("with host: %+v %v", l, err)
	}
	for _, bad := range []string{"ldap:///", "http://x/y", "ldap:///cn=x?a?weird"} {
		if _, err := parseLDAPCRLURL(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
	if u, err := distributionPointURIs(freshestCRLDER("http://x/delta.crl")); err != nil || len(u) != 1 || u[0] != "http://x/delta.crl" {
		t.Errorf("freshestCRL: %v %v", u, err)
	}
}
