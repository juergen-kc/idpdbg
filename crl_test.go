package main

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// idpDER builds an issuingDistributionPoint extension value.
func idpDER(uri string, onlyCA, someReasons bool) []byte {
	mk := func(v asn1.RawValue) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			panic(err) // a RawValue always marshals
		}
		return b
	}
	var body []byte
	if uri != "" {
		gn := mk(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(uri)})
		full := mk(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: gn})
		body = append(body, mk(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: full})...)
	}
	if onlyCA {
		body = append(body, mk(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte{0xFF}})...)
	}
	if someReasons {
		body = append(body, mk(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, Bytes: []byte{0x07, 0x80}})...)
	}
	return mk(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

type crlPKI struct {
	*ocspPKI
	mu   sync.Mutex
	mode string
	hits int
}

func newCRLPKI(t *testing.T) *crlPKI {
	p := &crlPKI{ocspPKI: newOCSPPKI(t), mode: "good"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		mode := p.mode
		p.hits++
		p.mu.Unlock()
		switch r.URL.Path {
		case "/ca.crt":
			w.Write(p.ca.Raw)
		case "/crl", "/crl2":
			if mode == "404" {
				http.NotFound(w, r)
				return
			}
			der, err := p.crl(mode, "http://"+r.Host+r.URL.Path)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			if mode == "pem" {
				der = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
			}
			w.Write(der)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	now := time.Now()
	// A leaf that names only the CRL (no OCSP), like a GTS or Let's Encrypt certificate.
	p.leaf = mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(0x5151), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(12 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature, CRLDistributionPoints: []string{srv.URL + "/crl"}, IssuingCertificateURL: []string{srv.URL + "/ca.crt"}},
		p.ca, &p.leafKey.PublicKey, p.caKey)
	return p
}

func (p *crlPKI) setMode(m string) { p.mu.Lock(); p.mode = m; p.mu.Unlock() }

func (p *crlPKI) crl(mode, url string) ([]byte, error) {
	now := time.Now()
	tpl := &x509.RevocationList{Number: big.NewInt(12), ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(99), RevocationTime: now.Add(-48 * time.Hour)}}}
	issuer, key := p.ca, crypto.Signer(p.caKey)
	switch mode {
	case "revoked":
		tpl.RevokedCertificateEntries = append(tpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(0x5151), RevocationTime: now.Add(-3 * time.Hour), ReasonCode: 1})
	case "hold":
		tpl.RevokedCertificateEntries = append(tpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: big.NewInt(0x5151), RevocationTime: now.Add(-3 * time.Hour), ReasonCode: 6})
	case "stale":
		tpl.ThisUpdate, tpl.NextUpdate = now.Add(-10*24*time.Hour), now.Add(-3*24*time.Hour)
	case "stranger": // same name, different key
		other, err := mkCertE(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, nil, &p.otherKey.PublicKey, p.otherKey)
		if err != nil {
			return nil, err
		}
		issuer, key = other, p.otherKey
	case "other-name": // right key, wrong issuer name
		other, err := mkCertE(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Some Other CA"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}, nil, &p.caKey.PublicKey, p.caKey)
		if err != nil {
			return nil, err
		}
		issuer = other
	case "delta":
		tpl.ExtraExtensions = []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: []byte{0x02, 0x01, 0x0B}}}
	case "idp-ok":
		tpl.ExtraExtensions = []pkix.Extension{{Id: oidIssuingDistributionPoint, Critical: true, Value: idpDER(url, false, false)}}
	case "idp-mismatch":
		tpl.ExtraExtensions = []pkix.Extension{{Id: oidIssuingDistributionPoint, Critical: true, Value: idpDER("http://elsewhere.example/shard7.crl", false, false)}}
	case "idp-ca-only":
		tpl.ExtraExtensions = []pkix.Extension{{Id: oidIssuingDistributionPoint, Critical: true, Value: idpDER(url, true, false)}}
	case "idp-some-reasons":
		tpl.ExtraExtensions = []pkix.Extension{{Id: oidIssuingDistributionPoint, Critical: true, Value: idpDER(url, false, true)}}
	}
	return x509.CreateRevocationList(rand.Reader, tpl, issuer, key)
}

func TestCRL(t *testing.T) {
	p := newCRLPKI(t)
	chain := pemOf(p.leaf, p.ca)
	allow := func(m M) M { m["allow_private_urls"] = true; return m }

	res := run(t, "pki.crl", allow(M{"cert": chain}), nil)
	noFailures(t, res)
	if res["cert_status"] != "good" || res["source"] != "downloaded" {
		t.Errorf("good: %v", res)
	}
	wantStatus(t, res, "CRL signature", "pass")
	wantStatus(t, res, "certificate status", "pass")

	for mode, want := range map[string][2]string{
		"revoked":          {"certificate status", "fail"},
		"hold":             {"certificate status", "fail"},
		"stale":            {"CRL fresh (before nextUpdate)", "fail"},
		"stranger":         {"CRL signature", "fail"},
		"other-name":       {"CRL issuer is the certificate's issuer", "fail"},
		"delta":            {"complete CRL", "fail"},
		"idp-ok":           {"certificate status", "pass"},
		"idp-mismatch":     {"CRL distribution point matches", "fail"},
		"idp-ca-only":      {"CRL scope covers this certificate", "fail"},
		"idp-some-reasons": {"CRL scope covers this certificate", "warn"},
		"pem":              {"certificate status", "pass"},
		"404":              {"CRL download", "fail"},
	} {
		p.setMode(mode)
		r := run(t, "pki.crl", allow(M{"cert": chain}), nil)
		wantStatus(t, r, want[0], want[1])
		switch mode {
		case "revoked":
			if r["cert_status"] != "revoked" || r["crls"].([]M)[0]["revocation_reason"] != "keyCompromise" {
				t.Errorf("revoked: %v", r)
			}
		case "hold":
			if !strings.Contains(checkOf(r, "certificate status").Detail, "on hold") {
				t.Errorf("hold: %v", checkOf(r, "certificate status"))
			}
		case "idp-mismatch", "idp-ca-only", "delta":
			if r["cert_status"] != "undetermined" {
				t.Errorf("%s: a CRL that cannot vouch said %v", mode, r["cert_status"])
			}
		case "idp-ok":
			noFailures(t, r)
		}
	}

	// A supplied CRL is checked without downloading anything.
	p.setMode("good")
	der, err := p.crl("revoked", "")
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	before := p.hits
	p.mu.Unlock()
	r := run(t, "pki.crl", M{"cert": chain, "crl": string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))}, nil)
	if r["cert_status"] != "revoked" || r["source"] != "supplied CRL" || p.hits != before {
		t.Errorf("supplied: %v", r)
	}

	// Certificate-supplied URLs are public-only unless allowed.
	if r := run(t, "pki.crl", M{"cert": chain}, nil); r["cert_status"] != "undetermined" || checkOf(r, "CRL download") == nil ||
		!strings.Contains(checkOf(r, "CRL download").Detail, "non-public") {
		t.Errorf("loopback CRL fetched: %v", r)
	}

	// No http CRL named: said plainly.
	noCDP := mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "x"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), CRLDistributionPoints: []string{"ldap://dir.example/cn=crl"}}, p.ca, &p.leafKey.PublicKey, p.caKey)
	r = run(t, "pki.crl", M{"cert": pemOf(noCDP, p.ca)}, nil)
	wantStatus(t, r, "CRL distribution point named", "info")
	wantStatus(t, r, "CRL distribution point", "info")
}

func TestTLSProbeCRL(t *testing.T) {
	p := newCRLPKI(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{p.leaf.Raw, p.ca.Raw}, PrivateKey: p.leafKey}}}
	srv.StartTLS()
	defer srv.Close()
	args := M{"host": srv.Listener.Addr().String(), "roots": pemOf(p.ca), "versions": false, "crl": true, "allow_private_urls": true}
	res := run(t, "tls.probe", args, nil)
	noFailures(t, res)
	wantStatus(t, res, "leaf certificate status", "pass")
	p.setMode("revoked")
	wantStatus(t, run(t, "tls.probe", args, nil), "leaf certificate status", "fail")

	// ocsp=true alone does not download the CRL.
	p.mu.Lock()
	before := p.hits
	p.mu.Unlock()
	run(t, "tls.probe", M{"host": srv.Listener.Addr().String(), "roots": pemOf(p.ca), "versions": false, "ocsp": true, "allow_private_urls": true}, nil)
	if p.hits != before {
		t.Error("CRL fetched with only ocsp=true")
	}

	// Without crl=true nothing is downloaded.
	p.mu.Lock()
	before = p.hits
	p.mu.Unlock()
	run(t, "tls.probe", M{"host": srv.Listener.Addr().String(), "roots": pemOf(p.ca), "versions": false, "allow_private_urls": true}, nil)
	if p.hits != before {
		t.Error("CRL fetched without crl=true")
	}
}

func TestParseIDP(t *testing.T) {
	idp, err := parseIDP(idpDER("http://c.pki.goog/we1/abc.crl", true, true))
	if err != nil || len(idp.URIs) != 1 || idp.URIs[0] != "http://c.pki.goog/we1/abc.crl" || !idp.OnlyCA || !idp.SomeReasons || idp.OnlyUser {
		t.Errorf("idp: %+v %v", idp, err)
	}
	if _, err := parseIDP([]byte{0x04, 0x00}); err == nil {
		t.Error("non-SEQUENCE accepted")
	}
}
