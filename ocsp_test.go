package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type ocspPKI struct {
	caKey, leafKey, otherKey *ecdsa.PrivateKey
	ca, leaf                 *x509.Certificate
	srv                      *httptest.Server
	mu                       sync.Mutex
	mode                     string
	hits                     int
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// mkCert issues tpl from parent; a nil parent makes it self-signed.
func mkCert(t *testing.T, tpl, parent *x509.Certificate, pub, signer any) *x509.Certificate {
	c, err := mkCertE(tpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mkCertE(tpl, parent *x509.Certificate, pub, signer any) (*x509.Certificate, error) {
	if parent == nil {
		parent = tpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func pemOf(cs ...*x509.Certificate) string {
	var s string
	for _, c := range cs {
		s += string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return s
}

// newOCSPPKI builds a CA, a leaf that names an in-process OCSP responder and
// caIssuers URL, and the responder, whose behaviour is set by mode.
func newOCSPPKI(t *testing.T) *ocspPKI {
	p := &ocspPKI{caKey: newKey(t), leafKey: newKey(t), otherKey: newKey(t), mode: "good"}
	now := time.Now()
	p.ca = mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign},
		nil, &p.caKey.PublicKey, p.caKey)
	p.srv = httptest.NewServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.srv.Close)
	p.leaf = mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "127.0.0.1"}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(12 * time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature, OCSPServer: []string{p.srv.URL + "/ocsp"}, IssuingCertificateURL: []string{p.srv.URL + "/ca.crt"}},
		p.ca, &p.leafKey.PublicKey, p.caKey)
	return p
}

func (p *ocspPKI) setMode(m string) { p.mu.Lock(); p.mode = m; p.mu.Unlock() }

func (p *ocspPKI) response(t *testing.T, mode string) []byte {
	der, err := p.responseE(mode)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (p *ocspPKI) responseE(mode string) ([]byte, error) {
	now := time.Now().Truncate(time.Second)
	tpl := ocsp.Response{Status: ocsp.Good, SerialNumber: p.leaf.SerialNumber, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(24 * time.Hour)}
	signerCert, signerKey := p.ca, crypto.Signer(p.caKey)
	switch mode {
	case "revoked":
		tpl.Status, tpl.RevokedAt, tpl.RevocationReason = ocsp.Revoked, now.Add(-2*time.Hour), ocsp.KeyCompromise
	case "unknown":
		tpl.Status = ocsp.Unknown
	case "stale":
		tpl.ThisUpdate, tpl.NextUpdate = now.Add(-72*time.Hour), now.Add(-48*time.Hour)
	case "no-next":
		tpl.NextUpdate = time.Time{}
	case "long":
		tpl.NextUpdate = now.Add(30 * 24 * time.Hour)
	case "stranger":
		signerKey = p.otherKey
	case "delegated", "delegated-no-eku":
		eku := []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
		if mode == "delegated-no-eku" {
			eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		rc, err := mkCertE(&x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "Test OCSP Responder"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), ExtKeyUsage: eku, KeyUsage: x509.KeyUsageDigitalSignature},
			p.ca, &p.otherKey.PublicKey, p.caKey)
		if err != nil {
			return nil, err
		}
		tpl.Certificate = rc
		signerCert, signerKey = rc, p.otherKey
	}
	return ocsp.CreateResponse(p.ca, signerCert, tpl, signerKey)
}

func (p *ocspPKI) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	mode := p.mode
	p.hits++
	p.mu.Unlock()
	switch r.URL.Path {
	case "/ca.crt":
		w.Write(p.ca.Raw)
	case "/ocsp":
		body, _ := io.ReadAll(r.Body)
		if _, err := ocsp.ParseRequest(body); err != nil || r.Method != "POST" || r.Header.Get("Content-Type") != "application/ocsp-request" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		switch mode {
		case "trylater":
			w.Write(ocsp.TryLaterErrorResponse)
		case "http500":
			w.WriteHeader(500)
		default:
			der, err := p.responseE(mode)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			w.Write(der)
		}
	default:
		http.NotFound(w, r)
	}
}

func TestOCSP(t *testing.T) {
	p := newOCSPPKI(t)
	chain := pemOf(p.leaf, p.ca)

	res := run(t, "pki.ocsp", M{"allow_private_urls": true, "cert": chain}, nil)
	noFailures(t, res)
	if res["cert_status"] != "good" || res["source"] != "live query" || res["next_update"] == nil {
		t.Errorf("good: %v", res)
	}
	wantStatus(t, res, "OCSP response signature", "pass")

	// The issuer comes from caIssuers when only the leaf is given.
	res = run(t, "pki.ocsp", M{"allow_private_urls": true, "cert": pemOf(p.leaf)}, nil)
	wantStatus(t, res, "issuer certificate fetched", "info")
	wantStatus(t, res, "certificate status", "pass")

	for mode, want := range map[string][2]string{
		"revoked":          {"certificate status", "fail"},
		"unknown":          {"certificate status", "fail"},
		"stale":            {"OCSP response fresh (before nextUpdate)", "fail"},
		"no-next":          {"OCSP nextUpdate", "warn"},
		"long":             {"OCSP validity interval", "warn"},
		"stranger":         {"OCSP response valid", "fail"},
		"trylater":         {"OCSP response status", "fail"},
		"http500":          {"OCSP responder answers", "fail"},
		"delegated":        {"delegated responder authorized (id-kp-OCSPSigning)", "pass"},
		"delegated-no-eku": {"delegated responder authorized (id-kp-OCSPSigning)", "fail"},
	} {
		p.setMode(mode)
		r := run(t, "pki.ocsp", M{"allow_private_urls": true, "cert": chain}, nil)
		wantStatus(t, r, want[0], want[1])
		if mode == "revoked" && (r["revocation_reason"] != "keyCompromise" || r["revoked_at"] == nil) {
			t.Errorf("revoked: %v", r)
		}
		if mode == "delegated" {
			noFailures(t, r)
		}
	}

	// A captured response is checked without contacting anyone.
	p.setMode("good")
	captured := base64.StdEncoding.EncodeToString(p.response(t, "revoked"))
	before := p.hits
	r := run(t, "pki.ocsp", M{"allow_private_urls": true, "cert": chain, "response": captured}, nil)
	if r["source"] != "supplied response" || r["cert_status"] != "revoked" || p.hits != before {
		t.Errorf("captured: %v (hits %d -> %d)", r, before, p.hits)
	}

	// The issuer is the certificate that signed the leaf, not whichever
	// comes first: an unrelated CA passed as issuer is skipped.
	strangerKey := newKey(t)
	stranger := mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "Unrelated CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, &strangerKey.PublicKey, strangerKey)
	r = run(t, "pki.ocsp", M{"allow_private_urls": true, "cert": chain, "issuer": pemOf(stranger)}, nil)
	noFailures(t, r)
	if r["issuer"].(M)["subject"] != "CN=Test CA" {
		t.Errorf("issuer picked: %v", r["issuer"])
	}

	// No issuer anywhere is an error, not a silent pass.
	orphan := mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "orphan"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), OCSPServer: []string{p.srv.URL + "/ocsp"}}, p.ca, &p.leafKey.PublicKey, p.caKey)
	if _, err := tryOp(t, "pki.ocsp", M{"allow_private_urls": true, "cert": pemOf(orphan)}); err == nil {
		t.Error("missing issuer accepted")
	}
	// A certificate without an OCSP URL says so.
	noURL := mkCert(t, &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "no-ocsp"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour)}, p.ca, &p.leafKey.PublicKey, p.caKey)
	wantStatus(t, run(t, "pki.ocsp", M{"allow_private_urls": true, "cert": pemOf(noURL, p.ca)}, nil), "OCSP responder named", "info")
}

func TestTLSProbeOCSP(t *testing.T) {
	p := newOCSPPKI(t)
	serve := func(staple []byte) string {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{p.leaf.Raw, p.ca.Raw}, PrivateKey: p.leafKey, OCSPStaple: staple}}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return srv.Listener.Addr().String()
	}
	roots := pemOf(p.ca)

	res := run(t, "tls.probe", M{"host": serve(p.response(t, "good")), "roots": roots, "versions": false}, nil)
	noFailures(t, res)
	wantStatus(t, res, "stapled certificate status", "pass")
	if res["ocsp_stapled_response"].(M)["cert_status"] != "good" || res["ocsp_live"] != nil {
		t.Errorf("stapled: %v %v", res["ocsp_stapled_response"], res["ocsp_live"])
	}

	// A stapled "revoked" fails even though the chain verifies.
	wantStatus(t, run(t, "tls.probe", M{"host": serve(p.response(t, "revoked")), "roots": roots, "versions": false}, nil), "stapled certificate status", "fail")

	// Without a staple, ocsp=true asks the responder; without it nothing is fetched.
	plain := serve(nil)
	before := p.hits
	run(t, "tls.probe", M{"host": plain, "roots": roots, "versions": false}, nil)
	if p.hits != before {
		t.Error("OCSP queried without ocsp=true")
	}
	p.setMode("revoked")
	res = run(t, "tls.probe", M{"host": plain, "roots": roots, "versions": false, "ocsp": true, "allow_private_urls": true}, nil)
	wantStatus(t, res, "live certificate status", "fail")
	if res["ocsp_live"].(M)["revocation_reason"] != "keyCompromise" {
		t.Errorf("live: %v", res["ocsp_live"])
	}
}

// URLs taken from certificates may not reach non-public addresses unless
// the caller allows it, and a probe only downloads the issuer on request.
func TestOCSPPublicOnly(t *testing.T) {
	p := newOCSPPKI(t)
	before := p.hits
	if _, err := tryOp(t, "pki.ocsp", M{"cert": pemOf(p.leaf, p.ca)}); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("loopback OCSP responder reached: %v", err)
	}
	if _, err := tryOp(t, "pki.ocsp", M{"cert": pemOf(p.leaf)}); err == nil {
		t.Error("loopback caIssuers reached")
	}
	if p.hits != before {
		t.Errorf("responder contacted %d times", p.hits-before)
	}
	// A responder URL the caller names is the caller's choice.
	if res := run(t, "pki.ocsp", M{"cert": pemOf(p.leaf, p.ca), "url": p.srv.URL + "/ocsp"}, nil); res["cert_status"] != "good" {
		t.Errorf("explicit url: %v", res)
	}

	// A server that staples a response but sends no issuer does not make
	// the probe download one.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{p.leaf.Raw}, PrivateKey: p.leafKey, OCSPStaple: p.response(t, "good")}}}
	srv.StartTLS()
	defer srv.Close()
	before = p.hits
	res := run(t, "tls.probe", M{"host": srv.Listener.Addr().String(), "roots": pemOf(p.ca), "versions": false}, nil)
	if p.hits != before {
		t.Error("probe fetched caIssuers without ocsp=true")
	}
	if res["ocsp_stapled_response"] == nil { // the issuer is found through the verified path
		t.Errorf("stapled response not checked: %v", res["checks"])
	}
	// Even with private URLs allowed and no verified path to find the
	// issuer in, nothing is downloaded unless ocsp=true.
	before = p.hits
	res = run(t, "tls.probe", M{"host": srv.Listener.Addr().String(), "versions": false, "allow_private_urls": true}, nil)
	// Windows' own chain building (used when no roots are given) downloads
	// missing issuers by itself; that is the OS, not idpdbg.
	if p.hits != before && runtime.GOOS != "windows" {
		t.Error("probe fetched caIssuers without ocsp=true")
	}
	wantStatus(t, res, "revocation: issuer certificate", "warn")
	before = p.hits
	run(t, "tls.probe", M{"host": srv.Listener.Addr().String(), "roots": pemOf(p.ca), "versions": false, "ocsp": true}, nil)
	if p.hits != before {
		t.Error("probe reached a loopback OCSP responder without allow_private_urls")
	}

	for ip, want := range map[string]bool{"127.0.0.1": true, "10.1.2.3": true, "192.168.0.1": true, "169.254.169.254": true, "100.64.0.1": true,
		"0.0.0.0": true, "::1": true, "fd00:ec2::254": true, "fe80::1": true, "::ffff:127.0.0.1": true, "8.8.8.8": false, "2606:4700::1111": false,
		// IPv4 hidden in IPv6, and the remaining special-purpose ranges.
		"64:ff9b::7f00:1": true, "64:ff9b::a9fe:a9fe": true, "64:ff9b::808:808": false, "64:ff9b:1::1": true, "2002:7f00:1::1": true,
		"2001:0:4136:e378::1": true, "::7f00:1": true, "2001:db8::1": true, "240.0.0.1": true, "255.255.255.255": true, "192.0.2.10": true,
		"198.51.100.7": true, "203.0.113.9": true, "224.0.0.251": true, "ff02::1": true, "1.1.1.1": false} {
		if blockedIP(net.ParseIP(ip)) != want {
			t.Errorf("blockedIP(%s) = %v", ip, !want)
		}
	}
}

// Public-only requests never use a proxy (it would resolve the name again)
// or a pooled connection (which would skip the dial check).
func TestPublicTransport(t *testing.T) {
	r := newRecorder(&tls.Config{})
	pub := r.public.(*http.Transport)
	if pub.Proxy != nil || !pub.DisableKeepAlives || pub.DialContext == nil {
		t.Errorf("public transport: proxy=%v keepalive-off=%v dial=%v", pub.Proxy != nil, pub.DisableKeepAlives, pub.DialContext != nil)
	}
	if r.base.(*http.Transport).Proxy == nil {
		t.Error("the normal transport lost proxy support")
	}
	// The dial itself refuses a name that resolves to loopback.
	if _, err := pub.DialContext(t.Context(), "tcp", "localhost:80"); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("dial to localhost: %v", err)
	}
}

type countingRT struct{ n int }

func (f *countingRT) RoundTrip(*http.Request) (*http.Response, error) {
	f.n++
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
}

// Guarded requests go through the public transport, not the normal one.
func TestDoPublicUsesPublicTransport(t *testing.T) {
	base, pub := &countingRT{}, &countingRT{}
	c := &Ctx{Context: t.Context(), Rec: &Recorder{base: base, public: pub}, Args: M{"timeout": 5}, Log: func(string, ...any) {}}
	if _, err := c.doPublic(false, "GET", "http://8.8.8.8/x", nil, nil); err != nil || pub.n != 1 || base.n != 0 {
		t.Errorf("public-only: err=%v public=%d base=%d", err, pub.n, base.n)
	}
	if _, err := c.doPublic(true, "GET", "http://10.0.0.1/x", nil, nil); err != nil || base.n != 1 {
		t.Errorf("allowed: err=%v base=%d", err, base.n)
	}
	if _, err := c.doPublic(false, "GET", "file:///etc/passwd", nil, nil); err == nil {
		t.Error("file URL accepted")
	}
}
