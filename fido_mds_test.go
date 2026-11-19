package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The pinned MDS roots are the GlobalSign certificates FIDO documents.
func TestMDSPinnedRoots(t *testing.T) {
	want := map[string]string{
		"GlobalSign":          "cbb522d7b7f127ad6a0113865bdf1cd4102e7d0759af635a7cf4720dc963c53b", // Root CA - R3
		"GlobalSign Root R46": "4fa3126d8d3a11d1c4855a4f807cbad6cf919d3a5a88b03bea2c6372d93c40c9",
	}
	for _, p := range []string{mdsRootR3, mdsRootR46} {
		certs := parsePEMCerts([]byte(p))
		if len(certs) != 1 {
			t.Fatal("bad root PEM")
		}
		sum := sha256.Sum256(certs[0].Raw)
		if want[certs[0].Subject.CommonName] != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: fingerprint %x", certs[0].Subject, sum)
		}
	}
}

type testMDS struct {
	root, leaf       *x509.Certificate
	rootKey, leafKey *ecdsa.PrivateKey
	srv              *httptest.Server
	blob             []byte
	downloads        atomic.Int32
}

func newTestCert(t *testing.T, cn string, dns []string, ca bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: cn}, DNSNames: dns,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: ca,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	if parent == nil {
		parent, parentKey = tmpl, k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, k.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

// newTestMDS serves a BLOB signed by a test CA and points the MDS code at
// it (pinned root, signer name, URL and cache path) for the test.
func newTestMDS(t *testing.T, entries []mdsEntry, nextUpdate string) *testMDS {
	m := &testMDS{}
	m.root, m.rootKey = newTestCert(t, "Test MDS Root", nil, true, nil, nil)
	m.leaf, m.leafKey = newTestCert(t, "mds.test", []string{"mds.test"}, false, m.root, m.rootKey)
	m.sign(t, entries, nextUpdate)
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.downloads.Add(1)
		w.Write(m.blob)
	}))
	t.Cleanup(m.srv.Close)
	roots, name, u, cache := mdsRootsPEM, mdsSignerName, mdsFetchURL, mdsCachePath
	t.Cleanup(func() { mdsRootsPEM, mdsSignerName, mdsFetchURL, mdsCachePath = roots, name, u, cache })
	mdsRootsPEM = []string{string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.root.Raw}))}
	mdsSignerName, mdsFetchURL = "mds.test", m.srv.URL
	dir := t.TempDir()
	mdsCachePath = func() (string, error) { return filepath.Join(dir, "mds.jwt"), nil }
	return m
}

func (m *testMDS) sign(t *testing.T, entries []mdsEntry, nextUpdate string) {
	b, _ := json.Marshal(mdsBlob{LegalHeader: "test", No: 7, NextUpdate: nextUpdate, Entries: entries})
	var claims M
	json.Unmarshal(b, &claims)
	x5c := []any{base64.StdEncoding.EncodeToString(m.leaf.Raw)}
	jws, err := signJWS(m.leafKey, "ES256", M{"typ": "JWT", "x5c": x5c}, claims)
	if err != nil {
		t.Fatal(err)
	}
	m.blob = []byte(jws)
}

func mdsTestEntries(k *fakeKey) []mdsEntry {
	root := base64.StdEncoding.EncodeToString(k.attCert)
	stmt := func(desc string) map[string]any {
		return map[string]any{"description": desc, "protocolFamily": "fido2", "attestationRootCertificates": []any{root},
			"userVerificationDetails": []any{[]any{map[string]any{"userVerificationMethod": "presence_internal"}}}}
	}
	cert, _ := x509.ParseCertificate(k.attCert)
	return []mdsEntry{
		{AAGUID: uuidString(k.aaguid), Statement: stmt("Fake Key"), StatusReports: []mdsStatusReport{{Status: "FIDO_CERTIFIED_L2", EffectiveDate: "2024-01-01", CertificateNumber: "TEST-1"}}},
		{AAGUID: "11111111-2222-3333-4444-555555555555", Statement: stmt("Broken Key"), StatusReports: []mdsStatusReport{
			{Status: "FIDO_CERTIFIED_L1", EffectiveDate: "2023-01-01"}, {Status: "ATTESTATION_KEY_COMPROMISE", EffectiveDate: "2025-06-01"}}},
		{KeyIDs: []string{attestationKeyID(cert)}, Statement: stmt("Fake Key (U2F)"), StatusReports: []mdsStatusReport{{Status: "FIDO_CERTIFIED", EffectiveDate: "2024-01-01"}}},
	}
}

func TestFIDOMetadataLookups(t *testing.T) {
	k := newFakeKey(t, false)
	future := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	m := newTestMDS(t, mdsTestEntries(k), future)

	res := run(t, "fido.metadata", M{"aaguid": uuidString(k.aaguid)}, nil)
	noFailures(t, res)
	wantStatus(t, res, "metadata BLOB signature and chain", "pass")
	wantStatus(t, res, "FIDO certification", "pass")
	if res["entry"].(M)["description"] != "Fake Key" || m.downloads.Load() != 1 {
		t.Fatalf("lookup: %v, %d downloads", res["entry"], m.downloads.Load())
	}
	// Cached: no second download.
	res = run(t, "fido.metadata", M{"search": "key"}, nil)
	if m.downloads.Load() != 1 || len(res["matches"].([]M)) != 3 || !strings.HasPrefix(str(res["blob"].(M)["source"]), "cache") {
		t.Fatalf("cache/search: %d downloads, %v", m.downloads.Load(), res["blob"])
	}
	bad := run(t, "fido.metadata", M{"aaguid": "11111111222233334444555555555555"}, nil)
	wantStatus(t, bad, "security status", "fail")
	// An attestation certificate: found by its AAGUID extension, chain checked.
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.attCert}))
	ac := run(t, "fido.metadata", M{"attestation_certificate": pemCert}, nil)
	wantStatus(t, ac, "attestation chains to the model's root in the FIDO metadata", "pass")
	// Unknown model.
	un := run(t, "fido.metadata", M{"aaguid": "00000000-0000-0000-0000-000000000001"}, nil)
	wantStatus(t, un, "authenticator in the FIDO metadata", "warn")
}

func TestFIDOMetadataRejectsBadBlobs(t *testing.T) {
	k := newFakeKey(t, false)
	future := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	m := newTestMDS(t, mdsTestEntries(k), future)
	good := m.blob

	// A changed payload: the signature no longer holds.
	parts := strings.Split(string(good), ".")
	other, _ := json.Marshal(mdsBlob{No: 8, NextUpdate: future})
	m.blob = []byte(parts[0] + "." + b64url(other) + "." + parts[2])
	res := run(t, "fido.metadata", M{"refresh": true}, nil)
	if c := checkOf(res, "metadata BLOB signature and chain"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "signature") {
		t.Errorf("tampered payload: %+v", c)
	}
	// Signed by a certificate from the pinned CA, but not for the MDS host.
	m.leaf, m.leafKey = newTestCert(t, "evil.test", []string{"evil.test"}, false, m.root, m.rootKey)
	m.sign(t, mdsTestEntries(k), future)
	res = run(t, "fido.metadata", M{"refresh": true}, nil)
	if c := checkOf(res, "metadata BLOB signature and chain"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "mds.test") {
		t.Errorf("wrong signer: %+v", c)
	}
	// A stale cached BLOB is downloaded again.
	m.leaf, m.leafKey = newTestCert(t, "mds.test", []string{"mds.test"}, false, m.root, m.rootKey)
	m.sign(t, mdsTestEntries(k), "2020-01-01")
	path, _ := mdsCachePath()
	os.WriteFile(path, m.blob, 0o600)
	m.sign(t, mdsTestEntries(k), future)
	before := m.downloads.Load()
	res = run(t, "fido.metadata", M{}, nil)
	if m.downloads.Load() != before+1 {
		t.Errorf("stale cache not refreshed: %v", res["blob"])
	}
	wantStatus(t, res, "metadata BLOB current", "pass")
}

func TestWebAuthnRegisterWithMetadata(t *testing.T) {
	for _, pin := range []bool{false, true} { // packed (AAGUID lookup), fido-u2f (key ID lookup)
		k := newFakeKey(t, pin)
		useFakeKey(t, k)
		newTestMDS(t, mdsTestEntries(k), time.Now().AddDate(0, 1, 0).Format("2006-01-02"))
		rp := newTestRP(t)
		rp.direct = true
		reg := run(t, "webauthn.register", M{"server": rp.url, "username": "m", "authenticator": "usb", "metadata": true}, nil)
		noFailures(t, reg)
		wantStatus(t, reg, "authenticator in the FIDO metadata", "pass")
		wantStatus(t, reg, "attestation chains to the model's root in the FIDO metadata", "pass")
		want := map[bool]string{false: "Fake Key", true: "Fake Key (U2F)"}[pin]
		if d := reg["metadata"].(M)["entry"].(M)["description"]; d != want {
			t.Errorf("pin=%v: matched %v, want %s", pin, d, want)
		}
	}
}
