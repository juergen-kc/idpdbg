package main

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Post-quantum certificates: ML-DSA (FIPS 204, RFC 9881) CAs and leaves,
// decoded, verified and served over TLS 1.3.
func TestPostQuantumPKI(t *testing.T) {
	ca := run(t, "pki.ca", M{"levels": 2, "ca_key_type": "ml-dsa-87", "key_type": "ml-dsa-65", "dns_names": "localhost", "ip_addresses": "127.0.0.1"}, nil)
	rootPEM := str(ca["root"].(M)["cert_pem"])
	leaf := ca["leaf"].(M)
	if leaf["certificate"].(M)["key"] != "ML-DSA-65" {
		t.Fatalf("leaf key: %v", leaf["certificate"].(M)["key"])
	}

	dec := run(t, "pki.decode", M{"input": str(leaf["chain_pem"]), "hostname": "localhost"}, nil)
	noFailures(t, dec)
	wantStatus(t, dec, "chain: certificate 1 is signed by certificate 2", "pass")
	if c := checkOf(dec, "leaf localhost: post-quantum key"); c == nil || !strings.Contains(c.Detail, "ML-DSA-65") {
		t.Errorf("post-quantum key: %+v", c)
	}
	if c := checkOf(dec, "leaf localhost: post-quantum signature"); c == nil || !strings.Contains(c.Detail, "ML-DSA-87") {
		t.Errorf("post-quantum signature: %+v", c)
	}
	wantStatus(t, dec, "leaf localhost: ML-DSA key usage only signs", "pass")

	ver := run(t, "pki.verify", M{"chain": str(leaf["chain_pem"]), "roots": rootPEM, "hostname": "localhost"}, nil)
	noFailures(t, ver)

	client := run(t, "pki.issue", M{"issuer_cert": str(ca["issuing"].(M)["cert_pem"]), "issuer_key": str(ca["issuing"].(M)["key_pem"]),
		"cn": "pq-client", "usage": "client", "dns_names": "", "ip_addresses": "", "key_type": "ml-dsa-44"}, nil)
	if client["certificate"].(M)["key"] != "ML-DSA-44" {
		t.Errorf("client key: %v", client["certificate"])
	}
	noFailures(t, run(t, "pki.verify", M{"chain": str(client["chain_pem"]), "roots": rootPEM, "usage": "client"}, nil))

	// An ML-DSA key with keyEncipherment breaks RFC 9881.
	k, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "bad.example"}, DNSNames: []string{"bad.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	bad := run(t, "pki.decode", M{"input": certPEM(cert)}, nil)
	if c := checkOf(bad, "leaf bad.example: ML-DSA key usage only signs"); c == nil || c.Status != "fail" || c.Detail != "keyEncipherment" {
		t.Errorf("keyEncipherment on ML-DSA: %+v", c)
	}

	// Served over TLS 1.3, with and without a post-quantum key exchange.
	pair, err := tls.X509KeyPair([]byte(str(leaf["chain_pem"])), []byte(str(leaf["key_pem"])))
	if err != nil {
		t.Fatal(err)
	}
	serve := func(groups []tls.CurveID) string {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, CurvePreferences: groups}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return strings.TrimPrefix(srv.URL, "https://")
	}
	pq := run(t, "tls.probe", M{"host": serve(nil), "roots": rootPEM, "versions": false}, nil)
	noFailures(t, pq)
	wantStatus(t, pq, "post-quantum key exchange", "pass")
	if pq["key_exchange"] != "X25519MLKEM768" || pq["chain"].([]M)[0]["key"] != "ML-DSA-65" {
		t.Errorf("key exchange %v, leaf %v", pq["key_exchange"], pq["chain"].([]M)[0]["key"])
	}
	sweep := run(t, "tls.probe", M{"host": serve(nil), "roots": rootPEM}, nil)
	wantStatus(t, sweep, "TLS 1.2 not offered", "info")
	wantStatus(t, sweep, "TLS 1.3 supported", "pass")
	classic := run(t, "tls.probe", M{"host": serve([]tls.CurveID{tls.X25519}), "roots": rootPEM, "versions": false}, nil)
	wantStatus(t, classic, "post-quantum key exchange", "info")
	if classic["key_exchange"] != "X25519" {
		t.Errorf("classical key exchange: %v", classic["key_exchange"])
	}
}

// ML-DSA certificates and a CSR made by OpenSSL 4.1 (testdata/pq).
func TestPostQuantumOpenSSL(t *testing.T) {
	read := func(n string) string {
		b, err := os.ReadFile("testdata/pq/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	root, leaf := read("root.pem"), read("leaf.pem")
	dec := run(t, "pki.decode", M{"input": leaf + root, "hostname": "pq.example"}, nil)
	noFailures(t, dec)
	wantStatus(t, dec, "chain: certificate 1 is signed by certificate 2", "pass")
	wantStatus(t, dec, "leaf pq.example: ML-DSA key usage only signs", "pass")
	if c := checkOf(dec, "leaf pq.example: post-quantum signature"); c == nil || !strings.Contains(c.Detail, "ML-DSA-65") {
		t.Errorf("signature: %+v", c)
	}
	noFailures(t, run(t, "pki.verify", M{"chain": leaf, "roots": root, "hostname": "pq.example"}, nil))
	csr := run(t, "pki.decode", M{"input": read("leaf.csr")}, nil)
	noFailures(t, csr)
	if csr["csrs"] == nil && csr["csr"] == nil {
		t.Errorf("CSR not decoded: %v", csr)
	}
}
