package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPKI(t *testing.T) {
	ca := run(t, "pki.ca", M{"levels": 3, "dns_names": "localhost", "ip_addresses": "127.0.0.1", "usage": "server", "must_staple": true,
		"crl_urls": "http://crl.example/issuing.crl", "ocsp_urls": "http://ocsp.example", "policies": "2.23.140.1.2.1"}, nil)
	noFailures(t, ca)
	rootPEM := str(ca["root"].(M)["cert_pem"])
	issuing := ca["issuing"].(M)
	leaf := ca["leaf"].(M)

	t.Run("hierarchy shape", func(t *testing.T) {
		if ca["intermediate"] == nil {
			t.Fatal("no intermediate at levels=3")
		}
		bc := issuing["certificate"].(M)["basic_constraints"].(M)
		if bc["ca"] != true || bc["max_path_len"] != 0 {
			t.Errorf("issuing CA basic constraints: %v", bc)
		}
		d := leaf["certificate"].(M)
		if d["must_staple"] != true || len(d["crl_distribution_points"].([]string)) != 1 || d["policies"].([]string)[0] != "2.23.140.1.2.1" {
			t.Errorf("leaf extensions missing: %v", d)
		}
		if two := run(t, "pki.ca", M{"levels": 2}, nil); two["intermediate"] != nil || two["issuing"] == nil {
			t.Errorf("levels=2 should give root and issuing only")
		}
	})

	t.Run("decode a chain", func(t *testing.T) {
		res := run(t, "pki.decode", M{"input": str(leaf["chain_pem"]), "hostname": "localhost"}, nil)
		noFailures(t, res)
		wantStatus(t, res, "chain: certificate 1 is signed by certificate 2", "pass")
		wantStatus(t, res, "first certificate is valid for localhost", "pass")
		if n := len(res["certificates"].([]M)); n != 3 {
			t.Errorf("expected leaf, issuing and intermediate, got %d", n)
		}
		// Out of order: the issuing CA first.
		blocks := strings.SplitAfter(str(leaf["chain_pem"]), "-----END CERTIFICATE-----\n")
		swapped := blocks[1] + blocks[0] + blocks[2]
		wantStatus(t, run(t, "pki.decode", M{"input": swapped}, nil), "chain: certificate 1 is signed by certificate 2", "fail")
		// Private keys in the input are never displayed.
		res = run(t, "pki.decode", M{"input": str(leaf["cert_pem"]) + str(leaf["key_pem"])}, nil)
		wantStatus(t, res, "private keys", "info")
		if _, err := runOp(t.Context(), findOp("pki.decode"), M{"input": str(leaf["key_pem"])}, false, nil); err == nil {
			t.Error("a key-only input should be refused")
		}
	})

	t.Run("verify", func(t *testing.T) {
		v := run(t, "pki.verify", M{"chain": str(leaf["chain_pem"]), "roots": rootPEM, "hostname": "localhost"}, nil)
		noFailures(t, v)
		if paths := v["paths"].([][]string); len(paths) != 1 || len(paths[0]) != 4 {
			t.Errorf("expected one path of four certificates: %v", paths)
		}
		wantStatus(t, run(t, "pki.verify", M{"chain": str(leaf["chain_pem"]), "roots": rootPEM, "hostname": "other.example"}, nil), "chain verifies", "fail")
		wantStatus(t, run(t, "pki.verify", M{"chain": str(leaf["chain_pem"]), "roots": rootPEM, "usage": "client"}, nil), "chain verifies", "fail")
		wantStatus(t, run(t, "pki.verify", M{"chain": str(leaf["chain_pem"]), "hostname": "localhost"}, nil), "chain verifies against the system trust store", "fail")
		wantStatus(t, run(t, "pki.verify", M{"chain": str(leaf["chain_pem"]), "roots": rootPEM, "at_time": time.Now().AddDate(1, 0, 0).Format(time.RFC3339)}, nil), "chain verifies", "fail")
	})

	t.Run("issue from an existing CA", func(t *testing.T) {
		client := run(t, "pki.issue", M{"issuer_cert": str(issuing["cert_pem"]) + str(ca["intermediate"].(M)["cert_pem"]), "issuer_key": str(issuing["key_pem"]),
			"cn": "alice", "usage": "client", "emails": "alice@example.com", "dns_names": "", "ip_addresses": "", "key_type": "rsa-2048"}, nil)
		d := client["certificate"].(M)
		if d["extended_key_usage"].([]string)[0] != "clientAuth" || d["key"] != "RSA 2048" {
			t.Errorf("client certificate: %v", d)
		}
		noFailures(t, run(t, "pki.verify", M{"chain": str(client["chain_pem"]), "roots": rootPEM, "usage": "client"}, nil))
		if _, err := runOp(t.Context(), findOp("pki.issue"), M{"issuer_cert": str(leaf["cert_pem"]), "issuer_key": str(leaf["key_pem"])}, false, nil); err == nil {
			t.Error("a leaf certificate was accepted as an issuer")
		}
	})

	t.Run("CSR and CRL", func(t *testing.T) {
		issuer, _ := x509.ParseCertificate(pemDER(str(issuing["cert_pem"])))
		key, _ := loadSigner(str(issuing["key_pem"]))
		leafCert, _ := x509.ParseCertificate(pemDER(str(leaf["cert_pem"])))
		crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
			Number: big.NewInt(7), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(24 * time.Hour),
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: leafCert.SerialNumber, RevocationTime: time.Now()}},
		}, issuer, key)
		if err != nil {
			t.Fatal(err)
		}
		crl := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER}))
		res := run(t, "pki.decode", M{"input": crl, "issuer_cert": str(issuing["cert_pem"]), "check_serial": leaf["certificate"].(M)["serial"]}, nil)
		wantStatus(t, res, "CRL: signature", "pass")
		wantStatus(t, res, "CRL: nextUpdate", "pass")
		wantStatus(t, res, "not revoked", "fail")
		wantStatus(t, run(t, "pki.decode", M{"input": crl}, nil), "CRL: signature", "warn")
		// Leading zeros and colon separators must not change the answer.
		serial := fmt.Sprintf("%040x", leafCert.SerialNumber)
		var colons []string
		for i := 0; i < len(serial); i += 2 {
			colons = append(colons, serial[i:i+2])
		}
		for _, form := range []string{serial, strings.Join(colons, ":"), strings.ToUpper(serial)} {
			wantStatus(t, run(t, "pki.decode", M{"input": crl, "check_serial": form}, nil), "not revoked", "fail")
		}
		wantStatus(t, run(t, "pki.decode", M{"input": crl, "check_serial": "01"}, nil), "not revoked", "pass")

		csrKey, _ := generateKey("ecdsa-p256")
		csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "svc"}, DNSNames: []string{"svc.example"}}, csrKey)
		csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
		wantStatus(t, run(t, "pki.decode", M{"input": csr}, nil), "self-signature", "pass")
	})

	t.Run("expired and SAN-less certificates are flagged", func(t *testing.T) {
		k, _ := generateKey("ecdsa-p256")
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "old"}, NotBefore: time.Now().AddDate(-2, 0, 0), NotAfter: time.Now().AddDate(-1, 0, 0)}
		c, _ := sign(tmpl, tmpl, k.Public(), k)
		issuedTmpl := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "no-san"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
		issuer, _ := x509.ParseCertificate(pemDER(str(issuing["cert_pem"])))
		ik, _ := loadSigner(str(issuing["key_pem"]))
		noSAN, _ := sign(issuedTmpl, issuer, k.Public(), ik)
		wantStatus(t, run(t, "pki.decode", M{"input": certPEM(c)}, nil), "validity", "fail")
		wantStatus(t, run(t, "pki.decode", M{"input": certPEM(noSAN)}, nil), "subjectAltName present", "fail")
	})
}

func TestTLSProbe(t *testing.T) {
	ca := run(t, "pki.ca", M{"levels": 2, "dns_names": "localhost", "ip_addresses": "127.0.0.1"}, nil)
	rootPEM := str(ca["root"].(M)["cert_pem"])
	leaf := ca["leaf"].(M)
	serverPair, err := tls.X509KeyPair([]byte(str(leaf["chain_pem"])), []byte(str(leaf["key_pem"])))
	if err != nil {
		t.Fatal(err)
	}
	client := run(t, "pki.issue", M{"issuer_cert": str(ca["issuing"].(M)["cert_pem"]), "issuer_key": str(ca["issuing"].(M)["key_pem"]), "cn": "probe-client", "usage": "client", "dns_names": "", "ip_addresses": ""}, nil)
	rootCert, _ := x509.ParseCertificate(pemDER(rootPEM))
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(rootCert)

	newServer := func(auth tls.ClientAuthType) string {
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverPair}, ClientAuth: auth, ClientCAs: clientCAs}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		return strings.TrimPrefix(srv.URL, "https://")
	}

	t.Run("plain TLS", func(t *testing.T) {
		addr := newServer(tls.NoClientCert)
		res := run(t, "tls.probe", M{"host": addr, "roots": rootPEM}, nil)
		noFailures(t, res)
		for _, n := range []string{"handshake", "server certificate chain verifies against the supplied roots", "TLS 1.0 refused", "TLS 1.1 refused", "TLS 1.3 supported"} {
			wantStatus(t, res, n, "pass")
		}
		if res["version"] != "TLS 1.3" || res["alpn"] != "http/1.1" { // the test server does not enable HTTP/2
			t.Errorf("version=%v alpn=%v", res["version"], res["alpn"])
		}
		wantStatus(t, run(t, "tls.probe", M{"host": addr}, nil), "server certificate chain verifies against the system trust store", "fail")
		_, port, _ := net.SplitHostPort(addr)
		wantStatus(t, run(t, "tls.probe", M{"host": "localhost:" + port, "sni": "other.example", "roots": rootPEM, "versions": false}, nil), "server certificate chain verifies", "fail")
	})

	t.Run("mutual TLS", func(t *testing.T) {
		addr := newServer(tls.RequireAndVerifyClientCert)
		without := run(t, "tls.probe", M{"host": addr, "roots": rootPEM, "versions": false}, nil)
		wantStatus(t, without, "handshake", "fail")
		wantStatus(t, without, "server requested a client certificate", "info")
		if cas := without["client_certificate_request"].(M)["acceptable_cas"].([]string); len(cas) != 1 || !strings.Contains(cas[0], "idpdbg Test Root CA") {
			t.Errorf("acceptable CAs: %v", cas)
		}
		with := run(t, "tls.probe", M{"host": addr, "roots": rootPEM, "versions": false, "mtls_cert": str(client["chain_pem"]), "mtls_key": str(client["key_pem"])}, nil)
		noFailures(t, with)
		if with["client_certificate_request"].(M)["certificate_sent"] != true {
			t.Error("client certificate not sent")
		}
	})
}

// Only a certificate that could serve TLS needs its names in the SAN; a
// client certificate (PIV, PKINIT) without one is fine.
func TestCertChecksSANOnlyForTLSServers(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mk := func(eku []x509.ExtKeyUsage) *x509.Certificate {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "alice"}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: eku}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	sanFail := func(c *x509.Certificate, role string) bool {
		var cs Checks
		certChecks(&cs, c, role)
		for _, ck := range cs {
			if strings.HasSuffix(ck.Name, "subjectAltName present") && ck.Status == "fail" {
				return true
			}
		}
		return false
	}
	if !sanFail(mk([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}), "leaf") || !sanFail(mk(nil), "leaf") {
		t.Error("a TLS server certificate without a SAN passed")
	}
	if sanFail(mk([]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}), "leaf") || sanFail(mk(nil), "client") {
		t.Error("a client certificate without a SAN failed")
	}
}
