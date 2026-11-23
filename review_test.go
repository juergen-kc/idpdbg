package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

// Regression tests for the findings of the whole-repository review.

var sigRe = regexp.MustCompile(`(?s)<ds:Signature.*</ds:Signature>`)

func TestReviewSAMLFixes(t *testing.T) {
	idpKey, idpCert, idpCertPEM, _ := selfSigned(t)
	spKey, _, _, spKeyPEM := selfSigned(t)
	_, _, otherPEM, _ := selfSigned(t)

	t.Run("signed Response covers its encrypted assertion", func(t *testing.T) {
		unsignedAssertion := sigRe.ReplaceAllString(samlResponse(t, idpKey, idpCert, "_r", acsURL, "idpdbg"), "")
		enc := encryptAssertion(t, unsignedAssertion, &spKey.PublicKey, encAES256GCM, encRSAOAEP11)
		doc := etree.NewDocument()
		doc.ReadFromString(enc)
		signed, err := signEnvelopedAfterIssuer(&spConfig{Key: idpKey, Cert: idpCert}, doc.Root())
		if err != nil {
			t.Fatal(err)
		}
		d := etree.NewDocument()
		d.SetRoot(signed)
		x, _ := d.WriteToString()
		res := run(t, "saml.decode", M{"message": base64.StdEncoding.EncodeToString([]byte(x)), "idp_cert": idpCertPEM, "sp_key": spKeyPEM,
			"sp_entity_id": "idpdbg", "acs_url": acsURL, "in_response_to": "_r"}, nil)
		noFailures(t, res)
		wantStatus(t, res, "response: signature", "pass")
		wantStatus(t, res, "every assertion is covered by a trusted signature", "pass")
	})

	t.Run("several trusted certificates and no KeyInfo", func(t *testing.T) {
		noKeyInfo := regexp.MustCompile(`(?s)<ds:KeyInfo>.*?</ds:KeyInfo>`).ReplaceAllString(samlResponse(t, idpKey, idpCert, "_r", acsURL, "idpdbg"), "")
		if strings.Contains(noKeyInfo, "KeyInfo") {
			t.Fatal("KeyInfo not removed")
		}
		res := run(t, "saml.decode", M{"message": base64.StdEncoding.EncodeToString([]byte(noKeyInfo)), "idp_cert": otherPEM + idpCertPEM}, nil)
		wantStatus(t, res, "assertion: signature", "pass")
		// and still fails when none of the certificates signed it
		_, _, thirdPEM, _ := selfSigned(t)
		wantStatus(t, run(t, "saml.decode", M{"message": base64.StdEncoding.EncodeToString([]byte(noKeyInfo)), "idp_cert": otherPEM + thirdPEM}, nil), "assertion: signature", "fail")
	})

	t.Run("an EncryptedKey for another SP key comes first", func(t *testing.T) {
		enc := encryptAssertion(t, samlResponse(t, idpKey, idpCert, "_r", acsURL, "idpdbg"), &spKey.PublicKey, encAES256GCM, encRSAOAEP)
		foreign := `<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="` + encRSAOAEP + `"/><xenc:CipherData><xenc:CipherValue>` +
			base64.StdEncoding.EncodeToString(make([]byte, 256)) + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey>`
		enc = strings.Replace(enc, "<ds:KeyInfo>", "<ds:KeyInfo>"+foreign, 1)
		if strings.Count(enc, "<xenc:EncryptedKey>") != 2 {
			t.Fatal("second EncryptedKey not inserted")
		}
		res := run(t, "saml.decode", M{"message": base64.StdEncoding.EncodeToString([]byte(enc)), "idp_cert": idpCertPEM, "sp_key": spKeyPEM}, nil)
		wantStatus(t, res, "assertion: decryption", "pass")
		wantStatus(t, res, "assertion: signature", "pass")
	})
}

func TestReviewLargeResponse(t *testing.T) {
	_, cert, _, _ := selfSigned(t)
	big := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example"><!--` + strings.Repeat("x", 9<<20) + `-->` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="` + nsSAMLP + `"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(cert.Raw) + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleSignOnService Binding="` + bindRedirect + `" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, big) }))
	defer srv.Close()
	res := run(t, "saml.metadata", M{"idp_metadata": srv.URL}, nil)
	if res["entity_id"] != "https://idp.example" {
		t.Errorf("a %d MiB metadata document was not read whole: %v", len(big)>>20, res["entity_id"])
	}
	tr := run(t, "saml.metadata", M{"idp_metadata": srv.URL, "trace": true}, nil)
	if body := tr["http_trace"].([]*Exchange)[0].ResponseBody; len(body) > 65<<10 {
		t.Errorf("the recorded copy should still be cut, got %d bytes", len(body))
	}
}

func TestResponseSizeBound(t *testing.T) {
	old := maxResponseBody
	maxResponseBody = 1 << 20
	defer func() { maxResponseBody = old }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 2<<20)) // twice the bound
	}))
	defer srv.Close()
	_, err := runOp(context.Background(), findOp("saml.metadata"), M{"idp_metadata": srv.URL}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("an oversized response was not refused: %v", err)
	}
}

func TestReviewKerberosSingleLogin(t *testing.T) {
	kdc := newMockKDC(t, "IDPDBG.TEST")
	kdc.users["alice"] = "alice-pw"
	kdc.addService("HTTP/web.idpdbg.test", "web-secret", 18)
	run(t, "krb.service_ticket", M{"principal": "alice@IDPDBG.TEST", "password": "alice-pw", "kdc": kdc.addr, "spn": "HTTP/web.idpdbg.test"}, nil)
	kdc.mu.Lock()
	defer kdc.mu.Unlock()
	// One login: an AS-REQ, the pre-authentication demand, and the retry.
	if kdc.asReqs != 2 {
		t.Errorf("service_ticket sent %d AS-REQs, want 2 (one login)", kdc.asReqs)
	}
}

func TestReviewTxCodeWithoutOffer(t *testing.T) {
	is := newMockIssuer(t)
	res := run(t, "vci.issue", M{"issuer": is.URL, "pre_authorized_code": "pac-1", "configuration_id": "pid", "tx_code": "1234"}, nil)
	noFailures(t, res)
	wantStatus(t, res, "credential issued", "pass")
}

func TestReviewGNAPHashMethod(t *testing.T) {
	as := newMockGNAP(t)
	as.sha512 = true
	access := []any{map[string]any{"type": "photo-api"}}
	res := run(t, "gnap.grant", M{"grant_endpoint": as.URL + "/gnap", "access": access, "interact": true, "finish_port": freePort(t), "open_browser": false, "wait": 10}, followURL(t, nil))
	noFailures(t, res)
	wantStatus(t, res, "interaction finish hash matches", "pass")
}

func TestReviewHSIDTokenWarning(t *testing.T) {
	tok := signHS([]byte("s"), "HS256", M{"typ": "JWT"}, M{"iss": "https://op.example", "sub": "a", "exp": 4102444800})
	var cs Checks
	c := &Ctx{Context: context.Background(), Args: M{"timeout": 5}}
	c.Rec = newRecorder(&tls.Config{})
	validateIDToken(c, &cs, M{"issuer": "https://op.example", "jwks_uri": "https://op.example/jwks"}, tok, "", "", "")
	ck := checkOf(M{"checks": cs}, "id_token: signature")
	if ck == nil || ck.Status != "warn" || !strings.Contains(ck.Detail, "client secret") {
		t.Errorf("HS256 warning: %+v", ck)
	}
}

func TestLooksLikePathWindows(t *testing.T) {
	for _, p := range []string{`C:\keys\sp.pem`, `c:/keys/sp.pem`, `.\sp.pem`, `..\keys\sp.pem`, `\\server\share\sp.pem`, "/etc/x", "./x", "~/x", "@x"} {
		if !looksLikePath(p) {
			t.Errorf("%q not recognised as a path", p)
		}
	}
	for _, s := range []string{"MIIBIjANBgkq", "eyJhbGciOi", "hello", "c:", "a:b"} {
		if looksLikePath(s) {
			t.Errorf("%q taken for a path", s)
		}
	}
}

// Over MCP a profile's sp_key signs what idpdbg sends, but does not decrypt
// a response the caller hands in; on the command line, and when passed in
// the call, it does.
func TestStoredSPKeyDoesNotDecryptSuppliedResponses(t *testing.T) {
	idpKey, idpCert, idpCertPEM, _ := selfSigned(t)
	spKey, _, _, spKeyPEM := selfSigned(t)
	dir := filepath.ToSlash(t.TempDir())
	keyFile := dir + "/sp.key"
	if err := os.WriteFile(keyFile, []byte(spKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IDPDBG_CONFIG", dir+"/config.json")
	if err := os.WriteFile(dir+"/config.json", []byte(`{"profiles":{"sp":{"sp_key":"`+keyFile+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	msg := base64.StdEncoding.EncodeToString([]byte(encryptAssertion(t, samlResponse(t, idpKey, idpCert, "_r", "https://sp.example/acs", "idpdbg"), &spKey.PublicKey, encAES256GCM, encRSAOAEP11)))
	decode := func(args M, cli bool) M {
		t.Helper()
		res, err := runOp(t.Context(), findOp("saml.decode"), args, cli, nil)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	r := decode(M{"profile": "sp", "message": msg, "idp_cert": idpCertPEM}, false)
	if c := checkOf(r, "assertion: decryption"); c == nil || c.Status != "warn" || !strings.Contains(c.Detail, "pass sp_key in the call") {
		t.Errorf("profile key decrypted a supplied response over MCP: %+v", c)
	}
	wantStatus(t, decode(M{"profile": "sp", "message": msg, "idp_cert": idpCertPEM, "sp_key": spKeyPEM}, false), "assertion: decryption", "pass")
	wantStatus(t, decode(M{"profile": "sp", "message": msg, "idp_cert": idpCertPEM}, true), "assertion: decryption", "pass")
}
