package main

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
)

const (
	encAES128CBC  = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	encAES256GCM  = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	encAES128GCM  = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	encRSAOAEP    = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	encRSAOAEP11  = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	encRSA15      = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	idpEntity     = "https://idp.example"
	sigRSASHA256q = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

// encryptAssertion replaces the signed Assertion of a Response with an
// EncryptedAssertion for the SP's key, using an implementation independent of
// the tool's decryption code.
func encryptAssertion(t *testing.T, responseXML string, spPub *rsa.PublicKey, dataAlg, keyAlg string) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(responseXML); err != nil {
		t.Fatal(err)
	}
	root := doc.Root()
	a := kid(root, "Assertion")
	ad := etree.NewDocument()
	ad.SetRoot(a.Copy())
	plain, _ := ad.WriteToBytes()

	size := 16
	if strings.Contains(dataAlg, "256") {
		size = 32
	}
	cek := make([]byte, size)
	rand.Read(cek)
	block, _ := aes.NewCipher(cek)
	var ct []byte
	if strings.HasSuffix(dataAlg, "-gcm") {
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		rand.Read(nonce)
		ct = append(nonce, gcm.Seal(nil, nonce, plain, nil)...)
	} else {
		pad := aes.BlockSize - len(plain)%aes.BlockSize
		plain = append(plain, bytes.Repeat([]byte{byte(pad)}, pad)...)
		iv := make([]byte, aes.BlockSize)
		rand.Read(iv)
		out := make([]byte, len(plain))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
		ct = append(iv, out...)
	}
	var wrapped []byte
	var err error
	keyMethod := `<xenc:EncryptionMethod Algorithm="` + keyAlg + `"/>`
	switch keyAlg {
	case encRSA15:
		wrapped, err = rsa.EncryptPKCS1v15(rand.Reader, spPub, cek)
	case encRSAOAEP:
		wrapped, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, spPub, cek, nil)
	case encRSAOAEP11:
		wrapped, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, spPub, cek, nil)
		keyMethod = `<xenc:EncryptionMethod Algorithm="` + keyAlg + `"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><xenc11:MGF xmlns:xenc11="http://www.w3.org/2009/xmlenc11#" Algorithm="http://www.w3.org/2009/xmlenc11#mgf1sha256"/></xenc:EncryptionMethod>`
	}
	if err != nil {
		t.Fatal(err)
	}
	encXML := `<saml:EncryptedAssertion xmlns:saml="` + nsSAML + `"><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
		`<xenc:EncryptionMethod Algorithm="` + dataAlg + `"/><ds:KeyInfo><xenc:EncryptedKey>` + keyMethod +
		`<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(wrapped) + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>` +
		`<xenc:CipherData><xenc:CipherValue>` + base64.StdEncoding.EncodeToString(ct) + `</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>`
	ed := etree.NewDocument()
	if err := ed.ReadFromString(encXML); err != nil {
		t.Fatal(err)
	}
	root.RemoveChild(a)
	root.AddChild(ed.Root())
	s, _ := doc.WriteToString()
	return s
}

func TestSAMLEncryption(t *testing.T) {
	idpKey, idpCert, idpCertPEM, _ := selfSigned(t)
	spKey, _, _, spKeyPEM := selfSigned(t)
	resp := samlResponse(t, idpKey, idpCert, "_req1", acsURL, "idpdbg")
	base := M{"idp_cert": idpCertPEM, "sp_key": spKeyPEM, "sp_entity_id": "idpdbg", "acs_url": acsURL, "in_response_to": "_req1"}
	with := func(extra M) M {
		out := M{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	cases := []struct {
		data, key, dataStatus string
		keyWarn               bool
	}{
		{encAES256GCM, encRSAOAEP11, "pass", false},
		{encAES128CBC, encRSAOAEP, "warn", false},
		{encAES128GCM, encRSA15, "pass", true},
	}
	for _, tc := range cases {
		t.Run(tc.data[strings.LastIndex(tc.data, "#")+1:]+"+"+tc.key[strings.LastIndex(tc.key, "#")+1:], func(t *testing.T) {
			msg := encryptAssertion(t, resp, &spKey.PublicKey, tc.data, tc.key)
			res := run(t, "saml.decode", with(M{"message": base64.StdEncoding.EncodeToString([]byte(msg))}), nil)
			noFailures(t, res)
			wantStatus(t, res, "assertion: decryption", "pass")
			wantStatus(t, res, "assertion: signature", "pass")
			wantStatus(t, res, "every assertion is covered", "pass")
			wantStatus(t, res, "assertion: data encryption algorithm", tc.dataStatus)
			if c := checkOf(res, "key transport algorithm"); tc.keyWarn != (c != nil && c.Status == "warn") {
				t.Errorf("key transport warning = %+v, want warn=%v", c, tc.keyWarn)
			}
			if a := res["assertions"].([]M)[0]; a["name_id"].(M)["value"] != "alice@example.com" {
				t.Errorf("decrypted assertion not analysed: %+v", a)
			}
		})
	}
	msg := base64.StdEncoding.EncodeToString([]byte(encryptAssertion(t, resp, &spKey.PublicKey, encAES256GCM, encRSAOAEP11)))
	_, _, _, otherKeyPEM := selfSigned(t)
	wantStatus(t, run(t, "saml.decode", with(M{"message": msg, "sp_key": otherKeyPEM}), nil), "assertion: decryption", "fail")
	noKey := with(M{"message": msg})
	delete(noKey, "sp_key")
	wantStatus(t, run(t, "saml.decode", noKey, nil), "assertion: decryption", "warn")
}

func TestSAMLRedirectSignature(t *testing.T) {
	_, _, certPEM, keyPEM := selfSigned(t)
	req := run(t, "saml.authn_request", M{"sso_url": "https://idp.example/sso", "binding": "redirect", "sign": true,
		"sp_key": keyPEM, "sp_cert": certPEM, "relay_state": "rs-1"}, nil)
	u := str(req["redirect_url"])
	wantStatus(t, run(t, "saml.decode", M{"message": u, "idp_cert": certPEM}, nil), "redirect binding signature", "pass")
	wantStatus(t, run(t, "saml.decode", M{"message": strings.Replace(u, "RelayState=rs-1", "RelayState=rs-2", 1), "idp_cert": certPEM}, nil), "redirect binding signature", "fail")
	_, _, otherPEM, _ := selfSigned(t)
	wantStatus(t, run(t, "saml.decode", M{"message": u, "idp_cert": otherPEM}, nil), "redirect binding signature", "fail")
	wantStatus(t, run(t, "saml.decode", M{"message": u}, nil), "redirect binding signature", "warn")
}

// redirectEncode signs and encodes a message for the HTTP-Redirect binding,
// independently of the tool's own encoder.
func redirectEncode(t *testing.T, key *rsa.PrivateKey, param, xmlStr, relay string) string {
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestSpeed)
	fw.Write([]byte(xmlStr))
	fw.Close()
	q := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relay != "" {
		q += "&RelayState=" + url.QueryEscape(relay)
	}
	q += "&SigAlg=" + url.QueryEscape(sigRSASHA256q)
	d := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

// redirectDecode verifies a Redirect-binding query signed by pub and returns
// the inflated message.
func redirectDecode(rawQuery string, pub *rsa.PublicKey) (*etree.Element, error) {
	raw := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(part, "=")
		raw[k] = v
	}
	signed := "SAMLRequest=" + raw["SAMLRequest"]
	if rs, ok := raw["RelayState"]; ok {
		signed += "&RelayState=" + rs
	}
	signed += "&SigAlg=" + raw["SigAlg"]
	sigB64, _ := url.QueryUnescape(raw["Signature"])
	sig, _ := base64.StdEncoding.DecodeString(sigB64)
	d := sha256.Sum256([]byte(signed))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, d[:], sig); err != nil {
		return nil, fmt.Errorf("request signature: %w", err)
	}
	b64, _ := url.QueryUnescape(raw["SAMLRequest"])
	compressed, _ := base64.StdEncoding.DecodeString(b64)
	x, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(x); err != nil {
		return nil, err
	}
	return doc.Root(), nil
}

func TestSAMLSingleLogout(t *testing.T) {
	idpKey, _, idpCertPEM, _ := selfSigned(t)
	spKey, _, spCertPEM, spKeyPEM := selfSigned(t)
	var mu sync.Mutex
	mode, spSLO := "ok", ""
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := redirectDecode(r.URL.RawQuery, &spKey.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
		if req.Tag != "LogoutRequest" || text(kid(req, "NameID")) != "alice@example.com" || text(kid(req, "SessionIndex")) != "s-1" {
			http.Error(w, "unexpected LogoutRequest", 400)
			return
		}
		mu.Lock()
		m, dest := mode, spSLO
		mu.Unlock()
		inResponseTo := req.SelectAttrValue("ID", "")
		if m == "wrong-inresponseto" {
			inResponseTo = "_someone-else"
		}
		resp := `<samlp:LogoutResponse xmlns:samlp="` + nsSAMLP + `" xmlns:saml="` + nsSAML + `" ID="_lr1" Version="2.0" IssueInstant="` + samlNow() +
			`" Destination="` + dest + `" InResponseTo="` + inResponseTo + `"><saml:Issuer>` + idpEntity + `</saml:Issuer><samlp:Status><samlp:StatusCode Value="` + samlStatusOK + `"/></samlp:Status></samlp:LogoutResponse>`
		relay, _ := url.QueryUnescape(strings.SplitN(strings.SplitN(r.URL.RawQuery, "RelayState=", 2)[1], "&", 2)[0])
		q := redirectEncode(t, idpKey, "SAMLResponse", resp, relay)
		if m == "unsigned" {
			q = q[:strings.Index(q, "&SigAlg=")]
		}
		http.Redirect(w, r, dest+"?"+q, http.StatusFound)
	}))
	defer idp.Close()

	for _, tc := range []struct{ mode, check, status string }{
		{"ok", "logout response: InResponseTo", "pass"},
		{"wrong-inresponseto", "logout response: InResponseTo", "fail"},
		{"unsigned", "LogoutResponse signed", "warn"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			port := freePort(t)
			mu.Lock()
			mode, spSLO = tc.mode, fmt.Sprintf("http://localhost:%d/saml/slo", port)
			mu.Unlock()
			res := run(t, "saml.logout", M{"slo_url": idp.URL + "/slo", "idp_cert": idpCertPEM, "sp_key": spKeyPEM, "sp_cert": spCertPEM, "sign": true,
				"name_id": "alice@example.com", "session_index": "s-1", "relay_state": "back-to-app", "slo_port": port, "open_browser": false, "wait": 10}, followURL(t, nil))
			wantStatus(t, res, tc.check, tc.status)
			if tc.mode == "ok" {
				noFailures(t, res)
				for _, n := range []string{"redirect binding signature", "logout response: status", "logout response: Destination", "RelayState echoed", "response is a LogoutResponse"} {
					wantStatus(t, res, n, "pass")
				}
			}
		})
	}
}

func TestSAMLArtifact(t *testing.T) {
	idpKey, idpCert, idpCertPEM, _ := selfSigned(t)
	_, _, spCertPEM, spKeyPEM := selfSigned(t)
	var mu sync.Mutex
	pending := map[string]string{} // artifact -> Response XML
	var lastArtifact string
	var resolveSigned bool
	mux := http.NewServeMux()
	idp := httptest.NewServer(mux)
	defer idp.Close()
	mux.HandleFunc("/metadata", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="`+idpEntity+`"><md:IDPSSODescriptor protocolSupportEnumeration="`+nsSAMLP+`">`+
			`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>`+base64.StdEncoding.EncodeToString(idpCert.Raw)+`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`+
			`<md:ArtifactResolutionService Binding="`+bindSOAP+`" Location="`+idp.URL+`/ars" index="1"/>`+
			`<md:SingleSignOnService Binding="`+bindRedirect+`" Location="`+idp.URL+`/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`)
	})
	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		b64 := r.URL.Query().Get("SAMLRequest")
		compressed, _ := base64.StdEncoding.DecodeString(b64)
		x, _ := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
		doc := etree.NewDocument()
		doc.ReadFromBytes(x)
		req := doc.Root()
		if req.SelectAttrValue("ProtocolBinding", "") != bindArtifact {
			http.Error(w, "this IdP only answers with artifacts", 400)
			return
		}
		acs := req.SelectAttrValue("AssertionConsumerServiceURL", "")
		art := make([]byte, 44)
		binary.BigEndian.PutUint16(art[0:2], 4)
		binary.BigEndian.PutUint16(art[2:4], 1)
		src := sha1.Sum([]byte(idpEntity))
		copy(art[4:24], src[:])
		rand.Read(art[24:])
		a := base64.StdEncoding.EncodeToString(art)
		mu.Lock()
		pending[a], lastArtifact = samlResponse(t, idpKey, idpCert, req.SelectAttrValue("ID", ""), acs, "idpdbg"), a
		mu.Unlock()
		http.Redirect(w, r, acs+"?SAMLart="+url.QueryEscape(a), http.StatusFound)
	})
	mux.HandleFunc("/ars", func(w http.ResponseWriter, r *http.Request) {
		doc := etree.NewDocument()
		if _, err := doc.ReadFrom(r.Body); err != nil || r.Header.Get("SOAPAction") == "" {
			http.Error(w, "bad SOAP request", 400)
			return
		}
		var found []*etree.Element
		findAll(doc.Root(), "ArtifactResolve", &found)
		if len(found) != 1 {
			http.Error(w, "no ArtifactResolve", 400)
			return
		}
		ar := found[0]
		mu.Lock()
		resolveSigned = kid(ar, "Signature") != nil
		msg := pending[text(kid(ar, "Artifact"))]
		delete(pending, text(kid(ar, "Artifact"))) // artifacts are single-use
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprint(w, `<SOAP-ENV:Envelope xmlns:SOAP-ENV="`+nsSOAP+`"><SOAP-ENV:Body><samlp:ArtifactResponse xmlns:samlp="`+nsSAMLP+`" xmlns:saml="`+nsSAML+
			`" ID="_ar1" Version="2.0" IssueInstant="`+samlNow()+`" InResponseTo="`+ar.SelectAttrValue("ID", "")+`"><saml:Issuer>`+idpEntity+
			`</saml:Issuer><samlp:Status><samlp:StatusCode Value="`+samlStatusOK+`"/></samlp:Status>`+msg+`</samlp:ArtifactResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>`)
	})

	port := freePort(t)
	res := run(t, "saml.login", M{"idp_metadata": idp.URL + "/metadata", "response_binding": "artifact", "sp_key": spKeyPEM, "sp_cert": spCertPEM,
		"acs_port": port, "open_browser": false, "wait": 10}, followURL(t, nil))
	noFailures(t, res)
	for _, n := range []string{"artifact: type code", "artifact: SourceID", "artifact: endpoint index known", "artifact response: status",
		"artifact response: InResponseTo", "artifact response: Issuer", "assertion: signature", "assertion: InResponseTo", "response: Issuer is the IdP entity ID"} {
		wantStatus(t, res, n, "pass")
	}
	wantStatus(t, res, "artifact response: signature", "info")
	if !strings.Contains(str(res["encoding"]), "Artifact") || !resolveSigned {
		t.Errorf("encoding=%v, ArtifactResolve signed=%v", res["encoding"], resolveSigned)
	}

	// Artifacts are single-use: resolving the same one again yields nothing.
	again, err := runOp(t.Context(), findOp("saml.resolve_artifact"), M{"artifact": lastArtifact, "idp_metadata": idp.URL + "/metadata", "idp_cert": idpCertPEM}, false, nil)
	if err == nil {
		t.Error("a used artifact resolved a second time")
	}
	wantStatus(t, again, "artifact response: carries a message", "fail")
	wantStatus(t, again, "ArtifactResolve signed", "info")

	// An artifact from someone else's IdP is caught by its SourceID.
	foreign := make([]byte, 44)
	binary.BigEndian.PutUint16(foreign[0:2], 4)
	binary.BigEndian.PutUint16(foreign[2:4], 1)
	other, _ := runOp(t.Context(), findOp("saml.resolve_artifact"), M{"artifact": base64.StdEncoding.EncodeToString(foreign), "idp_metadata": idp.URL + "/metadata"}, false, nil)
	wantStatus(t, other, "artifact: SourceID", "fail")
}

func TestSAMLAmbiguityAndDestinations(t *testing.T) {
	_, _, certPEM, keyPEM := selfSigned(t)

	t.Run("ambiguous Redirect queries are refused, not half-verified", func(t *testing.T) {
		req := run(t, "saml.authn_request", M{"sso_url": "https://idp.example/sso", "sign": true, "sp_key": keyPEM, "sp_cert": certPEM}, nil)
		u := str(req["redirect_url"])
		other := run(t, "saml.authn_request", M{"sso_url": "https://idp.example/sso", "force_authn": true}, nil)
		forged := str(other["encoded"])
		for name, bad := range map[string]string{
			"second message appended":   u + "&SAMLRequest=" + url.QueryEscape(forged),
			"encoded parameter name":    strings.Replace(u, "?SAMLRequest=", "?SAML%52equest=x&SAMLRequest=", 1),
			"request and response both": u + "&SAMLResponse=" + url.QueryEscape(forged),
		} {
			if _, err := runOp(t.Context(), findOp("saml.decode"), M{"message": bad, "idp_cert": certPEM}, false, nil); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	})

	t.Run("destinations from metadata obey the stored-credential origins", func(t *testing.T) {
		dir := filepath.ToSlash(t.TempDir()) // goes into JSON below
		keyFile := dir + "/sp.key"
		if err := os.WriteFile(keyFile, []byte(keyPEM), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("IDPDBG_CONFIG", dir+"/config.json")
		cfg := `{"profiles":{"sp":{"idp_metadata":"https://idp.example/metadata","sp_key":"` + keyFile + `","sp_cert":"` + strings.ReplaceAll(certPEM, "\n", `\n`) + `"}}}`
		if err := os.WriteFile(dir+"/config.json", []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		meta := func(host string) string {
			return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + idpEntity + `"><md:IDPSSODescriptor protocolSupportEnumeration="` + nsSAMLP + `">` +
				`<md:ArtifactResolutionService Binding="` + bindSOAP + `" Location="https://` + host + `/ars" index="1"/>` +
				`<md:SingleLogoutService Binding="` + bindRedirect + `" Location="https://` + host + `/slo"/>` +
				`<md:SingleSignOnService Binding="` + bindRedirect + `" Location="https://` + host + `/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`
		}
		art := make([]byte, 44)
		binary.BigEndian.PutUint16(art[0:2], 4)
		binary.BigEndian.PutUint16(art[2:4], 1)
		calls := map[string]M{
			"saml.authn_request":    {"sign": true},
			"saml.logout":           {"name_id": "alice", "sign": true, "open_browser": false, "wait": 1, "slo_port": freePort(t)},
			"saml.resolve_artifact": {"artifact": base64.StdEncoding.EncodeToString(art)},
		}
		for op, extra := range calls {
			for _, host := range []string{"evil.example", "idp.example"} {
				raw := M{"profile": "sp", "idp_metadata": meta(host)}
				for k, v := range extra {
					raw[k] = v
				}
				_, err := runOp(t.Context(), findOp(op), raw, false, nil)
				refused := err != nil && strings.Contains(err.Error(), "refusing to send")
				if refused != (host == "evil.example") {
					t.Errorf("%s via metadata on %s: refused=%v (err=%v)", op, host, refused, err)
				}
			}
		}
		// From the CLI with a key passed directly there is nothing stored to protect.
		if _, err := runOp(t.Context(), findOp("saml.authn_request"), M{"idp_metadata": meta("evil.example"), "sign": true, "sp_key": keyPEM, "sp_cert": certPEM}, true, nil); err != nil {
			t.Errorf("explicit key refused: %v", err)
		}
	})

	t.Run("a logout response in both query and body is refused", func(t *testing.T) {
		port := freePort(t)
		slo := fmt.Sprintf("http://localhost:%d/saml/slo", port)
		status := make(chan int, 1)
		log := func(format string, a ...any) {
			if !strings.HasPrefix(format, "Open this URL") {
				return
			}
			go func() {
				time.Sleep(50 * time.Millisecond)
				resp, err := http.PostForm(slo+"?SAMLResponse=x", url.Values{"SAMLResponse": {"y"}})
				if err != nil {
					status <- 0
					return
				}
				resp.Body.Close()
				status <- resp.StatusCode
			}()
		}
		_, err := runOp(t.Context(), findOp("saml.logout"), M{"slo_url": "https://idp.example/slo", "name_id": "alice", "slo_port": port, "open_browser": false, "wait": 1}, false, log)
		if code := <-status; code != http.StatusBadRequest || err == nil {
			t.Errorf("ambiguous POST: HTTP %d, op error %v", code, err)
		}
	})
}
