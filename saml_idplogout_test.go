package main

import (
	"bytes"
	"compress/flate"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// idpLogoutRequest builds the LogoutRequest an IdP sends the SP.
func idpLogoutRequest(dest, nameID, session string) string {
	return `<samlp:LogoutRequest xmlns:samlp="` + nsSAMLP + `" xmlns:saml="` + nsSAML + `" ID="_idp-lr-1" Version="2.0" IssueInstant="` + samlNow() +
		`" Destination="` + dest + `" NotOnOrAfter="` + time.Now().UTC().Add(5*time.Minute).Format(samlTimeLayout) + `"><saml:Issuer>` + idpEntity +
		`</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">` + nameID + `</saml:NameID><samlp:SessionIndex>` + session +
		`</samlp:SessionIndex></samlp:LogoutRequest>`
}

// signEnvelopedXML signs a message with an enveloped signature, as the POST
// and SOAP bindings carry it.
func signEnvelopedXML(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, xmlStr string) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlStr); err != nil {
		t.Fatal(err)
	}
	sctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}))
	sctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := sctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	s, _ := out.WriteToString()
	return s
}

func TestSAMLIdPInitiatedLogout(t *testing.T) {
	idpKey, idpCert, _, _ := selfSigned(t)
	_, _, spCertPEM, spKeyPEM := selfSigned(t)

	// The IdP: /start sends the browser to the SP with a LogoutRequest,
	// /slo takes the SP's LogoutResponse.
	var mu sync.Mutex
	var mode, spSLO string
	var got url.Values
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/start":
			dest, session := spSLO, "s-1"
			switch mode {
			case "wrong-destination":
				dest = "http://localhost:1/elsewhere"
			case "other-session":
				session = "s-2"
			}
			q := redirectEncode(t, idpKey, "SAMLRequest", idpLogoutRequest(dest, "alice@example.com", session), "rs-1")
			if mode == "unsigned" {
				q = q[:strings.Index(q, "&SigAlg=")]
			}
			http.Redirect(w, r, spSLO+"?"+q, http.StatusFound)
		case "/slo":
			r.ParseForm()
			got = r.Form
			fmt.Fprint(w, "logged out")
		}
	}))
	defer idp.Close()
	meta := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + idpEntity + `"><md:IDPSSODescriptor protocolSupportEnumeration="` + nsSAMLP + `">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>` + base64.StdEncoding.EncodeToString(idpCert.Raw) +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`<md:SingleLogoutService Binding="` + bindRedirect + `" Location="` + idp.URL + `/slo"/>` +
		`<md:SingleLogoutService Binding="` + bindPOST + `" Location="` + idp.URL + `/slo-post"/>` +
		`<md:SingleSignOnService Binding="` + bindRedirect + `" Location="` + idp.URL + `/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`

	args := func(port int, extra M) M {
		a := M{"idp_metadata": meta, "start_url": idp.URL + "/start", "sp_key": spKeyPEM, "sp_cert": spCertPEM, "sign": true,
			"name_id": "alice@example.com", "session_index": "s-1", "slo_port": port, "open_browser": false, "wait": 10}
		for k, v := range extra {
			a[k] = v
		}
		return a
	}
	setup := func(m string) int {
		port := freePort(t)
		mu.Lock()
		mode, spSLO, got = m, fmt.Sprintf("http://localhost:%d/saml/slo", port), nil
		mu.Unlock()
		return port
	}

	t.Run("Redirect binding through the browser", func(t *testing.T) {
		landed := make(chan string, 1)
		res := run(t, "saml.idp_logout", args(setup("ok"), nil), followURL(t, func(body string) { landed <- body }))
		noFailures(t, res)
		if b := <-landed; b != "logged out" { // the browser followed the answer to the IdP
			t.Errorf("browser ended on %q", b)
		}
		for _, n := range []string{"redirect binding signature", "LogoutRequest signed", "LogoutRequest: Issuer", "LogoutRequest: Destination",
			"LogoutRequest: not expired", "LogoutRequest names the expected NameID", "LogoutRequest names the expected session", "LogoutResponse signed", "LogoutResponse sent"} {
			wantStatus(t, res, n, "pass")
		}
		mu.Lock()
		defer mu.Unlock()
		if got.Get("SAMLResponse") == "" || got.Get("Signature") == "" || got.Get("RelayState") != "rs-1" {
			t.Fatalf("the IdP got: %v", got)
		}
		compressed, _ := base64.StdEncoding.DecodeString(got.Get("SAMLResponse"))
		x, _ := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
		doc := etree.NewDocument()
		doc.ReadFromBytes(x)
		r := doc.Root()
		if r.Tag != "LogoutResponse" || r.SelectAttrValue("InResponseTo", "") != "_idp-lr-1" || r.SelectAttrValue("Destination", "") != idp.URL+"/slo" ||
			kid(r, "Status", "StatusCode").SelectAttrValue("Value", "") != samlStatusOK {
			t.Errorf("LogoutResponse: %s", x)
		}
	})

	for m, want := range map[string][2]string{
		"unsigned":          {"LogoutRequest signed", "fail"},
		"wrong-destination": {"LogoutRequest: Destination", "fail"},
		"other-session":     {"LogoutRequest names the expected session", "fail"},
	} {
		t.Run(m, func(t *testing.T) {
			wantStatus(t, run(t, "saml.idp_logout", args(setup(m), nil), followURL(t, nil)), want[0], want[1])
		})
	}

	t.Run("POST binding, partial logout", func(t *testing.T) {
		port := setup("ok")
		body := make(chan string, 1)
		post := func(string, ...any) {}
		go func() {
			time.Sleep(200 * time.Millisecond)
			signed := signEnvelopedXML(t, idpKey, idpCert, idpLogoutRequest(spSLO, "alice@example.com", "s-1"))
			resp, err := http.PostForm(spSLO, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(signed))}, "RelayState": {"rs-2"}})
			if err != nil {
				body <- err.Error()
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body <- string(b)
		}()
		a := args(port, M{"status": "partial"})
		delete(a, "start_url")
		res := run(t, "saml.idp_logout", a, post)
		noFailures(t, res)
		wantStatus(t, res, "LogoutRequest signed", "pass")
		if res["binding"] != "HTTP-POST" || res["response_status"] != samlStatusOK {
			t.Errorf("result: %v", res)
		}
		page := <-body
		if !strings.Contains(page, `action="`+idp.URL+`/slo-post"`) || !strings.Contains(page, `name="SAMLResponse"`) || !strings.Contains(page, "rs-2") {
			t.Errorf("auto-post form: %s", page)
		}
		if !strings.Contains(fmt.Sprint(res["response"]), samlStatusPartial) {
			t.Errorf("PartialLogout not in the response: %v", res["response"])
		}
	})

	t.Run("SOAP back channel", func(t *testing.T) {
		port := setup("ok")
		body := make(chan string, 1)
		go func() {
			time.Sleep(200 * time.Millisecond)
			env := `<s:Envelope xmlns:s="` + nsSOAP11 + `"><s:Body>` + idpLogoutRequest(spSLO, "alice@example.com", "s-1") + `</s:Body></s:Envelope>`
			resp, err := http.Post(spSLO, "text/xml", strings.NewReader(env))
			if err != nil {
				body <- err.Error()
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			body <- string(b)
		}()
		a := args(port, M{"sign": false})
		delete(a, "start_url")
		res := run(t, "saml.idp_logout", a, func(string, ...any) {})
		wantStatus(t, res, "LogoutRequest signed", "warn")
		wantStatus(t, res, "LogoutResponse sent", "pass")
		reply := <-body
		doc := etree.NewDocument()
		if err := doc.ReadFromString(reply); err != nil {
			t.Fatalf("SOAP reply: %v: %s", err, reply)
		}
		var lr []*etree.Element
		findAll(doc.Root(), "LogoutResponse", &lr)
		if len(lr) != 1 || lr[0].SelectAttrValue("InResponseTo", "") != "_idp-lr-1" {
			t.Errorf("SOAP reply: %s", reply)
		}
	})
}
