package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// saml2Assertion returns a signed SAML 2.0 assertion on its own.
func saml2Assertion(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, audience string) string {
	doc := etree.NewDocument()
	doc.ReadFromString(samlResponse(t, key, cert, "", "https://rp.example/", audience))
	a := kid(doc.Root(), "Assertion")
	ctx, _ := etreeutils.NSBuildParentContext(a)
	det, _ := etreeutils.NSDetatch(ctx, a)
	d := etree.NewDocument()
	d.SetRoot(det)
	s, _ := d.WriteToString()
	return s
}

// saml11Assertion builds and signs a SAML 1.1 assertion (AssertionID).
func saml11Assertion(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, audience, role string) string {
	now := time.Now().UTC()
	ts := func(d time.Duration) string { return now.Add(d).Format(samlTimeLayout) }
	doc := etree.NewDocument()
	a := doc.CreateElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsSAML11)
	for k, v := range map[string]string{"MajorVersion": "1", "MinorVersion": "1", "AssertionID": "_a11", "Issuer": idpEntity, "IssueInstant": ts(0)} {
		a.CreateAttr(k, v)
	}
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", ts(-time.Minute))
	cond.CreateAttr("NotOnOrAfter", ts(time.Hour))
	cond.CreateElement("saml:AudienceRestrictionCondition").CreateElement("saml:Audience").SetText(audience)
	subject := func(parent *etree.Element) {
		s := parent.CreateElement("saml:Subject")
		s.CreateElement("saml:NameIdentifier").SetText("alice@example.com")
		s.CreateElement("saml:SubjectConfirmation").CreateElement("saml:ConfirmationMethod").SetText(saml11CMBearer)
	}
	as := a.CreateElement("saml:AuthenticationStatement")
	as.CreateAttr("AuthenticationMethod", "urn:oasis:names:tc:SAML:1.0:am:password")
	as.CreateAttr("AuthenticationInstant", ts(0))
	subject(as)
	st := a.CreateElement("saml:AttributeStatement")
	subject(st)
	at := st.CreateElement("saml:Attribute")
	at.CreateAttr("AttributeName", "role")
	at.CreateAttr("AttributeNamespace", "http://schemas.example/claims")
	at.CreateElement("saml:AttributeValue").SetText(role)
	sctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}))
	sctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	sctx.IdAttribute = "AssertionID"
	signed, err := sctx.SignEnveloped(a)
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	s, _ := out.WriteToString()
	return s
}

func rstr(ns, appliesTo, token string) string {
	now := time.Now().UTC()
	return `<t:RequestSecurityTokenResponse xmlns:t="` + ns + `"><t:Lifetime><wsu:Created xmlns:wsu="` + nsWSU + `">` + now.Format(samlTimeLayout) +
		`</wsu:Created><wsu:Expires xmlns:wsu="` + nsWSU + `">` + now.Add(time.Hour).Format(samlTimeLayout) + `</wsu:Expires></t:Lifetime>` +
		`<wsp:AppliesTo xmlns:wsp="` + nsWSP + `"><wsa:EndpointReference xmlns:wsa="` + nsWSA + `"><wsa:Address>` + appliesTo + `</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>` +
		`<t:RequestedSecurityToken>` + token + `</t:RequestedSecurityToken><t:TokenType>` + tokenSAML2 + `</t:TokenType></t:RequestSecurityTokenResponse>`
}

func TestWSFederation(t *testing.T) {
	key, cert, certPEM, _ := selfSigned(t)

	t.Run("decode SAML 2.0 and SAML 1.1 tokens", func(t *testing.T) {
		for name, tok := range map[string]string{"saml2": saml2Assertion(t, key, cert, "urn:idpdbg"), "saml11": saml11Assertion(t, key, cert, "urn:idpdbg", "admin")} {
			res := run(t, "wsfed.decode", M{"wresult": rstr(nsTrust2005, "urn:idpdbg", tok), "wtrealm": "urn:idpdbg", "sts_cert": certPEM}, nil)
			noFailures(t, res)
			for _, n := range []string{"assertion: signature", "RSTR AppliesTo", "RSTR lifetime", "audience includes"} {
				wantStatus(t, res, n, "pass")
			}
			if name == "saml11" && res["token"].(M)["attributes"].(M)["http://schemas.example/claims/role"].([]string)[0] != "admin" {
				t.Errorf("SAML 1.1 attributes: %v", res["token"])
			}
		}
		forged := strings.Replace(saml11Assertion(t, key, cert, "urn:idpdbg", "user"), ">user<", ">admin<", 1)
		wantStatus(t, run(t, "wsfed.decode", M{"wresult": rstr(nsTrust2005, "urn:idpdbg", forged), "sts_cert": certPEM}, nil), "assertion: signature", "fail")
		other := run(t, "wsfed.decode", M{"wresult": rstr(nsTrust2005, "urn:other", saml2Assertion(t, key, cert, "urn:other")), "wtrealm": "urn:idpdbg", "sts_cert": certPEM}, nil)
		wantStatus(t, other, "RSTR AppliesTo", "fail")
		wantStatus(t, other, "audience includes", "fail")
	})

	t.Run("passive sign-in through a mock STS", func(t *testing.T) {
		mux := http.NewServeMux()
		sts := httptest.NewServer(mux)
		defer sts.Close()
		mux.HandleFunc("/FederationMetadata.xml", func(w http.ResponseWriter, _ *http.Request) {
			fmt.Fprint(w, `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:wsa="`+nsWSA+`" entityID="`+idpEntity+`">`+
				`<md:RoleDescriptor xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">`+
				`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>`+base64.StdEncoding.EncodeToString(cert.Raw)+`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`+
				`<fed:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address>`+sts.URL+`/adfs/ls/</wsa:Address></wsa:EndpointReference></fed:PassiveRequestorEndpoint></md:RoleDescriptor></md:EntityDescriptor>`)
		})
		mux.HandleFunc("/adfs/ls/", func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			if q.Get("wa") != "wsignin1.0" {
				http.Error(w, "bad wa", 400)
				return
			}
			wresult := rstr(nsTrust2005, q.Get("wtrealm"), saml2Assertion(t, key, cert, q.Get("wtrealm")))
			fmt.Fprintf(w, `<html><body onload="document.forms[0].submit()"><form method="POST" action="%s"><input type="hidden" name="wa" value="wsignin1.0"/><input type="hidden" name="wresult" value="%s"/><input type="hidden" name="wctx" value="%s"/></form></body></html>`,
				html.EscapeString(q.Get("wreply")), html.EscapeString(wresult), html.EscapeString(q.Get("wctx")))
		})
		// The "browser" submits the auto-posting form the STS returns.
		field := func(body, name string) string {
			m := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`).FindStringSubmatch(body)
			if m == nil {
				return ""
			}
			return html.UnescapeString(m[1])
		}
		post := func(body string) {
			action := html.UnescapeString(regexp.MustCompile(`action="([^"]*)"`).FindStringSubmatch(body)[1])
			resp, err := http.PostForm(action, url.Values{"wa": {field(body, "wa")}, "wresult": {field(body, "wresult")}, "wctx": {field(body, "wctx")}})
			if err == nil {
				resp.Body.Close()
			}
		}
		res := run(t, "wsfed.login", M{"metadata": sts.URL + "/FederationMetadata.xml", "reply_port": freePort(t), "open_browser": false, "wait": 10}, followURL(t, post))
		noFailures(t, res)
		for _, n := range []string{"wctx returned unchanged", "token issuer is the STS entity ID", "assertion: signature", "RSTR AppliesTo"} {
			wantStatus(t, res, n, "pass")
		}
		meta := run(t, "wsfed.metadata", M{"metadata": sts.URL + "/FederationMetadata.xml"}, nil)
		if meta["passive_endpoint"] != sts.URL+"/adfs/ls/" {
			t.Errorf("metadata: %v", meta)
		}
	})
}

func TestWSTrust(t *testing.T) {
	key, cert, certPEM, _ := selfSigned(t)
	rpKey, rpCert, _, rpKeyPEM := selfSigned(t)
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := etree.NewDocument()
		doc.ReadFrom(r.Body)
		var user, pass, action []*etree.Element
		findAll(doc.Root(), "Username", &user)
		findAll(doc.Root(), "Password", &pass)
		findAll(doc.Root(), "Action", &action)
		w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
		env := func(body string) string {
			return `<s:Envelope xmlns:s="` + nsSOAP12 + `"><s:Body>` + body + `</s:Body></s:Envelope>`
		}
		if len(user) == 0 || text(user[0]) != "alice@example.com" || text(pass[0]) != "pw" {
			w.WriteHeader(500)
			fmt.Fprint(w, env(`<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value xmlns:a="`+nsWSSE+`">a:FailedAuthentication</s:Value></s:Subcode></s:Code><s:Reason><s:Text xml:lang="en-US">ID3242: The security token could not be authenticated or authorized.</s:Text></s:Reason></s:Fault>`))
			return
		}
		switch text(action[0]) {
		case nsTrust13 + "/RST/Issue":
			var ap []*etree.Element
			findAll(doc.Root(), "Address", &ap)
			appliesTo := text(ap[len(ap)-1])
			tok := saml2Assertion(t, key, cert, appliesTo)
			if appliesTo == "urn:encrypted" { // a relying party with an encryption certificate
				tok = encryptToken(t, tok, rpCert, &rpKey.PublicKey, encAES256GCM, encRSAOAEP11, false)
			}
			fmt.Fprint(w, env(`<trust:RequestSecurityTokenResponseCollection xmlns:trust="`+nsTrust13+`">`+
				rstr(nsTrust13, appliesTo, tok)+
				`</trust:RequestSecurityTokenResponseCollection>`))
		case nsTrust13 + "/RST/Validate":
			fmt.Fprint(w, env(`<trust:RequestSecurityTokenResponse xmlns:trust="`+nsTrust13+`"><trust:Status><trust:Code>`+nsTrust13+`/status/valid</trust:Code><trust:Reason>ok</trust:Reason></trust:Status></trust:RequestSecurityTokenResponse>`))
		}
	}))
	defer sts.Close()
	base := M{"endpoint": sts.URL + "/adfs/services/trust/13/usernamemixed", "username": "alice@example.com", "password": "pw", "applies_to": "urn:idpdbg", "sts_cert": certPEM}
	res := run(t, "wstrust.issue", base, nil)
	noFailures(t, res)
	for _, n := range []string{"STS response", "assertion: signature", "RSTR AppliesTo", "requested WS-Trust version"} {
		wantStatus(t, res, n, "pass")
	}
	enc := M{"rp_key": rpKeyPEM}
	for k, v := range base {
		if _, set := enc[k]; !set {
			enc[k] = v
		}
	}
	enc["applies_to"] = "urn:encrypted"
	res = run(t, "wstrust.issue", enc, nil)
	noFailures(t, res)
	for _, n := range []string{"token: decryption", "assertion: signature", "audience includes"} {
		wantStatus(t, res, n, "pass")
	}
	bad := M{}
	for k, v := range base {
		bad[k] = v
	}
	bad["password"] = "wrong"
	r := run(t, "wstrust.issue", bad, nil)
	if c := checkOf(r, "STS response"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "FailedAuthentication") {
		t.Errorf("fault not reported: %+v", c)
	}
	// The password never appears in the trace.
	traced := M{"trace": true}
	for k, v := range base {
		traced[k] = v
	}
	tr := run(t, "wstrust.issue", traced, nil)
	for _, ex := range tr["http_trace"].([]*Exchange) {
		if strings.Contains(ex.RequestBody, ">pw<") || !strings.Contains(ex.RequestBody, "Password") || !strings.Contains(ex.RequestBody, "<redacted>") {
			t.Errorf("password not redacted in the trace: %s", ex.RequestBody[:200])
		}
	}
	// An unsigned token is a failure, not a pass.
	unsigned := regexp.MustCompile(`(?s)<ds:Signature.*</ds:Signature>`).ReplaceAllString(saml2Assertion(t, key, cert, "urn:idpdbg"), "")
	wantStatus(t, run(t, "wsfed.decode", M{"wresult": rstr(nsTrust2005, "urn:idpdbg", unsigned), "sts_cert": certPEM}, nil), "assertion: signed", "fail")
	u11 := regexp.MustCompile(`(?s)<ds:Signature.*</ds:Signature>`).ReplaceAllString(saml11Assertion(t, key, cert, "urn:idpdbg", "user"), "")
	wantStatus(t, run(t, "wsfed.decode", M{"wresult": rstr(nsTrust2005, "urn:idpdbg", u11), "sts_cert": certPEM}, nil), "assertion: signed", "fail")
	v := run(t, "wstrust.validate", M{"endpoint": base["endpoint"], "username": "alice@example.com", "password": "pw", "token": saml2Assertion(t, key, cert, "urn:idpdbg")}, nil)
	noFailures(t, v)
	plain := run(t, "wstrust.issue", M{"endpoint": "http://sts.example/trust", "username": "u", "password": "p", "applies_to": "x"}, nil)
	if c := checkOf(plain, "STS response"); c == nil || !strings.Contains(c.Detail, "plain HTTP") {
		t.Errorf("password over plain HTTP not refused: %+v", c)
	}
}

// encryptToken encrypts a token to the relying party's public key, as an
// STS does: a bare xenc:EncryptedData (AD FS) or, with asAssertion, a SAML
// 2.0 EncryptedAssertion. The EncryptedKey names the relying party's
// certificate by thumbprint, as AD FS writes it.
func encryptToken(t *testing.T, token string, rpCert *x509.Certificate, rpPub *rsa.PublicKey, dataAlg, keyAlg string, asAssertion bool) string {
	t.Helper()
	wrapped := encryptAssertion(t, "<w>"+token+"</w>", rpPub, dataAlg, keyAlg)
	thumb := sha1.Sum(rpCert.Raw)
	wrapped = strings.Replace(wrapped, "<xenc:CipherData>", `<ds:KeyInfo><o:SecurityTokenReference xmlns:o="`+nsWSSE+`"><o:KeyIdentifier ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1">`+
		base64.StdEncoding.EncodeToString(thumb[:])+`</o:KeyIdentifier></o:SecurityTokenReference></ds:KeyInfo><xenc:CipherData>`, 1)
	doc := etree.NewDocument()
	if err := doc.ReadFromString(wrapped); err != nil {
		t.Fatal(err)
	}
	el := kid(doc.Root(), "EncryptedAssertion")
	if !asAssertion {
		el = kid(el, "EncryptedData")
	}
	ctx, _ := etreeutils.NSBuildParentContext(el)
	det, _ := etreeutils.NSDetatch(ctx, el)
	d := etree.NewDocument()
	d.SetRoot(det)
	s, _ := d.WriteToString()
	return s
}

func TestWSEncryptedTokens(t *testing.T) {
	key, cert, certPEM, _ := selfSigned(t)
	rpKey, rpCert, _, rpKeyPEM := selfSigned(t)
	_, _, _, otherKeyPEM := selfSigned(t)

	for _, tc := range []struct {
		name, token, dataAlg, keyAlg string
		asAssertion                  bool
	}{
		{"AD FS style: SAML 1.1 in EncryptedData, AES-256-CBC, RSA-OAEP", saml11Assertion(t, key, cert, "urn:idpdbg", "admin"), "http://www.w3.org/2001/04/xmlenc#aes256-cbc", encRSAOAEP, false},
		{"SAML 2.0 in EncryptedData", saml2Assertion(t, key, cert, "urn:idpdbg"), encAES256GCM, encRSAOAEP11, false},
		{"SAML 2.0 EncryptedAssertion", saml2Assertion(t, key, cert, "urn:idpdbg"), encAES256GCM, encRSAOAEP11, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wresult := rstr(nsTrust2005, "urn:idpdbg", encryptToken(t, tc.token, rpCert, &rpKey.PublicKey, tc.dataAlg, tc.keyAlg, tc.asAssertion))
			args := M{"wresult": wresult, "wtrealm": "urn:idpdbg", "sts_cert": certPEM, "rp_key": rpKeyPEM}
			res := run(t, "wsfed.decode", args, nil)
			noFailures(t, res)
			for _, n := range []string{"token: decryption", "assertion: signature", "audience includes", "RSTR AppliesTo"} {
				wantStatus(t, res, n, "pass")
			}
			if res["token_encrypted"] != true || res["decrypted_token_xml"] == nil {
				t.Errorf("output: %v", res)
			}
			if strings.HasSuffix(tc.dataAlg, "-cbc") {
				wantStatus(t, res, "assertion: data encryption algorithm", "warn")
				if res["token"].(M)["attributes"].(M)["http://schemas.example/claims/role"].([]string)[0] != "admin" {
					t.Errorf("SAML 1.1 attributes: %v", res["token"])
				}
			}

			// Without the key: said plainly, nothing else claimed.
			delete(args, "rp_key")
			r := run(t, "wsfed.decode", args, nil)
			wantStatus(t, r, "token: decryption", "warn")
			if checkOf(r, "assertion: signature") != nil {
				t.Error("an encrypted token was checked without decrypting it")
			}

			// The wrong key: the error names the certificate the STS used.
			args["rp_key"] = otherKeyPEM
			r = run(t, "wsfed.decode", args, nil)
			c := checkOf(r, "token: decryption")
			if c == nil || c.Status != "fail" || !strings.Contains(c.Detail, fmt.Sprintf("%X", sha1.Sum(rpCert.Raw))) {
				t.Errorf("wrong key: %+v", c)
			}
		})
	}

	// A forged token stays forged after decryption.
	forged := strings.Replace(saml11Assertion(t, key, cert, "urn:idpdbg", "user"), ">user<", ">admin<", 1)
	r := run(t, "wsfed.decode", M{"wresult": rstr(nsTrust2005, "urn:idpdbg", encryptToken(t, forged, rpCert, &rpKey.PublicKey, encAES256GCM, encRSAOAEP11, false)),
		"sts_cert": certPEM, "rp_key": rpKeyPEM}, nil)
	wantStatus(t, r, "token: decryption", "pass")
	wantStatus(t, r, "assertion: signature", "fail")

	// Tampered ciphertext under AES-GCM is refused.
	enc := encryptToken(t, saml2Assertion(t, key, cert, "urn:idpdbg"), rpCert, &rpKey.PublicKey, encAES256GCM, encRSAOAEP11, false)
	i := strings.LastIndex(enc, "<xenc:CipherValue>") + len("<xenc:CipherValue>") + 30
	flip := map[byte]byte{'A': 'B', 'B': 'A'}
	b := []byte(enc)
	if nb, ok := flip[b[i]]; ok {
		b[i] = nb
	} else {
		b[i] = 'A'
	}
	r = run(t, "wsfed.decode", M{"wresult": rstr(nsTrust2005, "urn:idpdbg", string(b)), "sts_cert": certPEM, "rp_key": rpKeyPEM}, nil)
	wantStatus(t, r, "token: decryption", "fail")
}
