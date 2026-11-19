package main

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// ---- helpers ----

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func run(t *testing.T, name string, args M, log func(string, ...any)) M {
	t.Helper()
	op := findOp(name)
	if op == nil {
		t.Fatalf("no op %s", name)
	}
	res, err := runOp(context.Background(), op, args, false, log)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func checkOf(res M, name string) *Check {
	cs, _ := res["checks"].(Checks)
	for i := range cs {
		if strings.Contains(cs[i].Name, name) {
			return &cs[i]
		}
	}
	return nil
}

func noFailures(t *testing.T, res M) {
	t.Helper()
	for _, c := range res["checks"].(Checks) {
		if c.Status == "fail" {
			t.Errorf("check failed: %s — %s", c.Name, c.Detail)
		}
	}
}

func wantStatus(t *testing.T, res M, name, status string) {
	t.Helper()
	c := checkOf(res, name)
	if c == nil {
		t.Fatalf("no check matching %q in %+v", name, res["checks"])
	}
	if c.Status != status {
		t.Errorf("check %q: got %s (%s), want %s", c.Name, c.Status, c.Detail, status)
	}
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, claims M) string {
	h, _ := json.Marshal(M{"alg": "RS256", "typ": "JWT", "kid": kid})
	p, _ := json.Marshal(claims)
	input := b64url(h) + "." + b64url(p)
	d := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64url(sig)
}

func selfSigned(t *testing.T) (*rsa.PrivateKey, *x509.Certificate, string, string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test idp"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return key, cert, certPEM, keyPEM
}

// ---- OIDC ----

func mockOP(t *testing.T, key *rsa.PrivateKey) *httptest.Server {
	var mu sync.Mutex
	var nonce, challenge string
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	jsonOut := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		jsonOut(w, M{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
			"jwks_uri": srv.URL + "/jwks", "introspection_endpoint": srv.URL + "/introspect", "userinfo_endpoint": srv.URL + "/userinfo",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jsonOut(w, M{"keys": []M{{"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64url(key.N.Bytes()), "e": b64url(big.NewInt(int64(key.E)).Bytes())}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		mu.Lock()
		nonce, challenge = q.Get("nonce"), q.Get("code_challenge")
		mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=the-code&state="+url.QueryEscape(q.Get("state"))+"&iss="+url.QueryEscape(srv.URL), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, _ := r.BasicAuth()
		if id == "" {
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			mu.Lock()
			defer mu.Unlock()
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "the-code" || b64url(sum[:]) != challenge {
				w.WriteHeader(400)
				jsonOut(w, M{"error": "invalid_grant", "error_description": "PKCE verification failed"})
				return
			}
			at := "opaque-access-token"
			idt := signRS256(t, key, "k1", M{"iss": srv.URL, "sub": "alice", "aud": id, "nonce": nonce,
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "at_hash": halfHash("RS256", at)})
			jsonOut(w, M{"access_token": at, "token_type": "Bearer", "expires_in": 3600, "id_token": idt})
		case "client_credentials":
			if secret != "s3cret" {
				w.WriteHeader(401)
				jsonOut(w, M{"error": "invalid_client"})
				return
			}
			at := signRS256(t, key, "k1", M{"iss": srv.URL, "sub": id, "aud": "api", "exp": time.Now().Add(time.Hour).Unix()})
			jsonOut(w, M{"access_token": at, "token_type": "Bearer", "expires_in": 3600})
		default:
			w.WriteHeader(400)
			jsonOut(w, M{"error": "unsupported_grant_type"})
		}
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer opaque-access-token" {
			w.WriteHeader(401)
			return
		}
		jsonOut(w, M{"sub": "alice", "email": "alice@example.com"})
	})
	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		jsonOut(w, M{"active": r.Form.Get("token") == "opaque-access-token", "sub": "alice", "exp": time.Now().Add(time.Hour).Unix()})
	})
	t.Cleanup(srv.Close)
	return srv
}

// followURL plays the browser: it fetches the URL announced through the log.
func followURL(t *testing.T, then func(body string)) func(string, ...any) {
	re := regexp.MustCompile(`https?://\S+`)
	return func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if !strings.HasPrefix(msg, "Open this URL") {
			return
		}
		go func() {
			time.Sleep(50 * time.Millisecond)
			resp, err := http.Get(re.FindString(msg))
			if err != nil {
				t.Errorf("browser: %v", err)
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if then != nil {
				then(string(b))
			}
		}()
	}
}

func TestOIDC(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	op := mockOP(t, key)

	t.Run("discover", func(t *testing.T) {
		res := run(t, "oidc.discover", M{"issuer": op.URL}, nil)
		wantStatus(t, res, "issuer matches", "pass")
		wantStatus(t, res, "jwks_uri is reachable", "pass")
		// httptest serves http://127.0.0.1, which the https check tolerates.
		noFailures(t, res)
	})

	t.Run("login with PKCE", func(t *testing.T) {
		res := run(t, "oidc.login", M{"issuer": op.URL, "client_id": "cli", "open_browser": false,
			"redirect_port": freePort(t), "wait": 10, "trace": true}, followURL(t, nil))
		noFailures(t, res)
		for _, name := range []string{"state matches", "iss response parameter", "id_token: signature", "id_token: nonce", "id_token: at_hash", "id_token: aud"} {
			wantStatus(t, res, name, "pass")
		}
		if len(res["http_trace"].([]*Exchange)) < 3 {
			t.Errorf("expected discovery, token and JWKS exchanges in the trace")
		}
	})

	t.Run("granted scopes that have no effect are flagged", func(t *testing.T) {
		// The mock serves an email claim but no profile claims and never
		// issues a refresh token.
		res := run(t, "oidc.login", M{"issuer": op.URL, "client_id": "cli", "open_browser": false,
			"redirect_port": freePort(t), "wait": 10, "scope": "openid profile email offline_access"}, followURL(t, nil))
		noFailures(t, res)
		wantStatus(t, res, "userinfo: sub matches the ID token", "pass")
		wantStatus(t, res, "scope email yields its claims", "pass")
		wantStatus(t, res, "scope profile yields its claims", "warn")
		wantStatus(t, res, "refresh token issued for offline_access", "warn")
		if c := checkOf(res, "scope phone"); c != nil {
			t.Errorf("a scope that was not requested was checked: %+v", c)
		}
		// Without offline_access there is nothing to say about refresh tokens.
		res = run(t, "oidc.login", M{"issuer": op.URL, "client_id": "cli", "open_browser": false,
			"redirect_port": freePort(t), "wait": 10, "scope": "openid"}, followURL(t, nil))
		if c := checkOf(res, "refresh token issued"); c != nil {
			t.Errorf("unexpected refresh token check: %+v", c)
		}
		ui := run(t, "oidc.userinfo", M{"issuer": op.URL, "access_token": "opaque-access-token", "scope": "openid profile"}, nil)
		wantStatus(t, ui, "scope profile yields its claims", "warn")
	})

	t.Run("client credentials and secret redaction", func(t *testing.T) {
		res := run(t, "oidc.client_credentials", M{"issuer": op.URL, "client_id": "svc", "client_secret": "s3cret", "client_auth": "post", "trace": true}, nil)
		noFailures(t, res)
		if res["access_token_decoded"] == nil {
			t.Error("JWT access token was not decoded")
		}
		b, _ := json.Marshal(res["http_trace"])
		if strings.Contains(string(b), "s3cret") {
			t.Error("client secret leaked into the trace")
		}
		bad := run(t, "oidc.client_credentials", M{"issuer": op.URL, "client_id": "svc", "client_secret": "wrong"}, nil)
		wantStatus(t, bad, "token response", "fail")
	})

	t.Run("introspect", func(t *testing.T) {
		res := run(t, "oidc.introspect", M{"issuer": op.URL, "token": "opaque-access-token"}, nil)
		wantStatus(t, res, "token is active", "pass")
	})

	t.Run("jwt verify and tamper", func(t *testing.T) {
		tok := signRS256(t, key, "k1", M{"iss": op.URL, "sub": "bob", "aud": "api", "exp": time.Now().Add(time.Hour).Unix()})
		res := run(t, "jwt.verify", M{"token": tok, "issuer": op.URL, "audience": "api"}, nil)
		noFailures(t, res)
		parts := strings.Split(tok, ".")
		forged, _ := json.Marshal(M{"iss": op.URL, "sub": "admin", "aud": "api", "exp": time.Now().Add(time.Hour).Unix()})
		res = run(t, "jwt.verify", M{"token": parts[0] + "." + b64url(forged) + "." + parts[2], "issuer": op.URL}, nil)
		wantStatus(t, res, "signature", "fail")
		expired := signRS256(t, key, "k1", M{"iss": op.URL, "exp": time.Now().Add(-time.Hour).Unix()})
		wantStatus(t, run(t, "jwt.verify", M{"token": expired, "issuer": op.URL}, nil), "exp", "fail")
		wantStatus(t, run(t, "jwt.verify", M{"token": tok, "issuer": op.URL, "audience": "other"}, nil), "aud", "fail")
	})
}

// ---- SAML ----

const acsURL = "https://sp.example/acs"

func samlResponse(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, inResponseTo, acs, audience string) string {
	now := time.Now().UTC()
	ts := func(d time.Duration) string { return now.Add(d).Format(samlTimeLayout) }
	doc := etree.NewDocument()
	a := doc.CreateElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsSAML)
	a.CreateAttr("ID", "_assertion1")
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", ts(0))
	a.CreateElement("saml:Issuer").SetText("https://idp.example")
	subj := a.CreateElement("saml:Subject")
	nid := subj.CreateElement("saml:NameID")
	nid.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nid.SetText("alice@example.com")
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("Recipient", acs)
	scd.CreateAttr("NotOnOrAfter", ts(5*time.Minute))
	scd.CreateAttr("InResponseTo", inResponseTo)
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", ts(-time.Minute))
	cond.CreateAttr("NotOnOrAfter", ts(5*time.Minute))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(audience)
	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", ts(0))
	as.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	at := a.CreateElement("saml:AttributeStatement").CreateElement("saml:Attribute")
	at.CreateAttr("Name", "role")
	at.CreateElement("saml:AttributeValue").SetText("user")

	sctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}))
	sctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := sctx.SignEnveloped(a)
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	r := out.CreateElement("samlp:Response")
	r.CreateAttr("xmlns:samlp", nsSAMLP)
	r.CreateAttr("xmlns:saml", nsSAML)
	r.CreateAttr("ID", "_response1")
	r.CreateAttr("Version", "2.0")
	r.CreateAttr("IssueInstant", ts(0))
	r.CreateAttr("Destination", acs)
	r.CreateAttr("InResponseTo", inResponseTo)
	r.CreateElement("saml:Issuer").SetText("https://idp.example")
	r.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", samlStatusOK)
	r.AddChild(signed)
	s, _ := out.WriteToString()
	return s
}

func TestSAML(t *testing.T) {
	key, cert, certPEM, keyPEM := selfSigned(t)

	t.Run("decode and verify a signed response", func(t *testing.T) {
		xmlStr := samlResponse(t, key, cert, "_req1", acsURL, "idpdbg")
		args := M{"message": base64.StdEncoding.EncodeToString([]byte(xmlStr)), "idp_cert": certPEM,
			"sp_entity_id": "idpdbg", "acs_url": acsURL, "in_response_to": "_req1"}
		res := run(t, "saml.decode", args, nil)
		noFailures(t, res)
		wantStatus(t, res, "assertion: signature", "pass")
		wantStatus(t, res, "every assertion is covered", "pass")
		a := res["assertions"].([]M)[0]
		if a["name_id"].(M)["value"] != "alice@example.com" || a["attributes"].(M)["role"].([]string)[0] != "user" {
			t.Errorf("assertion not decoded: %+v", a)
		}

		// A tampered attribute must break the signature.
		args["message"] = strings.Replace(xmlStr, ">user<", ">admin<", 1)
		wantStatus(t, run(t, "saml.decode", args, nil), "assertion: signature", "fail")

		// A different trusted certificate must not validate it.
		_, _, otherPEM, _ := selfSigned(t)
		args["message"], args["idp_cert"] = xmlStr, otherPEM
		wantStatus(t, run(t, "saml.decode", args, nil), "assertion: signature", "fail")

		// Without a trusted certificate it is only a warning, never a pass.
		delete(args, "idp_cert")
		wantStatus(t, run(t, "saml.decode", args, nil), "assertion: signature", "warn")

		// Wrong audience and wrong InResponseTo are caught.
		args["idp_cert"], args["sp_entity_id"], args["in_response_to"] = certPEM, "someone-else", "_other"
		res = run(t, "saml.decode", args, nil)
		wantStatus(t, res, "audience includes", "fail")
		wantStatus(t, res, "response: InResponseTo", "fail")
	})

	t.Run("signed AuthnRequest round trip", func(t *testing.T) {
		for _, binding := range []string{"post", "redirect"} {
			req := run(t, "saml.authn_request", M{"sso_url": "https://idp.example/sso", "binding": binding, "sign": true,
				"sp_key": keyPEM, "sp_cert": certPEM, "acs_url": acsURL, "relay_state": "rs"}, nil)
			if req["signed"] != true {
				t.Fatalf("%s: request not signed", binding)
			}
			msg := str(req["encoded"])
			if binding == "redirect" {
				msg = str(req["redirect_url"])
				// Verify the detached query-string signature the way an IdP would.
				raw := msg[strings.Index(msg, "?")+1:]
				signedPart, sigPart, _ := strings.Cut(raw, "&Signature=")
				sigB64, _ := url.QueryUnescape(sigPart)
				sig, _ := base64.StdEncoding.DecodeString(sigB64)
				d := sha256.Sum256([]byte(signedPart))
				if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, d[:], sig); err != nil {
					t.Errorf("redirect signature: %v", err)
				}
			}
			dec := run(t, "saml.decode", M{"message": msg, "idp_cert": certPEM}, nil)
			noFailures(t, dec)
			if dec["message_type"] != "AuthnRequest" {
				t.Errorf("%s: decoded as %v", binding, dec["message_type"])
			}
			if binding == "post" {
				wantStatus(t, dec, "request: signature", "pass")
			}
		}
	})

	t.Run("login through a mock IdP", func(t *testing.T) {
		port := freePort(t)
		acs := fmt.Sprintf("http://localhost:%d/saml/acs", port)
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := base64.StdEncoding.DecodeString(r.URL.Query().Get("SAMLRequest"))
			x, _ := io.ReadAll(flate.NewReader(bytes.NewReader(raw)))
			doc := etree.NewDocument()
			doc.ReadFromBytes(x)
			id := doc.Root().SelectAttrValue("ID", "")
			fmt.Fprint(w, base64.StdEncoding.EncodeToString([]byte(samlResponse(t, key, cert, id, acs, "idpdbg"))))
		}))
		defer idp.Close()
		res := run(t, "saml.login", M{"sso_url": idp.URL + "/sso", "idp_cert": certPEM, "acs_port": port, "open_browser": false, "wait": 10},
			followURL(t, func(body string) {
				resp, err := http.PostForm(acs, url.Values{"SAMLResponse": {body}})
				if err != nil {
					t.Errorf("post to ACS: %v", err)
					return
				}
				resp.Body.Close()
			}))
		noFailures(t, res)
		wantStatus(t, res, "assertion: InResponseTo", "pass")
		wantStatus(t, res, "assertion: Recipient", "pass")
	})
}

// ---- SCIM ----

func mockSCIM(t *testing.T, brokenPatch bool) *httptest.Server {
	var mu sync.Mutex
	store := map[string]map[string]M{"Users": {}, "Groups": {}}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", scimJSON)
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		kind := parts[0]
		coll, ok := store[kind]
		if !ok {
			w.WriteHeader(404)
			return
		}
		var body M
		json.NewDecoder(r.Body).Decode(&body)
		if len(parts) == 1 {
			switch r.Method {
			case "POST":
				if kind == "Users" {
					scimErr := func(status int, scimType string) {
						w.WriteHeader(status)
						json.NewEncoder(w).Encode(M{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": fmt.Sprint(status), "scimType": scimType})
					}
					if str(body["userName"]) == "" {
						scimErr(400, "invalidValue")
						return
					}
					for _, u := range coll {
						if str(u["userName"]) == str(body["userName"]) {
							scimErr(409, "uniqueness")
							return
						}
					}
				}
				n++
				id := fmt.Sprintf("id%d", n)
				body["id"] = id
				body["meta"] = M{"location": "http://" + r.Host + "/" + kind + "/" + id}
				coll[id] = body
				w.Header().Set("Location", "http://"+r.Host+"/"+kind+"/"+id)
				w.WriteHeader(201)
				json.NewEncoder(w).Encode(body)
			case "GET":
				m := regexp.MustCompile(`userName eq "(.*)"`).FindStringSubmatch(r.URL.Query().Get("filter"))
				res := []M{}
				for _, u := range coll {
					if m == nil || u["userName"] == m[1] {
						res = append(res, u)
					}
				}
				json.NewEncoder(w).Encode(M{"totalResults": len(res), "Resources": res})
			}
			return
		}
		obj, ok := coll[parts[1]]
		if !ok {
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(M{"detail": "not found", "status": "404"})
			return
		}
		switch r.Method {
		case "GET":
			json.NewEncoder(w).Encode(obj)
		case "PUT":
			body["id"], body["meta"] = obj["id"], obj["meta"]
			coll[parts[1]] = body
			json.NewEncoder(w).Encode(body)
		case "PATCH":
			for _, o := range body["Operations"].([]any) {
				op := o.(map[string]any)
				path := str(op["path"])
				switch {
				case brokenPatch:
				case path == "name.givenName":
					obj["name"].(map[string]any)["givenName"] = op["value"]
				case path == "active":
					obj["active"] = op["value"]
				case path == "members" && op["op"] == "add":
					obj["members"] = op["value"]
				case strings.HasPrefix(path, "members[") && op["op"] == "remove":
					delete(obj, "members")
				}
			}
			json.NewEncoder(w).Encode(obj)
		case "DELETE":
			delete(coll, parts[1])
			w.WriteHeader(204)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSCIM(t *testing.T) {
	srv := mockSCIM(t, false)
	for _, sc := range []string{"user_lifecycle", "group_lifecycle"} {
		res := run(t, "scim.scenario", M{"base_url": srv.URL, "scim_token": "tok", "scenario": sc}, nil)
		noFailures(t, res)
		wantStatus(t, res, "verify deletion", "pass")
	}
	// Everything created must be gone again.
	list := run(t, "scim.request", M{"base_url": srv.URL, "scim_token": "tok", "path": "/Users"}, nil)
	if n := list["response"].(map[string]any)["totalResults"]; n != float64(0) {
		t.Errorf("scenario left %v users behind", n)
	}

	// A server that accepts PATCH but ignores it is caught, and still cleaned up.
	broken := mockSCIM(t, true)
	res := run(t, "scim.scenario", M{"base_url": broken.URL, "scim_token": "tok"}, nil)
	wantStatus(t, res, "verify patch", "fail")
	wantStatus(t, res, "delete user", "pass")

	unauth := run(t, "scim.request", M{"base_url": srv.URL, "scim_token": "nope", "path": "/Users"}, nil)
	wantStatus(t, unauth, "response status", "fail")
}

// ---- MCP ----

func TestMCP(t *testing.T) {
	tok := "eyJhbGciOiJub25lIn0." + b64url([]byte(`{"sub":"x","exp":1}`)) + "."
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"jwt_decode","arguments":{"token":"` + tok + `"}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"jwt_decode","arguments":{"token":"@/etc/passwd"}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := serveMCP(strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	byID := map[float64]M{}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m M
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		if id, ok := m["id"].(float64); ok {
			byID[id] = m
		}
	}
	if byID[1]["result"].(map[string]any)["serverInfo"].(map[string]any)["name"] != "idpdbg" {
		t.Error("initialize: wrong serverInfo")
	}
	tools := byID[2]["result"].(map[string]any)["tools"].([]any)
	if len(tools) != len(registry) {
		t.Errorf("tools/list returned %d tools, registry has %d", len(tools), len(registry))
	}
	for _, tl := range tools {
		tm := tl.(map[string]any)
		if !regexp.MustCompile(`^[a-z0-9_]+$`).MatchString(str(tm["name"])) || tm["inputSchema"].(map[string]any)["type"] != "object" {
			t.Errorf("bad tool definition: %v", tm["name"])
		}
	}
	call := byID[3]["result"].(map[string]any)
	if call["isError"] != false || !strings.Contains(fmt.Sprint(call["content"]), "token is unsigned") && !strings.Contains(fmt.Sprint(call["content"]), `"alg": "none"`) {
		t.Errorf("jwt_decode call: %v", call)
	}
	// "@file" expansion is a CLI convenience and must not work over MCP.
	if r := byID[4]["result"].(map[string]any); r["isError"] != true || strings.Contains(fmt.Sprint(r["content"]), "root:") {
		t.Errorf("@file was expanded over MCP: %v", r)
	}
	if byID[5]["error"] == nil {
		t.Error("unknown tool should be a JSON-RPC error")
	}
}

// ---- guard rails for stored secrets and local files ----

func TestGuards(t *testing.T) {
	prep := func(name string, raw M, cli bool) error {
		_, _, err := prepare(findOp(name), raw, cli)
		return err
	}
	t.Setenv("IDPDBG_CONFIG", t.TempDir()+"/config.json")

	// An environment secret is not sent to a host the MCP caller chose.
	t.Setenv("IDPDBG_SCIM_TOKEN", "stored")
	if err := prep("scim.discover", M{"base_url": "https://evil.example/scim"}, false); err == nil {
		t.Error("MCP caller could send the env secret to an arbitrary host")
	}
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "good.example")
	if err := prep("scim.discover", M{"base_url": "https://good.example/scim"}, false); err != nil {
		t.Errorf("allowed host refused: %v", err)
	}
	// The allowance is for the encrypted default port only: no downgrade to
	// http, no other port, no free pass for loopback, no disabling TLS checks.
	for _, u := range []string{"http://good.example/scim", "https://good.example:8443/scim", "http://localhost:9999/scim"} {
		if err := prep("scim.discover", M{"base_url": u}, false); err == nil {
			t.Errorf("env secret allowed to %s", u)
		}
	}
	if err := prep("scim.discover", M{"base_url": "https://good.example/scim", "insecure": true}, false); err == nil {
		t.Error("MCP caller could disable TLS verification with a stored secret")
	}
	// Nor add a trust anchor of its own, which would let it intercept TLS.
	_, _, caPEM, _ := selfSigned(t)
	if err := prep("scim.discover", M{"base_url": "https://good.example/scim", "ca_cert": caPEM}, false); err == nil {
		t.Error("MCP caller could add a trusted CA with a stored secret")
	}
	if err := prep("scim.discover", M{"base_url": "https://good.example/scim", "ca_cert": caPEM}, true); err != nil {
		t.Errorf("CLI ca_cert with env secret refused: %v", err)
	}
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "good.example, http://localhost:9999")
	if err := prep("scim.discover", M{"base_url": "http://localhost:9999/scim"}, false); err != nil {
		t.Errorf("explicitly allowed origin refused: %v", err)
	}
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "good.example")
	// From the CLI the person chose both, and an explicit secret is always fine.
	if err := prep("scim.discover", M{"base_url": "https://other.example/scim"}, true); err != nil {
		t.Errorf("CLI with env secret refused: %v", err)
	}
	if err := prep("scim.discover", M{"base_url": "https://evil.example/scim", "scim_token": "explicit"}, false); err != nil {
		t.Errorf("explicit secret refused: %v", err)
	}

	// A profile's secret only goes to the profile's hosts, even from the CLI.
	t.Setenv("IDPDBG_SCIM_TOKEN", "")
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "")
	// Any readable file will do as a key path; forward slashes keep it valid
	// JSON on Windows.
	anyFile := filepath.ToSlash(filepath.Join(t.TempDir(), "any.pem"))
	if err := os.WriteFile(anyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := `{"profiles":{"dev":{"base_url":"https://scim.example/v2","scim_token":"tok","sp_key":"` + anyFile + `"},
		"oidc":{"issuer":"https://op.example","client_id":"c","client_secret":"s"},
		"pkj":{"issuer":"https://op.example","client_id":"c","client_auth":"private_key_jwt","client_key":"` + anyFile + `","sp_key":"` + anyFile + `"}}}`
	if err := os.WriteFile(configPath(), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cli := range []bool{true, false} {
		if err := prep("scim.discover", M{"profile": "dev"}, cli); err != nil {
			t.Errorf("profile on its own host refused: %v", err)
		}
		if err := prep("scim.discover", M{"profile": "dev", "base_url": "https://evil.example"}, cli); err == nil {
			t.Error("profile secret could be redirected to another host")
		}
		for _, u := range []string{"http://scim.example/v2", "https://scim.example:8443/v2"} {
			if err := prep("scim.discover", M{"profile": "dev", "base_url": u}, cli); err == nil {
				t.Errorf("profile secret allowed to %s", u)
			}
		}
	}

	// URLs the guard cannot place are refused, identifiers that merely look
	// like URLs are not, and an MCP caller cannot switch StartTLS off.
	if err := prep("scim.discover", M{"profile": "dev", "base_url": "gopher://scim.example/v2"}, false); err == nil {
		t.Error("unknown scheme slipped past the guard")
	}
	t.Setenv("IDPDBG_LDAP_PASSWORD", "stored")
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "ldap.example,ldap://ldap.example")
	for _, u := range []string{"cldap://ldap.example", "ldapi://%2Ftmp%2Fsock", "LDAP://evil.example"} {
		if err := prep("ldap.bind", M{"url": u, "bind_dn": "cn=x"}, false); err == nil {
			t.Errorf("stored LDAP password allowed with %s", u)
		}
	}
	if err := prep("ldap.bind", M{"url": "ldap://ldap.example", "bind_dn": "cn=x", "starttls": false}, false); err == nil {
		t.Error("MCP caller could switch StartTLS off with a stored secret")
	}
	if err := prep("ldap.bind", M{"url": "ldaps://ldap.example", "bind_dn": "cn=x"}, false); err != nil {
		t.Errorf("allowed LDAPS origin refused: %v", err)
	}
	if _, err := runOp(context.Background(), findOp("ldap.bind"), M{"url": "cldap://ldap.example", "ldap_password": "p", "bind_dn": "cn=x"}, false, nil); err == nil {
		t.Error("ldap operations accepted a scheme other than ldap/ldaps")
	}
	t.Setenv("IDPDBG_LDAP_PASSWORD", "")
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "")
	if err := prep("oidc.client_credentials", M{"profile": "oidc", "scope": "https://graph.example/.default", "audience": "https://api.example"}, false); err != nil {
		t.Errorf("URL-shaped identifiers were treated as destinations: %v", err)
	}

	// Text that merely contains PEM or XML markers is still a URL.
	for _, u := range []string{"https://evil.example/token?-----BEGIN", "https://evil.example/<x>", "https://evil.example/{x}"} {
		if err := prep("oidc.client_credentials", M{"profile": "oidc", "token_endpoint": u}, false); err == nil {
			t.Errorf("stored secret allowed to %s", u)
		}
	}
	if err := prep("saml.decode", M{"profile": "pkj", "message": "<x/>", "idp_cert": "https://evil.example/-----BEGIN"}, false); err == nil {
		t.Error("a URL in a content parameter slipped past the guard")
	}

	// Private keys from a profile are guarded like secrets: whatever they
	// sign may only go to the profile's origins.
	if err := prep("oidc.client_credentials", M{"profile": "pkj"}, false); err != nil {
		t.Errorf("profile key with its own origin refused: %v", err)
	}
	for _, raw := range []M{
		{"profile": "pkj", "token_endpoint": "https://evil.example/token"},
		{"profile": "pkj", "client_assertion_aud": "https://other.example"},
	} {
		if err := prep("oidc.client_credentials", raw, false); err == nil {
			t.Errorf("stored client_key usable with %v", raw)
		}
	}
	if err := prep("saml.authn_request", M{"profile": "pkj", "sso_url": "https://evil.example/sso"}, false); err == nil {
		t.Error("stored sp_key usable with a caller-chosen sso_url")
	}

	// File paths: refused from an MCP caller, accepted from the CLI or a profile.
	if err := prep("jwt.verify", M{"token": "x", "pem": anyFile}, false); err == nil {
		t.Error("MCP caller could name a local file")
	}
	if err := prep("jwt.verify", M{"token": "x", "pem": anyFile}, true); err != nil {
		t.Errorf("CLI file path refused: %v", err)
	}
	if err := prep("saml.decode", M{"message": "<x/>", "profile": "dev"}, false); err != nil {
		t.Errorf("profile file path refused: %v", err)
	}

	// Writing a file and leaving the SCIM origin are refused over MCP / always.
	if _, err := runOp(context.Background(), findOp("saml.sp_metadata"), M{"out": t.TempDir() + "/x.xml"}, false, nil); err == nil {
		t.Error("MCP caller could write a file")
	}
	if _, err := runOp(context.Background(), findOp("scim.request"), M{"base_url": "https://scim.example/v2", "path": "https://evil.example/Users"}, false, nil); err == nil {
		t.Error("absolute SCIM path could leave the base URL's origin")
	}

	// Credentials in requests never reach the trace.
	body := redactBody("application/x-www-form-urlencoded", []byte("refresh_token=aaa&code=bbb&subject_token=ccc&scope=openid"))
	if strings.Contains(body, "aaa") || strings.Contains(body, "bbb") || strings.Contains(body, "ccc") || !strings.Contains(body, "openid") {
		t.Errorf("redaction wrong: %s", body)
	}
	if h := flatHeaders(http.Header{"X-Api-Key": {"zzz"}, "Accept": {"a/b"}}, true); strings.Contains(h["X-Api-Key"], "zzz") || h["Accept"] != "a/b" {
		t.Errorf("header redaction wrong: %v", h)
	}
}

// An https redirect URI gets a TLS listener with a throwaway certificate,
// as FAPI 2.0 servers refuse http redirect URIs.
func TestLoginHTTPSRedirect(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	op := mockOP(t, key)
	port := freePort(t)
	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	re := regexp.MustCompile(`https?://\S+`)
	var sawWarning bool
	browser := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if strings.Contains(msg, "self-signed certificate") {
			sawWarning = true
		}
		if !strings.HasPrefix(msg, "Open this URL") {
			return
		}
		go func() {
			time.Sleep(50 * time.Millisecond)
			resp, err := insecure.Get(re.FindString(msg))
			if err != nil {
				t.Errorf("browser: %v", err)
				return
			}
			resp.Body.Close()
		}()
	}
	res := run(t, "oidc.login", M{"issuer": op.URL, "client_id": "cli", "open_browser": false, "wait": 10,
		"redirect_uri": fmt.Sprintf("https://localhost:%d/callback", port), "scope": "openid"}, browser)
	wantStatus(t, res, "state matches the request", "pass")
	wantStatus(t, res, "token response", "pass")
	if !sawWarning {
		t.Errorf("the person was not told about the self-signed certificate")
	}
}
