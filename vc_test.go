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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockIssuer struct {
	*httptest.Server
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	nonce string
	// The authorization code flow: codes handed out, with the PKCE
	// challenge, redirect URI and how the credential was asked for.
	codes       map[string]M
	issuerState string // the issuer_state the last authorization request carried
	mdoc        *testMdoc
}

func newMockIssuer(t *testing.T) *mockIssuer {
	is := &mockIssuer{codes: map[string]M{}, mdoc: newTestMdocIssuer(t)}
	is.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mux := http.NewServeMux()
	is.Server = httptest.NewServer(mux)
	t.Cleanup(is.Close)
	out := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		out(w, 200, M{"credential_issuer": is.URL, "credential_endpoint": is.URL + "/credential", "nonce_endpoint": is.URL + "/nonce",
			"credential_configurations_supported": M{"pid": M{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1", "scope": "pid_scope", "cryptographic_binding_methods_supported": []string{"jwk"},
				"proof_types_supported": M{"jwt": M{"proof_signing_alg_values_supported": []string{"ES256"}}}},
				"mdl": M{"format": "mso_mdoc", "doctype": "org.iso.18013.5.1.mDL", "cryptographic_binding_methods_supported": []string{"cose_key"},
					"proof_types_supported": M{"jwt": M{"proof_signing_alg_values_supported": []string{"ES256"}}}}}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		out(w, 200, M{"issuer": is.URL, "token_endpoint": is.URL + "/token", "authorization_endpoint": is.URL + "/authorize",
			"authorization_details_types_supported": []string{"openid_credential"}, "code_challenge_methods_supported": []string{"S256"},
			"authorization_response_iss_parameter_supported": true, "pre-authorized_grant_anonymous_access_supported": true})
	})
	// The person signs in at once: the code goes straight back.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		by := ""
		var ad []M
		if json.Unmarshal([]byte(q.Get("authorization_details")), &ad) == nil && len(ad) == 1 && ad[0]["type"] == "openid_credential" && ad[0]["credential_configuration_id"] == "pid" {
			by = "authorization_details"
		} else if q.Get("scope") == "pid_scope" {
			by = "scope"
		}
		if q.Get("client_id") != "wallet" || q.Get("code_challenge_method") != "S256" || by == "" {
			http.Error(w, "bad authorization request", 400)
			return
		}
		code := randToken(8)
		is.mu.Lock()
		is.codes[code] = M{"challenge": q.Get("code_challenge"), "redirect_uri": q.Get("redirect_uri"), "by": by}
		is.issuerState = q.Get("issuer_state")
		is.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state"))+"&iss="+url.QueryEscape(is.URL), http.StatusFound)
	})
	mux.HandleFunc("/.well-known/jwt-vc-issuer", func(w http.ResponseWriter, _ *http.Request) {
		k, _ := publicJWK(is.key.Public())
		k["kid"] = "iss-1"
		out(w, 200, M{"issuer": is.URL, "jwks": M{"keys": []M{k}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") == "authorization_code" {
			is.mu.Lock()
			c := is.codes[r.Form.Get("code")]
			delete(is.codes, r.Form.Get("code"))
			is.mu.Unlock()
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if c == nil || c["challenge"] != b64url(sum[:]) || c["redirect_uri"] != r.Form.Get("redirect_uri") || r.Form.Get("client_id") != "wallet" {
				out(w, 400, M{"error": "invalid_grant"})
				return
			}
			resp := M{"access_token": "at-1", "token_type": "Bearer", "expires_in": 300}
			if c["by"] == "authorization_details" {
				resp["authorization_details"] = []M{{"type": "openid_credential", "credential_configuration_id": "pid", "credential_identifiers": []string{"pid-1"}}}
			} else {
				resp["scope"] = "pid_scope"
			}
			w.Header().Set("Cache-Control", "no-store")
			out(w, 200, resp)
			return
		}
		if r.Form.Get("grant_type") != preAuthGrant || r.Form.Get("pre-authorized_code") != "pac-1" || r.Form.Get("tx_code") != "1234" {
			out(w, 400, M{"error": "invalid_grant"})
			return
		}
		out(w, 200, M{"access_token": "at-1", "token_type": "Bearer", "expires_in": 300})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		is.mu.Lock()
		is.nonce = randToken(8)
		n := is.nonce
		is.mu.Unlock()
		w.Header().Set("Cache-Control", "no-store")
		out(w, 200, M{"c_nonce": n})
	})
	mux.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at-1" {
			out(w, 401, M{"error": "invalid_token"})
			return
		}
		var req struct {
			ID     string                 `json:"credential_configuration_id"`
			Proofs struct{ JWT []string } `json:"proofs"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.Proofs.JWT) != 1 {
			out(w, 400, M{"error": "invalid_proof"})
			return
		}
		p, err := parseJWT(req.Proofs.JWT[0])
		jwk, _ := p.Header["jwk"].(map[string]any)
		pub, kerr := jwkPublicKey(jwk)
		is.mu.Lock()
		nonce := is.nonce
		is.mu.Unlock()
		if err != nil || kerr != nil || p.Header["typ"] != "openid4vci-proof+jwt" || verifySig(str(p.Header["alg"]), pub, p.SigningInput, p.Sig) != nil ||
			str(p.Claims["aud"]) != is.URL || str(p.Claims["nonce"]) != nonce {
			out(w, 400, M{"error": "invalid_proof"})
			return
		}
		if req.ID == "mdl" { // an mdoc bound to the proof's key
			m := *is.mdoc
			m.devicePub, _ = pub.(*ecdsa.PublicKey)
			out(w, 200, M{"credentials": []M{{"credential": b64url(m.issuerSigned(t))}}})
			return
		}
		disc := func(parts ...any) string {
			b, _ := json.Marshal(append([]any{randToken(16)}, parts...))
			return b64url(b)
		}
		given, family, birth := disc("given_name", "Erika"), disc("family_name", "Mustermann"), disc("birthdate", "1984-01-26")
		de, fr := disc("DE"), disc("FR")
		payload := M{"iss": is.URL, "vct": "urn:eudi:pid:1", "_sd_alg": "sha-256", "iat": time.Now().Unix(), "exp": time.Now().Add(24 * time.Hour).Unix(),
			"cnf": M{"jwk": jwk}, "_sd": []string{sdDigest("sha-256", given), sdDigest("sha-256", family), sdDigest("sha-256", birth)},
			"nationalities": []any{M{"...": sdDigest("sha-256", de)}, M{"...": sdDigest("sha-256", fr)}}}
		jwt, _ := signJWS(is.key, "ES256", M{"typ": "dc+sd-jwt", "kid": "iss-1"}, payload)
		out(w, 200, M{"credentials": []M{{"credential": jwt + "~" + given + "~" + family + "~" + birth + "~" + de + "~" + fr + "~"}}})
	})
	return is
}

// authOffer is an offer for the authorization code flow, with issuer_state.
func (is *mockIssuer) authOffer() string {
	o, _ := json.Marshal(M{"credential_issuer": is.URL, "credential_configuration_ids": []string{"pid"},
		"grants": M{"authorization_code": M{"issuer_state": "st-1"}}})
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(o))
}

func (is *mockIssuer) offer() string {
	o, _ := json.Marshal(M{"credential_issuer": is.URL, "credential_configuration_ids": []string{"pid"},
		"grants": M{preAuthGrant: M{"pre-authorized_code": "pac-1", "tx_code": M{"length": 4, "input_mode": "numeric", "description": "PIN from the letter"}}}})
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(o))
}

type mockVerifier struct {
	*httptest.Server
	base     string // http://localhost:port, matching the certificate
	key      *ecdsa.PrivateKey
	encKey   *ecdsa.PrivateKey
	cert     *x509.Certificate
	issuer   string
	mu       sync.Mutex
	received []M
	iacaPEM  string // trusted for mdoc presentations
}

func newMockVerifier(t *testing.T, issuer string) *mockVerifier {
	v := &mockVerifier{issuer: issuer}
	v.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v.encKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "verifier"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	v.cert, _ = sign(tmpl, tmpl, v.key.Public(), v.key)
	mux := http.NewServeMux()
	v.Server = httptest.NewServer(mux)
	t.Cleanup(v.Close)
	v.base = strings.Replace(v.URL, "127.0.0.1", "localhost", 1)
	mux.HandleFunc("/request/", func(w http.ResponseWriter, r *http.Request) {
		mode := strings.TrimPrefix(r.URL.Path, "/request/")
		mdoc := strings.HasPrefix(mode, "mdoc-")
		mode = strings.TrimPrefix(mode, "mdoc-")
		responseURI := v.base + "/response"
		if mode == "elsewhere" {
			responseURI, mode = "http://attacker.example/collect", "direct_post"
		}
		claims := M{"client_id": "x509_san_dns:localhost", "response_type": "vp_token", "response_mode": mode, "response_uri": responseURI,
			"nonce": "n-123", "state": "st-1", "aud": "https://self-issued.me/v2", "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
			"dcql_query": M{"credentials": []M{{"id": "pid", "format": "dc+sd-jwt", "meta": M{"vct_values": []string{"urn:eudi:pid:1"}},
				"claims": []M{{"path": []any{"given_name"}}, {"path": []any{"nationalities", nil}}}}}}}
		if mdoc {
			cl := []M{{"path": []any{"org.iso.18013.5.1", "family_name"}}, {"path": []any{"org.iso.18013.5.1", "age_over_18"}, "intent_to_retain": false}}
			if r.URL.Query().Get("bad_claims") != "" { // paths that are not [namespace, element]
				cl = []M{{"path": []any{"org.iso.18013.5.1", "family_name", "extra"}}, {"path": "org.iso.18013.5.1/age_over_18"}}
			}
			claims["dcql_query"] = M{"credentials": []M{{"id": "mdl", "format": "mso_mdoc", "meta": M{"doctype_value": "org.iso.18013.5.1.mDL"}, "claims": cl}}}
		}
		if mode == "direct_post.jwt" {
			ek, _ := publicJWK(v.encKey.Public())
			ek["kid"], ek["use"] = "enc-1", "enc"
			claims["client_metadata"] = M{"jwks": M{"keys": []M{ek}}, "encrypted_response_enc_values_supported": []string{"A128GCM"}}
		}
		jwt, _ := signJWS(v.key, "ES256", M{"typ": "oauth-authz-req+jwt", "x5c": []string{base64.StdEncoding.EncodeToString(v.cert.Raw)}}, claims)
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		fmt.Fprint(w, jwt)
	})
	mux.HandleFunc("/response", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		vpToken := r.PostForm.Get("vp_token")
		if jwe := r.PostForm.Get("response"); jwe != "" {
			priv := privateJWK(v.encKey)
			pb, _ := json.Marshal(priv)
			dec, err := runOp(r.Context(), findOp("jwe.decrypt"), M{"token": jwe, "key": string(pb)}, false, nil)
			if err != nil || hasFailure(dec) {
				http.Error(w, "cannot decrypt", 400)
				return
			}
			b, _ := json.Marshal(dec["payload"].(map[string]any)["vp_token"])
			vpToken = string(b)
		}
		var tok map[string][]string
		json.Unmarshal([]byte(vpToken), &tok)
		if len(tok["mdl"]) == 1 { // an mdoc: rebuild the OID4VP session and verify the device signature over it
			var thumb []byte
			if r.PostForm.Get("response") != "" {
				ek, _ := publicJWK(v.encKey.Public())
				thumb, _ = base64.RawURLEncoding.DecodeString(jwkThumbprint(ek))
			}
			st := oid4vpSessionTranscript("x509_san_dns:localhost", "n-123", thumb, v.base+"/response")
			res, err := runOp(r.Context(), findOp("mdoc.decode"), M{"credential": tok["mdl"][0], "session_transcript": hex.EncodeToString(st),
				"trust_anchors": v.iacaPEM, "doc_type": "org.iso.18013.5.1.mDL"}, false, nil)
			v.mu.Lock()
			v.received = append(v.received, res)
			v.mu.Unlock()
			if err != nil || hasFailure(res) {
				http.Error(w, "mdoc presentation rejected", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"redirect_uri":"https://verifier.example/done"}`)
			return
		}
		if len(tok["pid"]) != 1 {
			http.Error(w, "no pid presentation", 400)
			return
		}
		res, err := runOp(r.Context(), findOp("sdjwt.decode"), M{"token": tok["pid"][0], "issuer": v.issuer, "expected_aud": "x509_san_dns:localhost", "expected_nonce": "n-123"}, false, nil)
		v.mu.Lock()
		v.received = append(v.received, res)
		v.mu.Unlock()
		if err != nil || hasFailure(res) {
			http.Error(w, "presentation rejected", 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"redirect_uri":"https://verifier.example/done"}`)
	})
	return v
}

func TestVerifiableCredentials(t *testing.T) {
	is := newMockIssuer(t)

	t.Run("metadata and offer", func(t *testing.T) {
		res := run(t, "vci.metadata", M{"issuer": is.URL, "offer": is.offer(), "allow_private_urls": true}, nil)
		noFailures(t, res)
		wantStatus(t, res, "offered configuration pid is in the issuer metadata", "pass")
		wantStatus(t, res, "transaction code required", "info")
	})

	// The issuer comes from inside the offer, so a loopback test issuer needs
	// allow_private_urls; without it the offer cannot reach a local address.
	if _, err := tryOp(t, "vci.issue", M{"offer": is.offer(), "tx_code": "1234"}); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("an offer reached a loopback issuer: %v", err)
	}
	issued := run(t, "vci.issue", M{"offer": is.offer(), "tx_code": "1234", "allow_private_urls": true}, nil)
	noFailures(t, issued)
	for _, n := range []string{"token response", "nonce from the nonce endpoint", "credential issued", "credential 1: issuer signature", "credential 1: bound to the holder key", "credential 1: vct"} {
		wantStatus(t, issued, n, "pass")
	}
	cred := issued["credentials"].([]string)[0]
	hk, _ := json.Marshal(issued["holder_key"])
	holder := string(hk)

	t.Run("authorization code flow", func(t *testing.T) {
		for _, by := range []string{"auto", "scope"} {
			res := run(t, "vci.issue", M{"offer": is.authOffer(), "client_id": "wallet", "request_by": by, "redirect_port": freePort(t),
				"open_browser": false, "wait": 10, "allow_private_urls": true}, followURL(t, nil))
			noFailures(t, res)
			want := map[string]string{"auto": "authorization_details", "scope": "scope"}[by]
			if res["flow"] != "authorization code" || res["requested_by"] != want {
				t.Errorf("%s: flow %v, requested by %v", by, res["flow"], res["requested_by"])
			}
			for _, n := range []string{"issuer_state passed on", "state matches the request", "iss response parameter matches", "authorization code returned",
				"credential issued", "credential 1: bound to the holder key"} {
				wantStatus(t, res, n, "pass")
			}
			if by == "auto" {
				wantStatus(t, res, "token response names the credential", "pass")
			} else {
				wantStatus(t, res, "credential scope granted", "pass")
			}
			is.mu.Lock()
			st := is.issuerState
			is.mu.Unlock()
			if st != "st-1" {
				t.Errorf("%s: issuer_state at the authorization server: %q", by, st)
			}
		}
		// Wallet-initiated, without an offer.
		res := run(t, "vci.issue", M{"issuer": is.URL, "configuration_id": "pid", "client_id": "wallet", "redirect_port": freePort(t),
			"open_browser": false, "wait": 10, "allow_private_urls": true}, followURL(t, nil))
		wantStatus(t, res, "credential issued", "pass")
		if _, err := tryOp(t, "vci.issue", M{"offer": is.authOffer(), "allow_private_urls": true}); err == nil || !strings.Contains(err.Error(), "client_id") {
			t.Errorf("no client_id: %v", err)
		}
	})

	t.Run("an mso_mdoc credential", func(t *testing.T) {
		res := run(t, "vci.issue", M{"offer": is.offer(), "tx_code": "1234", "configuration_id": "mdl", "allow_private_urls": true}, nil)
		for _, n := range []string{"credential issued", "credential 1: issuer signature", "credential 1: every data element matches its MSO digest",
			"credential 1: bound to the holder key (MSO device key)"} {
			wantStatus(t, res, n, "pass")
		}
		if fam := res["credential_1"].(M)["namespaces"].(M)["org.iso.18013.5.1"].(M)["family_name"]; fam != "Mustermann" {
			t.Errorf("mdoc claims: %v", res["credential_1"])
		}
	})

	t.Run("issuance failures", func(t *testing.T) {
		if _, err := runOp(t.Context(), findOp("vci.issue"), M{"offer": is.offer(), "allow_private_urls": true}, false, nil); err == nil {
			t.Error("issued without the required tx_code")
		}
		wantStatus(t, run(t, "vci.issue", M{"offer": is.offer(), "tx_code": "0000", "allow_private_urls": true}, nil), "token response", "fail")
	})

	for _, mode := range []string{"direct_post", "direct_post.jwt"} {
		t.Run("present by "+mode, func(t *testing.T) {
			v := newMockVerifier(t, is.URL)
			req := "openid4vp://?client_id=" + url.QueryEscape("x509_san_dns:localhost") + "&request_uri=" + url.QueryEscape(v.base+"/request/"+mode)
			// The request_uri comes inside the request: a loopback verifier
			// needs allow_private_urls.
			if _, err := tryOp(t, "vp.request", M{"request": req, "trust_anchors": certPEM(v.cert)}); err == nil || !strings.Contains(err.Error(), "non-public") {
				t.Errorf("a request reached a loopback verifier: %v", err)
			}
			chk := run(t, "vp.request", M{"allow_private_urls": true, "request": req, "trust_anchors": certPEM(v.cert)}, nil)
			noFailures(t, chk)
			for _, n := range []string{"request object signature", "certificate dNSName matches", "response_uri host is the client_id DNS name", "chains to a trust anchor"} {
				wantStatus(t, chk, n, "pass")
			}
			res := run(t, "vp.present", M{"allow_private_urls": true, "request": req, "credential": cred, "holder_key": holder, "trust_anchors": certPEM(v.cert)}, nil)
			noFailures(t, res)
			wantStatus(t, res, "verifier accepted the presentation", "pass")
			if strings.Join(res["disclosed"].([]string), ",") != "given_name,nationalities[0],nationalities[1]" || strings.Join(res["withheld"].([]string), ",") != "birthdate,family_name" {
				t.Errorf("disclosed %v, withheld %v", res["disclosed"], res["withheld"])
			}
			got := v.received[len(v.received)-1]["claims"].(M)
			if got["given_name"] != "Erika" || got["family_name"] != nil || got["birthdate"] != nil {
				t.Errorf("the verifier saw %v", got)
			}
		})
	}

	// An mdoc from the issuer, presented over OID4VP with only the
	// requested elements and a device signature over the session.
	mdl := run(t, "vci.issue", M{"offer": is.offer(), "tx_code": "1234", "configuration_id": "mdl", "allow_private_urls": true}, nil)
	mdlCred := mdl["credentials"].([]string)[0]
	mk, _ := json.Marshal(mdl["holder_key"])
	mdlHolder := string(mk)
	iacaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: is.mdoc.iaca.Raw}))
	for _, mode := range []string{"direct_post", "direct_post.jwt"} {
		t.Run("present an mdoc by "+mode, func(t *testing.T) {
			v := newMockVerifier(t, is.URL)
			v.iacaPEM = iacaPEM
			req := "openid4vp://?client_id=" + url.QueryEscape("x509_san_dns:localhost") + "&request_uri=" + url.QueryEscape(v.base+"/request/mdoc-"+mode)
			args := M{"allow_private_urls": true, "request": req, "credential": mdlCred, "holder_key": mdlHolder, "trust_anchors": certPEM(v.cert)}
			res := run(t, "vp.present", args, nil)
			noFailures(t, res)
			for _, n := range []string{"a DCQL credential query matches", "holder_key is the MSO's device key", "device signature over the OID4VP session",
				"the DeviceResponse verifies", "verifier accepted the presentation"} {
				wantStatus(t, res, n, "pass")
			}
			if strings.Join(res["disclosed"].([]string), ",") != "org.iso.18013.5.1/age_over_18,org.iso.18013.5.1/family_name" ||
				strings.Join(res["withheld"].([]string), ",") != "org.iso.18013.5.1/birth_date,org.iso.18013.5.1/given_name" {
				t.Errorf("disclosed %v, withheld %v", res["disclosed"], res["withheld"])
			}
			got := v.received[len(v.received)-1]
			wantStatus(t, got, "device signature", "pass")
			claims := got["documents"].([]M)[0]["namespaces"].(M)["org.iso.18013.5.1"].(M)
			if claims["family_name"] != "Mustermann" || claims["given_name"] != nil || claims["birth_date"] != nil {
				t.Errorf("the verifier saw %v", claims)
			}
			// Another key is not the device key.
			args["holder_key"] = holder
			wantStatus(t, run(t, "vp.present", args, nil), "holder_key is the MSO's device key", "fail")
			// Claims that cannot be read never widen what is sent: nothing goes.
			args["holder_key"] = mdlHolder
			args["request"] = "openid4vp://?client_id=" + url.QueryEscape("x509_san_dns:localhost") + "&request_uri=" + url.QueryEscape(v.base+"/request/mdoc-"+mode+"?bad_claims=1")
			before := len(v.received)
			bad := run(t, "vp.present", args, nil)
			wantStatus(t, bad, "every requested claim is available", "fail")
			if c := checkOf(bad, "every requested claim is available"); !strings.Contains(c.Detail, "not [namespace, element]") {
				t.Errorf("unusable claims: %s", c.Detail)
			}
			if bad["vp_token"] != nil || len(v.received) != before {
				t.Error("a presentation was sent for unreadable claims")
			}
		})
	}

	t.Run("refusals", func(t *testing.T) {
		v := newMockVerifier(t, is.URL)
		req := "openid4vp://?client_id=" + url.QueryEscape("x509_san_dns:localhost") + "&request_uri=" + url.QueryEscape(v.base+"/request/elsewhere")
		res := run(t, "vp.present", M{"allow_private_urls": true, "request": req, "credential": cred, "holder_key": holder}, nil)
		wantStatus(t, res, "response_uri host is the client_id DNS name", "fail")
		wantStatus(t, res, "presentation sent", "info")
		if len(v.received) != 0 || res["vp_token"] != nil {
			t.Error("a presentation was built or sent for a request that failed its checks")
		}
		good := "openid4vp://?client_id=" + url.QueryEscape("x509_san_dns:localhost") + "&request_uri=" + url.QueryEscape(v.base+"/request/direct_post")
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ob, _ := json.Marshal(privateJWK(other))
		wantStatus(t, run(t, "vp.present", M{"allow_private_urls": true, "request": good, "credential": cred, "holder_key": string(ob), "trust_anchors": certPEM(v.cert)}, nil), "holder_key is the credential's cnf key", "fail")
		// A certificate nobody vouches for is not an identity.
		wantStatus(t, run(t, "vp.request", M{"allow_private_urls": true, "request": good}, nil), "verifier certificate trusted", "fail")
		// Unsigned requests: only redirect_uri, and only to that URI.
		unsigned := func(clientID, responseURI string) string {
			dq, _ := json.Marshal(M{"credentials": []M{{"id": "pid", "format": "dc+sd-jwt"}}})
			return "openid4vp://?" + url.Values{"client_id": {clientID}, "response_type": {"vp_token"}, "response_mode": {"direct_post"},
				"response_uri": {responseURI}, "nonce": {"n"}, "dcql_query": {string(dq)}}.Encode()
		}
		noFailures(t, run(t, "vp.request", M{"allow_private_urls": true, "request": unsigned("redirect_uri:https://v.example/cb", "https://v.example/cb")}, nil))
		wantStatus(t, run(t, "vp.request", M{"allow_private_urls": true, "request": unsigned("redirect_uri:https://v.example/cb", "https://attacker.example/cb")}, nil), "response or redirect URI is the client_id", "fail")
		for _, id := range []string{"verifier.example", "x509_san_dns:verifier.example", "decentralized_identifier:did:web:v.example"} {
			wantStatus(t, run(t, "vp.request", M{"allow_private_urls": true, "request": unsigned(id, "https://v.example/cb")}, nil), "request is signed", "fail")
		}
		before := len(v.received)
		r := run(t, "vp.present", M{"allow_private_urls": true, "request": unsigned("verifier.example", v.base+"/response"), "credential": cred, "holder_key": holder}, nil)
		if len(v.received) != before || r["vp_token"] != nil {
			t.Error("presented to an unauthenticated verifier without force")
		}
		mismatch := "openid4vp://?client_id=" + url.QueryEscape("x509_san_dns:evil.example") + "&request_uri=" + url.QueryEscape(v.base+"/request/direct_post")
		wantStatus(t, run(t, "vp.request", M{"allow_private_urls": true, "request": mismatch}, nil), "client_id in the URL equals", "fail")
	})
}
