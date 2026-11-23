package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
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
}

func newMockIssuer(t *testing.T) *mockIssuer {
	is := &mockIssuer{}
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
			"credential_configurations_supported": M{"pid": M{"format": "dc+sd-jwt", "vct": "urn:eudi:pid:1", "cryptographic_binding_methods_supported": []string{"jwk"},
				"proof_types_supported": M{"jwt": M{"proof_signing_alg_values_supported": []string{"ES256"}}}}}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		out(w, 200, M{"issuer": is.URL, "token_endpoint": is.URL + "/token", "pre-authorized_grant_anonymous_access_supported": true})
	})
	mux.HandleFunc("/.well-known/jwt-vc-issuer", func(w http.ResponseWriter, _ *http.Request) {
		k, _ := publicJWK(is.key.Public())
		k["kid"] = "iss-1"
		out(w, 200, M{"issuer": is.URL, "jwks": M{"keys": []M{k}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
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
		responseURI := v.base + "/response"
		if mode == "elsewhere" {
			responseURI, mode = "http://attacker.example/collect", "direct_post"
		}
		claims := M{"client_id": "x509_san_dns:localhost", "response_type": "vp_token", "response_mode": mode, "response_uri": responseURI,
			"nonce": "n-123", "state": "st-1", "aud": "https://self-issued.me/v2", "iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
			"dcql_query": M{"credentials": []M{{"id": "pid", "format": "dc+sd-jwt", "meta": M{"vct_values": []string{"urn:eudi:pid:1"}},
				"claims": []M{{"path": []any{"given_name"}}, {"path": []any{"nationalities", nil}}}}}}}
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
