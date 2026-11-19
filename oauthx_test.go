package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
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

// strictOP is a mock provider that enforces private_key_jwt, PAR, JAR and
// DPoP, so a passing test means the tool really did each of them right.
type strictOP struct {
	*httptest.Server
	mu                  sync.Mutex
	usedPAR, usedJAR    bool
	nonceChallenges     int
	params              map[string]url.Values // request_uri -> pushed parameters
	challenge, nonce    string
	dpopJKT             string
	mtlsAlias           string
	registrationDeleted bool
}

func pemPrivate(t *testing.T, k crypto.Signer) string {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newStrictOP(t *testing.T, opKey *rsa.PrivateKey, clientPub crypto.PublicKey) *strictOP {
	op := &strictOP{params: map[string]url.Values{}}
	mux := http.NewServeMux()
	op.Server = httptest.NewServer(mux)
	t.Cleanup(op.Close)
	jsonOut := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	verifyJWT := func(tok string, pub crypto.PublicKey) (*jwtParts, error) {
		p, err := parseJWT(tok)
		if err != nil {
			return nil, err
		}
		if err := verifySig(str(p.Header["alg"]), pub, p.SigningInput, p.Sig); err != nil {
			return nil, err
		}
		return p, nil
	}
	verifyClient := func(r *http.Request) error {
		if r.Form.Get("client_assertion_type") != assertionType {
			return fmt.Errorf("no client assertion")
		}
		p, err := verifyJWT(r.Form.Get("client_assertion"), clientPub)
		if err != nil {
			return err
		}
		cl := p.Claims
		exp, _ := claimTime(cl, "exp")
		if str(cl["iss"]) != "cli" || str(cl["sub"]) != "cli" || r.Form.Get("client_id") != "cli" || str(cl["aud"]) != op.URL || time.Now().After(exp) || str(cl["jti"]) == "" {
			return fmt.Errorf("bad assertion claims %v", cl)
		}
		return nil
	}
	decodeJAR := func(tok string) (url.Values, error) {
		p, err := verifyJWT(tok, clientPub)
		if err != nil {
			return nil, err
		}
		if p.Header["typ"] != "oauth-authz-req+jwt" || str(p.Claims["aud"]) != op.URL || str(p.Claims["iss"]) != "cli" {
			return nil, fmt.Errorf("bad request object %v %v", p.Header, p.Claims)
		}
		v := url.Values{}
		for k, c := range p.Claims {
			if s, ok := c.(string); ok {
				v.Set(k, s)
			}
		}
		return v, nil
	}
	// verifyProof checks a DPoP proof and returns the key thumbprint.
	verifyProof := func(r *http.Request, htu, accessToken string) (string, string) {
		p, err := parseJWT(r.Header.Get("DPoP"))
		if err != nil || p.Header["typ"] != "dpop+jwt" {
			return "", "malformed proof"
		}
		jwk, _ := p.Header["jwk"].(map[string]any)
		pub, err := jwkPublicKey(jwk)
		if err != nil || verifySig(str(p.Header["alg"]), pub, p.SigningInput, p.Sig) != nil {
			return "", "bad proof signature"
		}
		if str(p.Claims["htm"]) != r.Method || str(p.Claims["htu"]) != htu {
			return "", "htm/htu mismatch"
		}
		if accessToken != "" {
			sum := sha256.Sum256([]byte(accessToken))
			if str(p.Claims["ath"]) != b64url(sum[:]) {
				return "", "ath mismatch"
			}
		} else if str(p.Claims["nonce"]) != "n-1" {
			return "", "nonce"
		}
		return jwkThumbprint(jwk), ""
	}

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		m := M{"issuer": op.URL, "authorization_endpoint": op.URL + "/authorize", "token_endpoint": op.URL + "/token",
			"jwks_uri": op.URL + "/jwks", "userinfo_endpoint": op.URL + "/userinfo", "end_session_endpoint": op.URL + "/logout",
			"pushed_authorization_request_endpoint": op.URL + "/par", "request_parameter_supported": true,
			"dpop_signing_alg_values_supported": []string{"ES256"}, "token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
			"authorization_response_iss_parameter_supported": true, "response_types_supported": []string{"code"},
			"subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
			"code_challenge_methods_supported": []string{"S256"}}
		if op.mtlsAlias != "" {
			m["mtls_endpoint_aliases"] = M{"token_endpoint": op.mtlsAlias}
		}
		jsonOut(w, 200, m)
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		jsonOut(w, 200, M{"keys": []M{{"kty": "RSA", "kid": "k1", "n": b64url(opKey.N.Bytes()), "e": b64url(big.NewInt(int64(opKey.E)).Bytes())}}})
	})
	mux.HandleFunc("/par", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if err := verifyClient(r); err != nil {
			jsonOut(w, 401, M{"error": "invalid_client", "error_description": err.Error()})
			return
		}
		params := r.Form
		if ro := r.Form.Get("request"); ro != "" {
			var err error
			if params, err = decodeJAR(ro); err != nil {
				jsonOut(w, 400, M{"error": "invalid_request_object", "error_description": err.Error()})
				return
			}
			op.mu.Lock()
			op.usedJAR = true
			op.mu.Unlock()
		}
		op.mu.Lock()
		uri := fmt.Sprintf("urn:ietf:params:oauth:request_uri:%d", len(op.params))
		op.params[uri] = params
		op.usedPAR = true
		op.mu.Unlock()
		jsonOut(w, 201, M{"request_uri": uri, "expires_in": 60})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		op.mu.Lock()
		defer op.mu.Unlock()
		if uri := q.Get("request_uri"); uri != "" {
			if q = op.params[uri]; q == nil {
				http.Error(w, "unknown request_uri", 400)
				return
			}
		} else if ro := q.Get("request"); ro != "" {
			v, err := decodeJAR(ro)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			q, op.usedJAR = v, true
		}
		op.challenge, op.nonce, op.dpopJKT = q.Get("code_challenge"), q.Get("nonce"), q.Get("dpop_jkt")
		http.Redirect(w, r, q.Get("redirect_uri")+"?code=c1&state="+url.QueryEscape(q.Get("state"))+"&iss="+url.QueryEscape(op.URL), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if err := verifyClient(r); err != nil {
			jsonOut(w, 401, M{"error": "invalid_client", "error_description": err.Error()})
			return
		}
		op.mu.Lock()
		defer op.mu.Unlock()
		claims := M{"iss": op.URL, "sub": "alice", "aud": "api", "exp": time.Now().Add(time.Hour).Unix()}
		tokenType := "Bearer"
		if r.Header.Get("DPoP") != "" {
			jkt, problem := verifyProof(r, op.URL+"/token", "")
			if problem == "nonce" {
				op.nonceChallenges++
				w.Header().Set("DPoP-Nonce", "n-1")
				jsonOut(w, 400, M{"error": "use_dpop_nonce"})
				return
			}
			if problem != "" || (op.dpopJKT != "" && op.dpopJKT != jkt) {
				jsonOut(w, 400, M{"error": "invalid_dpop_proof", "error_description": problem})
				return
			}
			claims["cnf"], tokenType = M{"jkt": jkt}, "DPoP"
		}
		resp := M{"token_type": tokenType, "expires_in": 3600}
		at := signRS256(t, opKey, "k1", claims)
		resp["access_token"] = at
		if r.Form.Get("grant_type") == "authorization_code" {
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "c1" || b64url(sum[:]) != op.challenge {
				jsonOut(w, 400, M{"error": "invalid_grant"})
				return
			}
			resp["id_token"] = signRS256(t, opKey, "k1", M{"iss": op.URL, "sub": "alice", "aud": "cli", "nonce": op.nonce,
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "at_hash": halfHash("RS256", at)})
		}
		jsonOut(w, 200, resp)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		scheme, at, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		p, err := parseJWT(at)
		if err != nil {
			w.WriteHeader(401)
			return
		}
		cnf, _ := p.Claims["cnf"].(map[string]any)
		if cnf != nil {
			jkt, problem := verifyProof(r, op.URL+"/userinfo", at)
			if scheme != "DPoP" || problem != "" || jkt != str(cnf["jkt"]) {
				w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
				w.WriteHeader(401)
				return
			}
		}
		jsonOut(w, 200, M{"sub": "alice", "email": "alice@example.com"})
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("id_token_hint") == "" || q.Get("post_logout_redirect_uri") == "" {
			http.Error(w, "missing parameters", 400)
			return
		}
		http.Redirect(w, r, q.Get("post_logout_redirect_uri")+"?state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/register/cli", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer rat" {
			w.WriteHeader(401)
			return
		}
		op.mu.Lock()
		defer op.mu.Unlock()
		switch {
		case op.registrationDeleted:
			w.WriteHeader(401)
		case r.Method == "DELETE":
			op.registrationDeleted = true
			w.WriteHeader(204)
		default:
			jsonOut(w, 200, M{"client_id": "cli", "client_name": "test", "registration_access_token": "rat"})
		}
	})
	return op
}

func TestOAuthDepth(t *testing.T) {
	opKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	op := newStrictOP(t, opKey, &clientKey.PublicKey)
	clientPEM := pemPrivate(t, clientKey)
	pkj := M{"issuer": op.URL, "client_id": "cli", "client_auth": "private_key_jwt", "client_key": clientPEM}
	with := func(base M, extra M) M {
		out := M{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}

	t.Run("discover lists the advanced features", func(t *testing.T) {
		res := run(t, "oidc.discover", M{"issuer": op.URL}, nil)
		c := checkOf(res, "advanced features offered")
		for _, f := range []string{"PAR", "DPoP", "JAR", "private_key_jwt", "RP-initiated logout"} {
			if c == nil || !strings.Contains(c.Detail, f) {
				t.Errorf("feature %s not reported: %+v", f, c)
			}
		}
		wantStatus(t, res, "issuer identification", "pass")
	})

	t.Run("private_key_jwt", func(t *testing.T) {
		noFailures(t, run(t, "oidc.client_credentials", pkj, nil))
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		bad := run(t, "oidc.client_credentials", with(pkj, M{"client_key": pemPrivate(t, other)}), nil)
		wantStatus(t, bad, "token response", "fail")
	})

	t.Run("login with PAR, JAR, DPoP and private_key_jwt", func(t *testing.T) {
		res := run(t, "oidc.login", with(pkj, M{"par": true, "jar": true, "dpop": true, "open_browser": false,
			"redirect_port": freePort(t), "wait": 10, "scope": "openid email"}), followURL(t, nil))
		noFailures(t, res)
		for _, name := range []string{"PAR: response", "PAR: request_uri", "JAR: request object signed", "DPoP: token_type is DPoP",
			"DPoP: access token cnf.jkt", "id_token: signature", "id_token: nonce", "userinfo: response", "scope email yields"} {
			wantStatus(t, res, name, "pass")
		}
		wantStatus(t, res, "DPoP: server-provided nonce", "info")
		if !op.usedPAR || !op.usedJAR || op.nonceChallenges == 0 {
			t.Errorf("provider saw PAR=%v JAR=%v nonce challenges=%d", op.usedPAR, op.usedJAR, op.nonceChallenges)
		}
		if u := str(res["authorization_url"]); strings.Contains(u, "code_challenge") || !strings.Contains(u, "request_uri") {
			t.Errorf("with PAR only the request_uri should travel through the browser: %s", u)
		}
	})

	t.Run("JAR without PAR", func(t *testing.T) {
		res := run(t, "oidc.login", with(pkj, M{"jar": true, "open_browser": false, "redirect_port": freePort(t), "wait": 10, "scope": "openid"}), followURL(t, nil))
		noFailures(t, res)
		if res["request_object"] == nil {
			t.Error("request object not shown in the result")
		}
	})

	t.Run("DPoP-bound token used as a bearer token is refused", func(t *testing.T) {
		res := run(t, "oidc.login", with(pkj, M{"dpop": true, "open_browser": false, "redirect_port": freePort(t), "wait": 10, "scope": "openid"}), followURL(t, nil))
		at := str(res["token"].(M)["response"].(map[string]any)["access_token"])
		ui := run(t, "oidc.userinfo", M{"issuer": op.URL, "access_token": at}, nil)
		wantStatus(t, ui, "userinfo: response", "fail")
	})

	t.Run("RP-initiated logout", func(t *testing.T) {
		port := freePort(t)
		res := run(t, "oidc.logout", M{"issuer": op.URL, "client_id": "cli", "id_token_hint": "x.y.z", "open_browser": false, "wait": 10,
			"post_logout_redirect_uri": fmt.Sprintf("http://localhost:%d/logged-out", port)}, followURL(t, nil))
		noFailures(t, res)
		wantStatus(t, res, "state returned unchanged", "pass")
		urlOnly := run(t, "oidc.logout", M{"issuer": op.URL, "url_only": true}, nil)
		wantStatus(t, urlOnly, "id_token_hint supplied", "warn")
	})

	t.Run("registration management", func(t *testing.T) {
		base := M{"registration_client_uri": op.URL + "/register/cli", "registration_access_token": "rat"}
		noFailures(t, run(t, "oidc.register_manage", base, nil))
		noFailures(t, run(t, "oidc.register_manage", with(base, M{"action": "delete"}), nil))
		wantStatus(t, run(t, "oidc.register_manage", base, nil), "client configuration response", "fail")
	})

	t.Run("mutual TLS client authentication and bound tokens", func(t *testing.T) {
		_, _, certPEM, keyPEM := selfSigned(t)
		mtls := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			if len(r.TLS.PeerCertificates) == 0 || r.Form.Get("client_id") != "cli" {
				w.WriteHeader(401)
				return
			}
			p := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
			at := signRS256(t, opKey, "k1", M{"sub": "cli", "exp": time.Now().Add(time.Hour).Unix(), "cnf": M{"x5t#S256": b64url(p[:])}})
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			json.NewEncoder(w).Encode(M{"access_token": at, "token_type": "Bearer", "expires_in": 60})
		}))
		mtls.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
		mtls.StartTLS()
		defer mtls.Close()
		op.mtlsAlias = mtls.URL + "/token"
		defer func() { op.mtlsAlias = "" }()

		// The token endpoint comes from mtls_endpoint_aliases, not token_endpoint.
		res := run(t, "oidc.client_credentials", M{"issuer": op.URL, "client_id": "cli", "client_auth": "tls_client_auth",
			"mtls_cert": certPEM, "mtls_key": keyPEM, "insecure": true}, nil)
		noFailures(t, res)
		if res["token_endpoint"] != mtls.URL+"/token" {
			t.Errorf("mTLS alias not used: %v", res["token_endpoint"])
		}
		wantStatus(t, res, "mTLS: access token bound", "pass")
		// Without a certificate the TLS handshake itself fails.
		if _, err := runOp(t.Context(), findOp("oidc.client_credentials"), M{"token_endpoint": mtls.URL + "/token", "client_id": "cli", "insecure": true}, false, nil); err == nil {
			t.Error("request without a client certificate succeeded")
		}
	})

	t.Run("client_secret_jwt", func(t *testing.T) {
		var got url.Values
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			got = r.Form
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(M{"access_token": "x", "token_type": "Bearer", "expires_in": 60})
		}))
		defer srv.Close()
		run(t, "oidc.client_credentials", M{"token_endpoint": srv.URL, "client_id": "cli", "client_secret": "shh", "client_auth": "client_secret_jwt"}, nil)
		p, err := parseJWT(got.Get("client_assertion"))
		if err != nil || verifySig("HS256", []byte("shh"), p.SigningInput, p.Sig) != nil || got.Get("client_secret") != "" {
			t.Errorf("bad client_secret_jwt request: %v %v", got, err)
		}
		if str(p.Claims["aud"]) != srv.URL {
			t.Errorf("assertion aud should default to the endpoint without an issuer: %v", p.Claims["aud"])
		}
	})
}
