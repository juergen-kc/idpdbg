package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockDeviceAS is an authorization server whose device endpoint wants PKCE,
// as Keycloak does for clients that require it.
func mockDeviceAS(t *testing.T) *httptest.Server {
	var mu sync.Mutex
	challenge, polls := "", 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	out := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		out(w, 200, M{"issuer": srv.URL, "token_endpoint": srv.URL + "/token", "device_authorization_endpoint": srv.URL + "/device"})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("code_challenge") == "" || r.Form.Get("code_challenge_method") != "S256" {
			out(w, 400, M{"error": "invalid_request", "error_description": "Missing parameter: code_challenge_method"})
			return
		}
		mu.Lock()
		challenge = r.Form.Get("code_challenge")
		mu.Unlock()
		out(w, 200, M{"device_code": "dc-1", "user_code": "ABCD-EFGH", "verification_uri": srv.URL + "/activate", "expires_in": 600, "interval": 1})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("device_code") != "dc-1" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			out(w, 400, M{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
		if polls++; polls == 1 {
			out(w, 400, M{"error": "authorization_pending"})
			return
		}
		out(w, 200, M{"access_token": "at-1", "token_type": "Bearer", "expires_in": 300})
	})
	return srv
}

func TestDevicePKCE(t *testing.T) {
	as := mockDeviceAS(t)
	base := M{"issuer": as.URL, "client_id": "tv", "scope": "openid"}

	res := run(t, "oidc.device", base, nil)
	c := checkOf(res, "device authorization response")
	if c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "run again with pkce") {
		t.Fatalf("without pkce: want a failure that suggests pkce, got %+v", c)
	}

	start := time.Now()
	res = run(t, "oidc.device", merge(base, M{"pkce": true, "wait_for_user": true, "wait": 20}), nil)
	noFailures(t, res)
	if res["code_verifier"] == nil || res["token"] == nil {
		t.Fatalf("want a code_verifier and a token, got %v", res)
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("polling took %s", time.Since(start))
	}
}

func TestInactiveHint(t *testing.T) {
	jwt := func(claims M) string {
		b, _ := json.Marshal(claims)
		return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(b) + ".c2ln"
	}
	future := float64(time.Now().Add(time.Hour).Unix())
	if h := inactiveHint(jwt(M{"exp": float64(time.Now().Add(-time.Hour).Unix()), "aud": "web"}), "web"); !strings.Contains(h, "expired") {
		t.Errorf("expired token: %q", h)
	}
	if h := inactiveHint(jwt(M{"exp": future, "aud": []any{"account", "api"}}), "web"); !strings.Contains(h, "aud (account, api) does not include the introspecting client web") {
		t.Errorf("audience: %q", h)
	}
	if h := inactiveHint(jwt(M{"exp": future, "aud": "web"}), "web"); h != "" {
		t.Errorf("nothing to explain, got %q", h)
	}
	if h := inactiveHint("opaque-token", "web"); h != "" {
		t.Errorf("opaque token: %q", h)
	}
}
