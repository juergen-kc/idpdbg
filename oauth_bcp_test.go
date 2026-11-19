package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// laxAS breaks every rule the BCP probes look at: it redirects to any
// redirect_uri, offers the implicit grant, can be framed, ignores PKCE,
// accepts a code twice and keeps rotated refresh tokens valid.
func laxAS(t *testing.T) *httptest.Server {
	var mu sync.Mutex
	n := 0
	refresh := map[string]bool{}
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
		out(w, 200, M{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token",
			"grant_types_supported": []string{"authorization_code", "refresh_token", "password", "implicit"}, "response_types_supported": []string{"code", "token"},
			"code_challenge_methods_supported": []string{"plain", "S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "none"}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// A browser with a session (the test's) is sent straight back; one
		// without (the probe's own requests) gets a sign-in page.
		if r.Header.Get("X-Session") == "" {
			fmt.Fprint(w, `<html><form method="post"><input name="username"><input type="password" name="password"></form></html>`)
			return
		}
		if q.Get("response_type") == "token" { // the implicit grant, enabled
			http.Redirect(w, r, q.Get("redirect_uri")+"#access_token=implicit-at&token_type=Bearer&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
			return
		}
		if q.Get("response_type") != "code" {
			http.Error(w, "unsupported", 400)
			return
		}
		mu.Lock()
		n++
		code := fmt.Sprintf("code-%d", n)
		mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		switch r.Form.Get("grant_type") {
		case "authorization_code", "password":
		case "refresh_token":
			if !refresh[r.Form.Get("refresh_token")] {
				out(w, 400, M{"error": "invalid_grant"})
				return
			}
		default:
			out(w, 400, M{"error": "unsupported_grant_type"})
			return
		}
		n++
		rt := fmt.Sprintf("rt-%d", n)
		refresh[rt] = true
		out(w, 200, M{"access_token": fmt.Sprintf("at-%d", n), "token_type": "Bearer", "expires_in": 300, "refresh_token": rt})
	})
	return srv
}

// sessionBrowser follows the URLs an operation announces, as a browser that
// is already signed in.
func sessionBrowser(t *testing.T) func(string, ...any) {
	re := regexp.MustCompile(`https?://\S+`)
	return func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if !strings.HasPrefix(msg, "Open this URL") {
			return
		}
		go func() {
			time.Sleep(50 * time.Millisecond)
			// Follow redirects by hand: a fragment is posted to its page, as
			// idpdbg's callback page does in a real browser.
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			next := re.FindString(msg)
			for hop := 0; hop < 5 && next != ""; hop++ {
				u, _ := url.Parse(next)
				var resp *http.Response
				var err error
				if u.Fragment != "" {
					frag := u.Fragment
					u.Fragment = ""
					resp, err = client.Post(u.String(), "application/x-www-form-urlencoded", strings.NewReader(frag))
				} else {
					req, _ := http.NewRequest("GET", u.String(), nil)
					req.Header.Set("X-Session", "1")
					resp, err = client.Do(req)
				}
				if err != nil {
					t.Errorf("browser: %v", err)
					return
				}
				resp.Body.Close()
				next = ""
				if loc := resp.Header.Get("Location"); resp.StatusCode/100 == 3 && loc != "" {
					l, _ := u.Parse(loc)
					next = l.String()
				}
			}
		}()
	}
}

func TestBCPProbeFindsEverything(t *testing.T) {
	as := laxAS(t)
	args := M{"issuer": as.URL, "client_id": "spa", "redirect_port": freePort(t), "open_browser": false, "wait": 10}
	res := run(t, "oidc.bcp_probe", args, sessionBrowser(t))
	for _, c := range []string{"redirect URI exact matching: extra path segment", "redirect URI exact matching: extra query parameter",
		"PKCE enforced", "PKCE downgrade refused", "authorization code works only once"} {
		wantStatus(t, res, c, "fail")
	}
	// A code sent to another host can't be seen from here: inconclusive.
	wantStatus(t, res, "redirect URI exact matching: other host", "info")
	for _, c := range []string{"implicit grant refused", "sign-in page cannot be framed", "rotated refresh token stops working"} {
		wantStatus(t, res, c, "warn")
	}

	// Strict mode turns the BCP warnings into failures too.
	res = run(t, "oidc.bcp_probe", merge(args, M{"strict": true, "probes": []any{"implicit", "clickjacking"}}), sessionBrowser(t))
	wantStatus(t, res, "implicit grant refused", "fail")
	wantStatus(t, res, "sign-in page cannot be framed", "fail")
	wantStatus(t, res, "strict mode (RFC 9700)", "fail")
	if c := checkOf(res, "implicit grant refused"); c == nil || !strings.HasPrefix(c.Detail, "strict: ") {
		t.Errorf("strict detail: %+v", c)
	}
}

func TestBCPProbeRejectsUnknownProbe(t *testing.T) {
	op := findOp("oidc.bcp_probe")
	_, err := runOp(t.Context(), op, M{"issuer": laxAS(t).URL, "client_id": "spa", "probes": []any{"nope"}}, false, nil)
	if err == nil || !strings.Contains(err.Error(), `unknown probe "nope"`) {
		t.Errorf("err = %v", err)
	}
}

func TestStrictMode(t *testing.T) {
	as := laxAS(t)
	res := run(t, "oidc.discover", M{"issuer": as.URL}, nil)
	wantStatus(t, res, "implicit grant not offered", "warn")
	wantStatus(t, res, "asymmetric client authentication offered", "info")
	if checkOf(res, "strict mode") != nil {
		t.Errorf("strict summary without strict")
	}
	res = run(t, "oidc.discover", M{"issuer": as.URL, "strict": true}, nil)
	for _, c := range []string{"implicit grant not offered", "resource owner password grant not offered", "PKCE plain not offered",
		"no response type issues access tokens", "asymmetric client authentication offered", "sender-constrained access tokens offered"} {
		wantStatus(t, res, c, "fail")
	}
	wantStatus(t, res, "strict mode (RFC 9700)", "fail")
	// Plain informational checks stay as they are.
	wantStatus(t, res, "advanced features offered", "info")

	// Token responses: a bearer token from a shared-secret client.
	res = run(t, "oidc.refresh", M{"issuer": as.URL, "client_id": "spa", "refresh_token": "rt-unknown"}, nil)
	wantStatus(t, res, "token response", "fail")
}

func TestStrictTokenChecks(t *testing.T) {
	as := laxAS(t)
	// A public client whose refresh tokens are rotated but stay valid.
	res := run(t, "oidc.bcp_probe", M{"issuer": as.URL, "client_id": "spa", "redirect_port": freePort(t), "open_browser": false, "wait": 10,
		"probes": []any{"refresh_replay"}}, sessionBrowser(t))
	wantStatus(t, res, "rotated refresh token stops working", "warn")

	// A shared-secret client getting bearer tokens by password.
	res = run(t, "oidc.password", M{"issuer": as.URL, "client_id": "web", "client_secret": "s", "username": "u", "password": "p", "strict": true}, nil)
	wantStatus(t, res, "asymmetric client authentication", "fail")
	wantStatus(t, res, "access token is sender-constrained", "fail")
	wantStatus(t, res, "resource owner password grant not used", "fail")
	rt := str(find(res, "response", "refresh_token"))

	res = run(t, "oidc.refresh", M{"issuer": as.URL, "client_id": "spa", "refresh_token": rt, "strict": true}, nil)
	wantStatus(t, res, "refresh token rotation", "pass")
	if checkOf(res, "asymmetric client authentication") != nil {
		t.Errorf("a public client has no client authentication to judge")
	}
}

func TestFAPIDiscoverAndProbes(t *testing.T) {
	as := laxAS(t)
	res := run(t, "oidc.discover", M{"issuer": as.URL, "fapi": true}, nil)
	for _, c := range []string{"FAPI 2.0: pushed authorization requests", "FAPI 2.0: client authentication with private_key_jwt or mutual TLS",
		"FAPI 2.0: sender-constrained access tokens", "FAPI 2.0: iss in authorization responses", "FAPI 2.0 Security Profile"} {
		wantStatus(t, res, c, "fail")
	}
	wantStatus(t, res, "FAPI 2.0: PKCE with S256", "pass")
	wantStatus(t, res, "FAPI 2.0: endpoints use TLS", "info") // httptest serves loopback http
	// fapi implies strict.
	wantStatus(t, res, "strict mode (RFC 9700)", "fail")

	res = run(t, "oidc.bcp_probe", M{"issuer": as.URL, "client_id": "web", "client_secret": "s", "redirect_port": freePort(t),
		"open_browser": false, "wait": 10, "fapi": true, "probes": []any{"par_required", "dpop_code_binding"}}, sessionBrowser(t))
	wantStatus(t, res, "FAPI 2.0: authorization request without PAR refused", "fail")
	wantStatus(t, res, "FAPI 2.0: code bound to the DPoP key", "info") // needs dpop
}

func TestFAPITokenChecks(t *testing.T) {
	as := laxAS(t)
	res := run(t, "oidc.password", M{"issuer": as.URL, "client_id": "web", "client_secret": "s", "username": "u", "password": "p", "fapi": true}, nil)
	wantStatus(t, res, "FAPI 2.0: client authentication", "fail")
	wantStatus(t, res, "FAPI 2.0: client sender-constrains its tokens", "fail")
	wantStatus(t, res, "FAPI 2.0 Security Profile", "fail")

	res = run(t, "oidc.refresh", M{"issuer": as.URL, "client_id": "web", "client_secret": "s", "refresh_token": str(find(res, "response", "refresh_token")), "fapi": true}, nil)
	wantStatus(t, res, "refresh token rotation", "warn")
}
