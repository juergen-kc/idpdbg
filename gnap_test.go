package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
)

type mockGNAP struct {
	*httptest.Server
	mu      sync.Mutex
	grants  map[string]M // grant id -> {jwk, nonce, finish, as_nonce, ref}
	tokens  map[string]M // manage token -> {jwk, value, revoked}
	badHash bool
	sha512  bool // advertise a hash method the client never asked for
	n       int
}

var sigInputRe = regexp.MustCompile(`^sig1=\(([^)]*)\)(.*)$`)

// verifyGNAP checks a request's RFC 9421 signature and Content-Digest
// against the key the grant was made with.
func verifyGNAP(r *http.Request, body []byte, jwk map[string]any) error {
	m := sigInputRe.FindStringSubmatch(r.Header.Get("Signature-Input"))
	if m == nil {
		return errors.New("no sig1 Signature-Input")
	}
	var comps []string
	for _, c := range strings.Fields(m[1]) {
		comps = append(comps, strings.Trim(c, `"`))
	}
	if !strings.Contains(m[2], `tag="gnap"`) || !contains(comps, "@method") || !contains(comps, "@target-uri") {
		return errors.New("signature does not cover the GNAP minimum")
	}
	if len(body) > 0 && (!contains(comps, "content-digest") || r.Header.Get("Content-Digest") != contentDigest(body, "sha-256")) {
		return errors.New("content digest missing or wrong")
	}
	if r.Header.Get("Authorization") != "" && !contains(comps, "authorization") {
		return errors.New("authorization header not signed")
	}
	u, _ := url.Parse("http://" + r.Host + r.URL.RequestURI())
	hdrs := map[string]string{}
	for k := range r.Header {
		hdrs[strings.ToLower(k)] = r.Header.Get(k)
	}
	base, err := signatureBase(&sigRequest{Method: r.Method, URL: u, Headers: hdrs}, comps, "("+m[1]+")"+m[2])
	if err != nil {
		return err
	}
	sig, _ := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(r.Header.Get("Signature"), "sig1=:"), ":"))
	pub, err := jwkPublicKey(jwk)
	if err != nil {
		return err
	}
	return httpsigVerify(pub, str(jwk["alg"]), []byte(base), sig)
}

func newMockGNAP(t *testing.T) *mockGNAP {
	as := &mockGNAP{grants: map[string]M{}, tokens: map[string]M{}}
	mux := http.NewServeMux()
	as.Server = httptest.NewServer(mux)
	t.Cleanup(as.Close)
	out := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if v != nil {
			json.NewEncoder(w).Encode(v)
		}
	}
	issue := func(jwk any, access any, bearer bool) M {
		as.n++
		v := fmt.Sprintf("tok-%d", as.n)
		as.tokens["mng-"+v] = M{"jwk": jwk, "value": v}
		t := M{"value": v, "access": access, "manage": M{"uri": as.URL + "/token/mng-" + v, "access_token": M{"value": "mng-" + v}}}
		if bearer {
			t["flags"] = []string{"bearer"}
		}
		return t
	}
	mux.HandleFunc("/gnap", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			AccessToken struct{ Access []any } `json:"access_token"`
			Client      struct{ Key struct{ JWK map[string]any } }
			Interact    *struct{ Finish struct{ URI, Nonce string } }
		}
		json.Unmarshal(body, &req)
		if err := verifyGNAP(r, body, req.Client.Key.JWK); err != nil {
			out(w, 400, M{"error": M{"code": "invalid_client", "description": err.Error()}})
			return
		}
		as.mu.Lock()
		defer as.mu.Unlock()
		bearer := strings.Contains(fmt.Sprint(req.AccessToken.Access), "bearer-please")
		if req.Interact == nil {
			out(w, 200, M{"access_token": issue(req.Client.Key.JWK, req.AccessToken.Access, bearer)})
			return
		}
		as.n++
		gid := fmt.Sprintf("g%d", as.n)
		asNonce := randToken(8)
		as.grants[gid] = M{"jwk": req.Client.Key.JWK, "nonce": req.Interact.Finish.Nonce, "finish": req.Interact.Finish.URI, "as_nonce": asNonce, "access": req.AccessToken.Access}
		inter := M{"redirect": as.URL + "/interact/" + gid, "finish": asNonce}
		if as.sha512 {
			inter["hash_method"] = "sha-512"
		}
		out(w, 200, M{"interact": inter,
			"continue": M{"access_token": M{"value": "cont-" + gid}, "uri": as.URL + "/continue/" + gid, "wait": 5}})
	})
	mux.HandleFunc("/interact/", func(w http.ResponseWriter, r *http.Request) {
		as.mu.Lock()
		g := as.grants[strings.TrimPrefix(r.URL.Path, "/interact/")]
		ref := randToken(8)
		g["ref"] = ref
		h := sha256.Sum256([]byte(str(g["nonce"]) + "\n" + str(g["as_nonce"]) + "\n" + ref + "\n" + as.URL + "/gnap"))
		hash := b64url(h[:])
		if as.badHash {
			hash = b64url(make([]byte, 32))
		}
		as.mu.Unlock()
		http.Redirect(w, r, str(g["finish"])+"?hash="+url.QueryEscape(hash)+"&interact_ref="+url.QueryEscape(ref), http.StatusFound)
	})
	mux.HandleFunc("/continue/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		gid := strings.TrimPrefix(r.URL.Path, "/continue/")
		as.mu.Lock()
		defer as.mu.Unlock()
		g := as.grants[gid]
		var req M
		json.Unmarshal(body, &req)
		if r.Header.Get("Authorization") != "GNAP cont-"+gid {
			out(w, 401, M{"error": "invalid_continuation"})
			return
		}
		if err := verifyGNAP(r, body, g["jwk"].(map[string]any)); err != nil {
			out(w, 401, M{"error": M{"code": "invalid_client", "description": err.Error()}})
			return
		}
		if str(req["interact_ref"]) != str(g["ref"]) {
			out(w, 400, M{"error": "invalid_interaction"})
			return
		}
		out(w, 200, M{"access_token": issue(g["jwk"], g["access"], false)})
	})
	mux.HandleFunc("/token/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/token/")
		as.mu.Lock()
		defer as.mu.Unlock()
		tk := as.tokens[id]
		if tk == nil || r.Header.Get("Authorization") != "GNAP "+id || tk["revoked"] == true {
			out(w, 400, M{"error": "invalid_rotation"})
			return
		}
		if err := verifyGNAP(r, nil, tk["jwk"].(map[string]any)); err != nil {
			out(w, 401, M{"error": M{"code": "invalid_client", "description": err.Error()}})
			return
		}
		if r.Method == "DELETE" {
			tk["revoked"] = true
			w.WriteHeader(204)
			return
		}
		tk["revoked"] = true
		out(w, 200, M{"access_token": issue(tk["jwk"], nil, false)})
	})
	return as
}

func TestGNAP(t *testing.T) {
	as := newMockGNAP(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := keyPEM(priv)
	access := []any{map[string]any{"type": "photo-api", "actions": []any{"read"}}}

	t.Run("immediate grant, rotate, revoke", func(t *testing.T) {
		res := run(t, "gnap.grant", M{"grant_endpoint": as.URL + "/gnap", "access": access, "client_key": key}, nil)
		noFailures(t, res)
		wantStatus(t, res, "access token: bound to the client key", "pass")
		tok := res["response"].(map[string]any)["access_token"].(map[string]any)
		mng := tok["manage"].(map[string]any)
		mtok := str(mng["access_token"].(map[string]any)["value"])
		rot := run(t, "gnap.rotate", M{"manage_uri": mng["uri"], "token": mtok, "client_key": key}, nil)
		noFailures(t, rot)
		newMng := rot["response"].(map[string]any)["access_token"].(map[string]any)["manage"].(map[string]any)
		newTok := str(newMng["access_token"].(map[string]any)["value"])
		// Another key cannot use the grant.
		_, other, _ := ed25519.GenerateKey(rand.Reader)
		wantStatus(t, run(t, "gnap.revoke", M{"manage_uri": newMng["uri"], "token": newTok, "client_key": keyPEM(other)}, nil), "token revoked", "fail")
		noFailures(t, run(t, "gnap.revoke", M{"manage_uri": newMng["uri"], "token": newTok, "client_key": key}, nil))
		wantStatus(t, run(t, "gnap.rotate", M{"manage_uri": newMng["uri"], "token": newTok, "client_key": key}, nil), "token rotated", "fail")
	})

	t.Run("interactive grant with finish hash", func(t *testing.T) {
		res := run(t, "gnap.grant", M{"grant_endpoint": as.URL + "/gnap", "access": access, "interact": true, "finish_port": freePort(t), "open_browser": false, "wait": 10}, followURL(t, nil))
		noFailures(t, res)
		for _, n := range []string{"interaction finish hash matches", "continuation response", "continuation URI is at the AS", "access token: value present"} {
			wantStatus(t, res, n, "pass")
		}
		wantStatus(t, res, "client key", "info") // ephemeral
	})

	t.Run("injected finish redirect is caught", func(t *testing.T) {
		as.badHash = true
		defer func() { as.badHash = false }()
		res := run(t, "gnap.grant", M{"grant_endpoint": as.URL + "/gnap", "access": access, "interact": true, "finish_port": freePort(t), "open_browser": false, "wait": 10}, followURL(t, nil))
		wantStatus(t, res, "interaction finish hash matches", "fail")
		if res["continue_response"] != nil {
			t.Error("continued despite a wrong hash")
		}
	})

	t.Run("only http(s) URLs reach the system browser", func(t *testing.T) {
		for u, ok := range map[string]bool{"https://as.example/i": true, "http://localhost:1/x": true, "file:///etc/passwd": false,
			"x-apple.systempreferences:com.apple.preference": false, "javascript:alert(1)": false, "smb://evil/share": false, "https:///nohost": false} {
			if safeBrowserURL(u) != ok {
				t.Errorf("%s: safe=%v", u, !ok)
			}
		}
		if openBrowser("file:///etc/passwd") == nil {
			t.Error("a file URL was handed to the OS")
		}
	})

	t.Run("bearer tokens are flagged", func(t *testing.T) {
		res := run(t, "gnap.grant", M{"grant_endpoint": as.URL + "/gnap", "access": []any{"bearer-please"}}, nil)
		wantStatus(t, res, "access token: bound to the client key", "warn")
	})
}
