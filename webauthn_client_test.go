package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// An independent relying party (go-webauthn) behind the FIDO conformance
// API and a cookie-session "custom" API, to check the software
// authenticator against code that is not idpdbg's.

type rpUser struct {
	id    []byte
	name  string
	creds []gowebauthn.Credential
}

func (u *rpUser) WebAuthnID() []byte                           { return u.id }
func (u *rpUser) WebAuthnName() string                         { return u.name }
func (u *rpUser) WebAuthnDisplayName() string                  { return u.name }
func (u *rpUser) WebAuthnCredentials() []gowebauthn.Credential { return u.creds }

type testRP struct {
	t         *testing.T
	wa        *gowebauthn.WebAuthn
	srv       *httptest.Server
	url       string // http://localhost:port
	mu        sync.Mutex
	users     map[string]*rpUser
	sessions  map[string]*gowebauthn.SessionData // by username or cookie
	requireUV bool
	lastClone bool
	direct    bool // ask for direct attestation
}

func newTestRP(t *testing.T) *testRP {
	rp := &testRP{t: t, users: map[string]*rpUser{}, sessions: map[string]*gowebauthn.SessionData{}}
	mux := http.NewServeMux()
	rp.srv = httptest.NewServer(mux)
	t.Cleanup(rp.srv.Close)
	rp.url = strings.Replace(rp.srv.URL, "127.0.0.1", "localhost", 1)
	var err error
	rp.wa, err = gowebauthn.New(&gowebauthn.Config{RPID: "localhost", RPDisplayName: "Test RP", RPOrigins: []string{rp.url}})
	if err != nil {
		t.Fatal(err)
	}
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(v)
	}
	fail := func(w http.ResponseWriter, err error) {
		w.WriteHeader(400)
		reply(w, M{"status": "failed", "errorMessage": err.Error()})
	}
	merge := func(opts any) M { // conformance API: options fields at the top level
		b, _ := json.Marshal(opts)
		var m M
		json.Unmarshal(b, &m)
		m["status"], m["errorMessage"] = "ok", ""
		return m
	}
	body := func(r *http.Request) ([]byte, M) {
		b, _ := io.ReadAll(r.Body)
		var m M
		json.Unmarshal(b, &m)
		return b, m
	}

	// FIDO conformance API.
	mux.HandleFunc("/attestation/options", func(w http.ResponseWriter, r *http.Request) {
		_, m := body(r)
		u := rp.user(str(m["username"]))
		var ropts []gowebauthn.RegistrationOption
		if rp.direct {
			ropts = append(ropts, gowebauthn.WithConveyancePreference(protocol.PreferDirectAttestation))
		}
		creation, sess, err := rp.wa.BeginRegistration(u, ropts...)
		if err != nil {
			fail(w, err)
			return
		}
		rp.mu.Lock()
		rp.sessions[u.name] = sess
		rp.mu.Unlock()
		reply(w, merge(creation.Response))
	})
	mux.HandleFunc("/attestation/result", func(w http.ResponseWriter, r *http.Request) {
		b, _ := body(r)
		parsed, err := protocol.ParseCredentialCreationResponseBytes(b)
		if err != nil {
			fail(w, err)
			return
		}
		u, sess := rp.sessionFor(parsed.Response.CollectedClientData.Challenge)
		if u == nil {
			fail(w, io.EOF)
			return
		}
		cred, err := rp.wa.CreateCredential(u, *sess, parsed)
		if err != nil {
			fail(w, err)
			return
		}
		rp.mu.Lock()
		u.creds = append(u.creds, *cred)
		rp.mu.Unlock()
		reply(w, M{"status": "ok", "errorMessage": ""})
	})
	mux.HandleFunc("/assertion/options", func(w http.ResponseWriter, r *http.Request) {
		_, m := body(r)
		u := rp.user(str(m["username"]))
		var opts []gowebauthn.LoginOption
		if rp.requireUV {
			opts = append(opts, gowebauthn.WithUserVerification(protocol.VerificationRequired))
		}
		assertion, sess, err := rp.wa.BeginLogin(u, opts...)
		if err != nil {
			fail(w, err)
			return
		}
		rp.mu.Lock()
		rp.sessions[u.name] = sess
		rp.mu.Unlock()
		reply(w, merge(assertion.Response))
	})
	mux.HandleFunc("/assertion/result", func(w http.ResponseWriter, r *http.Request) {
		b, _ := body(r)
		parsed, err := protocol.ParseCredentialRequestResponseBytes(b)
		if err != nil {
			fail(w, err)
			return
		}
		u, sess := rp.sessionFor(parsed.Response.CollectedClientData.Challenge)
		if u == nil {
			fail(w, io.EOF)
			return
		}
		cred, err := rp.wa.ValidateLogin(u, *sess, parsed)
		if err != nil {
			fail(w, err)
			return
		}
		rp.mu.Lock()
		rp.lastClone = cred.Authenticator.CloneWarning
		for i := range u.creds {
			if bytes.Equal(u.creds[i].ID, cred.ID) {
				u.creds[i] = *cred
			}
		}
		rp.mu.Unlock()
		reply(w, M{"status": "ok", "errorMessage": ""})
	})

	// A demo-site style API: session cookie, {"publicKey": ...} options,
	// {"username", "response"} result, {"verified": true} verdict.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "page", Value: "seen", Path: "/", HttpOnly: true})
		w.Write([]byte("<html>demo</html>"))
	})
	mux.HandleFunc("/custom/reg/options", func(w http.ResponseWriter, r *http.Request) {
		if _, err := r.Cookie("page"); err != nil { // like webauthn.io: no page session, server error
			w.WriteHeader(500)
			w.Write([]byte("<h1>Server Error (500)</h1>"))
			return
		}
		_, m := body(r)
		for k := range m { // strict, like webauthn.io: unknown fields are a 400
			if k != "username" {
				w.WriteHeader(400)
				reply(w, M{"error": "unexpected field " + k})
				return
			}
		}
		if str(m["username"]) == "" {
			w.WriteHeader(400)
			reply(w, M{"error": "username required"})
			return
		}
		u := rp.user(str(m["username"]))
		creation, sess, err := rp.wa.BeginRegistration(u)
		if err != nil {
			fail(w, err)
			return
		}
		sid := make([]byte, 16)
		rand.Read(sid)
		rp.mu.Lock()
		rp.sessions["cookie:"+b64url(sid)] = sess
		rp.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: b64url(sid), Path: "/"})
		reply(w, creation)
	})
	mux.HandleFunc("/custom/reg/verify", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("sid")
		if err != nil {
			w.WriteHeader(401)
			reply(w, M{"verified": false, "error": "no session cookie"})
			return
		}
		_, m := body(r)
		rp.mu.Lock()
		sess := rp.sessions["cookie:"+ck.Value]
		rp.mu.Unlock()
		inner, _ := json.Marshal(m["response"])
		parsed, err := protocol.ParseCredentialCreationResponseBytes(inner)
		if err != nil || sess == nil {
			reply(w, M{"verified": false})
			return
		}
		if str(m["username"]) != "carol" { // result_extra must arrive
			reply(w, M{"verified": false, "error": "username missing from the result body"})
			return
		}
		u := rp.user(str(m["username"]))
		if _, err := rp.wa.CreateCredential(u, *sess, parsed); err != nil {
			reply(w, M{"verified": false, "error": err.Error()})
			return
		}
		reply(w, M{"verified": true})
	})
	return rp
}

func (rp *testRP) user(name string) *rpUser {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	if u := rp.users[name]; u != nil {
		return u
	}
	id := make([]byte, 16)
	rand.Read(id)
	u := &rpUser{id: id, name: name}
	rp.users[name] = u
	return u
}

func (rp *testRP) sessionFor(challenge string) (*rpUser, *gowebauthn.SessionData) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	for name, s := range rp.sessions {
		if s.Challenge == challenge {
			return rp.users[name], s
		}
	}
	// A tampered challenge matches no session: fall back to the latest
	// one so the RP's own challenge comparison is what rejects it.
	for name, s := range rp.sessions {
		if u := rp.users[name]; u != nil {
			return u, s
		}
	}
	return nil, nil
}

func TestWebAuthnAgainstRP(t *testing.T) {
	rp := newTestRP(t)
	base := M{"server": rp.url, "username": "alice"}
	with := func(m M) M {
		out := M{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range m {
			out[k] = v
		}
		return out
	}

	reg := run(t, "webauthn.register", with(M{}), nil)
	noFailures(t, reg)
	wantStatus(t, reg, "server accepts the registration", "pass")
	wantStatus(t, reg, "RP ID valid for the origin", "pass")
	cred, _ := reg["credential"].(string)
	if !strings.HasPrefix(cred, "idpdbg-webauthn:") || len(rp.users["alice"].creds) != 1 {
		t.Fatalf("no credential: %v", reg)
	}

	login := run(t, "webauthn.login", with(M{"credential": cred}), nil)
	noFailures(t, login)
	wantStatus(t, login, "server accepts the assertion", "pass")
	wantStatus(t, login, "options: allowCredentials lists this credential", "pass")
	cred2 := login["credential"].(string)
	if login["sign_count"] != uint32(1) || cred2 == cred {
		t.Errorf("counter: %v", login["sign_count"])
	}
	if l2 := run(t, "webauthn.login", with(M{"credential": cred2}), nil); l2["sign_count"] != uint32(2) || checkOf(l2, "server accepts the assertion").Status != "pass" {
		t.Errorf("second login: %v", l2)
	}

	// Other algorithms, packed self attestation, a synced passkey.
	for _, alg := range []int{-8, -257} {
		r := run(t, "webauthn.register", with(M{"username": "alg" + str(alg), "alg": alg, "attestation_format": "packed", "backup_eligible": true}), nil)
		noFailures(t, r)
		l := run(t, "webauthn.login", with(M{"username": "alg" + str(alg), "credential": r["credential"]}), nil)
		wantStatus(t, l, "server accepts the assertion", "pass")
	}

	// Every registration tamper is rejected by a correct RP.
	for _, tm := range registerTampers {
		r := run(t, "webauthn.register", with(M{"username": "tamper-" + tm, "tamper": tm, "attestation_format": "packed"}), nil)
		wantStatus(t, r, "server rejects "+tamperWhat[tm], "pass")
		if r["credential"] != nil {
			t.Errorf("%s: a tampered registration returned a credential", tm)
		}
	}
	// Login tampers (UV is tested below against an RP that requires it).
	for _, tm := range loginTampers {
		if tm == "no_user_verified" {
			continue
		}
		r := run(t, "webauthn.login", with(M{"credential": cred2, "tamper": tm}), nil)
		want := "pass"
		if tm == "counter_not_increased" { // go-webauthn accepts and flags a clone
			want = "warn"
		}
		wantStatus(t, r, "server rejects "+tamperWhat[tm], want)
	}
	if !rp.lastClone {
		t.Error("the RP did not see the counter problem")
	}
	rp.requireUV = true
	l := run(t, "webauthn.login", with(M{"credential": cred2, "tamper": "no_user_verified"}), nil)
	wantStatus(t, l, "server rejects "+tamperWhat["no_user_verified"], "pass")
	rp.requireUV = false
	if _, err := tryOp(t, "webauthn.login", with(M{"credential": cred2, "tamper": "no_user_verified"})); err == nil {
		t.Error("no_user_verified against an RP that does not require UV should be refused")
	}

	// A credential the RP does not list is caught before signing.
	other := run(t, "webauthn.register", M{"server": rp.url, "username": "bob"}, nil)
	l = run(t, "webauthn.login", with(M{"credential": other["credential"]}), nil)
	wantStatus(t, l, "options: allowCredentials lists this credential", "fail")
}

func TestWebAuthnCustomAPIAndOffline(t *testing.T) {
	rp := newTestRP(t)
	// Cookie session, wrapped options, nested result, {"verified": true}.
	r := run(t, "webauthn.register", M{"options_url": rp.url + "/custom/reg/options", "options_body": `{"username":"carol"}`,
		"result_url": rp.url + "/custom/reg/verify", "result_field": "response", "result_extra": `{"username":"carol"}`}, nil)
	noFailures(t, r)
	wantStatus(t, r, "server accepts the registration", "pass")
	wantStatus(t, r, "page loaded first", "info")
	if _, err := tryOp(t, "webauthn.register", M{"options_url": rp.url + "/custom/reg/options", "options_body": `{"username":"carol"}`, "page_url": "none",
		"result_url": rp.url + "/custom/reg/verify", "result_field": "response", "result_extra": `{"username":"carol"}`}); err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("without the page session the test RP should fail: %v", err)
	}

	// Offline: answer given options; the independent RP verifies the result.
	u := rp.user("dave")
	creation, sess, err := rp.wa.BeginRegistration(u)
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := json.Marshal(creation)
	off := run(t, "webauthn.register", M{"options": string(opts), "origin": rp.url}, nil)
	if off["api"] != "offline" || off["credential"] == nil {
		t.Fatalf("offline: %v", off)
	}
	resp, _ := json.Marshal(off["credential_response"])
	parsed, err := protocol.ParseCredentialCreationResponseBytes(resp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rp.wa.CreateCredential(u, *sess, parsed); err != nil {
		t.Errorf("go-webauthn rejects the offline response: %v", err)
	}
}

func TestWebAuthnOptionChecks(t *testing.T) {
	opts := func(rpID, userID, challenge string, algs ...int) string {
		var params []M
		for _, a := range algs {
			params = append(params, M{"type": "public-key", "alg": a})
		}
		b, _ := json.Marshal(M{"publicKey": M{"rp": M{"id": rpID, "name": "x"}, "user": M{"id": userID, "name": "alice@example.com", "displayName": "Alice"},
			"challenge": challenge, "pubKeyCredParams": params}})
		return string(b)
	}
	good := b64url(bytes.Repeat([]byte{7}, 32))
	res := run(t, "webauthn.register", M{"options": opts("example.com", b64url([]byte("opaque-handle-123")), good, -7, -257), "origin": "https://login.example.com"}, nil)
	noFailures(t, res)
	wantStatus(t, res, "options: pubKeyCredParams", "pass")

	wantStatus(t, run(t, "webauthn.register", M{"options": opts("example.com", b64url([]byte("u")), b64url([]byte("short")), -7), "origin": "https://example.com"}, nil),
		"options: challenge length", "fail")
	wantStatus(t, run(t, "webauthn.register", M{"options": opts("example.com", b64url([]byte("alice@example.com")), good, -7), "origin": "https://example.com"}, nil),
		"options: user.id carries no personal data", "warn")
	// webauthn.io style: the handle embeds the account name.
	wantStatus(t, run(t, "webauthn.register", M{"options": opts("example.com", b64url([]byte("site-alice@example.com-1")), good, -7), "origin": "https://example.com"}, nil),
		"options: user.id carries no personal data", "warn")
	nameOpts := strings.Replace(opts("example.com", b64url([]byte("webauthnio-carol")), good, -7), "alice@example.com", "carol", 1)
	wantStatus(t, run(t, "webauthn.register", M{"options": nameOpts, "origin": "https://example.com"}, nil), "options: user.id carries no personal data", "warn")
	wantStatus(t, run(t, "webauthn.register", M{"options": opts("example.com", b64url([]byte("u")), good, -257), "origin": "https://example.com"}, nil),
		"options: pubKeyCredParams includes ES256", "warn")
	for origin, rpID := range map[string]string{"https://example.com": "other.com", "https://evil-example.com": "example.com", "https://a.co.uk": "co.uk", "http://example.com": "example.com"} {
		r := run(t, "webauthn.register", M{"options": opts(rpID, b64url([]byte("u")), good, -7), "origin": origin}, nil)
		wantStatus(t, r, "RP ID valid for the origin", "fail")
		if r["credential"] != nil {
			t.Errorf("%s / %s: a browser would refuse, but a credential was made", origin, rpID)
		}
	}
	wantStatus(t, run(t, "webauthn.register", M{"options": opts("localhost", b64url([]byte("u")), good, -7), "origin": "http://localhost:8080"}, nil),
		"RP ID valid for the origin", "pass")
}

func TestCBOREncodeRoundTrip(t *testing.T) {
	v := map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": bytes.Repeat([]byte{1}, 300), -2: 70000, 3: -257}
	back, n, err := cborDecode(cborEncode(v))
	m, _ := back.(map[any]any)
	if err != nil || n != len(cborEncode(v)) || m["fmt"] != "none" || len(m["authData"].([]byte)) != 300 || m[int64(3)] != int64(-257) || m[int64(-2)] != int64(70000) {
		t.Errorf("round trip: %v %v", back, err)
	}
	if !bytes.Equal(cborEncode(map[any]any{-1: 1, 3: 1, 1: 1}), []byte{0xA3, 0x01, 0x01, 0x03, 0x01, 0x20, 0x01}) {
		t.Error("canonical key order")
	}
	// CTAP2 canonical order: shorter encodings first (24 encodes in 2 bytes).
	if !bytes.Equal(cborEncode(map[any]any{24: 0, 3: 0}), []byte{0xA2, 0x03, 0x00, 0x18, 0x18, 0x00}) {
		t.Error("length-first key order")
	}
}

// A credential kept in a profile is a stored secret: never taken from the
// profile over MCP, never used to sign offline, and only sent to the
// profile's origins.
func TestWebAuthnStoredCredentialGuard(t *testing.T) {
	rp := newTestRP(t)
	reg := run(t, "webauthn.register", M{"server": rp.url, "username": "erin"}, nil)
	cred := reg["credential"].(string)
	dir := t.TempDir()
	t.Setenv("IDPDBG_CONFIG", dir+"/config.json")
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "")
	cfg, _ := json.Marshal(M{"profiles": M{"wa": M{"credential": cred, "server": rp.url}}})
	if err := os.WriteFile(dir+"/config.json", cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	op := findOp("webauthn.login")
	// Over MCP the profile's credential is not used.
	if _, err := runOp(t.Context(), op, M{"profile": "wa", "username": "erin"}, false, nil); err == nil {
		t.Error("MCP caller used the profile's credential")
	}
	// From the CLI it works against the profile's own server...
	res, err := runOp(t.Context(), op, M{"profile": "wa", "username": "erin"}, true, nil)
	if err != nil || checkOf(res, "server accepts the assertion").Status != "pass" {
		t.Errorf("CLI with profile: %v %v", err, res)
	}
	// ...but not offline, and not to another origin.
	if _, err := runOp(t.Context(), op, M{"profile": "wa", "server": "", "options": `{"challenge":"` + b64url(make([]byte, 32)) + `","rpId":"localhost"}`, "origin": rp.url}, true, nil); err == nil {
		t.Error("stored credential signed offline")
	}
	if _, err := runOp(t.Context(), op, M{"profile": "wa", "server": "https://evil.example"}, true, nil); err == nil {
		t.Error("stored credential sent to another origin")
	}
}

func TestWebAuthnExtensions(t *testing.T) {
	ch := b64url(bytes.Repeat([]byte{9}, 32))
	mk := func(ext, sel string) string {
		return `{"rp":{"id":"example.com","name":"x"},"user":{"id":"` + b64url([]byte("h-1")) + `","name":"n","displayName":"n"},"challenge":"` + ch +
			`","pubKeyCredParams":[{"type":"public-key","alg":-7}],"authenticatorSelection":` + sel + `,"extensions":` + ext + `}`
	}
	r := run(t, "webauthn.register", M{"options": mk(`{"credProps":true,"largeBlob":{"support":"preferred"}}`, `{"residentKey":"preferred"}`), "origin": "https://example.com"}, nil)
	ext := r["credential_response"].(M)["clientExtensionResults"].(M)
	if cp, _ := ext["credProps"].(M); cp == nil || cp["rk"] != true {
		t.Errorf("credProps: %v", ext)
	}
	if c := checkOf(r, "options: extensions"); c == nil || !strings.Contains(c.Detail, "largeBlob") {
		t.Errorf("unsupported extension not named: %v", c)
	}
	r = run(t, "webauthn.register", M{"options": mk(`{"credProps":true}`, `{"residentKey":"discouraged"}`), "origin": "https://example.com"}, nil)
	if r["credential_response"].(M)["clientExtensionResults"].(M)["credProps"].(M)["rk"] != false {
		t.Error("credProps.rk should be false when the RP discourages resident keys")
	}
	r = run(t, "webauthn.register", M{"options": mk(`{}`, `{}`), "origin": "https://example.com"}, nil)
	if len(r["credential_response"].(M)["clientExtensionResults"].(M)) != 0 {
		t.Error("extension results without a request")
	}
}
