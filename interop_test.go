//go:build interop

// Interop tests against a real Keycloak, run by the "interop" CI job.
// Locally:
//
//	scripts/keycloak.sh
//	go test -tags interop -run Keycloak -v .
//
// The realm (users, clients, keys) is testdata/keycloak/idpdbg-realm.json.
// Its OIDC and SAML clients are registered for ports 8765 and 8766 on
// localhost, so these tests do not run in parallel.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	kcRealm  = "idpdbg"
	kcUser   = "alice"
	kcPass   = "alice-interop-pw" // test fixture from testdata/keycloak
	kcSecret = "idpdbg-interop-secret"
)

func kcBase() string {
	if u := os.Getenv("IDPDBG_KEYCLOAK_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:8080"
}

func kcIssuer() string { return kcBase() + "/realms/" + kcRealm }

// kcRun runs an operation as an MCP caller would (no CLI file paths), with
// a scripted browser answering the URL the operation announces.
func kcRun(t *testing.T, name string, args M, b *kcBrowser) M {
	t.Helper()
	op := findOp(name)
	if op == nil {
		t.Fatalf("no op %s", name)
	}
	var log func(string, ...any)
	if b != nil {
		log = b.log
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := runOp(ctx, op, args, false, log)
	if b != nil {
		b.wait(t)
	}
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

// kcClean fails the test on any failed check and logs warnings, which are
// findings about Keycloak rather than idpdbg bugs.
func kcClean(t *testing.T, res M) {
	t.Helper()
	cs, _ := res["checks"].(Checks)
	if len(cs) == 0 {
		t.Errorf("no checks in the result")
	}
	for _, c := range cs {
		switch c.Status {
		case "fail":
			t.Errorf("check failed: %s — %s", c.Name, c.Detail)
		case "warn":
			t.Logf("warn: %s — %s", c.Name, c.Detail)
		}
	}
}

func kcWant(t *testing.T, res M, check, status string) {
	t.Helper()
	c := checkOf(res, check)
	if c == nil {
		t.Errorf("no check %q", check)
	} else if c.Status != status {
		t.Errorf("check %q: %s (%s), want %s", check, c.Status, c.Detail, status)
	}
}

// kcBrowser plays the person in the browser: it signs in on Keycloak's
// login page, accepts consent and device-code pages, and submits the
// auto-posting SAML forms, until it lands back on idpdbg's listener.
type kcBrowser struct {
	t        *testing.T
	client   *http.Client
	userCode string
	done     chan error
	pending  int
	// loggedOut, when set, recognises the page an IdP shows after a logout
	// (it has no form to fill in).
	loggedOut func(u *url.URL, body string) bool
}

func newKCBrowser(t *testing.T) *kcBrowser {
	jar, _ := cookiejar.New(nil)
	// idpdbg's https loopback listener has a throwaway self-signed
	// certificate, which a person accepts in the browser; so does this one.
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &kcBrowser{t: t, client: &http.Client{Jar: jar, Timeout: 30 * time.Second, Transport: tr}, done: make(chan error, 16)}
}

var (
	urlRe   = regexp.MustCompile(`https?://\S+`)
	formRe  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputRe = regexp.MustCompile(`(?is)<(?:input|button)\b([^>]*)>`)
	attrRe  = regexp.MustCompile(`(?is)([a-z][a-z0-9_-]*)\s*=\s*"([^"]*)"`)
)

func (b *kcBrowser) log(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	var start string
	switch {
	case strings.HasPrefix(msg, "Open this URL"):
		start = urlRe.FindString(msg)
	case strings.HasPrefix(msg, "Go to "):
		start = urlRe.FindString(msg)
		if f := strings.Fields(msg); len(f) > 0 {
			b.userCode = f[len(f)-1]
		}
	default:
		return
	}
	b.pending++
	go func() {
		time.Sleep(100 * time.Millisecond)
		b.done <- b.browse(start)
	}()
}

// wait collects the outcome of every page visit the operation started.
func (b *kcBrowser) wait(t *testing.T) {
	for ; b.pending > 0; b.pending-- {
		select {
		case err := <-b.done:
			if err != nil {
				t.Errorf("browser: %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Errorf("browser: still busy")
		}
	}
}

func attrs(s string) map[string]string {
	m := map[string]string{}
	for _, a := range attrRe.FindAllStringSubmatch(s, -1) {
		m[strings.ToLower(a[1])] = html.UnescapeString(a[2])
	}
	return m
}

func (b *kcBrowser) browse(start string) error {
	resp, err := b.client.Get(start)
	for step := 0; step < 8; step++ {
		if err != nil {
			return err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if h := resp.Request.URL.Hostname(); h == "localhost" && resp.Request.URL.Port() != "8080" || h == "127.0.0.1" {
			return nil // back at idpdbg's listener
		}
		m := formRe.FindStringSubmatch(string(body))
		if m == nil && strings.HasSuffix(resp.Request.URL.Path, "/device/status") {
			if strings.Contains(string(body), "kc-error-message") {
				return fmt.Errorf("device approval failed: %.300s", body)
			}
			return nil // "device login successful"; idpdbg is polling
		}
		if m == nil && b.loggedOut != nil && b.loggedOut(resp.Request.URL, string(body)) {
			return nil // the IdP finished a logout that went through idpdbg's listener
		}
		if m == nil {
			return fmt.Errorf("stuck at %s (HTTP %d) without a form: %.300s", resp.Request.URL, resp.StatusCode, body)
		}
		fa := attrs(m[1])
		action, err := resp.Request.URL.Parse(fa["action"])
		if err != nil {
			return err
		}
		form := url.Values{}
		for _, in := range inputRe.FindAllStringSubmatch(m[2], -1) {
			ia := attrs(in[1])
			name := ia["name"]
			switch {
			case name == "":
			case name == "username":
				form.Set(name, kcUser)
			case name == "password":
				form.Set(name, kcPass)
			case name == "device_user_code" || name == "user_code":
				form.Set(name, b.userCode)
			case ia["type"] == "submit" && name != "accept" && name != "login":
				// a second button (cancel, deny) is not pressed
			default:
				form.Set(name, ia["value"])
			}
		}
		if strings.EqualFold(fa["method"], "get") {
			action.RawQuery = form.Encode()
			resp, err = b.client.Get(action.String())
		} else {
			resp, err = b.client.PostForm(action.String(), form)
		}
	}
	return fmt.Errorf("gave up after 8 pages")
}

// kcAdminToken signs in to the master realm's admin CLI client.
func kcAdminToken(t *testing.T) string {
	t.Helper()
	resp, err := http.PostForm(kcBase()+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"}, "password": {"admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("admin token: %v (HTTP %d)", err, resp.StatusCode)
	}
	return tok.AccessToken
}

func readFixture(t *testing.T, name string) string {
	b, err := os.ReadFile("testdata/keycloak/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func pkjKey(t *testing.T) string { return readFixture(t, "pkj-client.key") }

func web(extra ...M) M {
	return merge(M{"issuer": kcIssuer(), "client_id": "idpdbg-web", "client_secret": kcSecret}, extra...)
}

func pkj(t *testing.T, extra ...M) M {
	return merge(M{"issuer": kcIssuer(), "client_id": "idpdbg-pkj", "client_auth": "private_key_jwt",
		"client_key": pkjKey(t), "client_key_id": "pkj-1", "signing_alg": "ES256"}, extra...)
}

var browserArgs = M{"open_browser": false, "wait": 60}

func TestKeycloakInterop(t *testing.T) {
	if resp, err := http.Get(kcIssuer() + "/.well-known/openid-configuration"); err != nil || resp.StatusCode != 200 {
		t.Fatalf("Keycloak not reachable at %s: %v", kcIssuer(), err)
	}

	t.Run("oidc discover", func(t *testing.T) {
		res := kcRun(t, "oidc.discover", M{"issuer": kcIssuer()}, nil)
		kcClean(t, res)
		kcWant(t, res, "jwks_uri is reachable", "pass")
	})

	t.Run("jwks fetch", func(t *testing.T) {
		kcClean(t, kcRun(t, "jwks.fetch", M{"issuer": kcIssuer()}, nil))
	})

	var idToken string
	t.Run("oidc login: code + PKCE, client secret", func(t *testing.T) {
		res := kcRun(t, "oidc.login", web(browserArgs, M{"scope": "openid profile email"}), newKCBrowser(t))
		kcClean(t, res)
		kcWant(t, res, "state matches the request", "pass")
		kcWant(t, res, "iss response parameter matches the issuer", "pass")
		kcWant(t, res, "id_token: signature", "pass")
		kcWant(t, res, "id_token: nonce matches the request", "pass")
		kcWant(t, res, "userinfo: sub matches the ID token", "pass")
		idToken = str(find(res, "token", "response", "id_token"))
	})

	t.Run("oidc login: private_key_jwt, PAR, JAR, DPoP", func(t *testing.T) {
		res := kcRun(t, "oidc.login", pkj(t, browserArgs, M{"scope": "openid", "par": true, "jar": true, "dpop": true}), newKCBrowser(t))
		kcClean(t, res)
		kcWant(t, res, "PAR: response", "pass")
		kcWant(t, res, "DPoP: token_type is DPoP", "pass")
		kcWant(t, res, "id_token: signature", "pass")
	})

	t.Run("oidc client_credentials: private_key_jwt", func(t *testing.T) {
		kcClean(t, kcRun(t, "oidc.client_credentials", pkj(t), nil))
	})

	var access, refresh string
	t.Run("oidc password", func(t *testing.T) {
		res := kcRun(t, "oidc.password", web(M{"username": kcUser, "password": kcPass, "scope": "openid profile email"}), nil)
		kcClean(t, res)
		kcWant(t, res, "resource owner password grant not used", "warn")
		access = str(find(res, "response", "access_token"))
		refresh = str(find(res, "response", "refresh_token"))
		if access == "" || refresh == "" {
			t.Fatalf("no access or refresh token in the result")
		}
	})

	t.Run("oidc refresh", func(t *testing.T) {
		res := kcRun(t, "oidc.refresh", web(M{"refresh_token": refresh}), nil)
		kcClean(t, res)
		if r := str(find(res, "response", "refresh_token")); r != "" {
			refresh = r
		}
	})

	t.Run("jwt verify", func(t *testing.T) {
		kcClean(t, kcRun(t, "jwt.verify", M{"token": access, "issuer": kcIssuer(), "audience": "idpdbg-web"}, nil))
		// The negative case: an API expecting another audience must reject it.
		kcWant(t, kcRun(t, "jwt.verify", M{"token": access, "issuer": kcIssuer(), "audience": "https://api.example.com"}, nil), "aud: contains expected audience", "fail")
	})

	t.Run("oidc introspect", func(t *testing.T) {
		res := kcRun(t, "oidc.introspect", web(M{"token": access}), nil)
		kcClean(t, res)
		kcWant(t, res, "token is active", "pass")
	})

	t.Run("oidc introspect: token for another audience", func(t *testing.T) {
		other := str(find(kcRun(t, "oidc.client_credentials", pkj(t), nil), "response", "access_token"))
		res := kcRun(t, "oidc.introspect", web(M{"token": other}), nil)
		c := checkOf(res, "token is active")
		if c == nil || c.Status != "info" || !strings.Contains(c.Detail, "does not include the introspecting client idpdbg-web") {
			t.Errorf("want an inactive result explained by the audience, got %+v", c)
		}
	})

	t.Run("oidc userinfo", func(t *testing.T) {
		kcClean(t, kcRun(t, "oidc.userinfo", M{"issuer": kcIssuer(), "access_token": access, "scope": "openid profile email"}, nil))
	})

	t.Run("oidc token_exchange", func(t *testing.T) {
		kcClean(t, kcRun(t, "oidc.token_exchange", web(M{"subject_token": access}), nil))
	})

	t.Run("oidc revoke", func(t *testing.T) {
		kcClean(t, kcRun(t, "oidc.revoke", web(M{"token": refresh, "token_type_hint": "refresh_token"}), nil))
		res := kcRun(t, "oidc.introspect", web(M{"token": refresh}), nil)
		if c := checkOf(res, "token is active"); c == nil || c.Status == "pass" {
			t.Errorf("revoked refresh token still introspects as active: %+v", c)
		}
	})

	t.Run("oidc device", func(t *testing.T) {
		res := kcRun(t, "oidc.device", web(M{"scope": "openid", "pkce": true, "wait_for_user": true, "wait": 60}), newKCBrowser(t))
		kcClean(t, res)
		if find(res, "token") == nil {
			t.Errorf("no token after the device was approved")
		}
	})

	t.Run("oidc register and register_manage", func(t *testing.T) {
		iat := kcInitialAccessToken(t)
		res := kcRun(t, "oidc.register", M{"issuer": kcIssuer(), "initial_access_token": iat,
			"metadata": M{"client_name": "idpdbg interop", "redirect_uris": []any{"http://localhost:8765/callback"}}}, nil)
		kcClean(t, res)
		uri, rat := str(find(res, "response", "registration_client_uri")), str(find(res, "response", "registration_access_token"))
		if uri == "" || rat == "" {
			t.Fatalf("registration returned no client configuration endpoint or token")
		}
		res = kcRun(t, "oidc.register_manage", M{"registration_client_uri": uri, "registration_access_token": rat}, nil)
		kcClean(t, res)
		if r := str(find(res, "response", "registration_access_token")); r != "" {
			rat = r // Keycloak rotates it on every use
		}
		kcClean(t, kcRun(t, "oidc.register_manage", M{"registration_client_uri": uri, "registration_access_token": rat, "action": "delete"}, nil))
	})

	t.Run("oidc logout", func(t *testing.T) {
		if idToken == "" {
			t.Skip("no ID token from the login")
		}
		kcClean(t, kcRun(t, "oidc.logout", merge(browserArgs, M{"issuer": kcIssuer(), "client_id": "idpdbg-web", "id_token_hint": idToken}), newKCBrowser(t)))
	})

	t.Run("oidc bcp_probe", func(t *testing.T) {
		res := kcRun(t, "oidc.bcp_probe", web(browserArgs), newKCBrowser(t))
		kcClean(t, res)
		for _, c := range []string{"redirect URI exact matching: extra path segment", "redirect URI exact matching: extra query parameter",
			"redirect URI exact matching: other host", "implicit grant refused", "sign-in page cannot be framed",
			"PKCE enforced", "PKCE downgrade refused", "authorization code works only once", "tokens from a replayed code revoked"} {
			kcWant(t, res, c, "pass")
		}
		// idpdbg-web is confidential and Keycloak keeps old refresh tokens
		// valid by default: allowed, so only info.
		kcWant(t, res, "rotated refresh token stops working", "info")
	})

	t.Run("strict: discover", func(t *testing.T) {
		// Keycloak's defaults advertise the password and implicit grants and
		// plain PKCE, so strict mode must fail them.
		res := kcRun(t, "oidc.discover", M{"issuer": kcIssuer(), "strict": true}, nil)
		kcWant(t, res, "strict mode (RFC 9700)", "fail")
		kcWant(t, res, "resource owner password grant not offered", "fail")
		kcWant(t, res, "implicit grant not offered", "fail")
		kcWant(t, res, "sender-constrained access tokens offered", "pass")
	})

	t.Run("strict: login with private_key_jwt and DPoP", func(t *testing.T) {
		// A setup that follows the BCP passes strict mode.
		res := kcRun(t, "oidc.login", pkj(t, browserArgs, M{"scope": "openid", "par": true, "dpop": true, "strict": true}), newKCBrowser(t))
		kcClean(t, res)
		kcWant(t, res, "strict mode (RFC 9700)", "pass")
		kcWant(t, res, "access token is sender-constrained", "pass")
		kcWant(t, res, "asymmetric client authentication", "pass")
	})

	fapi := func(extra ...M) M {
		// A fixed dpop_key: dpop_code_binding must still redeem with another key.
		return pkj(t, append([]M{{"client_id": "idpdbg-fapi", "par": true, "dpop": true, "fapi": true, "scope": "openid",
			"redirect_uri": "https://localhost:8765/callback", "dpop_key": readFixture(t, "dpop.key")}}, extra...)...)
	}
	t.Run("fapi: discover", func(t *testing.T) {
		res := kcRun(t, "oidc.discover", M{"issuer": kcIssuer(), "fapi": true}, nil)
		kcWant(t, res, "FAPI 2.0 Security Profile", "pass")
		kcWant(t, res, "FAPI 2.0: iss in authorization responses", "pass")
		kcWant(t, res, "FAPI 2.0: endpoints use TLS", "info") // http on loopback in CI
	})

	t.Run("fapi: login", func(t *testing.T) {
		res := kcRun(t, "oidc.login", fapi(browserArgs), newKCBrowser(t))
		for _, c := range res["checks"].(Checks) {
			if c.Status != "pass" {
				t.Logf("%s\t%s\t%s", c.Status, c.Name, c.Detail)
			}
		}
		kcClean(t, res)
		kcWant(t, res, "FAPI 2.0 Security Profile", "pass")
	})

	t.Run("fapi: bcp_probe", func(t *testing.T) {
		// Includes code_lifetime, which waits 61 seconds.
		res := kcRun(t, "oidc.bcp_probe", fapi(browserArgs, M{"wait": 120}), newKCBrowser(t))
		kcClean(t, res)
		for _, c := range []string{"FAPI 2.0: authorization request without PAR refused", "FAPI 2.0: PAR without client authentication refused",
			"FAPI 2.0: PAR without redirect_uri refused", "FAPI 2.0: code bound to the DPoP key", "FAPI 2.0: authorization code expires within 60 s",
			"PKCE downgrade refused", "sign-in page cannot be framed", "authorization code works only once", "FAPI 2.0 Security Profile", "strict mode (RFC 9700)"} {
			kcWant(t, res, c, "pass")
		}
	})

	t.Run("vci issue: authorization code flow", func(t *testing.T) {
		kcSetupVCI(t)
		// Keycloak needs the credential's scope next to authorization_details,
		// which OID4VCI does not require; idpdbg says so.
		res := kcRun(t, "vci.issue", merge(browserArgs, M{"issuer": kcIssuer(), "configuration_id": "idpdbg-employee", "client_id": "idpdbg-wallet",
			"request_by": "authorization_details"}), newKCBrowser(t))
		kcWant(t, res, "token response", "fail")
		kcWant(t, res, "credential scope alongside authorization_details", "info")
		for _, by := range []string{"both", "scope"} {
			res := kcRun(t, "vci.issue", merge(browserArgs, M{"issuer": kcIssuer(), "configuration_id": "idpdbg-employee", "client_id": "idpdbg-wallet",
				"request_by": by, "par": by == "scope"}), newKCBrowser(t))
			kcClean(t, res)
			for _, c := range []string{"state matches the request", "authorization code returned", "nonce from the nonce endpoint", "credential issued",
				"credential 1: issuer signature", "credential 1: bound to the holder key", "credential 1: vct"} {
				kcWant(t, res, c, "pass")
			}
			if by == "both" {
				kcWant(t, res, "token response names the credential", "pass")
			}
			claims := fmt.Sprint(find(res, "credential_1", "claims"))
			if !strings.Contains(claims, "alice@example.com") || !strings.Contains(claims, "Interop") {
				t.Errorf("%s: credential claims: %s", by, claims)
			}
		}
	})

	samlMeta := kcIssuer() + "/protocol/saml/descriptor"
	t.Run("saml metadata", func(t *testing.T) {
		kcClean(t, kcRun(t, "saml.metadata", M{"idp_metadata": samlMeta}, nil))
	})

	var nameID, sessionIndex string
	t.Run("saml login", func(t *testing.T) {
		res := kcRun(t, "saml.login", merge(browserArgs, M{"idp_metadata": samlMeta}), newKCBrowser(t))
		kcClean(t, res)
		kcWant(t, res, "response: status is Success", "pass")
		kcWant(t, res, "every assertion is covered by a trusted signature", "pass")
		nameID = str(find(res, "name_id", "value"))
		sessionIndex = str(find(res, "authn_statement", "session_index"))
	})

	t.Run("saml login: signed request, encrypted assertion", func(t *testing.T) {
		key, crt := readFixture(t, "sp.key"), readFixture(t, "sp.crt")
		res := kcRun(t, "saml.login", merge(browserArgs, M{"idp_metadata": samlMeta, "sp_entity_id": "idpdbg-signed",
			"sign": true, "sp_key": key, "sp_cert": crt}), newKCBrowser(t))
		kcClean(t, res)
		kcWant(t, res, "response: status is Success", "pass")
		kcWant(t, res, "every assertion is covered by a trusted signature", "pass")
		if find(res, "EncryptedAssertion") == nil && !strings.Contains(fmt.Sprint(res["checks"]), "ncrypt") {
			t.Errorf("no sign of the encrypted assertion in the result")
		}
		n, si := str(find(res, "name_id", "value")), str(find(res, "authn_statement", "session_index"))
		if n == "" {
			t.Fatalf("no NameID: the assertion was not decrypted")
		}
		res = kcRun(t, "saml.logout", merge(browserArgs, M{"idp_metadata": samlMeta, "sp_entity_id": "idpdbg-signed",
			"sign": true, "sp_key": key, "sp_cert": crt, "name_id": n,
			"name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", "session_index": si}), newKCBrowser(t))
		kcClean(t, res)
		kcWant(t, res, "LogoutRequest signed", "pass")
	})

	t.Run("saml idp-initiated logout", func(t *testing.T) {
		b := newKCBrowser(t) // one browser: the logout ends the session the login started
		res := kcRun(t, "saml.login", merge(browserArgs, M{"idp_metadata": samlMeta}), b)
		kcClean(t, res)
		n, si := str(find(res, "name_id", "value")), str(find(res, "authn_statement", "session_index"))
		if sid, _, _ := strings.Cut(si, "::"); !kcUserSessionExists(t, sid) {
			t.Fatalf("no Keycloak session %q after the login", sid)
		}
		b.loggedOut = func(u *url.URL, body string) bool {
			return strings.Contains(u.Path, "/logout") || strings.Contains(body, "logged out")
		}
		res = kcRun(t, "saml.idp_logout", merge(browserArgs, M{"idp_metadata": samlMeta, "start_url": kcIssuer() + "/protocol/openid-connect/logout",
			"name_id": n, "session_index": si}), b)
		kcClean(t, res)
		for _, c := range []string{"redirect binding signature", "LogoutRequest signed", "LogoutRequest: Issuer", "LogoutRequest: Destination",
			"LogoutRequest names the expected NameID", "LogoutRequest names the expected session", "LogoutResponse sent"} {
			kcWant(t, res, c, "pass")
		}
		b.wait(t)
		// Keycloak's SessionIndex begins with its user session ID; that
		// session must be gone now.
		sid, _, _ := strings.Cut(si, "::")
		if sid == "" || kcUserSessionExists(t, sid) {
			t.Errorf("Keycloak session %q survived the logout", sid)
		}
	})

	t.Run("saml logout", func(t *testing.T) {
		if nameID == "" {
			t.Skip("no NameID from the login")
		}
		kcClean(t, kcRun(t, "saml.logout", merge(browserArgs, M{"idp_metadata": samlMeta, "name_id": nameID,
			"name_id_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", "session_index": sessionIndex}), newKCBrowser(t)))
	})
}

// kcUserSessionExists asks the admin API whether the test user still has
// the user session sid.
func kcUserSessionExists(t *testing.T, sid string) bool {
	t.Helper()
	get := func(path string, v any) {
		req, _ := http.NewRequest("GET", kcBase()+"/admin/realms/"+kcRealm+path, nil)
		req.Header.Set("Authorization", "Bearer "+kcAdminToken(t))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	var users []struct{ ID string }
	get("/users?exact=true&username="+url.QueryEscape(kcUser), &users)
	if len(users) != 1 {
		t.Fatalf("user %s: %v", kcUser, users)
	}
	var sessions []struct{ ID string }
	get("/users/"+users[0].ID+"/sessions", &sessions)
	for _, s := range sessions {
		if s.ID == sid {
			return true
		}
	}
	return false
}

// kcSetupVCI makes the realm an OID4VCI issuer (once): VCI enabled, an
// ES256 key with a CA-issued certificate (Keycloak follows HAIP, which wants
// an x5c chain and no self-signed signer; the keystore is mounted in the
// realm directory by scripts/keycloak.sh), the idpdbg-employee SD-JWT VC
// scope, the public client idpdbg-wallet, and the credential granted to
// alice. Done through the admin API: a clientScopes list in the realm file
// would replace Keycloak's default scopes.
func kcSetupVCI(t *testing.T) {
	t.Helper()
	tok := kcAdminToken(t)
	call := func(method, path, body string) (int, []byte) {
		req, _ := http.NewRequest(method, kcBase()+"/admin/realms/"+kcRealm+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	must := func(method, path, body string, ok ...int) []byte {
		code, b := call(method, path, body)
		for _, c := range ok {
			if code == c {
				return b
			}
		}
		t.Fatalf("%s %s: HTTP %d %s", method, path, code, b)
		return nil
	}
	if _, b := call("GET", "/clients?clientId=idpdbg-wallet", ""); strings.Contains(string(b), "idpdbg-wallet") {
		return // set up by an earlier run against this container
	}
	must("PUT", "", `{"verifiableCredentialsEnabled":true}`, 204)
	var realm struct{ ID string }
	json.Unmarshal(must("GET", "", "", 200), &realm)
	must("POST", "/components", `{"name":"vc-issuer","providerId":"java-keystore","providerType":"org.keycloak.keys.KeyProvider","parentId":"`+realm.ID+`",`+
		`"config":{"keystore":["/opt/keycloak/data/idpdbg/vc-issuer.p12"],"keystorePassword":["idpdbg-interop"],"keyAlias":["vc-issuer"],"keyPassword":["idpdbg-interop"],`+
		`"keystoreType":["PKCS12"],"algorithm":["ES256"],"priority":["300"],"active":["true"],"enabled":["true"]}}`, 201)
	mapper := func(claim, attr string) string {
		return `{"name":"` + claim + `","protocol":"oid4vc","protocolMapper":"oid4vc-user-attribute-mapper","config":{"claim.name":"` + claim + `","userAttribute":"` + attr + `"}}`
	}
	must("POST", "/client-scopes", `{"name":"idpdbg-employee","protocol":"oid4vc","attributes":{"vc.format":"dc+sd-jwt","vc.verifiable_credential_type":"https://idpdbg.example/employee",`+
		`"vc.credential_signing_alg":"ES256","vc.credential_build_config.token_jws_type":"dc+sd-jwt","vc.cryptographic_binding_methods_supported":"jwk",`+
		`"vc.binding_required":"true","vc.binding_required_proof_types":"jwt","include.in.token.scope":"true"},"protocolMappers":[`+
		mapper("given_name", "firstName")+","+mapper("family_name", "lastName")+","+mapper("email", "email")+`]}`, 201)
	must("POST", "/clients", `{"clientId":"idpdbg-wallet","publicClient":true,"standardFlowEnabled":true,"directAccessGrantsEnabled":false,`+
		`"redirectUris":["http://localhost:8765/*"],"attributes":{"pkce.code.challenge.method":"S256","oid4vci.enabled":"true"},"optionalClientScopes":["idpdbg-employee"]}`, 201)
	var users []struct{ ID string }
	json.Unmarshal(must("GET", "/users?exact=true&username="+kcUser, "", 200), &users)
	if len(users) != 1 {
		t.Fatalf("user %s not found", kcUser)
	}
	must("POST", "/users/"+users[0].ID+"/vc/credentials", `{"credentialScopeName":"idpdbg-employee"}`, 200, 201)
}

// kcInitialAccessToken asks the admin API for a one-use initial access
// token for dynamic client registration.
func kcInitialAccessToken(t *testing.T) string {
	t.Helper()
	req, _ := http.NewRequest("POST", kcBase()+"/admin/realms/"+kcRealm+"/clients-initial-access", strings.NewReader(`{"expiration":600,"count":1}`))
	req.Header.Set("Authorization", "Bearer "+kcAdminToken(t))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Token == "" {
		t.Fatalf("initial access token: %v (HTTP %d)", err, resp.StatusCode)
	}
	return out.Token
}
