package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// URLs a server supplies are held to public addresses unless the caller
// itself pointed idpdbg at a non-public one or allows private URLs.
func TestServerNamedURLPolicy(t *testing.T) {
	policy := func(op string, args M) func(*url.URL) bool {
		t.Helper()
		o := findOp(op)
		full, _, _, err := prepareGuarded(o, args, true)
		if err != nil {
			t.Fatal(err)
		}
		return serverNamedPolicy(&Ctx{Context: context.Background(), Op: o, Args: full})
	}
	u := func(s string) *url.URL { p, _ := url.Parse(s); return p }

	// A public issuer (a literal, so no DNS is needed): its own origin is the
	// caller's, everything else must be public.
	p := policy("oidc.discover", M{"issuer": "https://1.1.1.1/realms/x"})
	if p == nil {
		t.Fatal("no policy for a public issuer")
	}
	for s, want := range map[string]bool{
		"https://1.1.1.1/realms/x/protocol/openid-connect/certs": false, // the caller's origin
		"https://1.1.1.1:8443/jwks":                              true,  // another port is another origin
		"http://127.0.0.1:8080/jwks":                             true,
		"http://169.254.169.254/latest/meta-data/":               true,
	} {
		if got := p(u(s)); got != want {
			t.Errorf("server-named(%s) = %v, want %v", s, got, want)
		}
	}
	// An issuer on a private address: its metadata may name private URLs.
	if p := policy("oidc.discover", M{"issuer": "http://127.0.0.1:8080/realms/x"}); p == nil || p(u("http://10.0.0.5/jwks")) {
		t.Error("a private issuer's metadata was held to public addresses")
	}
	// allow_private_urls lifts it; with no URL from the caller there is none.
	if policy("oidc.discover", M{"issuer": "https://1.1.1.1", "allow_private_urls": true}) != nil {
		t.Error("allow_private_urls did not lift the policy")
	}
	if policy("jwt.decode", M{"token": "a.b.c"}) != nil {
		t.Error("a policy without any caller URL")
	}
	// Defaults and idpdbg's own listeners are not the caller's choice.
	if p := policy("oidc.login", M{"issuer": "https://1.1.1.1", "client_id": "c"}); p == nil || !p(u("http://localhost:8765/callback")) {
		t.Error("the default redirect_uri counted as a caller URL")
	}
}

func TestRecorderHoldsServerNamedURLsPublic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("{}")) }))
	defer srv.Close()
	c := &Ctx{Context: context.Background(), Args: M{"timeout": 5}}
	tc, err := baseTLSConfig(false, "")
	if err != nil {
		t.Fatal(err)
	}
	c.Rec = newRecorder(tc)
	c.Rec.serverNamed = func(u *url.URL) bool { return u.Path == "/from-metadata" }
	if _, err := c.do("GET", srv.URL+"/explicit", nil, nil); err != nil {
		t.Errorf("a caller URL was refused: %v", err)
	}
	_, err = c.do("GET", srv.URL+"/from-metadata", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Errorf("a server-named loopback URL was fetched: %v", err)
	}
}
