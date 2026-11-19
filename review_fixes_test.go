package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestJudgePAR(t *testing.T) {
	p := &bcpProbe{c: &Ctx{Context: context.Background(), Args: M{}}, report: M{}}
	p.judgePAR("a", "a", 200, M{"request_uri": "urn:x"}, "accepted")
	p.judgePAR("b", "b", 401, M{"error": "invalid_client"}, "accepted")
	p.judgePAR("c", "c", 500, M{}, "accepted")
	p.judgePAR("d", "d", 201, M{}, "accepted")
	want := map[string]string{"a": "fail", "b": "pass", "c": "info", "d": "fail"}
	for _, c := range p.cs {
		if c.Status != want[c.Name] {
			t.Errorf("%s: %s (%s), want %s", c.Name, c.Status, c.Detail, want[c.Name])
		}
	}
}

func TestRestrictsFraming(t *testing.T) {
	for d, want := range map[string]bool{
		"frame-ancestors 'none'":                 true,
		"frame-ancestors 'self'":                 true,
		"frame-ancestors https://app.example":    true,
		"frame-ancestors *":                      false,
		"frame-ancestors https:":                 false,
		"frame-ancestors 'self' *.example.com":   false,
		"frame-ancestors":                        false,
		"frame-ancestors 'self' https://*.x.com": false,
	} {
		if got := restrictsFraming(d); got != want {
			t.Errorf("%q: %v, want %v", d, got, want)
		}
	}
}

// The callback listener takes only a response with this run's state, so a
// forged request can neither end the run nor plant a result.
func TestCaptureRedirectIgnoresForeignState(t *testing.T) {
	port := freePort(t)
	c := &Ctx{Context: context.Background(), Args: M{"wait": 5, "open_browser": false}, Log: func(string, ...any) {}}
	cb := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	go func() {
		time.Sleep(100 * time.Millisecond)
		resp, err := http.PostForm(cb, url.Values{"code": {"forged"}, "state": {"wrong"}})
		if err == nil {
			if resp.StatusCode != 400 {
				t.Errorf("forged response: HTTP %d, want 400", resp.StatusCode)
			}
			resp.Body.Close()
		}
		resp, err = http.Get(cb + "?code=real&state=good")
		if err == nil {
			resp.Body.Close()
		}
	}()
	vals, err := captureRedirectScheme(c, "http://unused.example/", port, "/callback", "http", "good")
	if err != nil {
		t.Fatal(err)
	}
	if vals.Get("code") != "real" {
		t.Errorf("got code %q, want the real one", vals.Get("code"))
	}
}

func TestLoginRedirectMustBeLoopback(t *testing.T) {
	c := &Ctx{Args: M{"redirect_uri": "https://app.example/cb", "redirect_port": 8765, "redirect_path": "/callback"}}
	if _, _, _, err := loginRedirect(c); err == nil || !strings.Contains(err.Error(), "does not point at this machine") {
		t.Errorf("remote redirect_uri: %v", err)
	}
	c.Args["redirect_uri"] = "https://localhost/callback"
	if _, port, _, err := loginRedirect(c); err != nil || port != 443 {
		t.Errorf("https without a port: port %d, err %v; want 443", port, err)
	}
}

// Another process holding [::1]:port would get the browser's redirect.
func TestLoopbackRefusesIPv6Squatter(t *testing.T) {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback here")
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	stop, err := serveLoopback(port, http.NewServeMux())
	if err == nil {
		stop()
		t.Fatalf("listened although [::1]:%d is taken", port)
	}
	if !strings.Contains(err.Error(), "in use by another process") {
		t.Errorf("error: %v", err)
	}
}
