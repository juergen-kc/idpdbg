package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/beevik/etree"
)

// A discovery document must not redirect a stored client secret to a host
// the profile doesn't name.
func TestMetadataEndpointsAreGuarded(t *testing.T) {
	var evilHits atomic.Int32
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { evilHits.Add(1) }))
	defer evil.Close()
	var op *httptest.Server
	op = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(M{"issuer": op.URL, "token_endpoint": evil.URL + "/token"})
	}))
	defer op.Close()
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "")
	t.Setenv("IDPDBG_CONFIG", t.TempDir()+"/config.json")
	cfg := `{"profiles":{"op":{"issuer":"` + op.URL + `","client_id":"c","client_secret":"stored-secret"}}}`
	if err := os.WriteFile(configPath(), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cli := range []bool{true, false} {
		_, err := runOp(context.Background(), findOp("oidc.client_credentials"), M{"profile": "op"}, cli, nil)
		if err == nil || !strings.Contains(err.Error(), "token_endpoint from the provider's metadata") {
			t.Errorf("cli=%v: want a refusal, got %v", cli, err)
		}
	}
	if n := evilHits.Load(); n != 0 {
		t.Errorf("the other host received %d request(s)", n)
	}
}

func TestLocalhostKeyResponseStaysLocal(t *testing.T) {
	c := &Ctx{Context: context.Background(), Args: M{}}
	var cs Checks
	_, err := hwOriginGuard(c, &cs, &rpAPI{kind: "custom", resultURL: "https://evil.example/r"}, "http://localhost:3000", "localhost")
	if err == nil || !strings.Contains(err.Error(), "stays on this machine") {
		t.Errorf("remote destination for a localhost RP over MCP: %v", err)
	}
	if _, err := hwOriginGuard(c, &cs, &rpAPI{kind: "custom", resultURL: "http://localhost:3000/r", optionsURL: "http://localhost:3000/o"}, "http://localhost:3000", "localhost"); err != nil {
		t.Errorf("local destination refused: %v", err)
	}
}

func TestWithheldKeyResponseHidesTheAnswer(t *testing.T) {
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "account-session"})
		w.Write([]byte(`{"status":"ok","session_token":"account-token"}`))
	}))
	defer rp.Close()
	c := &Ctx{Context: context.Background(), Args: M{"timeout": 5}}
	c.Rec = newRecorder(nil)
	out := M{}
	withholdSigned(c, out, M{"id": "x", "type": "public-key", "response": M{"signature": "sig"}}, true)
	res, err := c.do("POST", rp.URL, nil, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	shown, _ := json.Marshal(M{"server_response": serverResponse(out, res), "trace": c.Rec.Items})
	for _, leak := range []string{"account-session", "account-token"} {
		if strings.Contains(string(shown), leak) {
			t.Errorf("%q reached the result or trace: %s", leak, shown)
		}
	}
}

func TestSAMLTextReadsPastComments(t *testing.T) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(`<Assertion><Subject><NameID>admin@example.com<!---->.evil.com</NameID></Subject></Assertion>`); err != nil {
		t.Fatal(err)
	}
	a := doc.Root()
	nid := kid(a, "Subject", "NameID")
	if got := text(nid); got != "admin@example.com.evil.com" {
		t.Errorf("text = %q, want the whole signed value", got)
	}
	var cs Checks
	out := describeAssertion(&cs, a, &samlExpect{})
	if v := out["name_id"].(M)["value"]; v != "admin@example.com.evil.com" {
		t.Errorf("name_id = %v", v)
	}
	if c := checkOf(M{"checks": cs}, "NameID free of XML comments"); c == nil || c.Status != "warn" {
		t.Errorf("want a warning about the comment, got %+v", c)
	}
}
