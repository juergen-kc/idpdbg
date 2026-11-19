package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestReport(t *testing.T) {
	op := findOp("oidc.login")
	var top, token Checks
	top.add("state matches the request", "pass", "", "RFC 6749 §10.12")
	top.add("iss response parameter matches the issuer", "warn", "<script>alert(1)</script>", "RFC 9207")
	token.add("id_token: signature", "fail", "bad signature", "OIDC Core §3.1.3.7")
	res := M{
		"checks":     top,
		"token":      M{"checks": token, "response": M{"access_token": "at"}},
		"http_trace": []*Exchange{{Method: "POST", URL: "https://idp.example/token", Status: 200}},
	}
	args := M{"issuer": "https://idp.example", "client_id": "cli", "client_secret": "s3cret-value", "client_key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}
	b, err := renderReport(op, args, res, nil, 2, time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	for _, want := range []string{
		"idpdbg oidc login", "1 fail", "1 warn", "1 pass", "exit 2: a check failed",
		"<h2>Needs attention</h2>", "<h2>Result</h2>", "<h2>token</h2>",
		"POST https://idp.example/token → 200", "&lt;script&gt;alert(1)&lt;/script&gt;",
		"https://idp.example", "(not shown: may hold credentials)",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	for _, leak := range []string{"<script>alert", "s3cret-value", "BEGIN PRIVATE KEY"} {
		if strings.Contains(page, leak) {
			t.Errorf("report contains %q", leak)
		}
	}
	// The failure comes before the warning in Needs attention, and says
	// which step it is from.
	att := page[strings.Index(page, "Needs attention"):strings.Index(page, "<h2>Result</h2>")]
	if f, w := strings.Index(att, "id_token: signature"), strings.Index(att, "iss response parameter"); f < 0 || w < 0 || f > w {
		t.Errorf("Needs attention order: fail at %d, warn at %d", f, w)
	}
	if !strings.Contains(att, ">token</td>") {
		t.Errorf("Needs attention does not name the step")
	}
}

func TestReportOfAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.html")
	if err := writeReport(path, findOp("oidc.discover"), M{"issuer": "https://x"}, nil, errors.New("connection refused"), 1); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "connection refused") || !strings.Contains(string(b), "exit 1: the run did not complete") {
		t.Errorf("error report: %s", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("report is readable by others: %v", fi.Mode())
	}
}

func TestCutReportFlag(t *testing.T) {
	path, rest, err := cutReportFlag([]string{"--issuer", "x", "--report", "out.html", "--trace"})
	if err != nil || path != "out.html" || strings.Join(rest, " ") != "--issuer x --trace" {
		t.Errorf("got %q %q %v", path, rest, err)
	}
	if path, _, _ := cutReportFlag([]string{"--report=r.html"}); path != "r.html" {
		t.Errorf("--report=: %q", path)
	}
	if _, _, err := cutReportFlag([]string{"--report"}); err == nil {
		t.Errorf("--report without a file name accepted")
	}
	// Not an operation parameter: MCP callers cannot write files with it.
	for _, op := range registry {
		for _, p := range op.allParams() {
			if p.Name == "report" {
				t.Errorf("%s has a report parameter", op.Name)
			}
		}
	}
}

func TestReportHidesCredentialLikeParameters(t *testing.T) {
	op := findOp("scim.request")
	args := M{"base_url": "https://scim.example", "headers": M{"Authorization": "Basic c2VjcmV0"}, "body": M{"password": "hunter2"}, "path": "/Users"}
	b, err := renderReport(op, args, M{}, nil, 0, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"c2VjcmV0", "hunter2"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("report shows %q", leak)
		}
	}
	if !strings.Contains(string(b), "https://scim.example") || !strings.Contains(string(b), "/Users") {
		t.Errorf("harmless parameters are missing")
	}
	// Every parameter of every operation: only the allow-listed strings,
	// booleans and numbers are shown, and never a secret.
	shown := map[string]bool{}
	for _, op := range registry {
		for _, p := range op.allParams() {
			if reportShows(p) {
				shown[p.Name] = true
				if p.Secret || p.Explicit {
					t.Errorf("%s: secret parameter %s would be shown", op.Name, p.Name)
				}
			}
		}
	}
	for _, name := range []string{"access_token", "subject_token", "keytab", "service_keytab", "headers", "jwks", "client_key",
		"pin", "artifact", "otp", "private_id", "extra", "input", "payload", "request", "response", "signature", "svid",
		"wresult", "interact_ref", "value", "body", "code", "token"} {
		if shown[name] {
			t.Errorf("%s would be shown", name)
		}
	}
	for _, name := range []string{"issuer", "client_id", "base_url", "spn", "scope", "url", "filter", "trace", "timeout"} {
		if !shown[name] {
			t.Errorf("%s is hidden", name)
		}
	}
}

func TestWriteReportReplacesFileAndLink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.html")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.txt")
	os.WriteFile(target, []byte("keep me"), 0o644)
	link := filepath.Join(dir, "link.html")
	if err := os.Symlink(target, link); err != nil {
		t.Skip("no symlinks here")
	}
	op := findOp("oidc.discover")
	for _, p := range []string{path, link} {
		if err := writeReport(p, op, M{"issuer": "https://x"}, M{}, nil, 0); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Lstat(p)
		if fi.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, want a regular 0600 file", p, fi.Mode())
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "keep me" {
		t.Errorf("the link's target was overwritten")
	}
}
