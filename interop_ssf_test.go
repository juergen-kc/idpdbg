//go:build interop

// Interop tests against a real Shared Signals transmitter, run by the
// "interop" CI jobs: SSFgo's conformance transmitter, an independent SSF 1.0
// and CAEP implementation that passes the OpenID Foundation's CAEP
// Interoperability Profile plans. Locally:
//
//	scripts/ssf.sh
//	go test -tags interop -run SSF -v .
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var ssfDir = smbEnv("IDPDBG_SSF_DIR", "testdata/ssf/run")

const (
	ssfIssuer   = "https://localhost:18443/ssfgo"
	ssfAudience = "ssf-test-client" // the audience SSFgo gives the streams of this client
)

func TestSSFInterop(t *testing.T) {
	ca, err := os.ReadFile(filepath.Join(ssfDir, "ca.pem"))
	if err != nil {
		t.Fatalf("%v (run scripts/ssf.sh)", err)
	}
	token, _ := os.ReadFile(filepath.Join(ssfDir, "token"))
	base := M{"issuer": ssfIssuer, "ca_cert": string(ca), "ssf_token": strings.TrimSpace(string(token))}
	interopEvents := []string{caepBase + "session-revoked", caepBase + "credential-change", caepBase + "device-compliance-change"}

	t.Run("ssf discover: an issuer with a path, SSF 1.0 final", func(t *testing.T) {
		res := kcRun(t, "ssf.discover", M{"issuer": base["issuer"], "ca_cert": base["ca_cert"]}, nil)
		kcClean(t, res)
		kcWant(t, res, "spec_version", "pass")
		if res["metadata_url"] != "https://localhost:18443/.well-known/ssf-configuration/ssfgo" {
			t.Errorf("metadata URL: %v", res["metadata_url"])
		}
	})

	t.Run("ssf poll stream: verification, three CAEP events, ack", func(t *testing.T) {
		created := kcRun(t, "ssf.stream", merge(base, M{"action": "create", "delivery": "poll", "events": interopEvents}), nil)
		kcClean(t, created)
		sid := str(created["response"].(map[string]any)["stream_id"])
		defer kcRun(t, "ssf.stream", merge(base, M{"action": "delete", "stream_id": sid}), nil)

		kcClean(t, kcRun(t, "ssf.stream", merge(base, M{"action": "verify", "stream_id": sid}), nil))
		var polled M
		for i := 0; i < 10; i++ { // the events follow two seconds after verification
			time.Sleep(time.Second)
			polled = kcRun(t, "ssf.poll", merge(base, M{"stream_id": sid, "audience": ssfAudience}), nil)
			if len(polled["jtis"].([]string)) >= 4 {
				break
			}
		}
		kcClean(t, polled)
		types := map[string]bool{}
		for _, s := range polled["sets"].([]M) {
			if d, ok := s["set"].(M); ok {
				for _, ty := range d["event_types"].([]string) {
					types[ty] = true
				}
			}
		}
		for _, want := range append(interopEvents, ssfEvBase+"verification") {
			if !types[want] {
				t.Errorf("no %s event among %v", want, types)
			}
		}
		after := kcRun(t, "ssf.poll", merge(base, M{"stream_id": sid, "audience": ssfAudience, "ack": polled["jtis"]}), nil)
		if again := kcRun(t, "ssf.poll", merge(base, M{"stream_id": sid, "audience": ssfAudience}), nil); len(again["jtis"].([]string)) != 0 {
			t.Errorf("acknowledged SETs delivered again: %v (ack answer %v)", again["jtis"], after["jtis"])
		}

		// A receiver with another audience rejects every SET.
		kcRun(t, "ssf.stream", merge(base, M{"action": "verify", "stream_id": sid}), nil)
		time.Sleep(3 * time.Second)
		other := kcRun(t, "ssf.poll", merge(base, M{"stream_id": sid, "audience": "https://not-this-receiver.example"}), nil)
		fails := 0
		for _, c := range other["checks"].(Checks) {
			if strings.HasSuffix(c.Name, "aud includes this receiver") && c.Status == "fail" {
				fails++
			}
		}
		if fails == 0 {
			t.Error("SETs for another audience were accepted")
		}
	})

	t.Run("ssf stream management", func(t *testing.T) {
		created := kcRun(t, "ssf.stream", merge(base, M{"action": "create", "delivery": "poll", "events": interopEvents}), nil)
		sid := str(created["response"].(map[string]any)["stream_id"])
		for _, a := range []M{
			{"action": "get"},
			{"action": "status"},
			{"action": "set_status", "status": "paused", "reason": "idpdbg interop"},
			{"action": "set_status", "status": "enabled"},
			{"action": "add_subject", "subject": map[string]any{"format": "email", "email": "alice@example.com"}},
			{"action": "remove_subject", "subject": map[string]any{"format": "email", "email": "alice@example.com"}},
		} {
			res := kcRun(t, "ssf.stream", merge(base, M{"stream_id": sid}, a), nil)
			kcClean(t, res)
		}
		kcWant(t, kcRun(t, "ssf.stream", merge(base, M{"stream_id": sid, "action": "get", "ssf_token": "wrong"}), nil), "transmitter accepted the request", "fail")
		kcClean(t, kcRun(t, "ssf.stream", merge(base, M{"stream_id": sid, "action": "delete"}), nil))
		kcWant(t, kcRun(t, "ssf.stream", merge(base, M{"stream_id": sid, "action": "get"}), nil), "transmitter accepted the request", "fail")
	})

	t.Run("ssf push over TLS, with the transmitter's own verification", func(t *testing.T) {
		port := freePort(t)
		created := kcRun(t, "ssf.stream", merge(base, M{"action": "create", "delivery": "push", "events": interopEvents,
			"endpoint_url": fmt.Sprintf("https://localhost:%d/ssf/events", port), "push_authorization": "Bearer idpdbg-push"}), nil)
		kcClean(t, created)
		kcWant(t, created, "push endpoint_url uses https", "pass")
		sid := str(created["response"].(map[string]any)["stream_id"])
		defer kcRun(t, "ssf.stream", merge(base, M{"action": "delete", "stream_id": sid}), nil)
		res := kcRun(t, "ssf.receive", merge(base, M{"stream_id": sid, "trigger_verification": true, "port": port,
			"expected_authorization": "Bearer idpdbg-push", "audience": ssfAudience, "max_events": 5, "wait": 20}), nil)
		kcClean(t, res)
		kcWant(t, res, "our verification event arrived", "pass")
		if n := len(res["received"].([]M)); n < 4 {
			t.Errorf("%d SETs pushed", n)
		}
	})
}
