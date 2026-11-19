package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type mockTransmitter struct {
	*httptest.Server
	key     *ecdsa.PrivateKey
	mu      sync.Mutex
	streams map[string]M
	queues  map[string]map[string]string // stream -> jti -> SET
	n       int
}

func (tr *mockTransmitter) set(t *testing.T, events M, extra M) (string, string) {
	tr.n++
	jti := fmt.Sprintf("jti-%d", tr.n)
	cl := M{"iss": tr.URL, "aud": "https://receiver.example", "iat": time.Now().Unix(), "jti": jti, "events": events}
	for k, v := range extra {
		cl[k] = v
	}
	tok, err := signJWS(tr.key, "ES256", M{"typ": "secevent+jwt", "kid": "t1"}, cl)
	if err != nil {
		t.Fatal(err)
	}
	return jti, tok
}

func newMockTransmitter(t *testing.T) *mockTransmitter {
	tr := &mockTransmitter{streams: map[string]M{}, queues: map[string]map[string]string{}}
	tr.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mux := http.NewServeMux()
	tr.Server = httptest.NewServer(mux)
	t.Cleanup(tr.Close)
	jsonOut := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		if v != nil {
			json.NewEncoder(w).Encode(v)
		}
	}
	supported := []string{caepBase + "session-revoked", caepBase + "credential-change", riscBase + "account-disabled"}
	mux.HandleFunc("/.well-known/ssf-configuration", func(w http.ResponseWriter, _ *http.Request) {
		jsonOut(w, 200, M{"spec_version": "1_0", "issuer": tr.URL, "jwks_uri": tr.URL + "/jwks", "delivery_methods_supported": []string{ssfPush, ssfPoll},
			"configuration_endpoint": tr.URL + "/streams", "status_endpoint": tr.URL + "/status", "add_subject_endpoint": tr.URL + "/subjects:add",
			"remove_subject_endpoint": tr.URL + "/subjects:remove", "verification_endpoint": tr.URL + "/verify"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		k, _ := publicJWK(tr.key.Public())
		k["kid"] = "t1"
		jsonOut(w, 200, M{"keys": []M{k}})
	})
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer mgmt" {
			jsonOut(w, 401, M{"err": "unauthorized"})
			return false
		}
		return true
	}
	mux.HandleFunc("/streams", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		tr.mu.Lock()
		defer tr.mu.Unlock()
		switch r.Method {
		case "POST":
			var req M
			json.NewDecoder(r.Body).Decode(&req)
			id := fmt.Sprintf("s%d", len(tr.streams)+1)
			var delivered []string
			for _, e := range req["events_requested"].([]any) {
				if contains(supported, str(e)) {
					delivered = append(delivered, str(e))
				}
			}
			d := req["delivery"].(map[string]any)
			if str(d["method"]) == ssfPoll {
				d["endpoint_url"] = tr.URL + "/poll/" + id
			}
			s := M{"stream_id": id, "iss": tr.URL, "aud": "https://receiver.example", "events_supported": supported,
				"events_requested": req["events_requested"], "events_delivered": delivered, "delivery": d}
			tr.streams[id], tr.queues[id] = s, map[string]string{}
			// A real event for the stream to deliver.
			jti, tok := tr.set(t, M{caepBase + "session-revoked": M{"event_timestamp": time.Now().Unix()}}, M{"sub_id": M{"format": "email", "email": "alice@example.com"}})
			tr.queues[id][jti] = tok
			jsonOut(w, 201, s)
		case "GET":
			jsonOut(w, 200, tr.streams[r.URL.Query().Get("stream_id")])
		case "DELETE":
			delete(tr.streams, r.URL.Query().Get("stream_id"))
			jsonOut(w, 204, nil)
		}
	})
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		var req M
		json.NewDecoder(r.Body).Decode(&req)
		tr.mu.Lock()
		s := tr.streams[str(req["stream_id"])]
		jti, tok := tr.set(t, M{ssfEvBase + "verification": M{"state": req["state"]}}, nil)
		d := s["delivery"].(map[string]any)
		if str(d["method"]) == ssfPoll {
			tr.queues[str(req["stream_id"])][jti] = tok
		}
		tr.mu.Unlock()
		w.WriteHeader(204)
		if str(d["method"]) == ssfPush {
			go func() {
				time.Sleep(50 * time.Millisecond)
				pr, _ := http.NewRequest("POST", str(d["endpoint_url"]), bytes.NewBufferString(tok))
				pr.Header.Set("Content-Type", "application/secevent+jwt")
				pr.Header.Set("Authorization", str(d["authorization_header"]))
				if resp, err := http.DefaultClient.Do(pr); err == nil {
					resp.Body.Close()
				}
			}()
		}
	})
	mux.HandleFunc("/poll/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(w, r) {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/poll/")
		var req struct {
			MaxEvents int      `json:"maxEvents"`
			Ack       []string `json:"ack"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		tr.mu.Lock()
		defer tr.mu.Unlock()
		for _, a := range req.Ack {
			delete(tr.queues[id], a)
		}
		jsonOut(w, 200, M{"sets": tr.queues[id], "moreAvailable": false})
	})
	return tr
}

func TestSSF(t *testing.T) {
	tr := newMockTransmitter(t)
	base := M{"issuer": tr.URL, "ssf_token": "mgmt"}
	with := func(extra M) M {
		out := M{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	noFailures(t, run(t, "ssf.discover", M{"issuer": tr.URL}, nil))

	t.Run("poll stream", func(t *testing.T) {
		created := run(t, "ssf.stream", with(M{"action": "create", "delivery": "poll", "events": []string{caepBase + "session-revoked", caepBase + "credential-change", caepBase + "risk-level-change"}}), nil)
		wantStatus(t, created, "requested event delivered", "warn") // risk-level-change is not supported
		for _, n := range []string{"stream_id returned", "stream iss", "poll endpoint_url", "transmitter accepted"} {
			wantStatus(t, created, n, "pass")
		}
		sid := str(created["response"].(map[string]any)["stream_id"])
		noFailures(t, run(t, "ssf.stream", with(M{"action": "verify", "stream_id": sid}), nil))
		polled := run(t, "ssf.poll", with(M{"stream_id": sid, "audience": "https://receiver.example"}), nil)
		noFailures(t, polled)
		jtis := polled["jtis"].([]string)
		if len(jtis) != 2 {
			t.Fatalf("expected the session-revoked and verification SETs, got %v", jtis)
		}
		after := run(t, "ssf.poll", with(M{"stream_id": sid, "ack": jtis}), nil)
		if len(after["jtis"].([]string)) != 0 {
			t.Errorf("acknowledged SETs delivered again: %v", after["jtis"])
		}
		wantStatus(t, run(t, "ssf.stream", M{"issuer": tr.URL, "ssf_token": "wrong", "action": "get", "stream_id": sid}, nil), "transmitter accepted", "fail")
		noFailures(t, run(t, "ssf.stream", with(M{"action": "delete", "stream_id": sid}), nil))
	})

	t.Run("push stream with verification", func(t *testing.T) {
		port := freePort(t)
		created := run(t, "ssf.stream", with(M{"action": "create", "delivery": "push", "events": []string{caepBase + "session-revoked"},
			"endpoint_url": fmt.Sprintf("http://localhost:%d/ssf/events", port), "push_authorization": "Bearer recv"}), nil)
		sid := str(created["response"].(map[string]any)["stream_id"])
		res := run(t, "ssf.receive", with(M{"stream_id": sid, "trigger_verification": true, "port": port, "expected_authorization": "Bearer recv",
			"audience": "https://receiver.example", "wait": 5}), nil)
		noFailures(t, res)
		for _, n := range []string{"verification requested", "SET 1: SET signature", "verification event echoes our state", "Content-Type is application/secevent+jwt"} {
			wantStatus(t, res, n, "pass")
		}
	})

	t.Run("a stored token only goes to the transmitter's origin", func(t *testing.T) {
		evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"issuer":"x","jwks_uri":"x","configuration_endpoint":"https://evil.example/streams","verification_endpoint":"https://evil.example/verify"}`)
		}))
		defer evil.Close()
		dir := t.TempDir()
		t.Setenv("IDPDBG_CONFIG", dir+"/c.json")
		os.WriteFile(dir+"/c.json", []byte(`{"profiles":{"s":{"issuer":"`+evil.URL+`","ssf_token":"mgmt"}}}`), 0o600)
		for _, raw := range []M{{"profile": "s", "action": "get", "stream_id": "s1"}, {"profile": "s", "action": "verify", "stream_id": "s1"}} {
			if _, err := runOp(t.Context(), findOp("ssf.stream"), raw, false, nil); err == nil || !strings.Contains(err.Error(), "refusing to send") {
				t.Errorf("token sent to a metadata endpoint on another origin: %v", err)
			}
		}
		if !findOp("ssf.poll").Mutating || !findOp("ssf.receive").Mutating {
			t.Error("poll and receive change remote state")
		}
	})

	t.Run("SETs that break the rules", func(t *testing.T) {
		good := func(events M, extra M) string { _, tok := tr.set(t, events, extra); return tok }
		email := M{"sub_id": M{"format": "email", "email": "alice@example.com"}}
		ok := good(M{caepBase + "credential-change": M{"credential_type": "password", "change_type": "update"}}, email)
		noFailures(t, run(t, "ssf.set", M{"token": ok, "issuer": tr.URL}, nil))
		parts := strings.Split(ok, ".")
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		plainJWT, _ := signJWS(tr.key, "ES256", M{"typ": "JWT", "kid": "t1"}, M{"iss": tr.URL, "iat": time.Now().Unix(), "jti": "x", "events": M{caepBase + "session-revoked": M{}}, "sub_id": M{"format": "opaque", "id": "1"}})
		forged, _ := signJWS(other, "ES256", M{"typ": "secevent+jwt", "kid": "t1"}, M{"iss": tr.URL, "iat": time.Now().Unix(), "jti": "x", "events": M{caepBase + "session-revoked": M{}}})
		for name, tc := range map[string]struct{ tok, check string }{
			"altered payload":      {parts[0] + "." + b64url([]byte(`{"iss":"`+tr.URL+`","events":{}}`)) + "." + parts[2], "SET signature"},
			"wrong signer":         {forged, "SET signature"},
			"plain JWT typ":        {plainJWT, "typ is secevent+jwt"},
			"missing members":      {good(M{caepBase + "credential-change": M{"credential_type": "password"}}, email), "event credential-change: required members"},
			"bad email subject":    {good(M{caepBase + "session-revoked": M{}}, M{"sub_id": M{"format": "email", "email": "not-an-address"}}), "email value is an address"},
			"iss_sub missing sub":  {good(M{caepBase + "session-revoked": M{}}, M{"sub_id": M{"format": "iss_sub", "iss": "https://x"}}), "sub_id: iss_sub has its required members"},
			"nobody it is about":   {good(M{caepBase + "session-revoked": M{}}, nil), "event session-revoked: subject"},
			"timestamp not a date": {good(M{caepBase + "session-revoked": M{"event_timestamp": "yesterday"}}, email), "NumericDate"},
		} {
			t.Run(name, func(t *testing.T) {
				wantStatus(t, run(t, "ssf.set", M{"token": tc.tok, "issuer": tr.URL}, nil), tc.check, "fail")
			})
		}
	})
}
