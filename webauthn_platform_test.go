package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

// Tests never reach the real Windows WebAuthn API, which would wait for a
// dialog; only the hardware test (IDPDBG_HW_TEST=1) puts it back.
var realPlatformAPI platformAuthenticator

func init() { realPlatformAPI, platformAPI = platformAPI, nil }

// fakePlatform plays the Windows WebAuthn API in front of a fakeKey: it
// hashes the client data, asks the key, and for a passkey sign-in "picks"
// the first account, as the Windows dialog lets the person do.
type fakePlatform struct {
	k             *fakeKey
	creates, gets int
	last          platformCreate
}

func (f *fakePlatform) Name() string { return "the emulated Windows WebAuthn API" }

func (f *fakePlatform) MakeCredential(r platformCreate) (*platformAttestation, error) {
	f.creates++
	f.last = r
	h := sha256.Sum256(r.ClientDataJSON)
	var params []any
	for _, a := range r.Algs {
		params = append(params, map[any]any{"alg": a, "type": "public-key"})
	}
	req := map[any]any{1: h[:], 2: map[any]any{"id": r.RPID, "name": r.RPName},
		3: map[any]any{"id": r.UserID, "name": r.UserName, "displayName": r.UserDisplayName}, 4: params}
	if r.ResidentKey {
		req[7] = map[any]any{"rk": true}
	}
	resp := f.k.cbor(0, ctapMakeCredential, cborEncode(req))
	if resp[0] != 0 {
		return nil, errors.New("NotAllowedError (0x800704C7)")
	}
	vals, raws, err := cborMapFields(resp[1:])
	if err != nil {
		return nil, err
	}
	return &platformAttestation{Format: vals[int64(1)].(string), AuthData: vals[int64(2)].([]byte), AttStmtRaw: raws[int64(3)], Transport: "usb"}, nil
}

func (f *fakePlatform) GetAssertion(r platformGet) (*platformAssertion, error) {
	f.gets++
	h := sha256.Sum256(r.ClientDataJSON)
	req := map[any]any{1: r.RPID, 2: h[:]}
	if len(r.Allow) > 0 {
		var allow []any
		for _, id := range r.Allow {
			allow = append(allow, map[any]any{"type": "public-key", "id": id})
		}
		req[3] = allow
	}
	resp := f.k.cbor(0, ctapGetAssertion, cborEncode(req))
	f.k.pending = nil
	if resp[0] != 0 {
		return nil, errors.New("NotAllowedError (0x800704C7)")
	}
	vals, _, err := cborMapFields(resp[1:])
	if err != nil {
		return nil, err
	}
	a := &platformAssertion{CredID: vals[int64(1)].(map[any]any)["id"].([]byte), AuthData: vals[int64(2)].([]byte), Signature: vals[int64(3)].([]byte)}
	if u, ok := vals[int64(4)].(map[any]any); ok {
		a.UserHandle, _ = u["id"].([]byte)
	}
	return a, nil
}

func useFakePlatform(t *testing.T, k *fakeKey) *fakePlatform {
	f := &fakePlatform{k: k}
	old := platformAPI
	platformAPI = f
	t.Cleanup(func() { platformAPI = old })
	return f
}

func TestWebAuthnThroughWindowsAPI(t *testing.T) {
	direct := newFakeKey(t, false) // a key on USB, used only when a device is named
	useFakeKey(t, direct)
	p := useFakePlatform(t, newFakeKey(t, false))
	rp := newTestRP(t)

	reg := run(t, "webauthn.register", M{"server": rp.url, "username": "win", "authenticator": "usb", "pin": "123456"}, nil)
	noFailures(t, reg)
	wantStatus(t, reg, "server accepts the registration", "pass")
	wantStatus(t, reg, "PIN", "info")
	if c := checkOf(reg, "protocol"); c == nil || !strings.Contains(c.Detail, "Windows") {
		t.Errorf("protocol: %+v", c)
	}
	if reg["key"].(M)["protocol"] != "windows" || p.creates != 1 || len(direct.creds) != 0 {
		t.Fatalf("key %v, platform calls %d, direct key used %d", reg["key"], p.creates, len(direct.creds))
	}
	if p.last.UserVerification != "preferred" || p.last.RPID != "localhost" || len(p.last.Algs) == 0 {
		t.Errorf("request: %+v", p.last)
	}

	login := run(t, "webauthn.login", M{"server": rp.url, "username": "win", "credential": reg["credential"]}, nil)
	noFailures(t, login)
	wantStatus(t, login, "server accepts the assertion", "pass")
	wantStatus(t, login, "assertion signature verifies with the registered key", "pass")
	if p.gets != 1 {
		t.Errorf("platform assertions: %d", p.gets)
	}

	// A passkey: Windows shows the account picker.
	run(t, "webauthn.register", M{"server": rp.url, "username": "pk", "authenticator": "usb", "resident_key": true}, nil)
	opts := `{"challenge":"` + b64url(randomBytes(32)) + `","rpId":"localhost"}`
	pk := run(t, "webauthn.login", M{"passkey": true, "origin": "http://localhost:1", "options": opts}, nil)
	noFailures(t, pk)
	wantStatus(t, pk, "passkey returned the user handle", "pass")

	// What only the direct path can do is refused, with the way out.
	if _, err := tryOp(t, "webauthn.register", M{"server": rp.url, "username": "x", "authenticator": "usb", "ctap": "u2f"}); err == nil || !strings.Contains(err.Error(), "talks to the key directly") {
		t.Errorf("ctap=u2f: %v", err)
	}
	_, err := runOp(context.Background(), findOp("webauthn.login"), M{"server": rp.url, "username": "win", "credential": login["credential"], "tamper": "no_user_present"}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "always asks for a touch") {
		t.Errorf("no_user_present: %v", err)
	}

	// A named device bypasses the Windows API.
	n := p.creates
	viaUSB := run(t, "webauthn.register", M{"server": rp.url, "username": "usb", "authenticator": "usb", "device": "0"}, nil)
	noFailures(t, viaUSB)
	if p.creates != n || len(direct.creds) != 1 {
		t.Errorf("device 0 went through the Windows API (%d calls) or missed the key (%d credentials)", p.creates-n, len(direct.creds))
	}
}

func TestWindowsDeviceElsewhere(t *testing.T) {
	old := platformAPI
	platformAPI = nil
	t.Cleanup(func() { platformAPI = old })
	rp := newTestRP(t)
	if _, err := tryOp(t, "webauthn.register", M{"server": rp.url, "username": "x", "authenticator": "usb", "device": "windows"}); err == nil || !strings.Contains(err.Error(), "only on Windows") {
		t.Errorf("device windows off Windows: %v", err)
	}
}
