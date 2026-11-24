package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestWebAuthnSecurityKey runs the security key path against the test
// relying party (go-webauthn). It needs a real key and a person to touch
// it, so it only runs with IDPDBG_HW_TEST=1.
func TestWebAuthnSecurityKey(t *testing.T) {
	if os.Getenv("IDPDBG_HW_TEST") != "1" {
		t.Skip("set IDPDBG_HW_TEST=1 with a security key connected")
	}
	if realPlatformAPI != nil { // on Windows: through the Windows WebAuthn API
		platformAPI = realPlatformAPI
		t.Cleanup(func() { platformAPI = nil })
	}
	rp := newTestRP(t)
	touch := func(what string) { fmt.Fprintf(os.Stderr, ">>> touch the key: %s\n", what) }
	base := func(extra M) M {
		m := M{"server": rp.url, "username": "hw", "timeout": 60}
		if extra["credential"] == nil {
			m["authenticator"] = "usb"
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}

	touch("registration (attestation none)")
	reg := run(t, "webauthn.register", base(nil), nil)
	noFailures(t, reg)
	wantStatus(t, reg, "server accepts the registration", "pass")
	cred, _ := reg["credential"].(string)
	if !strings.HasPrefix(cred, "idpdbg-webauthn:") {
		t.Fatalf("no credential: %v", reg)
	}

	touch("sign-in")
	login := run(t, "webauthn.login", base(M{"credential": cred}), nil)
	noFailures(t, login)
	wantStatus(t, login, "server accepts the assertion", "pass")
	wantStatus(t, login, "assertion signature verifies with the registered key", "pass")

	touch("sign-in with a wrong origin in the client data (the server must reject it)")
	bad := run(t, "webauthn.login", base(M{"credential": login["credential"], "tamper": "wrong_origin"}), nil)
	wantStatus(t, bad, "server rejects "+tamperWhat["wrong_origin"], "pass")

	rp.direct = true
	touch("registration (attestation direct)")
	reg2 := run(t, "webauthn.register", base(M{"username": "hw2"}), nil)
	noFailures(t, reg2)
	wantStatus(t, reg2, "server accepts the registration", "pass")
}
