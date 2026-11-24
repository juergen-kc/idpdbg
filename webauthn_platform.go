package main

import (
	"errors"
	"time"
)

// Security keys through the operating system's WebAuthn API instead of
// talking CTAP to the key: on Windows, webauthn.dll, which any user may
// call (talking to a key directly needs administrator rights there). The
// system shows its own dialogs for choosing the key, the PIN and the touch;
// idpdbg still builds the client data, so it checks and sends what the key
// returns exactly as on the direct path.

// platformAuthenticator is the system API. It is set on Windows when
// webauthn.dll is present, and replaced by tests.
type platformAuthenticator interface {
	Name() string
	MakeCredential(r platformCreate) (*platformAttestation, error)
	GetAssertion(r platformGet) (*platformAssertion, error)
}

var platformAPI platformAuthenticator

type platformCreate struct {
	RPID, RPName              string
	UserID                    []byte
	UserName, UserDisplayName string
	ClientDataJSON            []byte
	Algs                      []int64
	Exclude                   [][]byte
	ResidentKey               bool
	UserVerification          string // required, preferred, discouraged
	Timeout                   time.Duration
}

type platformAttestation struct {
	Format     string
	AuthData   []byte
	AttStmtRaw []byte // the attestation statement, CBOR
	Transport  string
}

type platformGet struct {
	RPID             string
	ClientDataJSON   []byte
	Allow            [][]byte
	UserVerification string
	Timeout          time.Duration
}

type platformAssertion struct {
	CredID, AuthData, Signature, UserHandle []byte
}

// usePlatform says whether this ceremony goes through the system API: by
// default where there is one, or when asked with device "windows". A
// device index, path or nfc reader still means talking to the key directly.
func usePlatform(c *Ctx) (bool, error) {
	dev := c.Str("device")
	switch {
	case dev == "windows" && platformAPI == nil:
		return false, errors.New("device windows uses the Windows WebAuthn API, which exists only on Windows (webauthn.dll)")
	case dev == "windows", dev == "" && platformAPI != nil:
		if c.Str("ctap") == "u2f" {
			return false, errors.New("ctap=u2f talks to the key directly; through the Windows WebAuthn API Windows chooses the protocol (pass a device from fido.devices, which needs administrator rights)")
		}
		return true, nil
	}
	return false, nil
}

func platformCheckParams(c *Ctx, cs *Checks) {
	if c.Str("pin") != "" {
		cs.add("PIN", "info", "not used: "+platformAPI.Name()+" asks for the key's PIN itself", "")
	}
}

func uvPolicy(p string) string {
	switch p {
	case "required", "discouraged":
		return p
	}
	return "preferred" // the WebAuthn default
}
