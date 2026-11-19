package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"
)

// CTAP2 authenticatorClientPIN (CTAP 2.1 §6.5): a shared secret with the
// key over ECDH, the PIN's hash sent encrypted in it, and a PIN/UV auth
// token back, which then MACs the client data hash of each operation.

const (
	ctapClientPIN = 0x06

	pinSubRetries      = 0x01
	pinSubKeyAgreement = 0x02
	pinSubGetToken     = 0x05 // CTAP 2.0 getPinToken
	pinSubGetTokenPerm = 0x09 // CTAP 2.1 getPinUvAuthTokenUsingPinWithPermissions

	permMakeCredential = 0x01
	permGetAssertion   = 0x02

	pinMinRetries = 3 // below this, idpdbg will not risk a PIN
)

type pinSession struct {
	proto  int
	shared []byte // protocol 1: 32 bytes; protocol 2: HMAC key || AES key
	cose   map[any]any
}

// pinAuth is authenticate(key, message): HMAC-SHA-256, truncated to 16
// bytes for protocol 1.
func pinAuth(proto int, key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	if proto == 1 {
		return m.Sum(nil)[:16]
	}
	return m.Sum(nil)
}

func newPinSession(d *ctapDevice, proto int) (*pinSession, error) {
	b, err := d.cbor(ctapClientPIN, map[any]any{1: proto, 2: pinSubKeyAgreement}, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("getKeyAgreement: %w", err)
	}
	m, _, err := cborMapFields(b)
	if err != nil {
		return nil, err
	}
	ka, _ := m[int64(1)].(map[any]any)
	x, _ := ka[int64(-2)].([]byte)
	y, _ := ka[int64(-3)].([]byte)
	if len(x) != 32 || len(y) != 32 {
		return nil, errors.New("getKeyAgreement: the key sent no P-256 public key")
	}
	peer, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, fmt.Errorf("getKeyAgreement: %w", err)
	}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	z, err := priv.ECDH(peer) // the shared point's x coordinate
	if err != nil {
		return nil, err
	}
	s, err := pinSessionFromZ(proto, z)
	if err != nil {
		return nil, err
	}
	pub := priv.PublicKey().Bytes()
	s.cose = map[any]any{1: 2, 3: -25, -1: 1, -2: pub[1:33], -3: pub[33:65]}
	return s, nil
}

// pinSessionFromZ derives the shared secret from the ECDH x coordinate:
// SHA-256(Z) for protocol 1, two HKDF-SHA-256 keys for protocol 2.
func pinSessionFromZ(proto int, z []byte) (*pinSession, error) {
	s := &pinSession{proto: proto}
	switch proto {
	case 1:
		h := sha256.Sum256(z)
		s.shared = h[:]
	case 2:
		salt := make([]byte, 32)
		hk, err := hkdf.Key(sha256.New, z, salt, "CTAP2 HMAC key", 32)
		if err != nil {
			return nil, err
		}
		ak, err := hkdf.Key(sha256.New, z, salt, "CTAP2 AES key", 32)
		if err != nil {
			return nil, err
		}
		s.shared = append(hk, ak...)
	default:
		return nil, fmt.Errorf("PIN/UV auth protocol %d is not supported", proto)
	}
	return s, nil
}

func (s *pinSession) aesKey() []byte {
	if s.proto == 2 {
		return s.shared[32:]
	}
	return s.shared
}

func (s *pinSession) encrypt(pt []byte) ([]byte, error) {
	blk, err := aes.NewCipher(s.aesKey())
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	if s.proto == 2 {
		rand.Read(iv)
	}
	ct := make([]byte, len(pt))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, pt)
	if s.proto == 2 {
		return append(iv, ct...), nil
	}
	return ct, nil
}

func (s *pinSession) decrypt(ct []byte) ([]byte, error) {
	blk, err := aes.NewCipher(s.aesKey())
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 16)
	if s.proto == 2 {
		if len(ct) < 16 {
			return nil, errors.New("ciphertext too short")
		}
		iv, ct = ct[:16], ct[16:]
	}
	if len(ct) == 0 || len(ct)%16 != 0 {
		return nil, errors.New("ciphertext is not whole AES blocks")
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(pt, ct)
	return pt, nil
}

// pinProtocolFor picks the PIN/UV auth protocol: 2 when the key offers it.
func pinProtocolFor(info map[any]any) int {
	proto := 0
	for _, p := range anyList(info[int64(6)]) {
		if v, ok := p.(int64); ok && (v == 2 || v == 1 && proto == 0) {
			proto = int(v)
		}
	}
	if proto == 0 {
		proto = 1 // CTAP 2.0 keys that omit the list speak protocol 1
	}
	return proto
}

func pinRetries(d *ctapDevice, proto int) (int, error) {
	b, err := d.cbor(ctapClientPIN, map[any]any{1: proto, 2: pinSubRetries}, 10*time.Second)
	if err != nil {
		return 0, err
	}
	m, _, err := cborMapFields(b)
	if err != nil {
		return 0, err
	}
	n, ok := m[int64(3)].(int64)
	if !ok {
		return 0, errors.New("getPINRetries: no count in the answer")
	}
	return int(n), nil
}

// pinToken trades the PIN for a PIN/UV auth token. It checks the retry
// counter first and never tries a PIN twice: a wrong PIN costs one of the
// key's few attempts.
func pinToken(d *ctapDevice, info map[any]any, pin string, perms int, rpID string) (token []byte, proto int, err error) {
	if n := utf8.RuneCountInString(pin); n < 4 || len(pin) > 63 {
		return nil, 0, errors.New("a PIN has 4 to 63 bytes (at least 4 characters)")
	}
	proto = pinProtocolFor(info)
	left, err := pinRetries(d, proto)
	if err != nil {
		return nil, 0, fmt.Errorf("getPINRetries: %w", err)
	}
	if left < pinMinRetries {
		return nil, 0, fmt.Errorf("only %d PIN attempts are left before the key blocks; idpdbg will not risk one (enter the PIN where you can see it, e.g. a browser)", left)
	}
	s, err := newPinSession(d, proto)
	if err != nil {
		return nil, 0, err
	}
	h := sha256.Sum256([]byte(pin))
	enc, err := s.encrypt(h[:16])
	if err != nil {
		return nil, 0, err
	}
	req := map[any]any{1: proto, 2: pinSubGetToken, 3: s.cose, 6: enc}
	opts, _ := info[int64(4)].(map[any]any)
	if opts["pinUvAuthToken"] == true {
		req[2], req[9] = pinSubGetTokenPerm, perms
		if rpID != "" {
			req[10] = rpID
		}
	}
	b, err := d.cbor(ctapClientPIN, req, 10*time.Second)
	if err != nil {
		var ce *ctapError
		if errors.As(err, &ce) && ce.code == 0x31 {
			if n, rerr := pinRetries(d, proto); rerr == nil {
				return nil, 0, fmt.Errorf("wrong PIN: %d attempts left before the key blocks", n)
			}
		}
		return nil, 0, err
	}
	m, _, err := cborMapFields(b)
	if err != nil {
		return nil, 0, err
	}
	encTok, _ := m[int64(2)].([]byte)
	if token, err = s.decrypt(encTok); err != nil {
		return nil, 0, fmt.Errorf("PIN token: %w", err)
	}
	if len(token) != 16 && len(token) != 32 {
		return nil, 0, fmt.Errorf("PIN token of %d bytes", len(token))
	}
	return token, proto, nil
}

// pinFor finds the PIN: the pin parameter (or IDPDBG_PIN / a profile), or,
// from a terminal, a prompt that does not echo. Empty when there is none.
func pinFor(c *Ctx, d *ctapDevice, why string) (string, error) {
	if p := c.Str("pin"); p != "" {
		return p, nil
	}
	if !c.CLI || !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", nil
	}
	fmt.Fprintf(os.Stderr, "PIN for %s %s (%s): ", safeText(d.info.Manufacturer), safeText(d.info.Product), safeText(why))
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	pin := strings.TrimRight(string(b), "\r\n")
	if c.Rec != nil {
		c.Rec.secrets = append(c.Rec.secrets, pin)
	}
	return pin, nil
}

// uvPlan is how a key will verify the user for one operation.
type uvPlan struct {
	how   string // "": no user verification; "pin"; "builtin" (the key's own, e.g. fingerprint)
	token []byte
	proto int
}

// params adds what the plan needs to a makeCredential (auth at 8, protocol
// at 9, options at 7) or getAssertion (6, 7, 5) request.
func (p uvPlan) params(req map[any]any, cdHash []byte, authKey, protoKey, optsKey int) {
	switch p.how {
	case "pin":
		req[authKey], req[protoKey] = pinAuth(p.proto, p.token, cdHash), p.proto
	case "builtin":
		opts, _ := req[optsKey].(map[any]any)
		if opts == nil {
			opts = map[any]any{}
		}
		opts["uv"] = true
		req[optsKey] = opts
	}
}

// planUV decides on user verification the way a browser does: required, or
// preferred (the WebAuthn default) when the key can verify; must is set
// when the key itself insists (a CTAP 2.0 key with a PIN set, making a
// credential). missing reports a PIN that is needed but not available.
func planUV(c *Ctx, d *ctapDevice, info map[any]any, policy string, must bool, perms int, rpID string) (plan uvPlan, missing bool, err error) {
	opts, _ := info[int64(4)].(map[any]any)
	pinSet, _ := opts["clientPin"].(bool)
	builtin, _ := opts["uv"].(bool)
	want := must || policy == "required" || policy != "discouraged" && (pinSet || builtin)
	switch {
	case !want:
		return uvPlan{}, false, nil
	case builtin:
		return uvPlan{how: "builtin"}, false, nil
	case pinSet:
		pin, err := pinFor(c, d, "user verification for "+rpID)
		if err != nil {
			return uvPlan{}, false, err
		}
		if pin == "" {
			return uvPlan{}, true, nil
		}
		tok, proto, err := pinToken(d, info, pin, perms, rpID)
		if err != nil {
			return uvPlan{}, false, err
		}
		return uvPlan{how: "pin", token: tok, proto: proto}, false, nil
	case policy == "required":
		return uvPlan{}, false, errors.New("the relying party requires user verification, but the key has no PIN set and no built-in verification (set a PIN with the vendor's tool)")
	}
	return uvPlan{}, false, nil
}

const pinMissingHint = "pass pin (better: IDPDBG_PIN or a profile), or run from a terminal to be asked for it"
