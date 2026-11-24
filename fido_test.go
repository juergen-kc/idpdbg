package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"encoding/binary"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKey is a CTAPHID authenticator in memory: CTAP2 (getInfo,
// makeCredential with packed attestation, getAssertion) and U2F (register,
// authenticate), with keepalives and a "touch needed" first U2F answer.
type fakeKey struct {
	t        *testing.T
	in       chan []byte
	mu       sync.Mutex
	asm      []byte // request being assembled
	asmCmd   byte
	asmLen   int
	cid      uint32
	pinSet   bool
	aaguid   []byte
	attKey   *ecdsa.PrivateKey
	attCert  []byte
	creds    map[string]*ecdsa.PrivateKey
	counter  uint32
	touched  bool // U2F: the next register succeeds
	requests []byte
	// ClientPIN
	pin      string
	retries  int
	v21      bool // CTAP 2.1: protocol 2, permissions token, makeCredUvNotRqd
	kaKey    *ecdh.PrivateKey
	token    []byte
	tokProto int
	// discoverable credentials, and what getNextAssertion still owes
	rks     []fakeRK
	pending [][]byte
	// credential management: 2.1 (credMgmt) or the preview (0x41)
	cmV21, cmPreview bool
	cmLie            bool // getCredsMetadata miscounts
	tokPerms         int64
	cmQueue          [][]byte
}

type fakeRK struct {
	rpID    string
	id      []byte
	user    map[any]any
	protect int64
}

func newFakeKey(t *testing.T, pinSet bool) *fakeKey {
	k := &fakeKey{t: t, in: make(chan []byte, 512), cid: 0x01020304, pinSet: pinSet, creds: map[string]*ecdsa.PrivateKey{}, pin: "123456", retries: 8}
	k.aaguid = bytes.Repeat([]byte{0xAB}, 16)
	k.attKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ext, _ := stdasn1.Marshal(k.aaguid)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		Subject:               pkix.Name{CommonName: "Fake Key", OrganizationalUnit: []string{"Authenticator Attestation"}, Organization: []string{"Test"}, Country: []string{"SE"}},
		BasicConstraintsValid: true, ExtraExtensions: []pkix.Extension{{Id: stdasn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}, Value: ext}}}
	k.attCert, _ = x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.attKey.Public(), k.attKey)
	return k
}

func (k *fakeKey) Close() error { return nil }

func (k *fakeKey) Read(timeout time.Duration) ([]byte, error) {
	select {
	case p := <-k.in:
		return p, nil
	case <-time.After(timeout):
		return nil, nil
	}
}

func (k *fakeKey) reply(cid uint32, cmd byte, data []byte) {
	frames, _ := ctaphidFrames(cid, cmd, data)
	for _, f := range frames {
		k.in <- f
	}
}

func (k *fakeKey) Write(p []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	cid := binary.BigEndian.Uint32(p)
	if p[4]&0x80 != 0 {
		k.asmCmd, k.asmLen = p[4], int(p[5])<<8|int(p[6])
		k.asm = append([]byte{}, p[7:min(64, 7+k.asmLen)]...)
	} else {
		k.asm = append(k.asm, p[5:]...)
	}
	if len(k.asm) < k.asmLen {
		return nil
	}
	data := k.asm[:k.asmLen]
	switch k.asmCmd {
	case ctaphidInit:
		resp := append(append([]byte{}, data...), 1, 2, 3, 4, 2, 5, 4, 3, 0x05)
		k.reply(cid, ctaphidInit, resp)
	case ctaphidPing:
		k.reply(cid, ctaphidPing, data)
	case ctaphidCancel:
	case ctaphidCBOR:
		k.requests = append(k.requests, data[0])
		k.reply(cid, ctaphidCBOR, k.cbor(cid, data[0], data[1:]))
	case ctaphidMsg:
		k.reply(cid, ctaphidMsg, k.u2f(data))
	default:
		k.reply(cid, ctaphidError, []byte{1})
	}
	return nil
}

func (k *fakeKey) keepalive(cid uint32) { k.reply(cid, ctaphidKeepalive, []byte{2}) }

func (k *fakeKey) cbor(cid uint32, cmd byte, b []byte) []byte {
	var req map[any]any
	if len(b) > 0 {
		v, _, err := cborDecode(b)
		if err != nil {
			return []byte{0x12}
		}
		req, _ = v.(map[any]any)
	}
	switch cmd {
	case ctapGetInfo:
		info := map[any]any{1: []any{"U2F_V2", "FIDO_2_0"}, 3: k.aaguid,
			4: map[any]any{"rk": true, "up": true, "plat": false, "clientPin": k.pinSet}, 6: []any{1}}
		if k.v21 {
			info[1] = []any{"U2F_V2", "FIDO_2_0", "FIDO_2_1"}
			info[4].(map[any]any)["pinUvAuthToken"] = true
			info[4].(map[any]any)["makeCredUvNotRqd"] = true
			info[6] = []any{2, 1}
		}
		if k.cmV21 {
			info[4].(map[any]any)["credMgmt"] = true
		}
		if k.cmPreview {
			info[1] = append(info[1].([]any), "FIDO_2_1_PRE")
			info[4].(map[any]any)["credentialMgmtPreview"] = true
		}
		return append([]byte{0}, cborEncode(info)...)
	case ctapClientPIN:
		return k.clientPIN(req)
	case ctapCredMgmt, ctapCredMgmtPreview:
		if cmd == ctapCredMgmt && !k.cmV21 || cmd == ctapCredMgmtPreview && !k.cmPreview {
			return []byte{0x01}
		}
		return k.credMgmt(cmd, req)
	case ctapGetNextAssertion:
		if len(k.pending) == 0 {
			return []byte{0x30} // NOT_ALLOWED
		}
		r := k.pending[0]
		k.pending = k.pending[1:]
		return r
	case ctapMakeCredential:
		cdHash := req[int64(1)].([]byte)
		uv, st := k.checkPinAuth(req, cdHash, 8, 9)
		if st != 0 {
			return []byte{st}
		}
		opts, _ := req[int64(7)].(map[any]any)
		if k.pinSet && !uv && (!k.v21 || opts["rk"] == true) {
			return []byte{0x36}
		}
		k.keepalive(cid)
		rp := req[int64(2)].(map[any]any)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		id := randomBytes(32)
		k.creds[string(id)] = key
		if opts["rk"] == true {
			k.rks = append(k.rks, fakeRK{rpID: rp["id"].(string), id: id, user: req[int64(3)].(map[any]any)})
		}
		rpHash := sha256.Sum256([]byte(rp["id"].(string)))
		flags := byte(0x41)
		if uv {
			flags |= 0x04
		}
		ad := append(append(rpHash[:], flags, 0, 0, 0, 0), k.aaguid...)
		ad = append(append(ad, 0, byte(len(id))), id...)
		ad = append(ad, cborEncode(coseOf(key.Public(), -7))...)
		sig, _ := webauthnSign(k.attKey, -7, append(append([]byte{}, ad...), cdHash...))
		return append([]byte{0}, cborEncode(map[any]any{1: "packed", 2: ad, 3: map[any]any{"alg": -7, "sig": sig, "x5c": []any{k.attCert}}})...)
	case ctapGetAssertion:
		cdHash := req[int64(2)].([]byte)
		uv, st := k.checkPinAuth(req, cdHash, 6, 7)
		if st != 0 {
			return []byte{st}
		}
		k.keepalive(cid)
		rpID := req[int64(1)].(string)
		rpHash := sha256.Sum256([]byte(rpID))
		flags := byte(1)
		if opts, ok := req[int64(5)].(map[any]any); ok && opts["up"] == false {
			flags = 0
		}
		if uv {
			flags |= 0x04
		}
		if req[int64(3)] == nil { // discoverable: every passkey for the RP
			var found []fakeRK
			for _, r := range k.rks {
				if r.rpID == rpID {
					found = append(found, r)
				}
			}
			if len(found) == 0 {
				return []byte{0x2E}
			}
			var resps [][]byte
			for i, r := range found {
				k.counter++
				ad := binary.BigEndian.AppendUint32(append(append([]byte{}, rpHash[:]...), flags), k.counter)
				sig, _ := webauthnSign(k.creds[string(r.id)], -7, append(append([]byte{}, ad...), cdHash...))
				m := map[any]any{1: map[any]any{"type": "public-key", "id": r.id}, 2: ad, 3: sig, 4: r.user}
				if i == 0 && len(found) > 1 {
					m[5] = len(found)
				}
				resps = append(resps, append([]byte{0}, cborEncode(m)...))
			}
			k.pending = resps[1:]
			return resps[0]
		}
		for _, a := range anyList(req[int64(3)]) {
			id := a.(map[any]any)["id"].([]byte)
			if key := k.creds[string(id)]; key != nil {
				k.counter++
				ad := binary.BigEndian.AppendUint32(append(rpHash[:], flags), k.counter)
				sig, _ := webauthnSign(key, -7, append(append([]byte{}, ad...), cdHash...))
				return append([]byte{0}, cborEncode(map[any]any{1: map[any]any{"type": "public-key", "id": id}, 2: ad, 3: sig})...)
			}
		}
		return []byte{0x2E}
	}
	return []byte{0x01}
}

func (k *fakeKey) u2f(apdu []byte) []byte {
	ins, p1 := apdu[1], apdu[2]
	n := int(apdu[5])<<8 | int(apdu[6])
	data := apdu[7 : 7+n]
	sw := func(b []byte, s uint16) []byte { return binary.BigEndian.AppendUint16(b, s) }
	switch ins {
	case 0x01:
		if !k.touched {
			k.touched = true
			return sw(nil, 0x6985)
		}
		k.touched = false
		chal, app := data[:32], data[32:64]
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		kh := randomBytes(40)
		k.creds[string(kh)] = key
		pub := elliptic.Marshal(elliptic.P256(), key.X, key.Y) //nolint:staticcheck // the U2F wire format
		signed := append(append(append(append([]byte{0}, app...), chal...), kh...), pub...)
		sig, _ := webauthnSign(k.attKey, -7, signed)
		resp := append(append(append([]byte{0x05}, pub...), byte(len(kh))), kh...)
		return sw(append(append(resp, k.attCert...), sig...), 0x9000)
	case 0x02:
		chal, app, kh := data[:32], data[32:64], data[65:65+int(data[64])]
		key := k.creds[string(kh)]
		if key == nil {
			return sw(nil, 0x6A80)
		}
		if p1 == 0x07 {
			return sw(nil, 0x6985)
		}
		k.counter++
		flags := byte(1)
		if p1 == 0x08 {
			flags = 0
		}
		resp := binary.BigEndian.AppendUint32([]byte{flags}, k.counter)
		sig, _ := webauthnSign(key, -7, append(append(append([]byte{}, app...), resp...), chal...))
		return sw(append(resp, sig...), 0x9000)
	}
	return sw(nil, 0x6D00)
}

// useFakeKey points device discovery at k for the rest of the test.
func useFakeKey(t *testing.T, k *fakeKey) {
	enum, open, why := hidEnumerate, hidOpen, hidUnavailable
	t.Cleanup(func() { hidEnumerate, hidOpen, hidUnavailable = enum, open, why })
	hidEnumerate = func() ([]hidInfo, error) {
		return []hidInfo{{Path: "fake:0", VendorID: 0x1234, ProductID: 0x5678, Manufacturer: "Test", Product: "Fake Key"}}, nil
	}
	hidOpen = func(string) (hidDevice, error) { return k, nil }
}

func TestCTAPHIDFramingAndKeepalive(t *testing.T) {
	k := newFakeKey(t, false)
	d, err := ctapInit(k, hidInfo{})
	if err != nil || d.cid != 0x01020304 || d.version != "5.4.3" || d.caps != 0x05 {
		t.Fatalf("init: %v %+v", err, d)
	}
	big := bytes.Repeat([]byte("0123456789"), 300) // 3000 bytes: 51 packets
	echo, err := d.transact(ctaphidPing, big, time.Second)
	if err != nil || !bytes.Equal(echo, big) {
		t.Fatalf("ping: %v, %d bytes back", err, len(echo))
	}
	statuses := 0
	d.onKeepalive = func(byte) { statuses++ }
	if _, err := d.cbor(ctapGetAssertion, map[any]any{1: "x", 2: make([]byte, 32), 3: []any{}}, time.Second); err == nil || !strings.Contains(err.Error(), "NO_CREDENTIALS") || statuses != 1 {
		t.Fatalf("getAssertion: %v, %d keepalives", err, statuses)
	}
	if _, err := d.transact(0xC0, nil, time.Second); err == nil || !strings.Contains(err.Error(), "invalid command") {
		t.Fatalf("CTAPHID error: %v", err)
	}
}

func TestFIDOInfoWithFakeKey(t *testing.T) {
	useFakeKey(t, newFakeKey(t, true))
	res := run(t, "fido.info", M{}, nil)
	wantStatus(t, res, "CTAP2 supported", "pass")
	wantStatus(t, res, "usable without a PIN (idpdbg)", "info")
	wantStatus(t, res, "PIN attempts left", "info")
	devs := run(t, "fido.devices", M{}, nil)
	if devs["count"] != 1 {
		t.Fatalf("devices: %v", devs)
	}
}

func TestWebAuthnFakeKeyAgainstRP(t *testing.T) {
	for _, pin := range []bool{false, true} {
		k := newFakeKey(t, pin)
		useFakeKey(t, k)
		rp := newTestRP(t)
		rp.direct = true
		user := map[bool]string{false: "ctap2", true: "u2f"}[pin]
		reg := run(t, "webauthn.register", M{"server": rp.url, "username": user, "authenticator": "usb"}, nil)
		noFailures(t, reg)
		wantStatus(t, reg, "server accepts the registration", "pass")
		if pin {
			wantStatus(t, reg, "attestation signature (fido-u2f)", "pass")
		} else {
			wantStatus(t, reg, "attestation signature (packed, x5c)", "pass")
			wantStatus(t, reg, "attestation certificate AAGUID matches the authenticator data", "pass")
		}
		if got := reg["key"].(M)["protocol"]; got != user {
			t.Errorf("protocol %v, want %s", got, user)
		}
		cred := reg["credential"].(string)
		login := run(t, "webauthn.login", M{"server": rp.url, "username": user, "credential": cred}, nil)
		noFailures(t, login)
		wantStatus(t, login, "server accepts the assertion", "pass")
		wantStatus(t, login, "assertion signature verifies with the registered key", "pass")
		bad := run(t, "webauthn.login", M{"server": rp.url, "username": user, "credential": login["credential"], "tamper": "no_user_present"}, nil)
		wantStatus(t, bad, "server rejects "+tamperWhat["no_user_present"], "pass")
	}

	// Attestation "none": the statement and AAGUID are not passed on.
	k := newFakeKey(t, false)
	useFakeKey(t, k)
	rp := newTestRP(t)
	reg := run(t, "webauthn.register", M{"server": rp.url, "username": "anon", "authenticator": "usb"}, nil)
	wantStatus(t, reg, "server accepts the registration", "pass")
	wantStatus(t, reg, "attestation sent", "info")
	if c := rp.users["anon"].creds; len(c) != 1 || !allZero(c[0].Authenticator.AAGUID) || c[0].AttestationType != "none" {
		t.Fatalf("RP got: %+v", c)
	}
}

func TestFIDOReportDescriptor(t *testing.T) {
	// CTAP 2.1 §11.2.8.2: the FIDO HID report descriptor.
	fido := unhex(t, "06D0F1 0901 A101 0920 1500 26FF00 7508 9540 8102 0921 1500 26FF00 7508 9540 9102 C0")
	// A boot keyboard's start: usage page Generic Desktop, usage Keyboard.
	kbd := unhex(t, "0501 0906 A101 0507 19E0 29E7 C0")
	if !isFIDOReportDescriptor(fido) || isFIDOReportDescriptor(kbd) || isFIDOReportDescriptor(fido[:3]) {
		t.Fatal("descriptor detection wrong")
	}
}

// A real key must not sign one site's assertion for delivery elsewhere when
// the caller is a model (MCP); from the CLI a mismatch is only a warning.
func TestSecurityKeyOriginGuard(t *testing.T) {
	k := newFakeKey(t, false)
	useFakeKey(t, k)
	rp := newTestRP(t)
	reg := run(t, "webauthn.register", M{"server": rp.url, "username": "g", "authenticator": "usb"}, nil)
	sc, _, _ := decodeSoftCredential(reg["credential"].(string))
	sc.RPID, sc.Origin = "bank.example", "" // forged, as an attacker would
	forged := sc.encode()
	opts := func(rpID string) string {
		return `{"challenge":"` + b64url(randomBytes(32)) + `","rpId":"` + rpID + `","allowCredentials":[{"type":"public-key","id":"` + reg["credential_response"].(M)["id"].(string) + `"}]}`
	}
	cases := []struct {
		args    M
		cli     bool
		wantErr string
	}{
		{M{"server": rp.url, "origin": "https://bank.example", "options": opts("bank.example")}, false, "origin must be the destination's"},
		{M{"origin": "https://bank.example", "options": opts("bank.example")}, false, "offline over MCP"},
		{M{"origin": "http://localhost:1234", "options": opts("localhost")}, false, ""},
		{M{"server": rp.url, "origin": "https://bank.example", "options": opts("bank.example")}, true, ""},
	}
	for i, tc := range cases {
		args := M{"credential": forged}
		if tc.args["origin"] == "http://localhost:1234" {
			args["credential"] = reg["credential"]
		}
		for k, v := range tc.args {
			args[k] = v
		}
		res, err := runOp(context.Background(), findOp("webauthn.login"), args, tc.cli, nil)
		switch {
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("case %d: want error %q, got %v", i, tc.wantErr, err)
		case tc.wantErr == "" && err != nil:
			t.Errorf("case %d: %v", i, err)
		case tc.cli && checkOf(res, "origin matches the destination") == nil:
			t.Errorf("case %d: no origin warning", i)
		}
	}
}

func TestSecurityKeyGuardRules(t *testing.T) {
	fido := &rpAPI{kind: "fido", optionsURL: "https://bank.example/attestation/options", resultURL: "https://bank.example/attestation/result"}
	split := &rpAPI{kind: "custom", optionsURL: "https://evil.example/options", resultURL: "https://bank.example/result"}
	mcp := &Ctx{Args: M{}, Rec: &Recorder{}}
	pasted := &Ctx{Args: M{"options": "{}"}, Rec: &Recorder{}}
	cli := &Ctx{Args: M{"options": "{}"}, Rec: &Recorder{}, CLI: true}
	var cs Checks
	if w, err := hwOriginGuard(mcp, &cs, fido, "https://bank.example", "bank.example"); err != nil || !w {
		t.Errorf("same site over MCP: withhold=%v err=%v", w, err)
	}
	if _, err := hwOriginGuard(mcp, &cs, split, "https://bank.example", "bank.example"); err == nil || !strings.Contains(err.Error(), "options from https://evil.example") {
		t.Errorf("options from another site: %v", err)
	}
	if _, err := hwOriginGuard(pasted, &cs, fido, "https://bank.example", "bank.example"); err == nil || !strings.Contains(err.Error(), "pasted options") {
		t.Errorf("pasted options: %v", err)
	}
	if w, err := hwOriginGuard(cli, &cs, split, "https://bank.example", "bank.example"); err != nil || w {
		t.Errorf("CLI: withhold=%v err=%v", w, err)
	}
	out := M{}
	cred := M{"id": "x", "type": "public-key", "response": M{"signature": "SIG", "authenticatorData": "AD", "clientDataJSON": "CD"}}
	withholdSigned(mcp, out, cred, true)
	if r := out["credential_response"].(M); r["response"] != nil || r["withheld"] == nil {
		t.Errorf("not withheld: %v", r)
	}
	if !containsFold(mcp.Rec.secrets, "SIG") || !containsFold(mcp.Rec.secrets, "AD") {
		t.Errorf("signature not redacted from traces: %v", mcp.Rec.secrets)
	}
}

func (k *fakeKey) checkPinAuth(req map[any]any, cdHash []byte, authKey, protoKey int64) (uv bool, status byte) {
	auth, ok := req[authKey].([]byte)
	if !ok {
		return false, 0
	}
	proto, _ := req[protoKey].(int64)
	if k.token == nil || int(proto) != k.tokProto || !bytes.Equal(auth, pinAuth(int(proto), k.token, cdHash)) {
		return false, 0x33 // PIN_AUTH_INVALID
	}
	return true, 0
}

func (k *fakeKey) clientPIN(req map[any]any) []byte {
	proto, _ := req[int64(1)].(int64)
	sub, _ := req[int64(2)].(int64)
	ok := func(m map[any]any) []byte { return append([]byte{0}, cborEncode(m)...) }
	switch sub {
	case pinSubRetries:
		return ok(map[any]any{3: k.retries})
	case pinSubKeyAgreement:
		k.kaKey, _ = ecdh.P256().GenerateKey(rand.Reader)
		pub := k.kaKey.PublicKey().Bytes()
		return ok(map[any]any{1: map[any]any{1: 2, 3: -25, -1: 1, -2: pub[1:33], -3: pub[33:65]}})
	case pinSubGetToken, pinSubGetTokenPerm:
		if sub == pinSubGetTokenPerm && (!k.v21 || req[int64(9)] == nil) {
			return []byte{0x02}
		}
		if k.retries == 0 {
			return []byte{0x32}
		}
		pc, _ := req[int64(3)].(map[any]any)
		x, _ := pc[int64(-2)].([]byte)
		y, _ := pc[int64(-3)].([]byte)
		peer, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
		if err != nil || k.kaKey == nil {
			return []byte{0x02}
		}
		z, _ := k.kaKey.ECDH(peer)
		sess, err := pinSessionFromZ(int(proto), z)
		if err != nil {
			return []byte{0x02}
		}
		enc, _ := req[int64(6)].([]byte)
		got, err := sess.decrypt(enc)
		want := sha256.Sum256([]byte(k.pin))
		if err != nil || !bytes.Equal(got, want[:16]) {
			k.retries--
			return []byte{0x31}
		}
		k.token, k.tokProto = randomBytes(32), int(proto)
		k.tokPerms, _ = req[int64(9)].(int64)
		if sub == pinSubGetToken {
			k.tokPerms = 0xFF // a CTAP 2.0 token may do anything
		}
		et, _ := sess.encrypt(k.token)
		return ok(map[any]any{2: et})
	}
	return []byte{0x3E}
}

func TestSecurityKeyPIN(t *testing.T) {
	for _, v21 := range []bool{false, true} {
		k := newFakeKey(t, true)
		k.v21 = v21
		useFakeKey(t, k)
		rp := newTestRP(t)
		name := map[bool]string{false: "ctap20", true: "ctap21"}[v21]
		reg := run(t, "webauthn.register", M{"server": rp.url, "username": name, "authenticator": "usb", "pin": "123456"}, nil)
		noFailures(t, reg)
		wantStatus(t, reg, "server accepts the registration", "pass")
		wantStatus(t, reg, "user verified (UV)", "pass")
		if got := reg["key"].(M)["protocol"]; got != "ctap2" {
			t.Errorf("%s: protocol %v", name, got)
		}
		proto := map[bool]string{false: "protocol 1", true: "protocol 2"}[v21]
		if c := checkOf(reg, "protocol"); c == nil || !strings.Contains(c.Detail, proto) {
			t.Errorf("%s: %+v", name, c)
		}
		if v21 && !bytes.Contains(k.requests, []byte{ctapClientPIN}) {
			t.Error("no ClientPIN request")
		}
		rp.requireUV = true
		login := run(t, "webauthn.login", M{"server": rp.url, "username": name, "credential": reg["credential"], "pin": "123456"}, nil)
		noFailures(t, login)
		wantStatus(t, login, "server accepts the assertion", "pass")
		wantStatus(t, login, "user verified (UV)", "pass")

		// UV required and no PIN to be had (MCP, no terminal): refused.
		nopin := run(t, "webauthn.login", M{"server": rp.url, "username": name, "credential": login["credential"]}, nil)
		if c := checkOf(nopin, "security key signed the assertion"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "needs the key's PIN") {
			t.Errorf("%s: required UV without PIN: %+v", name, c)
		}
	}

	// A wrong PIN costs exactly one attempt and is not retried.
	k := newFakeKey(t, true)
	useFakeKey(t, k)
	rp := newTestRP(t)
	reg := run(t, "webauthn.register", M{"server": rp.url, "username": "w", "authenticator": "usb", "pin": "999999"}, nil)
	if c := checkOf(reg, "security key made a credential"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "wrong PIN: 7 attempts left") || k.retries != 7 {
		t.Fatalf("wrong PIN: %+v, retries %d", c, k.retries)
	}
	// With few attempts left idpdbg does not try at all.
	k.retries = 2
	reg = run(t, "webauthn.register", M{"server": rp.url, "username": "w", "authenticator": "usb", "pin": "123456"}, nil)
	if c := checkOf(reg, "security key made a credential"); c == nil || !strings.Contains(c.Detail, "only 2 PIN attempts") || k.retries != 2 || k.token != nil {
		t.Fatalf("low retries: %+v, retries %d", c, k.retries)
	}
	// Without a PIN a CTAP 2.0 key with one set registers over U2F.
	k.retries = 8
	reg = run(t, "webauthn.register", M{"server": rp.url, "username": "u", "authenticator": "usb"}, nil)
	wantStatus(t, reg, "server accepts the registration", "pass")
	if reg["key"].(M)["protocol"] != "u2f" {
		t.Errorf("no-PIN fallback: %v", reg["key"])
	}
}

// A PIN from the environment is a stored secret: over MCP it is only used
// for relying parties named in IDPDBG_ALLOWED_HOSTS.
func TestSecurityKeyStoredPINGuard(t *testing.T) {
	k := newFakeKey(t, true)
	useFakeKey(t, k)
	rp := newTestRP(t)
	t.Setenv("IDPDBG_PIN", "123456")
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "")
	_, err := runOp(context.Background(), findOp("webauthn.register"), M{"server": rp.url, "username": "e", "authenticator": "usb"}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "IDPDBG_PIN") && !strings.Contains(err.Error(), "pin") {
		t.Fatalf("stored PIN sent to an unlisted host: %v", err)
	}
	t.Logf("refused: %v", err)
	t.Setenv("IDPDBG_ALLOWED_HOSTS", rp.url)
	res, err := runOp(context.Background(), findOp("webauthn.register"), M{"server": rp.url, "username": "e", "authenticator": "usb"}, false, nil)
	if err != nil || checkOf(res, "user verified (UV)").Status != "pass" {
		t.Fatalf("allowed host: %v %v", err, res["checks"])
	}
}

func TestPasskeySignIn(t *testing.T) {
	k := newFakeKey(t, true)
	k.v21 = true
	useFakeKey(t, k)
	rp := newTestRP(t)
	// Two passkeys for the site on the key.
	for _, u := range []string{"alice", "bob"} {
		reg := run(t, "webauthn.register", M{"server": rp.url, "username": u, "authenticator": "usb", "resident_key": true, "pin": "123456"}, nil)
		noFailures(t, reg)
		wantStatus(t, reg, "server accepts the registration", "pass")
	}
	if len(k.rks) != 2 {
		t.Fatalf("%d passkeys stored", len(k.rks))
	}
	// Options without allowCredentials: the key offers both accounts.
	opts := func() string {
		return `{"challenge":"` + b64url(randomBytes(32)) + `","rpId":"localhost","userVerification":"required"}`
	}
	res := run(t, "webauthn.login", M{"passkey": true, "origin": "http://localhost:1", "options": opts(), "pin": "123456"}, nil)
	if c := checkOf(res, "security key signed the assertion"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "pass account") {
		t.Fatalf("two accounts, none chosen: %+v", c)
	}
	if accts, _ := res["accounts"].([]M); len(accts) != 2 || accts[1]["user_name"] != "bob" {
		t.Fatalf("accounts: %v", res["accounts"])
	}
	res = run(t, "webauthn.login", M{"passkey": true, "origin": "http://localhost:1", "options": opts(), "pin": "123456", "account": "bob"}, nil)
	noFailures(t, res)
	wantStatus(t, res, "passkey returned the user handle", "pass")
	wantStatus(t, res, "user verified (UV)", "pass")
	if !strings.HasPrefix(str(res["credential"]), "idpdbg-webauthn:") {
		t.Fatalf("no credential returned: %v", res)
	}
	// Against the relying party: its own discoverable login (empty username).
	rp2 := newTestRP(t)
	k2 := newFakeKey(t, false)
	useFakeKey(t, k2)
	run(t, "webauthn.register", M{"server": rp2.url, "username": "carol", "authenticator": "usb", "resident_key": true}, nil)
	login := run(t, "webauthn.login", M{"passkey": true, "server": rp2.url, "username": "carol"}, nil)
	noFailures(t, login)
	wantStatus(t, login, "server accepts the assertion", "pass")
	// No passkey for another site.
	none := run(t, "webauthn.login", M{"passkey": true, "origin": "http://other.localhost:1", "options": `{"challenge":"` + b64url(randomBytes(32)) + `","rpId":"other.localhost"}`}, nil)
	if c := checkOf(none, "security key signed the assertion"); c == nil || !strings.Contains(c.Detail, "NO_CREDENTIALS") {
		t.Fatalf("no passkeys: %+v", c)
	}
}

func TestPasskeyPrivacyGuards(t *testing.T) {
	if got := safeText("ali\x1b[2Jce\x07\nbob"); got != "ali[2Jcebob" {
		t.Errorf("safeText: %q", got)
	}
	k := newFakeKey(t, false)
	useFakeKey(t, k)
	opts := `{"challenge":"` + b64url(randomBytes(32)) + `","rpId":"localhost"}`
	_, err := runOp(context.Background(), findOp("webauthn.login"), M{"passkey": true, "origin": "http://localhost:1", "options": opts, "tamper": "no_user_present"}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "reveal which accounts") {
		t.Errorf("silent account lookup allowed: %v", err)
	}
	var cs Checks
	out := M{}
	as := []assertion{{userName: "alice", user: []byte{1}}, {userName: "bob", user: []byte{2}}}
	chooseAccount(&Ctx{Args: M{}}, &cs, out, as, true)
	if l := out["accounts"].([]M); len(l) != 2 || l[0]["user_name"] != nil {
		t.Errorf("private account list leaks names: %v", l)
	}
}
