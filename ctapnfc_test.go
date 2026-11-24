package main

import (
	"bytes"
	"strings"
	"testing"
)

// fakeNFC puts a fakeKey behind ISO 7816: the FIDO applet, NFCCTAP_MSG with
// a status update while the key "waits for a touch", command chaining, and
// answers longer than 200 bytes split with 61xx.
type fakeNFC struct {
	k        *fakeKey
	applet   string // what SELECT answers: FIDO_2_0 or U2F_V2
	selected bool
	chain    []byte
	chained  int // chained command APDUs seen
	pending  []byte
	held     []byte // the CTAP2 answer behind a status update
	statuses int
	shortU2F int // U2F requests that came as short APDUs
}

func (f *fakeNFC) out(b []byte, sw uint16) []byte {
	if len(b) > 200 {
		f.pending = b[200:]
		n := len(f.pending)
		if n > 255 {
			n = 0
		}
		return append(append([]byte{}, b[:200]...), 0x61, byte(n))
	}
	return append(append([]byte{}, b...), byte(sw>>8), byte(sw))
}

func (f *fakeNFC) Transmit(cmd []byte) ([]byte, error) {
	cla, ins, p1 := cmd[0], cmd[1], cmd[2]
	if ins == 0xC0 {
		p := f.pending
		f.pending = nil
		return f.out(p, 0x9000), nil
	}
	if ins == 0xA4 {
		f.selected = bytes.Contains(cmd, fidoAID)
		if !f.selected {
			return []byte{0x6A, 0x82}, nil
		}
		return f.out([]byte(f.applet), 0x9000), nil
	}
	if !f.selected {
		return []byte{0x69, 0x85}, nil
	}
	var data []byte
	if len(cmd) > 5 && cmd[4] != 0 {
		data = cmd[5 : 5+int(cmd[4])]
	}
	if cla&0x10 != 0 {
		f.chain = append(f.chain, data...)
		f.chained++
		return []byte{0x90, 0x00}, nil
	}
	data = append(f.chain, data...)
	f.chain = nil
	switch {
	case cla == 0x80 && ins == nfcctapMsg && f.applet == "FIDO_2_0":
		f.k.nfcMode = true
		resp := f.k.cbor(0, data[0], data[1:])
		if f.k.nfcWaiting && p1 == 0x80 {
			f.k.nfcWaiting, f.held = false, resp
			f.statuses++
			return []byte{0x02, 0x91, 0x00}, nil // UP needed
		}
		f.k.nfcWaiting = false
		return f.out(resp, 0x9000), nil
	case cla == 0x80 && ins == nfcctapGetResponse:
		r := f.held
		f.held = nil
		return f.out(r, 0x9000), nil
	case cla == 0x00 && (ins == 0x01 || ins == 0x02):
		// U2F: rebuild the extended form fakeKey parses.
		ext := append([]byte{0, ins, p1, cmd[3], 0, byte(len(data) >> 8), byte(len(data))}, data...)
		if len(cmd) > 4 && cmd[4] != 0 {
			f.shortU2F++
		}
		r := f.k.u2f(ext)
		return f.out(r[:len(r)-2], uint16(r[len(r)-2])<<8|uint16(r[len(r)-1])), nil
	}
	return []byte{0x6D, 0x00}, nil
}

func (f *fakeNFC) Close() error { return nil }

func useFakeNFC(t *testing.T, f *fakeNFC) {
	listReaders = func() ([]string, error) { return []string{"Contact Reader", "ACS ACR122U PICC Interface"}, nil }
	connectCard = func(reader string) (cardConn, cardInfo, error) {
		if !strings.Contains(reader, "PICC") {
			return &fakeCard{objects: map[string][]byte{}}, cardInfo{Reader: reader}, nil // a card without the FIDO applet
		}
		return f, cardInfo{Reader: reader}, nil
	}
	t.Cleanup(func() { listReaders, connectCard = nil, nil })
}

func TestFIDOOverNFC(t *testing.T) {
	k := newFakeKey(t, true)
	k.v21, k.cmV21 = true, true
	f := &fakeNFC{k: k, applet: "FIDO_2_0"}
	useFakeNFC(t, f)
	useFakeKey(t, newFakeKey(t, false)) // a different key on USB, which must not be used

	devs := run(t, "fido.devices", M{}, nil)
	var nfc M
	for _, d := range devs["devices"].([]M) {
		if d["transport"] == "nfc" {
			nfc = d
		}
	}
	if nfc == nil || nfc["path"] != "nfc:ACS ACR122U PICC Interface" || nfc["applet"] != "FIDO_2_0" || devs["count"] != 2 {
		t.Fatalf("devices: %v", devs)
	}

	info := run(t, "fido.info", M{"device": "nfc"}, nil)
	wantStatus(t, info, "CTAP2 supported", "pass")
	wantStatus(t, info, "CTAP 2.1", "pass")
	if d := info["device"].(M); d["transport"] != "nfc (ISO 7816 over PC/SC)" || d["reader"] != "ACS ACR122U PICC Interface" {
		t.Errorf("device: %v", d)
	}

	// Register and sign in against a relying party, with the PIN: requests
	// longer than a short APDU are chained, and the touch is a status update.
	rp := newTestRP(t)
	reg := run(t, "webauthn.register", M{"server": rp.url, "username": "nfc", "authenticator": "usb", "device": "nfc:acr122", "pin": "123456", "resident_key": true}, nil)
	noFailures(t, reg)
	wantStatus(t, reg, "server accepts the registration", "pass")
	wantStatus(t, reg, "user verified (UV)", "pass")
	if f.chained == 0 || f.statuses == 0 {
		t.Errorf("chained APDUs %d, status updates %d", f.chained, f.statuses)
	}
	login := run(t, "webauthn.login", M{"server": rp.url, "username": "nfc", "credential": reg["credential"], "device": "nfc", "pin": "123456"}, nil)
	noFailures(t, login)
	wantStatus(t, login, "server accepts the assertion", "pass")

	// Credential management works the same way.
	creds := run(t, "fido.credentials", M{"device": "nfc", "pin": "123456"}, nil)
	noFailures(t, creds)
	if creds["stored"] != int64(1) {
		t.Errorf("credentials: %v", creds)
	}

	if _, err := tryOp(t, "fido.info", M{"device": "nfc:nonesuch"}); err == nil || !strings.Contains(err.Error(), "no reader matches") {
		t.Errorf("unknown reader: %v", err)
	}
}

func TestU2FOverNFC(t *testing.T) {
	k := newFakeKey(t, false)
	f := &fakeNFC{k: k, applet: "U2F_V2"}
	useFakeNFC(t, f)
	rp := newTestRP(t)
	reg := run(t, "webauthn.register", M{"server": rp.url, "username": "u2f", "authenticator": "usb", "device": "nfc"}, nil)
	noFailures(t, reg)
	wantStatus(t, reg, "server accepts the registration", "pass")
	if reg["key"].(M)["protocol"] != "u2f" || f.shortU2F == 0 {
		t.Errorf("protocol %v, short U2F APDUs %d", reg["key"], f.shortU2F)
	}
	login := run(t, "webauthn.login", M{"server": rp.url, "username": "u2f", "credential": reg["credential"], "device": "nfc"}, nil)
	noFailures(t, login)
	wantStatus(t, login, "server accepts the assertion", "pass")
	// No reader holds a FIDO applet.
	f.applet = "nope"
	if _, err := tryOp(t, "fido.info", M{"device": "nfc"}); err == nil || !strings.Contains(err.Error(), "no FIDO authenticator") {
		t.Errorf("no applet: %v", err)
	}
}
