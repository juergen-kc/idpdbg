package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// CTAPHID (FIDO CTAP 2.1 §11.2): messages split into 64-byte packets on a
// channel the authenticator allocates, and CTAP2 commands carried as CBOR.

const (
	ctaphidPing      = 0x81
	ctaphidInit      = 0x86
	ctaphidWink      = 0x88
	ctaphidCBOR      = 0x90
	ctaphidCancel    = 0x91
	ctaphidKeepalive = 0xBB
	ctaphidError     = 0xBF
	ctaphidBroadcast = 0xFFFFFFFF

	ctapMakeCredential   = 0x01
	ctapGetAssertion     = 0x02
	ctapGetInfo          = 0x04
	ctapGetNextAssertion = 0x08
)

var ctaphidErrors = map[byte]string{1: "invalid command", 2: "invalid parameter", 3: "invalid length", 4: "invalid sequence",
	5: "message timeout", 6: "channel busy", 0x0A: "lock required", 0x0B: "invalid channel", 0x7F: "other error"}

var ctap2Errors = map[byte]string{
	0x01: "CTAP1_ERR_INVALID_COMMAND", 0x02: "CTAP1_ERR_INVALID_PARAMETER", 0x03: "CTAP1_ERR_INVALID_LENGTH",
	0x11: "CTAP2_ERR_CBOR_UNEXPECTED_TYPE", 0x12: "CTAP2_ERR_INVALID_CBOR", 0x14: "CTAP2_ERR_MISSING_PARAMETER",
	0x15: "CTAP2_ERR_LIMIT_EXCEEDED", 0x19: "CTAP2_ERR_CREDENTIAL_EXCLUDED", 0x21: "CTAP2_ERR_PROCESSING",
	0x22: "CTAP2_ERR_INVALID_CREDENTIAL", 0x23: "CTAP2_ERR_USER_ACTION_PENDING", 0x24: "CTAP2_ERR_OPERATION_PENDING",
	0x26: "CTAP2_ERR_UNSUPPORTED_ALGORITHM", 0x27: "CTAP2_ERR_OPERATION_DENIED", 0x28: "CTAP2_ERR_KEY_STORE_FULL",
	0x2B: "CTAP2_ERR_UNSUPPORTED_OPTION", 0x2C: "CTAP2_ERR_INVALID_OPTION", 0x2D: "CTAP2_ERR_KEEPALIVE_CANCEL",
	0x2E: "CTAP2_ERR_NO_CREDENTIALS", 0x2F: "CTAP2_ERR_USER_ACTION_TIMEOUT", 0x30: "CTAP2_ERR_NOT_ALLOWED",
	0x31: "CTAP2_ERR_PIN_INVALID", 0x32: "CTAP2_ERR_PIN_BLOCKED", 0x33: "CTAP2_ERR_PIN_AUTH_INVALID",
	0x34: "CTAP2_ERR_PIN_AUTH_BLOCKED", 0x35: "CTAP2_ERR_PIN_NOT_SET", 0x36: "CTAP2_ERR_PUAT_REQUIRED",
	0x37: "CTAP2_ERR_PIN_POLICY_VIOLATION", 0x39: "CTAP2_ERR_REQUEST_TOO_LARGE", 0x3A: "CTAP2_ERR_ACTION_TIMEOUT",
	0x3B: "CTAP2_ERR_UP_REQUIRED", 0x3C: "CTAP2_ERR_UV_BLOCKED", 0x3E: "CTAP2_ERR_INTEGRITY_FAILURE",
	0x3F: "CTAP2_ERR_INVALID_SUBCOMMAND", 0x40: "CTAP2_ERR_UV_INVALID", 0x41: "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
}

var ctap2Hints = map[byte]string{
	0x19: "the key already holds a credential from the excludeCredentials list (registered before)",
	0x26: "the key supports none of the algorithms the relying party offered",
	0x27: "the user declined, or the key refused the operation",
	0x28: "the key's storage for discoverable credentials is full",
	0x2B: "the key does not support a requested option (user verification needs a PIN or biometric, which idpdbg does not send)",
	0x2E: "the key holds no credential for this relying party (wrong key, or the credential was made on another one)",
	0x2F: "nobody touched the key in time",
	0x31: "wrong PIN", 0x32: "the PIN is blocked: reset the key", 0x35: "no PIN is set",
	0x36: "the key needs its PIN (or built-in user verification) for this: pass pin, or with ctap=auto a registration falls back to U2F where it can",
	0x3B: "user presence is required",
}

type ctapError struct{ code byte }

func (e *ctapError) Error() string {
	name := ctap2Errors[e.code]
	if name == "" {
		name = fmt.Sprintf("CTAP2 error 0x%02x", e.code)
	}
	if h := ctap2Hints[e.code]; h != "" {
		return name + ": " + h
	}
	return name
}

var errTouchTimeout = errors.New("timed out waiting for the security key (was it touched?)")

type ctapDevice struct {
	hid         hidDevice
	info        hidInfo
	cid         uint32
	protocol    byte
	version     string
	caps        byte
	onKeepalive func(status byte)
}

// ctaphidFrames splits a message into an initialization packet and
// continuation packets.
func ctaphidFrames(cid uint32, cmd byte, data []byte) ([][]byte, error) {
	if len(data) > 57+128*59 {
		return nil, errors.New("CTAPHID message too long")
	}
	p := make([]byte, hidReportSize)
	binary.BigEndian.PutUint32(p, cid)
	p[4], p[5], p[6] = cmd, byte(len(data)>>8), byte(len(data))
	n := copy(p[7:], data)
	out := [][]byte{p}
	for seq := byte(0); n < len(data); seq++ {
		p = make([]byte, hidReportSize)
		binary.BigEndian.PutUint32(p, cid)
		p[4] = seq
		n += copy(p[5:], data[n:])
		out = append(out, p)
	}
	return out, nil
}

func (d *ctapDevice) send(cid uint32, cmd byte, data []byte) error {
	frames, err := ctaphidFrames(cid, cmd, data)
	if err != nil {
		return err
	}
	for _, p := range frames {
		if err := d.hid.Write(p); err != nil {
			return err
		}
	}
	return nil
}

func (d *ctapDevice) recv(cid uint32, cmd byte, deadline time.Time) ([]byte, error) {
	read := func() ([]byte, error) {
		left := time.Until(deadline)
		if left <= 0 {
			return nil, errTouchTimeout
		}
		p, err := d.hid.Read(left)
		if err != nil {
			return nil, err
		}
		if p == nil {
			return nil, errTouchTimeout
		}
		return p, nil
	}
	for {
		p, err := read()
		if err != nil {
			return nil, err
		}
		if len(p) < 7 || binary.BigEndian.Uint32(p) != cid || p[4]&0x80 == 0 {
			continue // another channel, or a stray continuation packet
		}
		n := int(p[5])<<8 | int(p[6])
		switch p[4] {
		case ctaphidKeepalive:
			if d.onKeepalive != nil && n > 0 {
				d.onKeepalive(p[7])
			}
			continue
		case ctaphidError:
			msg := ctaphidErrors[p[7]]
			if msg == "" {
				msg = fmt.Sprintf("0x%02x", p[7])
			}
			return nil, fmt.Errorf("CTAPHID error: %s", msg)
		}
		if p[4] != cmd {
			return nil, fmt.Errorf("CTAPHID: expected command 0x%02x, got 0x%02x", cmd, p[4])
		}
		data := append([]byte{}, p[7:min(len(p), 7+n)]...)
		for seq := byte(0); len(data) < n; {
			q, err := read()
			if err != nil {
				return nil, err
			}
			if len(q) < 5 || binary.BigEndian.Uint32(q) != cid {
				continue
			}
			if q[4] != seq {
				return nil, fmt.Errorf("CTAPHID: continuation packet %d out of sequence (expected %d)", q[4], seq)
			}
			seq++
			data = append(data, q[5:]...)
		}
		return data[:n], nil
	}
}

// transact sends a command and waits for its answer. When the wait runs
// out (usually: nobody touched the key) it cancels the request.
func (d *ctapDevice) transact(cmd byte, data []byte, timeout time.Duration) ([]byte, error) {
	if err := d.send(d.cid, cmd, data); err != nil {
		return nil, err
	}
	resp, err := d.recv(d.cid, cmd, time.Now().Add(timeout))
	if errors.Is(err, errTouchTimeout) && cmd == ctaphidCBOR {
		d.send(d.cid, ctaphidCancel, nil)
		d.recv(d.cid, cmd, time.Now().Add(time.Second)) // the cancelled request's answer
	}
	return resp, err
}

func ctapInit(h hidDevice, info hidInfo) (*ctapDevice, error) {
	d := &ctapDevice{hid: h, info: info}
	nonce := make([]byte, 8)
	rand.Read(nonce)
	if err := d.send(ctaphidBroadcast, ctaphidInit, nonce); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := d.recv(ctaphidBroadcast, ctaphidInit, deadline)
		if err != nil {
			return nil, fmt.Errorf("CTAPHID_INIT: %w", err)
		}
		if len(resp) >= 17 && bytes.Equal(resp[:8], nonce) {
			d.cid = binary.BigEndian.Uint32(resp[8:12])
			d.protocol, d.caps = resp[12], resp[16]
			d.version = fmt.Sprintf("%d.%d.%d", resp[13], resp[14], resp[15])
			return d, nil
		}
	}
}

// cbor runs a CTAP2 command and returns the response map's raw bytes.
func (d *ctapDevice) cbor(cmd byte, params map[any]any, timeout time.Duration) ([]byte, error) {
	if d.caps&0x04 == 0 {
		return nil, errors.New("this key speaks only U2F (CTAP1), not CTAP2")
	}
	req := []byte{cmd}
	if params != nil {
		req = append(req, cborEncode(params)...)
	}
	resp, err := d.transact(ctaphidCBOR, req, timeout)
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, errors.New("empty CTAP2 response")
	}
	if resp[0] != 0 {
		return nil, &ctapError{code: resp[0]}
	}
	return resp[1:], nil
}

// cborMapFields decodes a CBOR map and also returns each value's raw
// encoding, so that parts can be passed on byte for byte.
func cborMapFields(b []byte) (map[any]any, map[any][]byte, error) {
	if len(b) == 0 || b[0]>>5 != 5 {
		return nil, nil, errors.New("CTAP2 response is not a CBOR map")
	}
	count, off := uint64(b[0]&0x1F), 1
	switch {
	case count == 24 && len(b) > 1:
		count, off = uint64(b[1]), 2
	case count == 25 && len(b) > 2:
		count, off = uint64(binary.BigEndian.Uint16(b[1:3])), 3
	case count > 23:
		return nil, nil, errors.New("CTAP2 response map header not supported")
	}
	vals, raws := map[any]any{}, map[any][]byte{}
	for i := uint64(0); i < count; i++ {
		k, kn, err := cborDecode(b[off:])
		if err != nil {
			return nil, nil, err
		}
		v, vn, err := cborDecode(b[off+kn:])
		if err != nil {
			return nil, nil, err
		}
		vals[k], raws[k] = v, b[off+kn:off+kn+vn]
		off += kn + vn
	}
	return vals, raws, nil
}

// ---- finding and opening keys ----

func fidoDevices() ([]hidInfo, error) {
	if hidEnumerate == nil {
		return nil, errors.New(hidUnavailable)
	}
	return hidEnumerate()
}

func pickFIDO(sel string) (hidInfo, error) {
	devs, err := fidoDevices()
	if err != nil {
		return hidInfo{}, err
	}
	if sel == "" {
		switch len(devs) {
		case 0:
			return hidInfo{}, errors.New("no FIDO security key found: plug one in")
		case 1:
			return devs[0], nil
		}
		var names []string
		for i, d := range devs {
			names = append(names, fmt.Sprintf("%d: %s %s (%s)", i, d.Manufacturer, d.Product, d.Path))
		}
		return hidInfo{}, errors.New("several security keys are connected; pass device: " + strings.Join(names, "; "))
	}
	if i, err := strconv.Atoi(sel); err == nil && i >= 0 && i < len(devs) {
		return devs[i], nil
	}
	for _, d := range devs {
		if d.Path == sel {
			return d, nil
		}
	}
	return hidInfo{}, fmt.Errorf("no security key %q (fido devices lists them)", sel)
}

// withFIDO opens a key, runs f, and closes it, all on one OS thread (macOS
// delivers input reports to the run loop of the thread that opened it).
func withFIDO(c *Ctx, sel string, f func(*ctapDevice) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	info, err := pickFIDO(sel)
	if err != nil {
		return err
	}
	h, err := hidOpen(info.Path)
	if err != nil {
		return err
	}
	defer h.Close()
	d, err := ctapInit(h, info)
	if err != nil {
		return err
	}
	prompted := false
	d.onKeepalive = func(status byte) {
		if status == 2 && !prompted && c != nil && c.Log != nil {
			prompted = true
			c.Log("Touch your security key (%s %s)...", safeText(info.Manufacturer), safeText(info.Product))
		}
	}
	return f(d)
}
