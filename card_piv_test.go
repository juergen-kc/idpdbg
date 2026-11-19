package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"
)

// fakePIV emulates a PIV applet with a PIN, a 3DES management key (no GET
// METADATA, as on older YubiKeys), on-card keys and certificate objects.
type fakePIV struct {
	pin       string
	retries   int
	verified  bool
	mgmt      cipher.Block
	witness   []byte
	authed    bool
	keys      map[byte]any // slot -> *rsa.PrivateKey or *ecdsa.PrivateKey
	objects   map[string][]byte
	chain     []byte
	pinTries  int // VERIFY commands that carried a PIN
	generated int
	closed    bool
}

func newFakePIV(t *testing.T, pin string, mgmtKey []byte) *fakePIV {
	blk, err := des.NewTripleDESCipher(mgmtKey)
	if err != nil {
		t.Fatal(err)
	}
	return &fakePIV{pin: pin, retries: 3, mgmt: blk, keys: map[byte]any{}, objects: map[string][]byte{}}
}

func sw(b []byte, s uint16) []byte { return append(append([]byte{}, b...), byte(s>>8), byte(s)) }

func (f *fakePIV) Transmit(cmd []byte) ([]byte, error) {
	cla, ins, p1, p2 := cmd[0], cmd[1], cmd[2], cmd[3]
	var data []byte
	if len(cmd) > 5 {
		data = cmd[5 : 5+int(cmd[4])]
	}
	if cla&0x10 != 0 {
		f.chain = append(f.chain, data...)
		return sw(nil, 0x9000), nil
	}
	data = append(f.chain, data...)
	f.chain = nil
	_ = p1
	switch ins {
	case 0xA4:
		return sw(nil, 0x9000), nil
	case 0x20:
		if len(cmd) == 4 {
			if f.verified {
				return sw(nil, 0x9000), nil
			}
			if f.retries == 0 {
				return sw(nil, 0x6983), nil
			}
			return sw(nil, 0x63C0|uint16(f.retries)), nil
		}
		f.pinTries++
		if f.retries == 0 {
			return sw(nil, 0x6983), nil
		}
		if string(bytes.TrimRight(data, "\xff")) != f.pin {
			f.retries--
			return sw(nil, 0x63C0|uint16(f.retries)), nil
		}
		f.retries, f.verified = 3, true
		return sw(nil, 0x9000), nil
	case 0xF7:
		return sw(nil, 0x6D00), nil // no GET METADATA on this card
	case 0x87:
		ts, _ := parseTLV(data)
		if p2 == 0x9B {
			w := findTLV(ts, 0x80)
			if w != nil && len(w.Value) == 0 {
				f.witness = make([]byte, 8)
				rand.Read(f.witness)
				enc := make([]byte, 8)
				f.mgmt.Encrypt(enc, f.witness)
				return sw(tlvBytes([]byte{0x7C}, tlvBytes([]byte{0x80}, enc)), 0x9000), nil
			}
			c := findTLV(ts, 0x81)
			if w == nil || c == nil || !bytes.Equal(w.Value, f.witness) {
				return sw(nil, 0x6982), nil
			}
			f.authed = true
			resp := make([]byte, 8)
			f.mgmt.Encrypt(resp, c.Value)
			return sw(tlvBytes([]byte{0x7C}, tlvBytes([]byte{0x82}, resp)), 0x9000), nil
		}
		if !f.verified {
			return sw(nil, 0x6982), nil
		}
		in := findTLV(ts, 0x81)
		var out []byte
		switch k := f.keys[p2].(type) {
		case *rsa.PrivateKey:
			out = new(big.Int).Exp(new(big.Int).SetBytes(in.Value), k.D, k.N).FillBytes(make([]byte, k.Size()))
		case *ecdsa.PrivateKey:
			out, _ = ecdsa.SignASN1(rand.Reader, k, in.Value)
		default:
			return sw(nil, 0x6A80), nil
		}
		return sw(tlvBytes([]byte{0x7C}, tlvBytes([]byte{0x82}, out)), 0x9000), nil
	case 0x47:
		if !f.authed {
			return sw(nil, 0x6982), nil
		}
		ts, _ := parseTLV(data)
		alg := findTLV(ts, 0x80).Value[0]
		f.generated++
		switch alg {
		case 0x07:
			k, _ := rsa.GenerateKey(rand.Reader, 2048)
			f.keys[p2] = k
			e := big.NewInt(int64(k.E)).Bytes()
			return sw(tlvBytes([]byte{0x7F, 0x49}, append(tlvBytes([]byte{0x81}, k.N.Bytes()), tlvBytes([]byte{0x82}, e)...)), 0x9000), nil
		case 0x11:
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			f.keys[p2] = k
			pt := elliptic.Marshal(elliptic.P256(), k.X, k.Y) //nolint:staticcheck
			return sw(tlvBytes([]byte{0x7F, 0x49}, tlvBytes([]byte{0x86}, pt)), 0x9000), nil
		}
		return sw(nil, 0x6A80), nil
	case 0xDB:
		if !f.authed {
			return sw(nil, 0x6982), nil
		}
		ts, _ := parseTLV(data)
		tag, obj := findTLV(ts, 0x5C), findTLV(ts, 0x53)
		f.objects[strings.ToUpper(hex.EncodeToString(tag.Value))] = tlvBytes([]byte{0x53}, obj.Value)
		return sw(nil, 0x9000), nil
	case 0xCB:
		ts, _ := parseTLV(data)
		tag := strings.ToUpper(hex.EncodeToString(findTLV(ts, 0x5C).Value))
		if tag == "5FC109" && !f.verified { // printed information needs the PIN
			return sw(nil, 0x6982), nil
		}
		if obj, ok := f.objects[tag]; ok {
			return sw(obj, 0x9000), nil
		}
		return sw(nil, 0x6A82), nil
	}
	return sw(nil, 0x6D00), nil
}

func (f *fakePIV) Close() error { f.closed = true; f.verified, f.authed = false, false; return nil }

func TestPIVKeyLifecycleAndPKINIT(t *testing.T) {
	mgmtKey := bytes.Repeat([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}, 3)
	card := newFakePIV(t, "123456", mgmtKey)
	listReaders = func() ([]string, error) { return []string{"Emulated YubiKey CCID"}, nil }
	connectCard = func(reader string) (cardConn, cardInfo, error) { return card, cardInfo{Reader: reader}, nil }
	t.Cleanup(func() { listReaders, connectCard = nil, nil })
	secrets := M{"piv_pin": "123456", "management_key": hex.EncodeToString(mgmtKey)}
	with := func(base, extra M) M {
		out := M{}
		for _, m := range []M{base, extra} {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}

	// A wrong management key changes nothing.
	if _, err := tryOp(t, "card.piv_generate", with(secrets, M{"common_name": "alice", "management_key": strings.Repeat("00", 24)})); err == nil || !strings.Contains(err.Error(), "management key") || card.generated != 0 {
		t.Fatalf("wrong management key: %v (generated %d)", err, card.generated)
	}

	gen := run(t, "card.piv_generate", with(secrets, M{"common_name": "alice", "upn": "alice@idpdbg.test"}), nil)
	noFailures(t, gen)
	block, _ := pem.Decode([]byte(str(gen["csr"])))
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "alice" {
		t.Fatalf("CSR: %v", err)
	}
	if !card.closed {
		t.Error("card left open")
	}

	// The lab CA issues a certificate for the card's key, with the UPN.
	pki := newTestPKI(t)
	var sanExt pkix.Extension
	for _, e := range csr.Extensions {
		if e.Id.Equal(oidSubjectAltName) {
			sanExt = e
		}
	}
	issued := issueTestCert(t, &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "alice"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtraExtensions: []pkix.Extension{sanExt}}, pki.caCert, csr.PublicKey, pki.caKey)
	issuedPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issued.Raw}))
	if _, upns := pkinitSANs(issued); len(upns) != 1 || upns[0] != "alice@idpdbg.test" {
		t.Errorf("UPN did not survive the CSR: %v", upns)
	}

	// A certificate for another key is refused before anything is written.
	res := run(t, "card.piv_import", with(secrets, M{"cert": pki.clientPEM}), nil)
	wantStatus(t, res, "certificate matches the slot's key", "fail")
	if _, ok := card.objects["5FC105"]; ok {
		t.Fatal("a mismatched certificate was written")
	}
	noFailures(t, run(t, "card.piv_import", with(secrets, M{"cert": issuedPEM}), nil))

	// A slot with a certificate is not regenerated by accident.
	if _, err := tryOp(t, "card.piv_generate", with(secrets, M{"common_name": "alice"})); err == nil || !strings.Contains(err.Error(), "overwrite") {
		t.Errorf("overwrite guard: %v", err)
	}

	// PKINIT with the card's key, in both modes (RSA decrypts on the card).
	kdc := newMockKDC(t, "IDPDBG.TEST")
	roots := x509.NewCertPool()
	roots.AddCert(pki.caCert)
	kdc.pk = &mockPKINIT{kdcChain: []*x509.Certificate{pki.kdcCert}, kdcKey: pki.kdcKey, clientRoots: roots}
	pk := run(t, "krb.pkinit", M{"principal": "alice@IDPDBG.TEST", "kdc": kdc.addr, "pkinit_piv_slot": "9a", "piv_pin": "123456", "ca_cert": pki.caPEM}, nil)
	noFailures(t, pk)
	if !strings.Contains(str(pk["private_key"]), "PIV slot 9A") || pk["public_key_encryption"].(M)["tgt"] == nil || pk["diffie_hellman"].(M)["tgt"] == nil {
		t.Errorf("PKINIT with the card: %v / %v", pk["private_key"], pk)
	}

	// PIN safety: a wrong PIN is reported with what is left and not retried;
	// with fewer than two attempts left it is not tried at all.
	tries := card.pinTries
	_, err = tryOp(t, "krb.pkinit", M{"principal": "alice@IDPDBG.TEST", "kdc": kdc.addr, "pkinit_piv_slot": "9a", "piv_pin": "654321"})
	if err == nil || !strings.Contains(err.Error(), "wrong PIN: 2 attempt(s) left") || card.pinTries != tries+1 {
		t.Errorf("wrong PIN: %v (tries %d)", err, card.pinTries-tries)
	}
	card.retries = 1
	_, err = tryOp(t, "krb.pkinit", M{"principal": "alice@IDPDBG.TEST", "kdc": kdc.addr, "pkinit_piv_slot": "9a", "piv_pin": "123456"})
	if err == nil || !strings.Contains(err.Error(), "1 attempt(s) left") || card.pinTries != tries+1 {
		t.Errorf("low retries: %v (tries %d)", err, card.pinTries-tries)
	}
}

func TestPIVSlots(t *testing.T) {
	for in, want := range map[string]string{"9a": "5FC105", "9E": "5FC101", "82": "5FC10D", "95": "5FC120"} {
		s, err := pivSlotFor(in)
		if err != nil || strings.ToUpper(hex.EncodeToString(s.object)) != want {
			t.Errorf("%s: %v %X", in, err, s.object)
		}
	}
	for _, bad := range []string{"9b", "81", "96", "", "9a9"} {
		if _, err := pivSlotFor(bad); err == nil {
			t.Errorf("slot %q accepted", bad)
		}
	}
}

// A management key kept on the card behind the PIN (ykman
// change-management-key --protect) is read from there, not asked for.
func TestPIVProtectedManagementKey(t *testing.T) {
	mgmtKey := bytes.Repeat([]byte{0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69, 0x78}, 3)
	card := newFakePIV(t, "246810", mgmtKey)
	card.objects["5FFF00"] = enc(0x53, enc(0x80, enc(0x81, []byte{0x02})))
	card.objects["5FC109"] = enc(0x53, enc(0x88, enc(0x89, mgmtKey)))
	listReaders = func() ([]string, error) { return []string{"Emulated YubiKey CCID"}, nil }
	connectCard = func(reader string) (cardConn, cardInfo, error) { return card, cardInfo{Reader: reader}, nil }
	t.Cleanup(func() { listReaders, connectCard = nil, nil })

	gen := run(t, "card.piv_generate", M{"common_name": "bob", "piv_pin": "246810"}, nil)
	noFailures(t, gen)
	if gen["management_key"] != "PIN-protected on the card" || gen["csr"] == nil || card.generated != 1 {
		t.Errorf("protected key: %v, generated %d", gen["management_key"], card.generated)
	}
	if card.pinTries != 1 {
		t.Errorf("PIN presented %d times, want once per session", card.pinTries)
	}
	for k, v := range gen {
		if strings.Contains(strings.ToLower(fmt.Sprint(v)), hex.EncodeToString(mgmtKey)) {
			t.Errorf("management key leaked in %q", k)
		}
	}
	// Without the PIN it cannot be read, and nothing is generated.
	if _, err := tryOp(t, "card.piv_generate", M{"common_name": "bob", "piv_pin": "000000", "overwrite": true}); err == nil || !strings.Contains(err.Error(), "wrong PIN") || card.generated != 1 {
		t.Errorf("wrong PIN: %v, generated %d", err, card.generated)
	}

	// The old PIN-derived mode is named, not attempted.
	card.objects["5FFF00"] = enc(0x53, enc(0x80, enc(0x81, []byte{0x00}), enc(0x82, bytes.Repeat([]byte{1}, 16))))
	if _, err := tryOp(t, "card.piv_generate", M{"common_name": "bob", "piv_pin": "246810", "overwrite": true}); err == nil || !strings.Contains(err.Error(), "PIN-derived") {
		t.Errorf("derived key: %v", err)
	}
}
