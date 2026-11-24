package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

// fakePGP emulates an OpenPGP card applet: PW1 with a retry counter and
// the two verification modes, the three keys, the signature counter, and
// the operations that need them.
type fakePGP struct {
	pin             string
	tries           int
	verified81      bool
	verified82      bool
	multiSig        bool
	keys            map[string]any // slot -> private key
	created         uint32
	fps             map[string][]byte
	sigCount        int
	verifies        int
	chain           []byte
	ops             []byte
	kdf             bool
	ed25519Prefixed bool
}

var pgpSlotOrder = []string{"signature", "decryption", "authentication"}

func newFakePGP(keys map[string]any) *fakePGP {
	f := &fakePGP{pin: "123456", tries: 3, keys: keys, created: uint32(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).Unix()), fps: map[string][]byte{}}
	return f
}

func (f *fakePGP) attr(slot string) []byte {
	oid := func(h string) []byte { b, _ := hex.DecodeString(h); return b }
	switch k := f.keys[slot].(type) {
	case *rsa.PrivateKey:
		return []byte{1, byte(k.N.BitLen() >> 8), byte(k.N.BitLen()), 0, 17, 0}
	case *ecdsa.PrivateKey:
		o := map[int]string{256: "2A8648CE3D030107", 384: "2B81040022"}[k.Curve.Params().BitSize]
		if slot == "decryption" {
			return append([]byte{0x12}, oid(o)...)
		}
		return append([]byte{0x13}, oid(o)...)
	case ed25519.PrivateKey:
		return append([]byte{0x16}, oid("2B06010401DA470F01")...)
	case *ecdh.PrivateKey:
		return append([]byte{0x12}, oid("2B060104019755010501")...)
	}
	return []byte{1, 8, 0, 0, 17, 0}
}

func (f *fakePGP) publicTemplate(slot string) []byte {
	switch k := f.keys[slot].(type) {
	case *rsa.PrivateKey:
		return tlvBytes([]byte{0x7F, 0x49}, append(tlvBytes([]byte{0x81}, k.N.Bytes()), tlvBytes([]byte{0x82}, big.NewInt(int64(k.E)).Bytes())...))
	case *ecdsa.PrivateKey:
		return tlvBytes([]byte{0x7F, 0x49}, tlvBytes([]byte{0x86}, elliptic.Marshal(k.Curve, k.X, k.Y))) //nolint:staticcheck
	case ed25519.PrivateKey:
		p := []byte(k.Public().(ed25519.PublicKey))
		if f.ed25519Prefixed {
			p = append([]byte{0x40}, p...)
		}
		return tlvBytes([]byte{0x7F, 0x49}, tlvBytes([]byte{0x86}, p))
	case *ecdh.PrivateKey:
		return tlvBytes([]byte{0x7F, 0x49}, tlvBytes([]byte{0x86}, k.PublicKey().Bytes()))
	}
	return nil
}

func (f *fakePGP) ard() []byte {
	var fps, times []byte
	for _, s := range pgpSlotOrder {
		if fp := f.fps[s]; fp != nil {
			fps = append(fps, fp...)
			times = append(times, byte(f.created>>24), byte(f.created>>16), byte(f.created>>8), byte(f.created))
		} else {
			fps = append(fps, make([]byte, 20)...)
			times = append(times, 0, 0, 0, 0)
		}
	}
	multi := byte(0)
	if f.multiSig {
		multi = 1
	}
	ext := byte(0x30)
	if f.kdf {
		ext |= 0x01
	}
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00}
	disc := bytes.Join([][]byte{
		tlvBytes([]byte{0xC0}, []byte{ext, 0, 0, 0xFF, 4, 0xC0, 0, 0xFF, 0, 0}),
		tlvBytes([]byte{0xC1}, f.attr("signature")), tlvBytes([]byte{0xC2}, f.attr("decryption")), tlvBytes([]byte{0xC3}, f.attr("authentication")),
		tlvBytes([]byte{0xC4}, []byte{multi, 127, 127, 127, byte(f.tries), 0, 3}),
		tlvBytes([]byte{0xC5}, fps), tlvBytes([]byte{0xCD}, times),
	}, nil)
	return tlvBytes([]byte{0x6E}, append(tlvBytes([]byte{0x4F}, aid), tlvBytes([]byte{0x73}, disc)...))
}

func (f *fakePGP) Transmit(cmd []byte) ([]byte, error) {
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
	f.ops = append(f.ops, ins)
	switch ins {
	case 0xA4:
		return sw(nil, 0x9000), nil
	case 0xCA:
		switch uint16(p1)<<8 | uint16(p2) {
		case 0x006E:
			return sw(f.ard(), 0x9000), nil
		case 0x007A:
			c := f.sigCount
			return sw(tlvBytes([]byte{0x7A}, tlvBytes([]byte{0x93}, []byte{byte(c >> 16), byte(c >> 8), byte(c)})), 0x9000), nil
		case 0x00F9:
			return sw(tlvBytes([]byte{0xF9}, tlvBytes([]byte{0x81}, []byte{3})), 0x9000), nil
		}
		return sw(nil, 0x6A88), nil
	case 0x47:
		for i, crt := range []byte{0xB6, 0xB8, 0xA4} {
			if p1 == 0x81 && len(data) > 0 && data[0] == crt {
				if t := f.publicTemplate(pgpSlotOrder[i]); t != nil {
					return sw(t, 0x9000), nil
				}
				return sw(nil, 0x6A88), nil
			}
		}
		return sw(nil, 0x6A80), nil
	case 0x20:
		f.verifies++
		if f.tries == 0 {
			return sw(nil, 0x6983), nil
		}
		if string(data) != f.pin {
			f.tries--
			return sw(nil, 0x6982), nil
		}
		f.tries = 3
		if p2 == 0x81 {
			f.verified81 = true
		} else {
			f.verified82 = true
		}
		return sw(nil, 0x9000), nil
	case 0x2A, 0x88:
		switch {
		case ins == 0x2A && p1 == 0x9E: // sign
			if !f.verified81 {
				return sw(nil, 0x6982), nil
			}
			if !f.multiSig {
				f.verified81 = false
			}
			f.sigCount++
			return f.sign(f.keys["signature"], data)
		case ins == 0x88: // authenticate
			if !f.verified82 {
				return sw(nil, 0x6982), nil
			}
			return f.sign(f.keys["authentication"], data)
		case ins == 0x2A && p1 == 0x80: // decipher
			if !f.verified82 {
				return sw(nil, 0x6982), nil
			}
			switch k := f.keys["decryption"].(type) {
			case *rsa.PrivateKey:
				if data[0] != 0 {
					return sw(nil, 0x6A80), nil
				}
				pt, err := rsa.DecryptPKCS1v15(nil, k, data[1:])
				if err != nil {
					return sw(nil, 0x6A80), nil
				}
				return sw(pt, 0x9000), nil
			default:
				ts, err := parseTLV(data)
				if err != nil || len(ts) == 0 || ts[0].Tag != 0xA6 {
					return sw(nil, 0x6A80), nil
				}
				pt := findTLV(findTLV(ts[0].Kids, 0x7F49).Kids, 0x86)
				var priv *ecdh.PrivateKey
				if e, ok := k.(*ecdsa.PrivateKey); ok {
					priv, _ = e.ECDH()
				} else {
					priv = k.(*ecdh.PrivateKey)
				}
				peer, err := priv.Curve().NewPublicKey(pt.Value)
				if err != nil {
					return sw(nil, 0x6A80), nil
				}
				z, _ := priv.ECDH(peer)
				return sw(z, 0x9000), nil
			}
		}
	}
	return sw(nil, 0x6D00), nil
}

func (f *fakePGP) sign(key any, in []byte) ([]byte, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		em := append(append([]byte{0, 1}, bytes.Repeat([]byte{0xFF}, k.Size()-len(in)-3)...), 0)
		em = append(em, in...)
		return sw(new(big.Int).Exp(new(big.Int).SetBytes(em), k.D, k.N).FillBytes(make([]byte, k.Size())), 0x9000), nil
	case *ecdsa.PrivateKey:
		r, s, _ := ecdsa.Sign(rand.Reader, k, in)
		n := (k.Curve.Params().BitSize + 7) / 8
		return sw(append(r.FillBytes(make([]byte, n)), s.FillBytes(make([]byte, n))...), 0x9000), nil
	case ed25519.PrivateKey:
		return sw(ed25519.Sign(k, in), 0x9000), nil
	}
	return sw(nil, 0x6A88), nil
}

func (f *fakePGP) Close() error { return nil }

func useFakePGP(t *testing.T, f *fakePGP) {
	listReaders = func() ([]string, error) { return []string{"Emulated OpenPGP CCID"}, nil }
	connectCard = func(reader string) (cardConn, cardInfo, error) { return f, cardInfo{Reader: reader}, nil }
	t.Cleanup(func() { listReaders, connectCard = nil, nil })
}

func TestOpenPGPCardRSA(t *testing.T) {
	keys := map[string]any{}
	for _, s := range pgpSlotOrder {
		keys[s], _ = rsa.GenerateKey(rand.Reader, 2048)
	}
	f := newFakePGP(keys)
	for _, s := range pgpSlotOrder {
		k := keys[s].(*rsa.PrivateKey)
		f.fps[s] = (&pgpPublic{algo: 1, n: k.N.Bytes(), e: big.NewInt(int64(k.E)).Bytes()}).v4Fingerprint(f.created)
	}
	useFakePGP(t, f)

	res := runCLI(t, "card.openpgp_sign", M{"openpgp_pin": "123456", "message": "hello"})
	noFailures(t, res)
	if str(res["signature"]) == "" {
		t.Error("no signature from the CLI")
	}
	wantStatus(t, res, "public key matches the stored fingerprint", "pass")
	wantStatus(t, res, "signature verifies with the slot's public key", "pass")
	wantStatus(t, res, "signature counter went up by one", "pass")
	if res["key"].(M)["algorithm"] != "RSA 2048" || !strings.Contains(str(res["key"].(M)["public_key_pem"]), "PUBLIC KEY") {
		t.Errorf("key: %v", res["key"])
	}
	auth := run(t, "card.openpgp_sign", M{"openpgp_pin": "123456", "slot": "authentication", "hash": "sha512"}, nil)
	noFailures(t, auth)
	wantStatus(t, auth, "card signed (INTERNAL AUTHENTICATE)", "pass")
	if checkOf(auth, "signature counter") != nil {
		t.Error("signature counter checked for an authentication")
	}

	dec := run(t, "card.openpgp_decrypt", M{"openpgp_pin": "123456"}, nil)
	noFailures(t, dec)
	wantStatus(t, dec, "the card's answer is the value idpdbg encrypted", "pass")
	ct, _ := rsa.EncryptPKCS1v15(rand.Reader, &keys["decryption"].(*rsa.PrivateKey).PublicKey, []byte("session key"))
	given := runCLI(t, "card.openpgp_decrypt", M{"openpgp_pin": "123456", "ciphertext": hex.EncodeToString(ct)})
	if given["plaintext"] != hex.EncodeToString([]byte("session key")) {
		t.Errorf("plaintext: %v", given)
	}
	// Over MCP the card is no oracle: caller data is refused, and the test
	// signature is not handed out.
	n := len(f.ops)
	for op, a := range map[string]M{"card.openpgp_sign": {"message": "a commit to sign"}, "card.openpgp_decrypt": {"ciphertext": hex.EncodeToString(ct)}} {
		a["openpgp_pin"] = "123456"
		if _, err := runOp(context.Background(), findOp(op), a, false, nil); err == nil || !strings.Contains(err.Error(), "only accepted from the CLI") {
			t.Errorf("%s over MCP: %v", op, err)
		}
	}
	if len(f.ops) != n {
		t.Errorf("the card was used for refused calls: % X", f.ops[n:])
	}
	if mcp, err := runOp(context.Background(), findOp("card.openpgp_sign"), M{"openpgp_pin": "123456"}, false, nil); err != nil || mcp["signature"] != nil {
		t.Errorf("MCP self-test: %v, signature %v", err, mcp["signature"])
	}
	if !bytes.Contains(f.ops, []byte{0x2A}) {
		t.Error("no PSO")
	}

	// A wrong PIN costs one attempt and is not retried.
	before := f.verifies
	if _, err := tryOp(t, "card.openpgp_sign", M{"openpgp_pin": "654321"}); err == nil || !strings.Contains(err.Error(), "wrong PIN: 2 attempt(s) left") || f.verifies != before+1 {
		t.Fatalf("wrong PIN: %v, %d verifies", err, f.verifies-before)
	}
	// With one attempt left idpdbg does not try.
	f.tries = 1
	if _, err := tryOp(t, "card.openpgp_sign", M{"openpgp_pin": "123456"}); err == nil || !strings.Contains(err.Error(), "1 attempt(s) left") || f.verifies != before+1 {
		t.Fatalf("last attempt: %v", err)
	}
	f.tries = 3
	// No PIN to be had (MCP, no terminal): refused before VERIFY.
	if _, err := tryOp(t, "card.openpgp_sign", M{}); err == nil || !strings.Contains(err.Error(), "openpgp_pin") || f.verifies != before+1 {
		t.Fatalf("no PIN: %v", err)
	}
	// A KDF-hashed PIN is refused rather than sent wrongly.
	f.kdf = true
	if _, err := tryOp(t, "card.openpgp_sign", M{"openpgp_pin": "123456"}); err == nil || !strings.Contains(err.Error(), "KDF") {
		t.Fatalf("KDF: %v", err)
	}
	f.kdf = false
	// A fingerprint that does not match the key.
	f.fps["signature"] = bytes.Repeat([]byte{7}, 20)
	mism := run(t, "card.openpgp_sign", M{"openpgp_pin": "123456"}, nil)
	wantStatus(t, mism, "public key matches the stored fingerprint", "warn")
	// An empty slot: no PIN is spent.
	f.fps["signature"] = nil
	v := f.verifies
	empty := run(t, "card.openpgp_sign", M{"openpgp_pin": "123456"}, nil)
	wantStatus(t, empty, "signature key present", "fail")
	if f.verifies != v {
		t.Error("PIN spent on an empty slot")
	}
}

func TestOpenPGPCardECC(t *testing.T) {
	sigKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	decKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_, authKey, _ := ed25519.GenerateKey(rand.Reader)
	f := newFakePGP(map[string]any{"signature": sigKey, "decryption": decKey, "authentication": authKey})
	f.multiSig = true
	p256oid, _ := hex.DecodeString("2A8648CE3D030107")
	f.fps["signature"] = (&pgpPublic{algo: 0x13, oid: p256oid, curve: "P-256", point: elliptic.Marshal(elliptic.P256(), sigKey.X, sigKey.Y)}).v4Fingerprint(f.created) //nolint:staticcheck
	for _, s := range []string{"decryption", "authentication"} {
		k := map[string]any{"decryption": decKey.PublicKey(), "authentication": authKey.Public()}[s]
		var pub pgpPublic
		if s == "decryption" {
			oid, _ := hex.DecodeString("2B060104019755010501")
			pub = pgpPublic{algo: 0x12, oid: oid, curve: "Curve25519", point: k.(*ecdh.PublicKey).Bytes()}
		} else {
			oid, _ := hex.DecodeString("2B06010401DA470F01")
			pub = pgpPublic{algo: 0x16, oid: oid, curve: "Ed25519", point: k.(ed25519.PublicKey)}
		}
		f.fps[s] = pub.v4Fingerprint(f.created)
	}
	useFakePGP(t, f)

	res := run(t, "card.openpgp_sign", M{"openpgp_pin": "123456"}, nil)
	noFailures(t, res)
	wantStatus(t, res, "public key matches the stored fingerprint", "pass")
	wantStatus(t, res, "signature verifies with the slot's public key", "pass")
	if res["key"].(M)["algorithm"] != "ECDSA P-256" {
		t.Errorf("key: %v", res["key"])
	}
	auth := run(t, "card.openpgp_sign", M{"openpgp_pin": "123456", "slot": "authentication"}, nil)
	noFailures(t, auth)
	wantStatus(t, auth, "signature verifies with the slot's public key", "pass")
	f.ed25519Prefixed = true // a card that sends the 0x40-prefixed point
	auth = run(t, "card.openpgp_sign", M{"openpgp_pin": "123456", "slot": "authentication"}, nil)
	noFailures(t, auth)

	dec := run(t, "card.openpgp_decrypt", M{"openpgp_pin": "123456"}, nil)
	noFailures(t, dec)
	wantStatus(t, dec, "the card's answer is the value idpdbg encrypted", "pass")
	wantStatus(t, dec, "public key matches the stored fingerprint", "pass")
	if _, err := tryOp(t, "card.openpgp_sign", M{"openpgp_pin": "123456", "slot": "decryption"}); err == nil {
		t.Error("signing with the decryption slot")
	}
}

func runCLI(t *testing.T, name string, args M) M {
	t.Helper()
	res, err := runOp(context.Background(), findOp(name), args, true, nil)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

// OpenPGP v4 fingerprints of keys GnuPG 2.5 made, as GnuPG printed them: an
// independent check of v4Fingerprint for every algorithm the cards use.
func TestOpenPGPFingerprintsAgainstGnuPG(t *testing.T) {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	for _, c := range []struct {
		name    string
		pub     pgpPublic
		created uint32
		fpr     string
	}{
		{"RSA 2048", pgpPublic{algo: 0x01, n: h("A738AFC52C94A86ECD823EC1351CB766A99541819C78F672AE193321EEDFC6A56D10FDA905A71CA1BDF87118375FC6A5B77258F5EFC5FAB6CF7612A85A11E53FBD1352DCD4DC9519773DC6118619A20D7BA32AA04D855DDA663F31DD57458606ADD74385C17CBFB2CAEAAFACCEE41540F0A4A55569FF609AC6DAFC2BBC894840E702AD73DF5B5CC421BEFC765B577537EF4585208047B10192963155711ADD339151B45BF6CBEC972F8F445CC7E189D882DC0571E348850FB8DB319F72F99B87BC39AFBB1D93DC1D8E677FB36A62FCFD7F4B0646FAACA061F123E61F094B065B30AC8DF90B801BB2C040BBBF148FE0806887AD039051473A7472B6F47B2DC41F"), e: h("010001")}, 1795548247, "C8C29D87CA906F51BC525A6A3404B95D23BC7DE2"},
		{"ECDSA P-256", pgpPublic{algo: 0x13, oid: h("2A8648CE3D030107"), curve: "P-256", point: h("049EE2B3E419543A9DFBE510136F65DD231FB3626AC40217DD9B0F742684F864B8703F3D1C174AD9C5BD2B75DB5D3D833D4E25C6007BCD7A11D3998A709722711A")}, 1795548247, "C927E2E3FBB001829762F7750CFAECACC029E75F"},
		{"EdDSA Ed25519", pgpPublic{algo: 0x16, oid: h("2B06010401DA470F01"), curve: "Ed25519", point: h("407FCD72901CFC1AD0B9A7C1873C4D863F8A06D81B28E8CC20B5F47A3B58FBAE55")}, 1795548256, "B2C647E9AF75E8D7B63412CAC713466C2A8AF242"},
		{"ECDH Curve25519", pgpPublic{algo: 0x12, oid: h("2B060104019755010501"), curve: "Curve25519", point: h("407CE97D0BE3C860F67622C320C1CBCCC9C50DF310319F23AEB014D8FC06524211")}, 1795548257, "4B99651555CF7059375EB2381E65BDAF0D84E43E"},
	} {
		if got := strings.ToUpper(hex.EncodeToString(c.pub.v4Fingerprint(c.created))); got != c.fpr {
			t.Errorf("%s: %s, GnuPG says %s", c.name, got, c.fpr)
		}
	}
}
