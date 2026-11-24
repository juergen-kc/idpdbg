package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// enc builds one BER-TLV with the right length form.
func enc(tag uint32, v ...[]byte) []byte {
	val := bytes.Join(v, nil)
	var t []byte
	for x := tag; x > 0; x >>= 8 {
		t = append([]byte{byte(x)}, t...)
	}
	switch l := len(val); {
	case l < 0x80:
		t = append(t, byte(l))
	case l < 0x100:
		t = append(t, 0x81, byte(l))
	default:
		t = append(t, 0x82, byte(l>>8), byte(l))
	}
	return append(t, val...)
}

// fascn encodes a FASC-N from its 5-bit characters (four data bits least
// significant first, then odd parity) and appends the LRC.
func fascn(fields ...string) []byte {
	chars := []int{0x0B}
	for i, f := range fields {
		for _, r := range f {
			chars = append(chars, int(r-'0'))
		}
		if i < len(fields)-1 {
			chars = append(chars, 0x0D)
		}
	}
	chars = append(chars, 0x0F)
	lrc := 0
	for _, c := range chars {
		lrc ^= c
	}
	chars = append(chars, lrc)
	out := make([]byte, 25)
	pos := 0
	for _, c := range chars {
		ones := 0
		for j := 0; j < 4; j++ {
			bit := c >> j & 1
			ones += bit
			out[pos/8] |= byte(bit) << (7 - pos%8)
			pos++
		}
		if ones%2 == 0 {
			out[pos/8] |= 1 << (7 - pos%8)
		}
		pos++
	}
	return out
}

func TestAPDU(t *testing.T) {
	sel := run(t, "card.apdu", M{"command": "00 A4 04 00 09 A0 00 00 03 08 00 00 10 00 00", "response": "61 08 4F 06 00 00 10 00 01 00 90 00"}, nil)
	cmd := sel["command"].(M)
	if cmd["instruction"] != "SELECT" || cmd["applet"] != "PIV" || cmd["le"] != 0 {
		t.Errorf("select: %v", cmd)
	}
	wantStatus(t, sel, "status word 9000", "pass")
	if tl := sel["response"].(M)["tlv"].([]M); tl[0]["tag"] != "61" || tl[0]["children"] == nil {
		t.Errorf("response TLV: %v", tl)
	}
	// PINs never reach the output.
	for _, c := range []string{"0020008008313233343536FFFF", "002C008110313233343536FFFF3132333435363738", "000300000A7301FF0102030405060708",
		"00FF FF FE 1A 9B 18 010203040506070801020304050607080102030405060708"} {
		out, _ := json.Marshal(run(t, "card.apdu", M{"command": c}, nil))
		if strings.Contains(string(out), "313233") || strings.Contains(string(out), "0102030405") {
			t.Errorf("secret data shown for %s: %s", c, out)
		}
	}
	v := run(t, "card.apdu", M{"command": "0020008008313233343536FFFF"}, nil)["command"].(M)
	if v["key_reference"] != "PIV PIN" || !strings.Contains(v["data"].(string), "8 bytes") {
		t.Errorf("verify: %v", v)
	}
	// An OpenPGP key import is hidden; a PIV certificate PUT DATA is not.
	if d := run(t, "card.apdu", M{"command": "00DB3FFF06" + "4D04B6007F48"}, nil)["command"].(M)["data"]; !strings.Contains(d.(string), "not shown") {
		t.Errorf("key import shown: %v", d)
	}
	if d := run(t, "card.apdu", M{"command": "00DB3FFF07" + "5C035FC1055300"}, nil)["command"].(M)["data"]; d != "5C035FC1055300" {
		t.Errorf("PUT DATA: %v", d)
	}
	// Deny-by-default writes: chained blocks, PIN-protected objects and
	// non-public OpenPGP objects are hidden; public ones are shown.
	for _, c := range []string{"10DB3FFF04" + "01020304", "00DB3FFF0D" + "5C035FC109" + "5306880489020102", "00DA00D50401020304",
		"00DA00F90401020304", "000B00000401020304", "10DA005B0401020304"} {
		if d := run(t, "card.apdu", M{"command": c}, nil)["command"].(M)["data"]; !strings.Contains(d.(string), "not shown") {
			t.Errorf("%s shown: %v", c, d)
		}
	}
	if d := run(t, "card.apdu", M{"command": "00DA5F50047777772E"}, nil)["command"].(M)["data"]; d != "7777772E" {
		t.Errorf("public URL hidden: %v", d)
	}
	if d := run(t, "card.apdu", M{"command": "00DB3FFF07" + "5C035FC1155300"}, nil)["command"].(M)["data"]; d != "5C035FC1155300" {
		t.Errorf("retired cert hidden: %v", d)
	}
	// The PIN-protected management key never shows in a decoded response.
	out, _ := json.Marshal(run(t, "card.apdu", M{"response": "5308" + "8806" + "8904AABBCCDD" + "9000"}, nil))
	if strings.Contains(string(out), "AABBCCDD") {
		t.Errorf("management key shown: %s", out)
	}
	out, _ = json.Marshal(run(t, "card.piv", M{"data": "5308" + "8806" + "8904AABBCCDD"}, nil))
	if strings.Contains(string(out), "AABBCCDD") {
		t.Errorf("card.piv shows the management key: %s", out)
	}
	g := run(t, "card.apdu", M{"command": "00CB3FFF055C035FC10200"}, nil)["command"].(M)
	if g["object_name"] != "CHUID" {
		t.Errorf("GET DATA PIV: %v", g)
	}
	if g := run(t, "card.apdu", M{"command": "00CA006E00"}, nil)["command"].(M); g["object_name"] != "Application Related Data" {
		t.Errorf("GET DATA OpenPGP: %v", g)
	}
	if e := run(t, "card.apdu", M{"command": "00CB3FFF000005" + "5C035FC102" + "0000"}, nil)["command"].(M); e["object_name"] != "CHUID" || e["le"] != 0 {
		t.Errorf("extended: %v", e)
	}
	for sw, want := range map[string]string{"63C2": "warn", "63C0": "fail", "6983": "fail", "6982": "fail", "6A82": "fail", "6105": "info", "6C10": "warn"} {
		wantStatus(t, run(t, "card.apdu", M{"response": sw}, nil), "status word "+sw, want)
	}
	if m := run(t, "card.apdu", M{"response": "63C2"}, nil)["response"].(M)["meaning"]; !strings.Contains(m.(string), "2 tries left") {
		t.Errorf("63C2: %v", m)
	}
	if _, err := tryOp(t, "card.apdu", M{"command": "00A40400"}); err != nil {
		t.Errorf("case 1 APDU: %v", err)
	}
	if _, err := tryOp(t, "card.apdu", M{"command": "00A4040009A000"}); err == nil {
		t.Error("Lc past the end accepted")
	}
}

func tryOp(t *testing.T, name string, args M) (M, error) {
	t.Helper()
	return runOp(t.Context(), findOp(name), args, false, nil)
}

func TestFASCN(t *testing.T) {
	// The spec-built encoder against a hand-checked first byte: start
	// sentinel 11010 then '9' = 1001 + parity 1 -> 1101 0100 11.. = D4.
	known := fascn("9999", "9999", "999999", "0", "1", "1112223333"+"1"+"1223"+"2")
	if known[0] != 0xD4 {
		t.Errorf("encoder: %X", known)
	}
	f, problems := decodeFASCN(known)
	if len(problems) > 0 || f["agency_code"] != "9999" || f["system_code"] != "9999" || f["credential_number"] != "999999" ||
		f["person_identifier"] != "1112223333" || f["organizational_identifier"] != "1223" {
		t.Errorf("FASC-N: %v %v", f, problems)
	}
	if _, problems := decodeFASCN(fascn("9999", "9999", "999999", "0", "1", "11122233331122")); len(problems) == 0 {
		t.Error("short PI/OC/OI/POA not flagged")
	}
	b := fascn("0032", "0001", "092446", "0", "1", "1112223333"+"1"+"1223"+"2")
	f, problems = decodeFASCN(b)
	if len(problems) > 0 || f["agency_code"] != "0032" || f["credential_number"] != "092446" || f["person_association"] != "2" {
		t.Errorf("round trip: %v %v", f, problems)
	}
	bad := append([]byte(nil), b...)
	bad[3] ^= 0x10
	if _, problems := decodeFASCN(bad); len(problems) == 0 {
		t.Error("flipped bit not caught")
	}
	// Two flipped bits in the LRC character keep its parity: only the LRC catches it.
	lrc := append([]byte(nil), b...)
	lrc[24] ^= 0x18
	if _, problems := decodeFASCN(lrc); len(problems) != 1 || !strings.Contains(problems[0], "redundancy") {
		t.Errorf("LRC: %v", problems)
	}
}

func TestPIVObjects(t *testing.T) {
	guid := bytes.Repeat([]byte{0x11}, 16)
	chuid := func(exp string, signed bool) string {
		sig := []byte{}
		if signed {
			sig = []byte{0x30, 0x00}
		}
		return hex.EncodeToString(enc(0x53, enc(0x30, fascn("0032", "0001", "092446", "0", "1", "1112223333112232")), enc(0x34, guid),
			enc(0x35, []byte(exp)), enc(0x3E, sig), enc(0xFE)))
	}
	res := run(t, "card.piv", M{"data": chuid("20991231", true)}, nil)
	noFailures(t, res)
	if res["object"] != "chuid" || res["expires"] != "2099-12-31" || res["guid"] != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("chuid: %v", res)
	}
	wantStatus(t, run(t, "card.piv", M{"data": chuid("20200101", true)}, nil), "CHUID not expired", "fail")
	wantStatus(t, run(t, "card.piv", M{"data": chuid("20991231", false)}, nil), "issuer signature present", "warn")

	_, cert, _, _ := selfSigned(t)
	plain := enc(0x53, enc(0x70, cert.Raw), enc(0x71, []byte{0}), enc(0xFE))
	res = run(t, "card.piv", M{"data": hex.EncodeToString(plain)}, nil)
	if res["object"] != "certificate" || res["certificate"] == nil || checkOf(res, "certificate parses").Status != "pass" {
		t.Errorf("cert: %v", res)
	}
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(cert.Raw)
	w.Close()
	res = run(t, "card.piv", M{"data": hex.EncodeToString(enc(0x53, enc(0x70, gz.Bytes()), enc(0x71, []byte{1}), enc(0xFE)))}, nil)
	wantStatus(t, res, "compressed certificate inflates", "pass")
	wantStatus(t, res, "certificate parses", "pass")
	wantStatus(t, run(t, "card.piv", M{"data": hex.EncodeToString(enc(0x53, enc(0x70, cert.Raw[:40]), enc(0x71, []byte{0})))}, nil), "certificate parses", "fail")

	disc := run(t, "card.piv", M{"data": hex.EncodeToString(enc(0x7E, enc(0x4F, []byte{0xA0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0}), enc(0x5F2F, []byte{0x60, 0x20})))}, nil)
	pol := disc["pin_usage_policy"].(M)
	if disc["object"] != "discovery" || pol["piv_pin"] != true || pol["global_pin"] != true || pol["primary"] != "global PIN" {
		t.Errorf("discovery: %v", disc)
	}
}

func TestOpenPGPCard(t *testing.T) {
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00}
	fps := append(bytes.Repeat([]byte{0xAA}, 20), make([]byte, 40)...)
	gen := make([]byte, 12)
	binary.BigEndian.PutUint32(gen, 1700000000)
	ard := func(rsaBits uint16, pw []byte) string {
		rsa := []byte{0x01, byte(rsaBits >> 8), byte(rsaBits), 0x00, 0x11, 0x00}
		return hex.EncodeToString(enc(0x6E, enc(0x4F, aid), enc(0x5F52, []byte{0, 0x73, 0, 0, 0xE0, 0x05, 0x90, 0x00}),
			enc(0x73, enc(0xC0, []byte{0x7D, 0, 0x0B, 0xFE, 0x08, 0, 0, 0xFF, 0, 0}), enc(0xC1, rsa),
				enc(0xC2, append([]byte{0x12}, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01)),
				enc(0xC3, append([]byte{0x16}, 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01)),
				enc(0xC4, pw), enc(0xC5, fps), enc(0xCD, gen))))
	}
	res := run(t, "card.openpgp", M{"data": ard(4096, []byte{0, 127, 127, 127, 3, 0, 3})}, nil)
	noFailures(t, res)
	a := res["aid"].(M)
	if a["version"] != "3.4" || a["serial"] != "12345678" || !strings.Contains(a["manufacturer"].(string), "Yubico") {
		t.Errorf("aid: %v", a)
	}
	keys := res["keys"].([]M)
	if keys[0]["fingerprint"] != strings.Repeat("AA", 20) || keys[0]["generated"] != "2023-11-14T22:13:20Z" || keys[1]["fingerprint"] != nil {
		t.Errorf("keys: %v", keys)
	}
	if keys[0]["attributes"].(M)["bits"] != 4096 || keys[1]["attributes"].(M)["curve"] != "Curve25519 (ECDH)" || keys[2]["attributes"].(M)["curve"] != "Ed25519" {
		t.Errorf("algorithms: %v", keys)
	}
	if res["extended_capabilities"].(M)["key_import"] != true || res["pin_status"].(M)["pw1_tries_left"] != byte(3) {
		t.Errorf("caps/pins: %v %v", res["extended_capabilities"], res["pin_status"])
	}
	wantStatus(t, res, "decryption key", "info")
	wantStatus(t, run(t, "card.openpgp", M{"data": ard(4096, []byte{0, 127, 127, 127, 0, 0, 3})}, nil), "PW1 (user PIN) retries", "fail")
	yk := run(t, "card.openpgp", M{"data": ard(2048, []byte{0xFF, 127, 127, 127, 3, 0, 3})}, nil) // as a YubiKey 5.1 sends it
	wantStatus(t, yk, "PW1 signature policy byte", "info")
	if yk["pin_status"].(M)["pw1_valid_for_multiple_signatures"] != true {
		t.Errorf("FF read as one signature per PIN: %v", yk["pin_status"])
	}
	wantStatus(t, run(t, "card.openpgp", M{"data": ard(4096, []byte{0, 127, 127, 127, 3, 0, 1})}, nil), "PW3 (admin PIN) retries", "warn")
	wantStatus(t, run(t, "card.openpgp", M{"data": ard(1024, []byte{0, 127, 127, 127, 3, 0, 3})}, nil), "signature: key size", "warn")
}

func TestTLVErrors(t *testing.T) {
	for _, in := range []string{"5F", "5F2F", "7082FFFF00", "53850000000001"} {
		if ts, err := parseTLV(mustHex(t, in)); err == nil {
			t.Errorf("%s parsed: %v", in, ts)
		}
	}
	if _, err := cardBytes("not hex !!"); err == nil {
		t.Error("garbage accepted")
	}
}

func mustHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeCard emulates a token with PIV and OpenPGP applets. It answers in
// chunks with 61xx, asks for the right Le with 6Cxx, and records every
// instruction so the test can prove no PIN was ever sent.
type fakeCard struct {
	selected string
	objects  map[string][]byte // "piv:5FC102", "pgp:006E"
	pending  []byte
	seen     []byte
	closed   bool
}

func (f *fakeCard) Transmit(cmd []byte) ([]byte, error) {
	f.seen = append(f.seen, cmd[1])
	reply := func(b []byte) []byte {
		if len(b) > 100 {
			f.pending = b[100:]
			n := len(f.pending)
			if n > 255 {
				n = 0
			}
			return append(append([]byte(nil), b[:100]...), 0x61, byte(n))
		}
		return append(append([]byte(nil), b...), 0x90, 0x00)
	}
	switch cmd[1] {
	case 0xC0:
		p := f.pending
		f.pending = nil
		return reply(p), nil
	case 0xA4:
		aid := strings.ToUpper(hex.EncodeToString(cmd[5 : 5+int(cmd[4])]))
		switch {
		case strings.HasPrefix(aid, "A000000308"):
			f.selected = "piv"
		case aid == "D27600012401":
			f.selected = "pgp"
		default:
			return []byte{0x6A, 0x82}, nil
		}
		for k := range f.objects { // an applet exists only if it holds something
			if strings.HasPrefix(k, f.selected+":") {
				return []byte{0x90, 0x00}, nil
			}
		}
		f.selected = ""
		return []byte{0x6A, 0x82}, nil
	case 0xCB:
		if obj, ok := f.objects["piv:"+strings.ToUpper(hex.EncodeToString(cmd[7:7+int(cmd[6])]))]; ok && f.selected == "piv" {
			return reply(obj), nil
		}
	case 0xCA:
		key := "pgp:" + strings.ToUpper(hex.EncodeToString(cmd[2:4]))
		if obj, ok := f.objects[key]; ok && f.selected == "pgp" {
			if key == "pgp:5F50" && int(cmd[4]) != len(obj) {
				return []byte{0x6C, byte(len(obj))}, nil
			}
			return reply(obj), nil
		}
	}
	return []byte{0x6A, 0x82}, nil
}

func (f *fakeCard) Close() error { f.closed = true; return nil }

func TestCardRead(t *testing.T) {
	_, cert, _, _ := selfSigned(t)
	aid := []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00}
	card := &fakeCard{objects: map[string][]byte{
		"piv:5FC105": enc(0x53, enc(0x70, cert.Raw), enc(0x71, []byte{0}), enc(0xFE)),
		"piv:5FC102": enc(0x53, enc(0x30, fascn("0032", "0001", "092446", "0", "1", "1112223333112232")), enc(0x34, bytes.Repeat([]byte{1}, 16)),
			enc(0x35, []byte("20991231")), enc(0x3E, []byte{0x30, 0})),
		"piv:7E":   enc(0x7E, enc(0x4F, []byte{0xA0, 0, 0, 3, 8, 0, 0, 0x10, 0, 1, 0}), enc(0x5F2F, []byte{0x40, 0x00})),
		"pgp:006E": enc(0x6E, enc(0x4F, aid), enc(0x73, enc(0xC1, []byte{1, 8, 0, 0, 0x11, 0}), enc(0xC4, []byte{0, 127, 127, 127, 2, 0, 3}))),
		"pgp:5F50": []byte("https://keys.example/a.asc"),
	}}
	listReaders = func() ([]string, error) { return []string{"Other Reader", "Emulated Token CCID"}, nil }
	connectCard = func(reader string) (cardConn, cardInfo, error) {
		return card, cardInfo{Reader: reader, ATR: append([]byte{0x3B, 0xF8, 0x13, 0x00}, []byte("Emulated")...)}, nil
	}
	t.Cleanup(func() { listReaders, connectCard = nil, nil })

	res := run(t, "card.read", M{"reader": "emulated"}, nil)
	for _, c := range res["checks"].(Checks) { // the test certificate has no SAN; everything else is clean
		if c.Status == "fail" && !strings.Contains(c.Name, "subjectAltName") {
			t.Errorf("check failed: %s — %s", c.Name, c.Detail)
		}
	}
	if res["reader"] != "Emulated Token CCID" || res["atr_text"] != "Emulated" || !card.closed {
		t.Errorf("reader: %v %v closed=%v", res["reader"], res["atr_text"], card.closed)
	}
	piv := res["piv"].(M)
	if piv["chuid"].(M)["expires"] != "2099-12-31" || piv["cert_9a_piv_authentication"].(M)["certificate"] == nil || piv["cert_9c_digital_signature"] != nil {
		t.Errorf("piv: %v", piv)
	}
	wantStatus(t, res, "PIV cert_9a_piv_authentication: certificate parses", "pass")
	pgp := res["openpgp"].(M)
	if pgp["public_key_url"] != "https://keys.example/a.asc" || pgp["pin_status"].(M)["pw1_tries_left"] != byte(2) {
		t.Errorf("openpgp: %v", pgp)
	}
	if bytes.ContainsAny(card.seen, "\x20\x24\x2C") {
		t.Errorf("card saw a PIN instruction: % X", card.seen)
	}
	if !bytes.Contains(card.seen, []byte{0xC0}) {
		t.Error("GET RESPONSE chaining not exercised")
	}
	if l := run(t, "card.read", M{"list": true}, nil); len(l["readers"].([]string)) != 2 || l["piv"] != nil {
		t.Errorf("list: %v", l)
	}
	if _, err := tryOp(t, "card.read", M{"reader": "nope"}); err == nil {
		t.Error("unknown reader accepted")
	}
	// A card with neither applet is information, not failure.
	card2 := &fakeCard{objects: map[string][]byte{}}
	connectCard = func(reader string) (cardConn, cardInfo, error) { return card2, cardInfo{Reader: reader}, nil }
	empty := run(t, "card.read", M{}, nil)
	noFailures(t, empty)
	wantStatus(t, empty, "PIV: select", "info")
	listReaders = nil
	if _, err := tryOp(t, "card.read", M{}); err == nil || !strings.Contains(err.Error(), "PC/SC") {
		t.Errorf("no PC/SC: %v", err)
	}
}
