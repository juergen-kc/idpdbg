package main

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Smart cards: BER-TLV, ISO 7816-4 APDUs and status words, PIV data
// objects (SP 800-73-4) and the OpenPGP card's Application Related Data.

type tlv struct {
	Tag   uint32
	Value []byte
	Kids  []tlv
}

// parseTLV reads BER-TLV; constructed values are parsed into Kids.
func parseTLV(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		if b[0] == 0x00 || b[0] == 0xff { // padding between objects
			b = b[1:]
			continue
		}
		first := b[0]
		tag := uint32(first)
		i := 1
		if first&0x1f == 0x1f {
			for {
				if i >= len(b) || i > 3 {
					return out, errors.New("truncated tag")
				}
				tag = tag<<8 | uint32(b[i])
				i++
				if b[i-1]&0x80 == 0 {
					break
				}
			}
		}
		if i >= len(b) {
			return out, errors.New("truncated length")
		}
		l := int(b[i])
		i++
		if l&0x80 != 0 {
			n := l & 0x7f
			if n == 0 || n > 3 || i+n > len(b) {
				return out, errors.New("bad length")
			}
			l = 0
			for _, x := range b[i : i+n] {
				l = l<<8 | int(x)
			}
			i += n
		}
		if i+l > len(b) {
			return out, fmt.Errorf("tag %X: length %d runs past the data", tag, l)
		}
		t := tlv{Tag: tag, Value: b[i : i+l]}
		if first&0x20 != 0 {
			t.Kids, _ = parseTLV(t.Value)
		} else if tag == 0x53 { // PIV wraps every object in 53 although it is a primitive tag
			if kids, err := parseTLV(t.Value); err == nil {
				t.Kids = kids
			}
		}
		out = append(out, t)
		b = b[i+l:]
	}
	return out, nil
}

func findTLV(ts []tlv, tag uint32) *tlv {
	for i := range ts {
		if ts[i].Tag == tag {
			return &ts[i]
		}
	}
	for i := range ts {
		if t := findTLV(ts[i].Kids, tag); t != nil {
			return t
		}
	}
	return nil
}

func cardBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	compact := strings.NewReplacer(" ", "", "\n", "", ":", "", "\t", "").Replace(s)
	if b, err := hex.DecodeString(compact); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(compact); err == nil {
		return b, nil
	}
	return nil, errors.New("input is neither hex nor base64")
}

// ---- APDUs ----

var aidNames = []struct{ prefix, name string }{
	{"A000000308000010000100", "PIV"}, {"A00000030800001000", "PIV"}, {"D27600012401", "OpenPGP card"},
	{"A0000005272101", "Yubico OATH"}, {"A0000005272001", "Yubico OTP"}, {"A0000006472F0001", "FIDO U2F / CTAP"},
	{"A000000527471117", "Yubico Management"}, {"A000000527210701", "YubiHSM Auth"}, {"A00000015141434C00", "Global Platform ISD"},
}

func aidName(aid []byte) string {
	h := strings.ToUpper(hex.EncodeToString(aid))
	for _, a := range aidNames {
		if strings.HasPrefix(h, a.prefix) {
			return a.name
		}
	}
	return ""
}

var insNames = map[byte]string{0xA4: "SELECT", 0xCA: "GET DATA (OpenPGP)", 0xCB: "GET DATA (PIV)", 0xC0: "GET RESPONSE", 0x20: "VERIFY",
	0x24: "CHANGE REFERENCE DATA", 0x2C: "RESET RETRY COUNTER", 0x87: "GENERAL AUTHENTICATE", 0x47: "GENERATE ASYMMETRIC KEY PAIR",
	0xDB: "PUT DATA (PIV)", 0xDA: "PUT DATA (OpenPGP)", 0x2A: "PERFORM SECURITY OPERATION", 0x88: "INTERNAL AUTHENTICATE",
	0x44: "ACTIVATE FILE", 0xE6: "TERMINATE DF", 0xFD: "GET VERSION (Yubico)", 0xF8: "GET SERIAL (Yubico)", 0xA1: "LIST (OATH)", 0xA2: "CALCULATE (OATH)", 0x01: "PUT (OATH)", 0x03: "SET CODE (OATH)", 0xFE: "IMPORT ASYMMETRIC KEY (Yubico PIV)", 0xFF: "SET MANAGEMENT KEY (Yubico PIV)"}

func swMeaning(sw1, sw2 byte) (string, string) {
	sw := uint16(sw1)<<8 | uint16(sw2)
	switch {
	case sw == 0x9000:
		return "success", "pass"
	case sw1 == 0x61:
		return fmt.Sprintf("success; %d more bytes: send GET RESPONSE", sw2), "info"
	case sw1 == 0x6C:
		return fmt.Sprintf("wrong Le: repeat with Le=%d", sw2), "warn"
	case sw1 == 0x63 && sw2&0xF0 == 0xC0:
		n := sw2 & 0x0F
		st := "warn"
		if n == 0 {
			st = "fail"
		}
		if n == 1 {
			return "verification failed: 1 try left", st
		}
		return fmt.Sprintf("verification failed: %d tries left", n), st
	}
	m := map[uint16]string{0x6281: "returned data may be corrupted", 0x6282: "end of data reached before Le bytes", 0x6283: "selected file invalidated",
		0x6400: "execution error", 0x6581: "memory failure", 0x6700: "wrong length", 0x6882: "secure messaging not supported",
		0x6982: "security status not satisfied (PIN or authentication needed)", 0x6983: "authentication method blocked",
		0x6984: "reference data not usable", 0x6985: "conditions of use not satisfied", 0x6986: "command not allowed",
		0x6A80: "incorrect data", 0x6A81: "function not supported", 0x6A82: "file or application not found",
		0x6A84: "not enough memory", 0x6A86: "incorrect P1-P2", 0x6A88: "referenced data not found", 0x6B00: "wrong P1-P2",
		0x6D00: "instruction not supported", 0x6E00: "class not supported", 0x6F00: "no precise diagnosis"}[sw]
	if m == "" {
		m = "unknown status"
	}
	return m, "fail"
}

func runAPDU(c *Ctx) (M, error) {
	var cs Checks
	out := M{}
	if s := c.Str("command"); s != "" {
		b, err := cardBytes(s)
		if err != nil || len(b) < 4 {
			return nil, errors.New("command must be at least CLA INS P1 P2 in hex")
		}
		cmd := M{"cla": fmt.Sprintf("%02X", b[0]), "ins": fmt.Sprintf("%02X", b[1]), "p1": fmt.Sprintf("%02X", b[2]), "p2": fmt.Sprintf("%02X", b[3])}
		if n := insNames[b[1]]; n != "" {
			cmd["instruction"] = n
		}
		if b[0]&0x10 != 0 {
			cmd["chained"] = true
		}
		var data []byte
		rest := b[4:]
		switch {
		case len(rest) == 1:
			cmd["le"] = int(rest[0])
		case len(rest) == 3 && rest[0] == 0: // extended Le only
			cmd["le"] = int(binary.BigEndian.Uint16(rest[1:3]))
		case len(rest) > 3 && rest[0] == 0: // extended length
			lc := int(binary.BigEndian.Uint16(rest[1:3]))
			if 3+lc > len(rest) {
				return nil, errors.New("extended Lc runs past the command")
			}
			data = rest[3 : 3+lc]
			if len(rest) >= 3+lc+2 {
				cmd["le"] = int(binary.BigEndian.Uint16(rest[3+lc:]))
			}
		case len(rest) > 1:
			lc := int(rest[0])
			if 1+lc > len(rest) {
				return nil, errors.New("Lc runs past the command")
			}
			data = rest[1 : 1+lc]
			if len(rest) > 1+lc {
				cmd["le"] = int(rest[1+lc])
			}
		}
		if secretAPDU(b[0], b[1], b[2], b[3], data) {
			// Reference data and key material: PINs, PUKs, management
			// keys, imported private keys. Never echo them.
			cmd["data"] = fmt.Sprintf("<%d bytes of secret data, not shown>", len(data))
			data = nil
		}
		switch b[1] {
		case 0xA4:
			if b[2] == 0x04 {
				cmd["aid"] = strings.ToUpper(hex.EncodeToString(data))
				if n := aidName(data); n != "" {
					cmd["applet"] = n
				}
			}
		case 0x20, 0x24, 0x2C:
			cmd["key_reference"] = map[byte]string{0x00: "PIV global PIN", 0x80: "PIV PIN", 0x81: "PIV PUK, or OpenPGP PW1 for signing",
				0x82: "OpenPGP PW1 (decrypt, authenticate)", 0x83: "OpenPGP PW3 (admin)"}[b[3]]
		case 0xCB, 0xCA:
			if t, _ := parseTLV(data); len(t) > 0 && t[0].Tag == 0x5C {
				cmd["object"] = strings.ToUpper(hex.EncodeToString(t[0].Value))
				cmd["object_name"] = pivObjects[strings.ToUpper(hex.EncodeToString(t[0].Value))]
			} else if b[1] == 0xCA {
				tag := strings.ToUpper(hex.EncodeToString(b[2:4]))
				cmd["object"], cmd["object_name"] = tag, openpgpDOs[tag]
			}
		}
		if data != nil {
			cmd["data"] = strings.ToUpper(hex.EncodeToString(data))
		}
		out["command"] = cmd
	}
	if s := c.Str("response"); s != "" {
		b, err := cardBytes(s)
		if err != nil || len(b) < 2 {
			return nil, errors.New("response must end with SW1 SW2 in hex")
		}
		sw1, sw2 := b[len(b)-2], b[len(b)-1]
		meaning, status := swMeaning(sw1, sw2)
		resp := M{"sw": fmt.Sprintf("%02X%02X", sw1, sw2), "meaning": meaning, "data_length": len(b) - 2}
		if len(b) > 2 {
			if t, err := parseTLV(b[:len(b)-2]); err == nil && len(t) > 0 {
				resp["tlv"] = describeTLV(t)
			} else if err != nil {
				resp["data"] = strings.ToUpper(hex.EncodeToString(b[:len(b)-2]))
				resp["tlv_error"] = err.Error()
			}
		}
		out["response"] = resp
		cs.add("status word "+resp["sw"].(string), status, meaning, "ISO/IEC 7816-4 §5.6")
	}
	if out["command"] == nil && out["response"] == nil {
		return nil, errors.New("pass command and/or response")
	}
	out["checks"] = cs
	return out, nil
}

// secretAPDU reports commands whose data may be a PIN, PUK, reset code,
// management key or private key. Writes are deny-by-default: PUT DATA
// shows only objects known to be public, and any chained write is hidden
// because its later blocks cannot be told apart from key material.
func secretAPDU(cla, ins, p1, p2 byte, data []byte) bool {
	if len(data) == 0 {
		return false
	}
	switch ins {
	case 0x20, 0x24, 0x2C, 0xFE, 0xFF, // VERIFY, CHANGE/RESET, Yubico import key / set management key
		0x01, 0x03, 0x0B: // Yubico OATH/HSM-auth PUT, OATH SET CODE, HSM-auth change password
		return true
	case 0xDA: // OpenPGP PUT DATA, P1-P2 is the data object
		return cla&0x10 != 0 || !publicPGPDOs[uint16(p1)<<8|uint16(p2)]
	case 0xDB: // PIV PUT DATA, or OpenPGP odd PUT DATA (key import)
		if cla&0x10 != 0 {
			return true
		}
		t, _ := parseTLV(data)
		return len(t) == 0 || t[0].Tag != 0x5C || !publicPIVObject(strings.ToUpper(hex.EncodeToString(t[0].Value)))
	}
	return false
}

// OpenPGP data objects whose contents are public (readable without a PIN).
var publicPGPDOs = map[uint16]bool{0x005B: true, 0x5F2D: true, 0x5F35: true, 0x5F50: true, 0x005E: true, 0x0101: true, 0x0102: true,
	0x00C1: true, 0x00C2: true, 0x00C3: true, 0x00C4: true, 0x00C7: true, 0x00C8: true, 0x00C9: true, 0x00CA: true, 0x00CB: true,
	0x00CC: true, 0x00CE: true, 0x00CF: true, 0x00D0: true, 0x00D6: true, 0x00D7: true, 0x00D8: true, 0x7F21: true, 0x00DA: true}

// publicPIVObject is true for certificates, CHUID, CCC, discovery and key
// history. Printed information (5FC109) is not: YubiKeys keep a
// PIN-protected management key there, and vendor objects may hold secrets.
func publicPIVObject(tag string) bool {
	switch tag {
	case "5FC101", "5FC102", "5FC105", "5FC107", "5FC10A", "5FC10B", "5FC10C", "7E":
		return true
	}
	if len(tag) == 6 && tag[:4] == "5FC1" { // retired key management certificates 5FC10D-5FC120
		var n int
		fmt.Sscanf(tag[4:], "%X", &n)
		return n >= 0x0D && n <= 0x20
	}
	return false
}

func describeTLV(ts []tlv) []M { return describeTLVIn(ts, 0) }

// describeTLVIn hides key-like values: a YubiKey's PIN-protected data
// object (53 { 88 { 89 key } }) carries the PIV management key.
func describeTLVIn(ts []tlv, parent uint32) []M {
	var out []M
	for _, t := range ts {
		e := M{"tag": fmt.Sprintf("%X", t.Tag), "length": len(t.Value)}
		if parent == 0x53 && t.Tag == 0x88 {
			e["value"] = "<PIN-protected data (may hold the management key), not shown>"
		} else if len(t.Kids) > 0 {
			e["children"] = describeTLVIn(t.Kids, t.Tag)
		} else if len(t.Value) <= 64 {
			e["value"] = strings.ToUpper(hex.EncodeToString(t.Value))
		}
		out = append(out, e)
	}
	return out
}

// ---- PIV ----

var pivObjects = map[string]string{"5FC102": "CHUID", "5FC107": "Card Capability Container", "5FC105": "X.509 certificate for PIV Authentication (9A)",
	"5FC10A": "X.509 certificate for Digital Signature (9C)", "5FC10B": "X.509 certificate for Key Management (9D)",
	"5FC101": "X.509 certificate for Card Authentication (9E)", "5FC103": "Cardholder fingerprints", "5FC106": "Security Object",
	"5FC108": "Cardholder facial image", "5FC109": "Printed information", "7E": "Discovery object", "5FC10C": "Key history object"}

// decodeFASCN reads the 200-bit FASC-N: 40 characters of four data bits
// (least significant first) and an odd parity bit (SP 800-73-4 / TIG SCEPACS).
func decodeFASCN(b []byte) (M, []string) {
	var problems []string
	if len(b) != 25 {
		return nil, []string{fmt.Sprintf("FASC-N is %d bytes, not 25", len(b))}
	}
	bit := func(i int) int { return int(b[i/8]>>(7-uint(i%8))) & 1 }
	var chars []int
	for c := 0; c < 40; c++ {
		v, ones := 0, 0
		for j := 0; j < 5; j++ {
			x := bit(c*5 + j)
			ones += x
			if j < 4 {
				v |= x << j
			}
		}
		if ones%2 != 1 {
			problems = append(problems, fmt.Sprintf("character %d fails its parity check", c+1))
		}
		chars = append(chars, v)
	}
	if chars[0] != 0x0B {
		problems = append(problems, "missing start sentinel")
	}
	lrc := 0
	for _, v := range chars[:39] {
		lrc ^= v
	}
	if lrc != chars[39] {
		problems = append(problems, "longitudinal redundancy check does not match")
	}
	var fields []string
	cur := ""
	for _, v := range chars[1:] {
		switch v {
		case 0x0D, 0x0F: // field separator, end sentinel
			fields = append(fields, cur)
			cur = ""
			if v == 0x0F {
				goto done
			}
		default:
			cur += fmt.Sprint(v)
		}
	}
done:
	out := M{"raw": strings.ToUpper(hex.EncodeToString(b))}
	names := []string{"agency_code", "system_code", "credential_number", "credential_series", "individual_credential_issue"}
	for i, n := range names {
		if i < len(fields) {
			out[n] = fields[i]
		}
	}
	if len(fields) > 5 { // PI OC OI POA run together before the end sentinel
		last := fields[5]
		if len(last) == 16 {
			out["person_identifier"], out["organizational_category"], out["organizational_identifier"], out["person_association"] = last[:10], last[10:11], last[11:15], last[15:]
		} else {
			out["remainder"] = last
			problems = append(problems, fmt.Sprintf("PI/OC/OI/POA is %d digits, not 16", len(last)))
		}
	}
	return out, problems
}

func pivCertificate(cs *Checks, ts []tlv) M {
	ct := findTLV(ts, 0x70)
	if !cs.ok(ct != nil, "certificate present (tag 70)", "", "SP 800-73-4 Part 1 Table 15") {
		return nil
	}
	der := ct.Value
	if info := findTLV(ts, 0x71); info != nil && len(info.Value) > 0 && info.Value[0]&0x01 != 0 {
		zr, err := gzip.NewReader(bytes.NewReader(der))
		if err == nil {
			der, err = io.ReadAll(io.LimitReader(zr, 1<<20))
		}
		if !cs.ok(err == nil, "compressed certificate inflates", detailOr(err, "gzip"), "SP 800-73-4 Part 1 Table 15") {
			return nil
		}
	}
	cert, err := x509.ParseCertificate(der)
	if !cs.ok(err == nil, "certificate parses", detailOr(err, ""), "RFC 5280") {
		return nil
	}
	certChecks(cs, cert, "client") // card certificates authenticate their holder
	return certDetail(cert)
}

func runPIV(c *Ctx) (M, error) {
	b, err := cardBytes(c.Str("data"))
	if err != nil {
		return nil, err
	}
	return decodePIV(b, c.Str("object"))
}

func decodePIV(b []byte, kind string) (M, error) {
	ts, err := parseTLV(b)
	if err != nil && len(ts) == 0 {
		return nil, fmt.Errorf("not BER-TLV: %w", err)
	}
	if len(ts) == 1 && ts[0].Tag == 0x53 { // GET DATA wraps objects in tag 53
		ts, _ = parseTLV(ts[0].Value)
	}
	var cs Checks
	out := M{}
	if kind == "" || kind == "auto" {
		switch {
		case findTLV(ts, 0x70) != nil:
			kind = "certificate"
		case findTLV(ts, 0x30) != nil || findTLV(ts, 0x34) != nil:
			kind = "chuid"
		case len(ts) > 0 && ts[0].Tag == 0x7E:
			kind = "discovery"
		case findTLV(ts, 0xC1) != nil:
			kind = "keyhistory"
		default:
			kind = "unknown"
		}
	}
	out["object"] = kind
	switch kind {
	case "chuid":
		if f := findTLV(ts, 0x30); f != nil {
			fascn, problems := decodeFASCN(f.Value)
			out["fasc_n"] = fascn
			cs.ok(len(problems) == 0, "FASC-N well-formed", strings.Join(problems, "; "), "TIG SCEPACS §6")
		}
		if g := findTLV(ts, 0x34); g != nil {
			out["guid"] = uuidString(g.Value)
			cs.warn(!allZero(g.Value), "GUID set", uuidString(g.Value), "SP 800-73-4 Part 1 §3.1.2")
		}
		if e := findTLV(ts, 0x35); e != nil {
			exp, err := time.Parse("20060102", string(e.Value))
			if cs.ok(err == nil, "expiration date readable", string(e.Value), "SP 800-73-4 Part 1 §3.1.2") {
				out["expires"] = exp.Format("2006-01-02")
				cs.ok(time.Now().Before(exp.Add(24*time.Hour)), "CHUID not expired", "expires "+exp.Format("2006-01-02"), "SP 800-73-4 Part 1 §3.1.2")
			}
		}
		if u := findTLV(ts, 0x36); u != nil {
			out["cardholder_uuid"] = uuidString(u.Value)
		}
		sig := findTLV(ts, 0x3E)
		cs.warn(sig != nil && len(sig.Value) > 0, "issuer signature present", "the CHUID is signed by the card issuer (CMS)", "SP 800-73-4 Part 1 §3.1.2")
	case "certificate":
		out["certificate"] = pivCertificate(&cs, ts)
	case "discovery":
		d := ts[0].Kids
		if a := findTLV(d, 0x4F); a != nil {
			out["aid"] = strings.ToUpper(hex.EncodeToString(a.Value))
		}
		if p := findTLV(d, 0x5F2F); p != nil && len(p.Value) == 2 {
			pol := M{"piv_pin": p.Value[0]&0x40 != 0, "global_pin": p.Value[0]&0x20 != 0, "on_card_comparison": p.Value[0]&0x10 != 0,
				"virtual_contact_interface": p.Value[0]&0x08 != 0}
			if p.Value[0]&0x20 != 0 {
				pol["primary"] = map[byte]string{0x10: "PIV PIN", 0x20: "global PIN"}[p.Value[1]]
			}
			out["pin_usage_policy"] = pol
		}
	case "keyhistory":
		if k := findTLV(ts, 0xC1); k != nil && len(k.Value) == 1 {
			out["keys_with_on_card_certs"] = k.Value[0]
		}
		if k := findTLV(ts, 0xC2); k != nil && len(k.Value) == 1 {
			out["keys_with_off_card_certs"] = k.Value[0]
		}
		if u := findTLV(ts, 0xF3); u != nil {
			out["off_card_cert_url"] = string(u.Value)
		}
	default:
		out["tlv"] = describeTLVIn(ts, 0x53) // contents of the 53 wrapper
	}
	out["checks"] = cs
	return out, nil
}

// ---- OpenPGP card ----

var openpgpDOs = map[string]string{"006E": "Application Related Data", "0065": "Cardholder Related Data", "007A": "Security Support Template",
	"005E": "Login data", "5F50": "URL", "004F": "AID", "00C4": "PW status bytes", "7F21": "Cardholder certificate"}

var pgpManufacturers = map[uint16]string{0x0005: "ZeitControl", 0x0006: "Yubico", 0xF517: "FSIJ (Gnuk)"}

var curveOIDs = map[string]string{"2A8648CE3D030107": "NIST P-256", "2B81040022": "NIST P-384", "2B81040023": "NIST P-521",
	"2B060104019755010501": "Curve25519 (ECDH)", "2B06010401DA470F01": "Ed25519", "2B2403030208010107": "brainpoolP256r1",
	"2B240303020801010B": "brainpoolP384r1", "2B240303020801010D": "brainpoolP512r1"}

func pgpAlgorithm(cs *Checks, slot string, v []byte) M {
	if len(v) == 0 {
		return nil
	}
	switch v[0] {
	case 0x01:
		if len(v) < 5 {
			return M{"algorithm": "RSA", "error": "short attributes"}
		}
		bits := int(binary.BigEndian.Uint16(v[1:3]))
		cs.warn(bits >= 2048, slot+": key size", fmt.Sprintf("RSA %d", bits), "NIST SP 800-131A")
		return M{"algorithm": "RSA", "bits": bits, "exponent_bits": binary.BigEndian.Uint16(v[3:5])}
	case 0x12, 0x13, 0x16:
		oid := strings.ToUpper(hex.EncodeToString(v[1:]))
		oid = strings.TrimSuffix(strings.TrimSuffix(oid, "FF"), "00") // optional import-format byte
		name := curveOIDs[oid]
		if name == "" {
			name = "OID " + oid
		}
		return M{"algorithm": map[byte]string{0x12: "ECDH", 0x13: "ECDSA", 0x16: "EdDSA"}[v[0]], "curve": name}
	}
	return M{"algorithm": fmt.Sprintf("algorithm id %d", v[0])}
}

func runOpenPGP(c *Ctx) (M, error) {
	b, err := cardBytes(c.Str("data"))
	if err != nil {
		return nil, err
	}
	return decodeOpenPGP(b)
}

func decodeOpenPGP(b []byte) (M, error) {
	ts, err := parseTLV(b)
	if err != nil && len(ts) == 0 {
		return nil, fmt.Errorf("not BER-TLV: %w", err)
	}
	if len(ts) == 1 && ts[0].Tag == 0x6E {
		ts = ts[0].Kids
	}
	var cs Checks
	out := M{}
	if a := findTLV(ts, 0x4F); a != nil && len(a.Value) >= 14 {
		v := a.Value
		manuf := binary.BigEndian.Uint16(v[8:10])
		name := pgpManufacturers[manuf]
		if manuf >= 0xFF00 {
			name = "test card range"
		}
		out["aid"] = M{"version": fmt.Sprintf("%d.%d", v[6], v[7]), "manufacturer": fmt.Sprintf("%04X %s", manuf, name), "serial": fmt.Sprintf("%08X", binary.BigEndian.Uint32(v[10:14]))}
		cs.ok(bytes.HasPrefix(v, []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}), "AID is the OpenPGP application", strings.ToUpper(hex.EncodeToString(v[:6])), "OpenPGP card 3.4 §4.2.1")
	}
	slots := []string{"signature", "decryption", "authentication"}
	keys := []M{}
	for i, s := range slots {
		k := M{"slot": s}
		if fp := findTLV(ts, 0xC5); fp != nil && len(fp.Value) >= 60 {
			f := fp.Value[i*20 : i*20+20]
			if allZero(f) {
				k["fingerprint"] = nil
			} else {
				k["fingerprint"] = strings.ToUpper(hex.EncodeToString(f))
			}
		}
		if gd := findTLV(ts, 0xCD); gd != nil && len(gd.Value) >= 12 {
			if gen := binary.BigEndian.Uint32(gd.Value[i*4:]); gen != 0 {
				k["generated"] = time.Unix(int64(gen), 0).UTC().Format(time.RFC3339)
			}
		}
		if al := findTLV(ts, uint32(0xC1+i)); al != nil {
			// Key-size advice only matters for a key that exists.
			target := &cs
			if k["fingerprint"] == nil {
				target = &Checks{}
			}
			k["attributes"] = pgpAlgorithm(target, s, al.Value)
		}
		if k["fingerprint"] == nil {
			cs.add(s+" key", "info", "no key in this slot", "OpenPGP card 3.4 §4.4.3")
		}
		keys = append(keys, k)
	}
	out["keys"] = keys
	if pw := findTLV(ts, 0xC4); pw != nil && len(pw.Value) >= 7 {
		v := pw.Value
		// 00: PW1 is needed for every signature; 01: one VERIFY allows
		// several. Some cards (YubiKey 5.1) send FF; GnuPG reads any
		// non-zero value as "several", and so does idpdbg.
		if v[0] > 1 {
			cs.add("PW1 signature policy byte", "info", fmt.Sprintf("%02X, where the specification has 00 or 01: read as valid for several signatures, as GnuPG does", v[0]), "OpenPGP card 3.4 §4.4.1")
		}
		out["pin_status"] = M{"pw1_valid_for_multiple_signatures": v[0] != 0, "pw1_max_length": v[1], "rc_max_length": v[2], "pw3_max_length": v[3],
			"pw1_tries_left": v[4], "reset_code_tries_left": v[5], "pw3_tries_left": v[6]}
		for _, p := range []struct {
			name string
			n    byte
		}{{"PW1 (user PIN)", v[4]}, {"PW3 (admin PIN)", v[6]}} {
			switch {
			case p.n == 0:
				cs.add(p.name+" retries", "fail", "blocked: no tries left", "OpenPGP card 3.4 §4.4.1")
			case p.n == 1:
				cs.add(p.name+" retries", "warn", "one try left", "OpenPGP card 3.4 §4.4.1")
			default:
				cs.add(p.name+" retries", "pass", fmt.Sprintf("%d left", p.n), "OpenPGP card 3.4 §4.4.1")
			}
		}
	}
	if ext := findTLV(ts, 0xC0); ext != nil && len(ext.Value) > 0 {
		out["extended_capabilities"] = M{"secure_messaging": ext.Value[0]&0x80 != 0, "get_challenge": ext.Value[0]&0x40 != 0,
			"key_import": ext.Value[0]&0x20 != 0, "pw_status_changeable": ext.Value[0]&0x10 != 0, "private_dos": ext.Value[0]&0x08 != 0,
			"algorithm_attributes_changeable": ext.Value[0]&0x04 != 0, "aes": ext.Value[0]&0x02 != 0, "kdf": ext.Value[0]&0x01 != 0}
	}
	out["checks"] = cs
	return out, nil
}

func init() {
	register(
		&Op{
			Name:    "card.apdu",
			Summary: "Decode ISO 7816-4 APDUs: a command (CLA/INS/P1/P2, Lc, data, Le; instruction and applet names; PIV/OpenPGP objects; PINs in VERIFY and friends are never shown) and/or a response (data as BER-TLV, status word meaning such as retries left or GET RESPONSE needed).",
			Params: []Param{
				{Name: "command", Type: "string", Desc: "Command APDU, hex"},
				{Name: "response", Type: "string", Desc: "Response APDU (data then SW1 SW2), hex"}},
			Run: runAPDU,
		},
		&Op{
			Name:    "card.piv",
			Summary: "Decode a PIV data object (SP 800-73-4): CHUID with FASC-N, GUID, expiry and issuer signature; certificates (compressed or not) with full X.509 checks; the discovery object and PIN usage policy; key history. Input is the GET DATA response, hex or base64.",
			Params: []Param{
				{Name: "data", Type: "string", Required: true, File: true, Desc: "The object (tag 53 wrapper or its contents), hex or base64"},
				{Name: "object", Type: "string", Enum: []string{"auto", "chuid", "certificate", "discovery", "keyhistory"}, Desc: "Which object it is", Default: "auto"}},
			Run: runPIV,
		},
		&Op{
			Name:    "card.openpgp",
			Summary: "Decode an OpenPGP card's Application Related Data (6E): version, manufacturer and serial, per-slot key algorithm, fingerprint and generation date, PIN retry counters (blocked PINs fail), and extended capabilities.",
			Params:  []Param{{Name: "data", Type: "string", Required: true, File: true, Desc: "Application Related Data (GET DATA 006E), hex or base64"}},
			Run:     runOpenPGP,
		},
	)
}
