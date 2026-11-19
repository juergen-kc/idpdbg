package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// OATH one-time passwords (HOTP RFC 4226, TOTP RFC 6238, otpauth:// URIs)
// and Yubico OTP.

func oathHash(alg string) (func() hash.Hash, error) {
	switch strings.ToUpper(strings.ReplaceAll(alg, "-", "")) {
	case "", "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("unsupported algorithm %q (SHA1, SHA256 or SHA512)", alg)
}

// hotp is RFC 4226 §5.3 with the hash RFC 6238 allows.
func hotp(secret []byte, counter uint64, digits int, h func() hash.Hash) string {
	m := hmac.New(h, secret)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, counter)
	m.Write(b)
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, code%uint32(math.Pow10(digits)))
}

func decodeOTPSecret(s, format string) ([]byte, error) {
	switch format {
	case "hex":
		return hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	case "ascii":
		return []byte(s), nil
	}
	clean := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "-", ""))
	if b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.TrimRight(clean, "=")); err == nil {
		return b, nil
	}
	return nil, errors.New("secret is not valid base32 (pass secret_format hex or ascii for other encodings)")
}

type oathParams struct {
	Type, Alg, Issuer, Account string
	Secret                     []byte
	Digits                     int
	Period, Counter            int64
}

func parseOTPAuth(u string) (*oathParams, error) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme != "otpauth" {
		return nil, errors.New("not an otpauth:// URI")
	}
	q := p.Query()
	o := &oathParams{Type: strings.ToLower(p.Host), Alg: q.Get("algorithm"), Issuer: q.Get("issuer"), Digits: 6, Period: 30}
	label, _ := url.PathUnescape(strings.TrimPrefix(p.Path, "/"))
	if iss, acct, ok := strings.Cut(label, ":"); ok {
		o.Account = strings.TrimSpace(acct)
		if o.Issuer == "" {
			o.Issuer = iss
		}
	} else {
		o.Account = label
	}
	if o.Secret, err = decodeOTPSecret(q.Get("secret"), ""); err != nil {
		return nil, err
	}
	if d := q.Get("digits"); d != "" {
		o.Digits, _ = strconv.Atoi(d)
	}
	if v := q.Get("period"); v != "" {
		o.Period, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := q.Get("counter"); v != "" {
		o.Counter, _ = strconv.ParseInt(v, 10, 64)
	}
	return o, nil
}

func oathChecks(cs *Checks, o *oathParams) {
	bits := len(o.Secret) * 8
	switch {
	case bits < 128:
		cs.add("secret length", "fail", fmt.Sprintf("%d bits; at least 128 are required", bits), "RFC 4226 §4 R6")
	case bits < 160:
		cs.add("secret length", "warn", fmt.Sprintf("%d bits; 160 are recommended", bits), "RFC 4226 §4 R6")
	default:
		cs.add("secret length", "pass", fmt.Sprintf("%d bits", bits), "RFC 4226 §4 R6")
	}
	cs.ok(o.Digits == 6 || o.Digits == 7 || o.Digits == 8, "digits is 6, 7 or 8", strconv.Itoa(o.Digits), "RFC 4226 §5.3")
	if o.Type == "totp" && o.Period != 30 {
		cs.add("period", "info", fmt.Sprintf("%ds; many authenticator apps support only 30s", o.Period), "RFC 6238 §5.2")
	}
	if a := strings.ToUpper(o.Alg); a != "" && a != "SHA1" {
		cs.add("algorithm", "info", a+": some authenticator apps ignore it and compute SHA-1 codes", "RFC 6238 §1.2")
	}
}

func runOATH(c *Ctx) (M, error) {
	var o *oathParams
	var err error
	if u := c.Str("uri"); u != "" {
		if o, err = parseOTPAuth(u); err != nil {
			return nil, err
		}
	} else {
		if c.Str("secret") == "" {
			return nil, errors.New("pass uri, or secret")
		}
		o = &oathParams{Type: c.Str("type"), Alg: c.Str("algorithm"), Digits: c.Int("digits"), Period: int64(c.Int("period")), Counter: int64(c.Int("counter"))}
		if o.Secret, err = decodeOTPSecret(c.Str("secret"), c.Str("secret_format")); err != nil {
			return nil, err
		}
	}
	h, err := oathHash(o.Alg)
	if err != nil {
		return nil, err
	}
	var cs Checks
	oathChecks(&cs, o)
	if o.Digits < 6 || o.Digits > 10 {
		return nil, fmt.Errorf("digits %d is not usable", o.Digits)
	}
	out := M{"type": o.Type, "algorithm": strings.ToUpper(map[bool]string{true: "SHA1", false: o.Alg}[o.Alg == ""]), "digits": o.Digits}
	if o.Issuer != "" || o.Account != "" {
		out["issuer"], out["account"] = o.Issuer, o.Account
	}
	now := time.Now().Unix()
	if t := c.Str("at_time"); t != "" {
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			now = n
		} else if tt, err := time.Parse(time.RFC3339, t); err == nil {
			now = tt.Unix()
		} else {
			return nil, errors.New("at_time must be Unix seconds or RFC 3339")
		}
	}
	base := o.Counter
	if o.Type == "totp" {
		if o.Period <= 0 {
			return nil, errors.New("period must be positive")
		}
		base = now / o.Period
		out["period"], out["time_step"] = o.Period, base
		out["valid_for_seconds"] = o.Period - now%o.Period
	} else {
		out["counter"] = base
	}
	out["code"] = hotp(o.Secret, uint64(base), o.Digits, h)
	if code := strings.ReplaceAll(c.Str("code"), " ", ""); code != "" {
		w := int64(c.Int("window"))
		found := false
		for d := -w; d <= w && !found; d++ {
			if o.Type == "hotp" && d < 0 {
				continue // HOTP only looks ahead (RFC 4226 §7.2)
			}
			if base+d >= 0 && hmac.Equal([]byte(hotp(o.Secret, uint64(base+d), o.Digits, h)), []byte(code)) {
				found = true
				out["matched_offset"] = d
				if o.Type == "hotp" {
					out["next_counter"] = base + d + 1
				}
			}
		}
		detail := "no match"
		if found {
			detail = fmt.Sprintf("matched at offset %+d", out["matched_offset"])
		}
		cs.ok(found, "code verifies", detail, map[string]string{"totp": "RFC 6238 §5.2", "hotp": "RFC 4226 §7.2"}[o.Type])
		if found && o.Type == "totp" && out["matched_offset"] != int64(0) {
			cs.add("clock drift", "info", fmt.Sprintf("the code is %+d time steps away: the device or server clock is off", out["matched_offset"]), "RFC 6238 §6")
		}
	}
	out["checks"] = cs
	return out, nil
}

// ---- Yubico OTP ----

const modhexAlphabet = "cbdefghijklnrtuv"

func modhexDecode(s string) ([]byte, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s)%2 != 0 {
		return nil, errors.New("modhex has an odd length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi, lo := strings.IndexByte(modhexAlphabet, s[i]), strings.IndexByte(modhexAlphabet, s[i+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("%q is not modhex (letters cbdefghijklnrtuv only; a keyboard layout may have changed them)", s[i:i+2])
		}
		out[i/2] = byte(hi<<4 | lo)
	}
	return out, nil
}

// crc16 is ISO 13239 as Yubico OTP uses it; a valid token leaves 0xf0b8.
func crc16(b []byte) uint16 {
	crc := uint16(0xffff)
	for _, x := range b {
		crc ^= uint16(x)
		for i := 0; i < 8; i++ {
			if crc&1 != 0 {
				crc = crc>>1 ^ 0x8408
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

func runYubicoOTP(c *Ctx) (M, error) {
	otp := strings.ToLower(strings.TrimSpace(c.Str("otp")))
	var cs Checks
	out := M{}
	defer func() { out["checks"] = cs }()
	if !cs.ok(len(otp) >= 32 && len(otp) <= 64, "OTP length", fmt.Sprintf("%d characters (public ID 0-16, token 32)", len(otp)), "Yubico OTP") {
		return out, nil
	}
	pub, tok := otp[:len(otp)-32], otp[len(otp)-32:]
	pubBytes, err := modhexDecode(pub)
	if err != nil {
		cs.add("public ID is modhex", "fail", err.Error(), "Yubico OTP")
		return out, nil
	}
	cipherTok, err := modhexDecode(tok)
	if err != nil {
		cs.add("token is modhex", "fail", err.Error(), "Yubico OTP")
		return out, nil
	}
	out["public_id"], out["public_id_hex"] = pub, hex.EncodeToString(pubBytes)
	if len(pubBytes) == 6 && pubBytes[0] == 0 && pubBytes[1] == 0 {
		out["serial"] = binary.BigEndian.Uint32(pubBytes[2:])
	}
	if c.Str("aes_key") == "" {
		cs.add("token decrypted", "info", "pass aes_key to decrypt and check the token", "Yubico OTP")
		return out, nil
	}
	key, err := hex.DecodeString(strings.ReplaceAll(c.Str("aes_key"), " ", ""))
	if err != nil || len(key) != 16 {
		return out, errors.New("aes_key must be 16 bytes of hex")
	}
	block, _ := aes.NewCipher(key)
	p := make([]byte, 16)
	block.Decrypt(p, cipherTok)
	if !cs.ok(crc16(p) == 0xf0b8, "token CRC", "a wrong key or a corrupted OTP fails here", "Yubico OTP") {
		return out, nil
	}
	tokOut := M{"private_id": hex.EncodeToString(p[0:6]), "usage_counter": binary.LittleEndian.Uint16(p[6:8]),
		"timestamp": uint32(p[8]) | uint32(p[9])<<8 | uint32(p[10])<<16, "session_counter": p[11], "random": hex.EncodeToString(p[12:14])}
	out["token"] = tokOut
	if id := c.Str("private_id"); id != "" {
		cs.ok(strings.EqualFold(id, hex.EncodeToString(p[0:6])), "private ID matches", "", "Yubico OTP")
	}
	if c.Has("last_usage_counter") {
		lu, ls := c.Int("last_usage_counter"), c.Int("last_session_counter")
		u, s := int(binary.LittleEndian.Uint16(p[6:8])), int(p[11])
		fresh := u > lu || (u == lu && s > ls)
		cs.ok(fresh, "counters advanced (not a replay)", fmt.Sprintf("now %d/%d, last seen %d/%d", u, s, lu, ls), "Yubico OTP")
	}
	return out, nil
}

func init() {
	register(
		&Op{
			Name:    "oath.code",
			Summary: "Compute an OATH one-time password (HOTP RFC 4226 or TOTP RFC 6238; SHA-1, SHA-256 or SHA-512; 6 to 8 digits) from a secret or an otpauth:// URI, and optionally verify a code within a window, reporting clock drift. Checks secret length and settings authenticator apps may ignore.",
			Params: []Param{
				{Name: "uri", Type: "string", Secret: true, Explicit: true, Desc: "otpauth://totp/... or otpauth://hotp/... URI (it contains the secret)"},
				{Name: "secret", Type: "string", Secret: true, Explicit: true, Desc: "Shared secret (base32 by default)"},
				{Name: "secret_format", Type: "string", Enum: []string{"base32", "hex", "ascii"}, Desc: "Encoding of secret", Default: "base32"},
				{Name: "type", Type: "string", Enum: []string{"totp", "hotp"}, Desc: "Algorithm when not from a URI", Default: "totp"},
				{Name: "algorithm", Type: "string", Enum: []string{"SHA1", "SHA256", "SHA512"}, Desc: "HMAC hash", Default: "SHA1"},
				{Name: "digits", Type: "int", Desc: "Code length", Default: 6},
				{Name: "period", Type: "int", Desc: "TOTP time step in seconds", Default: 30},
				{Name: "counter", Type: "int", Desc: "HOTP counter", Default: 0},
				{Name: "at_time", Type: "string", Desc: "TOTP at this time (Unix seconds or RFC 3339) instead of now"},
				{Name: "code", Type: "string", Desc: "A code to verify"},
				{Name: "window", Type: "int", Desc: "Steps either side (TOTP) or ahead (HOTP) to accept", Default: 1}},
			Run: runOATH,
		},
		&Op{
			Name:    "yubico.otp",
			Summary: "Decode a Yubico OTP: modhex public ID (and serial when it encodes one) and token; with the AES key, decrypt the token, check its CRC, private ID and counters (replay detection).",
			Params: []Param{
				{Name: "otp", Type: "string", Required: true, Desc: "The OTP as typed by the YubiKey"},
				{Name: "aes_key", Type: "string", Secret: true, Explicit: true, Desc: "The slot's AES-128 key, hex"},
				{Name: "private_id", Type: "string", Desc: "Expected private ID, hex"},
				{Name: "last_usage_counter", Type: "int", Desc: "Last usage counter seen for this key"},
				{Name: "last_session_counter", Type: "int", Desc: "Last session counter seen", Default: 0}},
			Run: runYubicoOTP,
		},
	)
}
