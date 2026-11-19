package main

import (
	"crypto/aes"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestOATHKnownAnswers(t *testing.T) {
	// RFC 4226 Appendix D.
	secret := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	for i, want := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		if got := run(t, "oath.code", M{"secret": secret, "type": "hotp", "counter": i}, nil)["code"]; got != want {
			t.Errorf("RFC 4226 counter %d: %v, want %s", i, got, want)
		}
	}
	// RFC 6238 Appendix B (8 digits, 30 s).
	seeds := map[string]string{"SHA1": "12345678901234567890", "SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234"}
	vectors := []struct {
		t    string
		want map[string]string
	}{
		{"59", map[string]string{"SHA1": "94287082", "SHA256": "46119246", "SHA512": "90693936"}},
		{"1111111109", map[string]string{"SHA1": "07081804", "SHA256": "68084774", "SHA512": "25091201"}},
		{"1111111111", map[string]string{"SHA1": "14050471", "SHA256": "67062674", "SHA512": "99943326"}},
		{"1234567890", map[string]string{"SHA1": "89005924", "SHA256": "91819424", "SHA512": "93441116"}},
		{"2000000000", map[string]string{"SHA1": "69279037", "SHA256": "90698825", "SHA512": "38618901"}},
		{"20000000000", map[string]string{"SHA1": "65353130", "SHA256": "77737706", "SHA512": "47863826"}},
	}
	for _, v := range vectors {
		for alg, want := range v.want {
			got := run(t, "oath.code", M{"secret": seeds[alg], "secret_format": "ascii", "algorithm": alg, "digits": 8, "at_time": v.t}, nil)["code"]
			if got != want {
				t.Errorf("RFC 6238 %s at %s: %v, want %s", alg, v.t, got, want)
			}
		}
	}
}

func TestOATHVerifyAndURI(t *testing.T) {
	uri := "otpauth://totp/ACME%20Co:alice@example.com?secret=" + base32.StdEncoding.EncodeToString([]byte("12345678901234567890")) + "&issuer=ACME%20Co&algorithm=SHA1&digits=8&period=30"
	res := run(t, "oath.code", M{"uri": uri, "at_time": "1111111111", "code": "07081804"}, nil) // the previous step's code
	noFailures(t, res)
	if res["issuer"] != "ACME Co" || res["account"] != "alice@example.com" || res["matched_offset"] != int64(-1) {
		t.Errorf("uri/verify: %v", res)
	}
	wantStatus(t, res, "clock drift", "info")
	wantStatus(t, run(t, "oath.code", M{"uri": uri, "at_time": "1111111111", "code": "07081804", "window": 0}, nil), "code verifies", "fail")
	// HOTP looks only ahead and says where to resume.
	sec := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	h := run(t, "oath.code", M{"secret": sec, "type": "hotp", "counter": 3, "code": "338314", "window": 2}, nil)
	if h["next_counter"] != int64(5) {
		t.Errorf("HOTP resync: %v", h["next_counter"])
	}
	wantStatus(t, run(t, "oath.code", M{"secret": sec, "type": "hotp", "counter": 3, "code": "359152", "window": 2}, nil), "code verifies", "fail")
	wantStatus(t, run(t, "oath.code", M{"secret": "JBSWY3DPEHPK3PXP"}, nil), "secret length", "fail") // 80 bits
}

func TestYubicoOTP(t *testing.T) {
	// Build a token the way a YubiKey does, independently of the decoder.
	key, _ := hex.DecodeString("ecde18dbe76fbd0c33330f1c354871db")
	plain := make([]byte, 16)
	copy(plain, []byte{0x87, 0x92, 0xeb, 0xfe, 0x26, 0xcc}) // private ID
	binary.LittleEndian.PutUint16(plain[6:], 19)            // usage counter
	plain[8], plain[9], plain[10] = 0x34, 0x12, 0x00        // timestamp
	plain[11] = 3                                           // session counter
	plain[12], plain[13] = 0xab, 0xcd
	crc := ^crc16(plain[:14])
	binary.LittleEndian.PutUint16(plain[14:], crc)
	ct := make([]byte, 16)
	block, _ := aes.NewCipher(key)
	block.Encrypt(ct, plain)
	modhex := func(b []byte) string {
		var s strings.Builder
		for _, x := range b {
			s.WriteByte(modhexAlphabet[x>>4])
			s.WriteByte(modhexAlphabet[x&15])
		}
		return s.String()
	}
	otp := modhex([]byte{0, 0, 0, 0x12, 0xd6, 0x87}) + modhex(ct) // public ID encoding serial 1234567
	res := run(t, "yubico.otp", M{"otp": otp, "aes_key": hex.EncodeToString(key), "private_id": "8792ebfe26cc", "last_usage_counter": 19, "last_session_counter": 2}, nil)
	noFailures(t, res)
	tok := res["token"].(M)
	if tok["usage_counter"] != uint16(19) || tok["session_counter"] != byte(3) || res["serial"] != uint32(1234567) {
		t.Errorf("decoded: %v serial %v", tok, res["serial"])
	}
	wantStatus(t, run(t, "yubico.otp", M{"otp": otp, "aes_key": hex.EncodeToString(key), "last_usage_counter": 19, "last_session_counter": 3}, nil), "not a replay", "fail")
	wantStatus(t, run(t, "yubico.otp", M{"otp": otp, "aes_key": "00112233445566778899aabbccddeeff"}, nil), "token CRC", "fail")
	wantStatus(t, run(t, "yubico.otp", M{"otp": strings.Replace(otp, "c", "a", 1)}, nil), "public ID is modhex", "fail")
}
