package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"reflect"
	"sort"
	"testing"
)

func TestCBORKnownAnswers(t *testing.T) {
	// RFC 8949 Appendix A.
	cases := map[string]any{
		"00": int64(0), "17": int64(23), "1818": int64(24), "1903e8": int64(1000), "1bffffffffffffffff": uint64(math.MaxUint64),
		"20": int64(-1), "3903e7": int64(-1000), "f4": false, "f5": true, "f6": nil,
		"f93c00": 1.0, "f9c400": -4.0, "fa47c35000": 100000.0, "fb3ff199999999999a": 1.1,
		"6449455446": "IETF", "4401020304": []byte{1, 2, 3, 4}, "83010203": []any{int64(1), int64(2), int64(3)},
		"a201020304": map[any]any{int64(1): int64(2), int64(3): int64(4)}, "c11a514b67b0": int64(1363896240),
	}
	for h, want := range cases {
		b, _ := hex.DecodeString(h)
		got, n, err := cborDecode(b)
		if err != nil || n != len(b) || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %#v (%d bytes, %v), want %#v", h, got, n, err, want)
		}
	}
	for _, bad := range []string{"5f", "9f", "1a0000", "62aa", "8401", "bf"} {
		b, _ := hex.DecodeString(bad)
		if _, _, err := cborDecode(b); err == nil {
			t.Errorf("%s: malformed or indefinite input accepted", bad)
		}
	}
}

// cborEnc is a minimal encoder written independently of the decoder.
func cborEnc(v any) []byte {
	head := func(major byte, n uint64) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n < 256:
			return []byte{major<<5 | 24, byte(n)}
		case n < 65536:
			b := []byte{major<<5 | 25, 0, 0}
			binary.BigEndian.PutUint16(b[1:], uint16(n))
			return b
		}
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
	switch t := v.(type) {
	case int:
		if t >= 0 {
			return head(0, uint64(t))
		}
		return head(1, uint64(-1-t))
	case string:
		return append(head(3, uint64(len(t))), t...)
	case []byte:
		return append(head(2, uint64(len(t))), t...)
	case []any:
		out := head(4, uint64(len(t)))
		for _, e := range t {
			out = append(out, cborEnc(e)...)
		}
		return out
	case map[any]any:
		var keys []any
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return string(cborEnc(keys[i])) < string(cborEnc(keys[j])) })
		out := head(5, uint64(len(t)))
		for _, k := range keys {
			out = append(append(out, cborEnc(k)...), cborEnc(t[k])...)
		}
		return out
	}
	panic("cborEnc: unsupported type")
}

func TestWebAuthnCeremonies(t *testing.T) {
	cred, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	coseKey := map[any]any{1: 2, 3: -7, -1: 1, -2: cred.X.FillBytes(make([]byte, 32)), -3: cred.Y.FillBytes(make([]byte, 32))}
	rpHash := sha256.Sum256([]byte("example.com"))
	credID := []byte("credential-id-123")
	challenge := []byte("server-challenge-0001")

	authData := func(flags byte, count uint32, attested bool) []byte {
		b := append(append([]byte{}, rpHash[:]...), flags, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(b[33:], count)
		if attested {
			aaguid := make([]byte, 16)
			l := []byte{0, byte(len(credID))}
			b = append(append(append(append(b, aaguid...), l...), credID...), cborEnc(coseKey)...)
		}
		return b
	}
	clientData := func(typ, origin string, ch []byte) []byte {
		b, _ := json.Marshal(map[string]any{"type": typ, "challenge": b64url(ch), "origin": origin, "crossOrigin": false})
		return b
	}
	signOver := func(ad, cd []byte) []byte {
		h := sha256.Sum256(cd)
		d := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
		sig, _ := ecdsa.SignASN1(rand.Reader, cred, d[:])
		return sig
	}
	expect := M{"expected_challenge": b64url(challenge), "expected_origin": "https://example.com", "rp_id": "example.com"}
	with := func(extra M) M {
		out := M{}
		for k, v := range expect {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}

	// Registration with packed self attestation.
	regAD := authData(0x45, 0, true) // UP, UV, AT
	regCD := clientData("webauthn.create", "https://example.com", challenge)
	attObj := cborEnc(map[any]any{"fmt": "packed", "authData": regAD, "attStmt": map[any]any{"alg": -7, "sig": signOver(regAD, regCD)}})
	pkc, _ := json.Marshal(M{"id": b64url(credID), "type": "public-key", "response": M{"clientDataJSON": b64url(regCD), "attestationObject": b64url(attObj)}})
	reg := run(t, "webauthn.decode", with(M{"credential": string(pkc), "require_uv": true}), nil)
	noFailures(t, reg)
	for _, n := range []string{"attestation signature (packed, self)", "challenge matches", "origin matches", "rpIdHash", "user present", "user verified"} {
		wantStatus(t, reg, n, "pass")
	}
	ad := reg["authenticator_data"].(M)
	if ad["credential_id"] != b64url(credID) || ad["aaguid"] != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("credential data: %v", ad)
	}
	registeredKey := ad["credential_public_key"].(M)["pem"].(string)

	// Authentication with the registered key.
	authAD := authData(0x01, 7, false)
	authCD := clientData("webauthn.get", "https://example.com", challenge)
	sig := signOver(authAD, authCD)
	assert := func(extra M) M {
		base := M{"client_data_json": b64url(authCD), "authenticator_data": b64url(authAD), "signature": b64url(sig), "public_key": registeredKey}
		for k, v := range extra {
			base[k] = v
		}
		return with(base)
	}
	res := run(t, "webauthn.decode", assert(M{"prior_sign_count": 6}), nil)
	noFailures(t, res)
	wantStatus(t, res, "assertion signature", "pass")
	wantStatus(t, res, "user verified", "info")
	// The same assertion keyed by the COSE key instead of PEM.
	noFailures(t, run(t, "webauthn.decode", assert(M{"public_key": b64url(cborEnc(coseKey))}), nil))

	for name, tc := range map[string]struct {
		extra M
		check string
	}{
		"phishing origin":       {M{"client_data_json": b64url(clientData("webauthn.get", "https://examp1e.com", challenge))}, "origin matches"},
		"replayed challenge":    {M{"expected_challenge": b64url([]byte("a-newer-challenge"))}, "challenge matches"},
		"other relying party":   {M{"rp_id": "evil.example"}, "rpIdHash"},
		"altered client data":   {M{"client_data_json": b64url(append(authCD, ' '))}, "assertion signature"},
		"cloned authenticator":  {M{"prior_sign_count": 9}, "signature counter increased"},
		"user verification off": {M{"require_uv": true}, "user verified"},
	} {
		t.Run(name, func(t *testing.T) { wantStatus(t, run(t, "webauthn.decode", assert(tc.extra), nil), tc.check, "fail") })
	}
	bsWithoutBE := authData(0x11, 1, false)
	wantStatus(t, run(t, "webauthn.decode", M{"authenticator_data": b64url(bsWithoutBE)}, nil), "backup flags consistent", "fail")
}
