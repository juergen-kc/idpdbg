package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// RFC 7516 Appendix A.3: A128KW with A128CBC-HS256.
const (
	rfc7516A3Key = `{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}`
	rfc7516A3JWE = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
		"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ." +
		"AxY8DCtDaGlsbGljb3RoZQ." +
		"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY." +
		"U0m_YmjN04DJvceFICbCVQ"
)

func TestJWEKnownAnswers(t *testing.T) {
	res := run(t, "jwe.decrypt", M{"token": rfc7516A3JWE, "key": rfc7516A3Key}, nil)
	noFailures(t, res)
	if res["payload_text"] != "Live long and prosper." {
		t.Errorf("RFC 7516 A.3 plaintext: %q", res["payload_text"])
	}
	// One altered ciphertext byte must fail authentication.
	parts := strings.Split(rfc7516A3JWE, ".")
	ct, _ := b64urlDecode(parts[3])
	ct[0] ^= 1
	parts[3] = b64url(ct)
	wantStatus(t, run(t, "jwe.decrypt", M{"token": strings.Join(parts, "."), "key": rfc7516A3Key}, nil), "decrypted and authenticated", "fail")

	// RFC 7518 Appendix C: ECDH-ES key agreement for A128GCM, apu "Alice", apv "Bob".
	alice := `{"kty":"EC","crv":"P-256","x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0","y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}`
	bob := `{"kty":"EC","crv":"P-256","x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ","y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck","d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}`
	bobKey, err := loadPrivateKey(bob)
	if err != nil {
		t.Fatal(err)
	}
	var epk M
	json.Unmarshal([]byte(alice), &epk)
	pub, err := epkPublic(epk)
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := toECDHPrivate(bobKey)
	z, _ := priv.ECDH(pub)
	if got := b64url(concatKDF(z, "A128GCM", []byte("Alice"), []byte("Bob"), 128)); got != "VqqN6vgjbSBcIijNcacQGg" {
		t.Errorf("RFC 7518 C derived key: %s", got)
	}

	// RFC 3394 §4.1: 128-bit key wrapped with a 128-bit KEK.
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	wrapped, _ := aesKeyWrap(kek, key)
	if hex.EncodeToString(wrapped) != "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5" {
		t.Errorf("RFC 3394 wrap: %x", wrapped)
	}
	if back, err := aesKeyUnwrap(kek, wrapped); err != nil || hex.EncodeToString(back) != hex.EncodeToString(key) {
		t.Errorf("RFC 3394 unwrap: %x %v", back, err)
	}
}

func TestJWERoundTrips(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	xKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	xPriv := `{"kty":"OKP","crv":"X25519","x":"` + b64url(xKey.PublicKey().Bytes()) + `","d":"` + b64url(xKey.Bytes()) + `"}`
	xPub := `{"kty":"OKP","crv":"X25519","x":"` + b64url(xKey.PublicKey().Bytes()) + `"}`
	oct256 := `{"kty":"oct","k":"` + b64url(make([]byte, 32)) + `"}`
	oct128 := `{"kty":"oct","k":"` + b64url(make([]byte, 16)) + `"}`
	cases := []struct{ alg, enc, pub, priv string }{
		{"RSA-OAEP-256", "A256GCM", publicKeyPEM(&rsaKey.PublicKey), keyPEM(rsaKey)},
		{"RSA-OAEP", "A128CBC-HS256", publicKeyPEM(&rsaKey.PublicKey), keyPEM(rsaKey)},
		{"ECDH-ES", "A256GCM", publicKeyPEM(&ecKey.PublicKey), keyPEM(ecKey)},
		{"ECDH-ES+A256KW", "A256CBC-HS512", publicKeyPEM(&ecKey.PublicKey), keyPEM(ecKey)},
		{"ECDH-ES+A128KW", "A128GCM", xPub, xPriv},
		{"A128KW", "A192GCM", oct128, oct128},
		{"dir", "A256GCM", oct256, oct256},
	}
	for _, tc := range cases {
		t.Run(tc.alg+"/"+tc.enc, func(t *testing.T) {
			enc := run(t, "jwe.encrypt", M{"alg": tc.alg, "enc": tc.enc, "key": tc.pub, "claims": map[string]any{"sub": "alice"}}, nil)
			dec := run(t, "jwe.decrypt", M{"token": enc["token"], "key": tc.priv}, nil)
			noFailures(t, dec)
			if dec["payload"].(map[string]any)["sub"] != "alice" {
				t.Errorf("payload: %v", dec["payload"])
			}
		})
	}
	t.Run("PBES2", func(t *testing.T) {
		enc := run(t, "jwe.encrypt", M{"alg": "PBES2-HS256+A128KW", "enc": "A128GCM", "password": "correct horse", "payload": "hi"}, nil)
		noFailures(t, run(t, "jwe.decrypt", M{"token": enc["token"], "password": "correct horse"}, nil))
		wantStatus(t, run(t, "jwe.decrypt", M{"token": enc["token"], "password": "wrong"}, nil), "content key recovered", "fail")
	})
	t.Run("wrong key and weak algorithms", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		enc := run(t, "jwe.encrypt", M{"alg": "RSA-OAEP-256", "key": publicKeyPEM(&rsaKey.PublicKey), "payload": "x"}, nil)
		wantStatus(t, run(t, "jwe.decrypt", M{"token": enc["token"], "key": keyPEM(other)}, nil), "content key recovered", "fail")
		wantStatus(t, run(t, "jwe.decrypt", M{"token": enc["token"], "key": keyPEM(rsaKey)}, nil), "decrypted", "pass")
		oaep1 := run(t, "jwe.encrypt", M{"alg": "RSA-OAEP", "key": publicKeyPEM(&rsaKey.PublicKey), "payload": "x"}, nil)
		wantStatus(t, run(t, "jwe.decrypt", M{"token": oaep1["token"], "key": keyPEM(rsaKey)}, nil), "key management algorithm", "info")
	})
	t.Run("nested signed JWT", func(t *testing.T) {
		signed := run(t, "jwt.sign", M{"claims": map[string]any{"sub": "bob"}, "key": keyPEM(ecKey), "expires_in": 60}, nil)
		enc := run(t, "jwe.encrypt", M{"alg": "ECDH-ES", "key": publicKeyPEM(&ecKey.PublicKey), "payload": signed["token"], "cty": "JWT"}, nil)
		dec := run(t, "jwe.decrypt", M{"token": enc["token"], "key": keyPEM(ecKey)}, nil)
		if dec["nested_jwt"] == nil {
			t.Fatal("nested JWT not decoded")
		}
		noFailures(t, run(t, "jwt.verify", M{"token": signed["token"], "pem": publicKeyPEM(&ecKey.PublicKey)}, nil))
	})
}

func TestJWTSign(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, alg := range []string{"RS256", "PS384"} {
		tok := run(t, "jwt.sign", M{"claims": map[string]any{"iss": "me"}, "key": keyPEM(rsaKey), "alg": alg, "kid": "k1"}, nil)
		if tok["header"].(M)["alg"] != alg {
			t.Errorf("alg %v", tok["header"])
		}
		noFailures(t, run(t, "jwt.verify", M{"token": tok["token"], "pem": publicKeyPEM(&rsaKey.PublicKey)}, nil))
	}
	hs := run(t, "jwt.sign", M{"claims": map[string]any{"iss": "me"}, "secret": "s3cret", "expires_in": 30}, nil)
	noFailures(t, run(t, "jwt.verify", M{"token": hs["token"], "secret": "s3cret"}, nil))
	wantStatus(t, run(t, "jwt.verify", M{"token": hs["token"], "secret": "nope"}, nil), "signature", "fail")
}

func TestSDJWT(t *testing.T) {
	// RFC 9901 §4.2.1 / §4.2.3: the digest of a published example disclosure.
	if got := sdDigest("sha-256", "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"); got != "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0" {
		t.Errorf("RFC 9901 example digest: %s", got)
	}

	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	holderJWK, _ := publicJWK(holderKey.Public())
	disc := func(parts ...any) string {
		b, _ := json.Marshal(parts)
		return b64url(b)
	}
	salt := func() string { b := make([]byte, 16); rand.Read(b); return b64url(b) }
	given := disc(salt(), "given_name", "Erika")
	family := disc(salt(), "family_name", "Mustermann")
	nat := disc(salt(), "DE")
	unused := disc(salt(), "email", "not@referenced.example")
	decoy := sdDigest("sha-256", "decoy")
	payload := M{"iss": "https://issuer.example", "vct": "https://credentials.example/identity", "_sd_alg": "sha-256",
		"exp": 4102444800, "cnf": M{"jwk": holderJWK},
		"_sd":           []string{sdDigest("sha-256", given), sdDigest("sha-256", family), decoy},
		"nationalities": []any{M{"...": sdDigest("sha-256", nat)}, "FR"}}
	issuerJWT, err := signJWS(issuerKey, "ES256", M{"typ": "dc+sd-jwt"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	present := func(discs []string, kbKey *ecdsa.PrivateKey, nonce string) string {
		s := issuerJWT + "~" + strings.Join(discs, "~") + "~"
		kb, _ := signJWS(kbKey, "ES256", M{"typ": "kb+jwt"}, M{"iat": time.Now().Unix(), "aud": "https://verifier.example", "nonce": nonce, "sd_hash": sdDigest("sha-256", s)})
		return s + kb
	}
	base := M{"pem": publicKeyPEM(&issuerKey.PublicKey), "expected_aud": "https://verifier.example", "expected_nonce": "n-1"}
	with := func(tok string) M {
		m := M{"token": tok}
		for k, v := range base {
			m[k] = v
		}
		return m
	}

	res := run(t, "sdjwt.decode", with(present([]string{given, family, nat}, holderKey, "n-1")), nil)
	noFailures(t, res)
	cl := res["claims"].(M)
	if cl["given_name"] != "Erika" || cl["family_name"] != "Mustermann" || len(cl["nationalities"].([]any)) != 2 || cl["_sd"] != nil || cl["_sd_alg"] != nil {
		t.Errorf("reconstructed claims: %v", cl)
	}
	for _, n := range []string{"issuer signature", "KB-JWT signed by the holder", "KB-JWT sd_hash", "KB-JWT nonce", "KB-JWT aud", "vct present"} {
		wantStatus(t, res, n, "pass")
	}
	if res["undisclosed_digests"] != 1 {
		t.Errorf("undisclosed digests: %v", res["undisclosed_digests"])
	}

	// Selective disclosure: withholding a claim is fine.
	partial := run(t, "sdjwt.decode", with(present([]string{given}, holderKey, "n-1")), nil)
	noFailures(t, partial)
	if partial["claims"].(M)["family_name"] != nil || len(partial["claims"].(M)["nationalities"].([]any)) != 1 {
		t.Errorf("withheld claims leaked: %v", partial["claims"])
	}

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Same salt and name, different value: valid JSON whose digest the issuer never signed.
	var g []any
	gb, _ := b64urlDecode(given)
	json.Unmarshal(gb, &g)
	tampered := disc(g[0], "given_name", "Eve")
	for name, tc := range map[string]struct{ tok, check string }{
		"unreferenced disclosure": {present([]string{given, unused}, holderKey, "n-1"), "disclosure email: referenced"},
		"altered disclosure":      {present([]string{tampered}, holderKey, "n-1"), "referenced by the issuer"},
		"wrong nonce":             {present([]string{given}, holderKey, "n-2"), "KB-JWT nonce"},
		"KB-JWT from another key": {present([]string{given}, other, "n-1"), "KB-JWT signed by the holder"},
		"presentation re-ordered": {issuerJWT + "~" + family + "~" + given + "~" + strings.Split(present([]string{given, family}, holderKey, "n-1"), "~")[3], "sd_hash"},
	} {
		t.Run(name, func(t *testing.T) {
			r, err := runOp(t.Context(), findOp("sdjwt.decode"), with(tc.tok), false, nil)
			if err != nil {
				return // a disclosure that no longer decodes is refused outright
			}
			wantStatus(t, r, tc.check, "fail")
		})
	}
	wantStatus(t, run(t, "sdjwt.decode", M{"token": issuerJWT + "~" + given + "~", "pem": base["pem"]}, nil), "key binding JWT present", "warn")
	wantStatus(t, run(t, "sdjwt.decode", M{"token": issuerJWT + "~bm90LWpzb24~", "pem": base["pem"]}, nil), "disclosure 1: well-formed", "fail")
	wantStatus(t, run(t, "sdjwt.decode", M{"token": present([]string{given}, holderKey, "n-1"), "pem": publicKeyPEM(&other.PublicKey)}, nil), "issuer signature", "fail")
}

func TestTools(t *testing.T) {
	h := func(args M, alg string) string {
		return run(t, "tools.hash", args, nil)["hashes"].(M)[alg].(M)["hex"].(string)
	}
	// FIPS 180-4 and FIPS 202 examples for "abc"; RFC 4231 test case 2.
	known := map[string]string{
		"sha256":   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		"sha512":   "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		"sha3-256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
		"sha1":     "a9993e364706816aba3e25717850c26c9cd0d89d",
	}
	for alg, want := range known {
		if got := h(M{"input": "abc", "algorithms": []string{alg}}, alg); got != want {
			t.Errorf("%s(abc) = %s", alg, got)
		}
	}
	if got := h(M{"input": "what do ya want for nothing?", "hmac_key": "Jefe"}, "sha256"); got != "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" {
		t.Errorf("RFC 4231 case 2: %s", got)
	}
	if got := h(M{"input": "616263", "from": "hex", "algorithms": "sha256"}, "sha256"); got != known["sha256"] {
		t.Errorf("hex input: %s", got)
	}
	wantStatus(t, run(t, "tools.hash", M{"input": "abc", "algorithms": "md5"}, nil), "md5 collision resistance", "warn")
	// The left half is what at_hash uses.
	at := run(t, "tools.hash", M{"input": "opaque-access-token"}, nil)["hashes"].(M)["sha256"].(M)["left_half_base64url"]
	if at != halfHash("RS256", "opaque-access-token") {
		t.Errorf("left half %v", at)
	}

	enc := run(t, "tools.encode", M{"input": "<samlp:AuthnRequest/>"}, nil)
	dec := run(t, "tools.decode", M{"input": url.QueryEscape(enc["deflate_base64"].(string))}, nil)
	if dec["use"] != "saml decode" {
		t.Errorf("SAML redirect encoding not recognised: %v", dec)
	}
	steps := dec["decodings"].([]M)
	if last := steps[len(steps)-1]; last["result"].(M)["text"] != "<samlp:AuthnRequest/>" {
		t.Errorf("decode chain: %v", steps)
	}
	if run(t, "tools.decode", M{"input": "eyJhbGciOiJub25lIn0.e30."}, nil)["use"] != "jwt decode" {
		t.Error("JWT not recognised")
	}
	if run(t, "tools.decode", M{"input": rfc7516A3JWE}, nil)["use"] != "jwe decrypt" {
		t.Error("JWE not recognised")
	}
}

func TestHostileInputs(t *testing.T) {
	hdr := func(h M) string { b, _ := json.Marshal(h); return b64url(b) }
	oct := `{"kty":"oct","k":"` + b64url(make([]byte, 16)) + `"}`
	for name, tok := range map[string]string{
		"GCMKW with a short iv":  hdr(M{"alg": "A128GCMKW", "enc": "A128GCM", "iv": "AA", "tag": "AA"}) + "." + b64url(make([]byte, 16)) + ".AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA",
		"GCM content, short iv":  hdr(M{"alg": "dir", "enc": "A128GCM"}) + "..AA.AA.AAAAAAAAAAAAAAAAAAAAAA",
		"GCM content, short tag": hdr(M{"alg": "dir", "enc": "A128GCM"}) + "..AAAAAAAAAAAAAAAA.AA.AA",
	} {
		t.Run(name, func(t *testing.T) {
			res, err := runOp(t.Context(), findOp("jwe.decrypt"), M{"token": tok, "key": oct}, false, nil)
			if err != nil && strings.Contains(err.Error(), "internal error") {
				t.Fatalf("panicked: %v", err)
			}
			if !hasFailure(res) {
				t.Errorf("hostile token not rejected: %v", res["checks"])
			}
		})
	}
	slow := hdr(M{"alg": "PBES2-HS256+A128KW", "enc": "A128GCM", "p2s": "AAAAAAAAAAAAAAAAAAAAAA", "p2c": 1e12}) + "." + b64url(make([]byte, 24)) + ".AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"
	res := run(t, "jwe.decrypt", M{"token": slow, "password": "x"}, nil)
	if c := checkOf(res, "content key recovered"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "exceeds") {
		t.Errorf("unbounded p2c: %+v", c)
	}

	// A CBOR map whose key is a map: refused instead of panicking.
	for _, h := range []string{"a1a001", "a18001"} {
		b, _ := hex.DecodeString(h)
		if _, _, err := cborDecode(b); err == nil {
			t.Errorf("%s accepted", h)
		}
	}

	// A panic anywhere in an operation becomes an error.
	boom := &Op{Name: "test.boom", Run: func(*Ctx) (M, error) { var m map[string]int; m["x"] = 1; return nil, nil }}
	if _, err := safeRun(boom, &Ctx{}); err == nil || !strings.Contains(err.Error(), "internal error") {
		t.Errorf("panic not recovered: %v", err)
	}
}

func TestStoredKeysNotUsedForSigningOverMCP(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("IDPDBG_CONFIG", dir+"/config.json")
	t.Setenv("IDPDBG_SECRET", "env-secret")
	t.Setenv("IDPDBG_HMAC_KEY", "env-key")
	os.WriteFile(dir+"/config.json", []byte(`{"profiles":{"p":{"secret":"profile-secret","hmac_key":"k","password":"pw"}}}`), 0o600)
	claims := map[string]any{"sub": "x"}
	for _, raw := range []M{{"claims": claims}, {"claims": claims, "profile": "p"}} {
		if _, err := runOp(t.Context(), findOp("jwt.sign"), raw, false, nil); err == nil {
			t.Errorf("MCP caller signed with a stored secret: %v", raw)
		}
		if res, err := runOp(t.Context(), findOp("jwt.sign"), raw, true, nil); err != nil || res["token"] == nil {
			t.Errorf("CLI could not use the stored secret: %v", err)
		}
	}
	if res, _ := runOp(t.Context(), findOp("tools.hash"), M{"input": "x", "profile": "p"}, false, nil); res["mode"] == "HMAC" {
		t.Error("MCP caller computed an HMAC with a stored key")
	}
	if res, _ := runOp(t.Context(), findOp("tools.hash"), M{"input": "x", "hmac_key": "given"}, false, nil); res["mode"] != "HMAC" {
		t.Error("an explicitly passed HMAC key should still work over MCP")
	}
}
