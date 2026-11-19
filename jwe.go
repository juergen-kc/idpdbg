package main

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"strings"
	"time"
)

// JWE (RFC 7516 / RFC 7518): every registered key management and content
// encryption algorithm, plus loading keys from PEM or JWK.

// ---- keys ----

func looksLikeJSON(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "{") }

// parseJWKJSON returns the first key of a JWK or JWKS.
func parseJWKJSON(s string) (M, error) {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	keys := jwksKeys(v)
	if len(keys) == 0 {
		return nil, errors.New("no JWK found")
	}
	return keys[0], nil
}

// loadPrivateKey reads a private key from PEM or a JWK, returning
// *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey, *ecdh.PrivateKey
// (X25519) or []byte (oct).
func loadPrivateKey(s string) (any, error) {
	if !looksLikeJSON(s) {
		return loadSigner(s)
	}
	k, err := parseJWKJSON(s)
	if err != nil {
		return nil, err
	}
	d, _ := b64urlDecode(str(k["d"]))
	switch str(k["kty"]) {
	case "oct":
		return b64urlDecode(str(k["k"]))
	case "RSA":
		pub, err := jwkPublicKey(k)
		if err != nil {
			return nil, err
		}
		p, err1 := jwkBig(k, "p")
		q, err2 := jwkBig(k, "q")
		if err1 != nil || err2 != nil || len(d) == 0 {
			return nil, errors.New("an RSA private JWK needs d, p and q")
		}
		priv := &rsa.PrivateKey{PublicKey: *pub.(*rsa.PublicKey), D: new(big.Int).SetBytes(d), Primes: []*big.Int{p, q}}
		priv.Precompute()
		return priv, priv.Validate()
	case "EC":
		pub, err := jwkPublicKey(k)
		if err != nil {
			return nil, err
		}
		if len(d) == 0 {
			return nil, errors.New("the JWK has no private part d")
		}
		return &ecdsa.PrivateKey{PublicKey: *pub.(*ecdsa.PublicKey), D: new(big.Int).SetBytes(d)}, nil
	case "OKP":
		switch str(k["crv"]) {
		case "Ed25519":
			return ed25519.NewKeyFromSeed(d), nil
		case "X25519":
			return ecdh.X25519().NewPrivateKey(d)
		}
	}
	return nil, fmt.Errorf("unsupported private JWK (kty %q)", str(k["kty"]))
}

// loadPublicKeyAny reads a public key from a JWK/JWKS, a PEM certificate or
// public key, or the public half of a private key.
func loadPublicKeyAny(s string) (any, error) {
	if looksLikeJSON(s) {
		k, err := parseJWKJSON(s)
		if err != nil {
			return nil, err
		}
		if str(k["kty"]) == "OKP" && str(k["crv"]) == "X25519" {
			x, _ := b64urlDecode(str(k["x"]))
			return ecdh.X25519().NewPublicKey(x)
		}
		return jwkPublicKey(k)
	}
	if k, err := loadPublicKeyPEM(s); err == nil {
		return k, nil
	}
	if priv, err := loadSigner(s); err == nil {
		return priv.Public(), nil
	}
	return nil, errors.New("no public key found (expected a JWK, a PEM certificate or a PEM public key)")
}

func toECDHPrivate(k any) (*ecdh.PrivateKey, error) {
	switch v := k.(type) {
	case *ecdh.PrivateKey:
		return v, nil
	case *ecdsa.PrivateKey:
		return v.ECDH()
	}
	return nil, fmt.Errorf("ECDH-ES needs an EC or X25519 private key, not %T", k)
}

func toECDHPublic(k any) (*ecdh.PublicKey, error) {
	switch v := k.(type) {
	case *ecdh.PublicKey:
		return v, nil
	case *ecdsa.PublicKey:
		return v.ECDH()
	}
	return nil, fmt.Errorf("ECDH-ES needs an EC or X25519 public key, not %T", k)
}

func ecdhJWK(pub *ecdh.PublicKey) M {
	b := pub.Bytes()
	switch pub.Curve() {
	case ecdh.X25519():
		return M{"kty": "OKP", "crv": "X25519", "x": b64url(b)}
	case ecdh.P256():
		return M{"kty": "EC", "crv": "P-256", "x": b64url(b[1:33]), "y": b64url(b[33:])}
	case ecdh.P384():
		return M{"kty": "EC", "crv": "P-384", "x": b64url(b[1:49]), "y": b64url(b[49:])}
	default:
		return M{"kty": "EC", "crv": "P-521", "x": b64url(b[1:67]), "y": b64url(b[67:])}
	}
}

func epkPublic(epk M) (*ecdh.PublicKey, error) {
	if str(epk["kty"]) == "OKP" && str(epk["crv"]) == "X25519" {
		x, _ := b64urlDecode(str(epk["x"]))
		return ecdh.X25519().NewPublicKey(x)
	}
	pub, err := jwkPublicKey(epk)
	if err != nil {
		return nil, fmt.Errorf("epk: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("epk is not an EC key")
	}
	if !ec.Curve.IsOnCurve(ec.X, ec.Y) {
		return nil, errors.New("epk is not on its curve (invalid-curve attack?)")
	}
	_ = elliptic.P256
	return ec.ECDH()
}

// ---- primitives ----

var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// aesKeyWrap and aesKeyUnwrap implement RFC 3394.
func aesKeyWrap(kek, key []byte) ([]byte, error) {
	if len(key)%8 != 0 || len(key) < 16 {
		return nil, errors.New("key wrap: key length must be a multiple of 8, at least 16")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(key) / 8
	a := append([]byte{}, defaultIV...)
	r := make([][]byte, n)
	for i := range r {
		r[i] = append([]byte{}, key[i*8:(i+1)*8]...)
	}
	buf := make([]byte, 16)
	for j := 0; j < 6; j++ {
		for i := 0; i < n; i++ {
			copy(buf, a)
			copy(buf[8:], r[i])
			block.Encrypt(buf, buf)
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buf[:8])^t)
			copy(r[i], buf[8:])
		}
	}
	out := append([]byte{}, a...)
	for _, ri := range r {
		out = append(out, ri...)
	}
	return out, nil
}

func aesKeyUnwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped)%8 != 0 || len(wrapped) < 24 {
		return nil, errors.New("key unwrap: bad wrapped key length")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(wrapped)/8 - 1
	a := append([]byte{}, wrapped[:8]...)
	r := make([][]byte, n)
	for i := range r {
		r[i] = append([]byte{}, wrapped[(i+1)*8:(i+2)*8]...)
	}
	buf := make([]byte, 16)
	for j := 5; j >= 0; j-- {
		for i := n - 1; i >= 0; i-- {
			t := uint64(n*j + i + 1)
			binary.BigEndian.PutUint64(buf, binary.BigEndian.Uint64(a)^t)
			copy(buf[8:], r[i])
			block.Decrypt(buf, buf)
			copy(a, buf[:8])
			copy(r[i], buf[8:])
		}
	}
	if subtle.ConstantTimeCompare(a, defaultIV) != 1 {
		return nil, errors.New("key unwrap: integrity check failed (wrong key?)")
	}
	var out []byte
	for _, ri := range r {
		out = append(out, ri...)
	}
	return out, nil
}

// concatKDF is the single-step KDF of NIST SP 800-56A as profiled by
// RFC 7518 §4.6.2.
func concatKDF(z []byte, algID string, apu, apv []byte, keyBits int) []byte {
	lp := func(b []byte) []byte {
		out := make([]byte, 4, 4+len(b))
		binary.BigEndian.PutUint32(out, uint32(len(b)))
		return append(out, b...)
	}
	other := append(lp([]byte(algID)), lp(apu)...)
	other = append(other, lp(apv)...)
	supp := make([]byte, 4)
	binary.BigEndian.PutUint32(supp, uint32(keyBits))
	other = append(other, supp...)
	var out []byte
	for counter := uint32(1); len(out)*8 < keyBits; counter++ {
		h := sha256.New()
		c := make([]byte, 4)
		binary.BigEndian.PutUint32(c, counter)
		h.Write(c)
		h.Write(z)
		h.Write(other)
		out = h.Sum(out)
	}
	return out[:keyBits/8]
}

// maxPBES2Count bounds the work a token can demand; this tool encrypts with 600,000.
const maxPBES2Count = 2_000_000

var encKeyBits = map[string]int{"A128GCM": 128, "A192GCM": 192, "A256GCM": 256, "A128CBC-HS256": 256, "A192CBC-HS384": 384, "A256CBC-HS512": 512}

func kwBits(alg string) int {
	switch {
	case strings.Contains(alg, "A128"):
		return 128
	case strings.Contains(alg, "A192"):
		return 192
	}
	return 256
}

// contentDecrypt and contentEncrypt cover AES-GCM and AES-CBC + HMAC-SHA2.
func contentDecrypt(enc string, cek, iv, ct, tag, aad []byte) ([]byte, error) {
	if strings.HasSuffix(enc, "GCM") {
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, err
		}
		if len(iv) != 12 || len(tag) != 16 {
			return nil, fmt.Errorf("%s needs a 96-bit IV and a 128-bit tag, got %d and %d bits", enc, len(iv)*8, len(tag)*8)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		return gcm.Open(nil, iv, append(append([]byte{}, ct...), tag...), aad)
	}
	macKey, encKey, h, err := cbcHSKeys(enc, cek)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(cbcHSTag(h, macKey, aad, iv, ct), tag) {
		return nil, errors.New("authentication tag mismatch (wrong key, or the token was altered)")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	if len(ct)%aes.BlockSize != 0 || len(iv) != aes.BlockSize || len(ct) == 0 {
		return nil, errors.New("bad ciphertext or IV length for AES-CBC")
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	pad := int(plain[len(plain)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(plain) {
		return nil, errors.New("bad padding")
	}
	return plain[:len(plain)-pad], nil
}

func cbcHSKeys(enc string, cek []byte) (macKey, encKey []byte, h func() hash.Hash, err error) {
	h = map[string]func() hash.Hash{"A128CBC-HS256": sha256.New, "A192CBC-HS384": sha512.New384, "A256CBC-HS512": sha512.New}[enc]
	if h == nil {
		return nil, nil, nil, fmt.Errorf("unsupported enc %q", enc)
	}
	if len(cek)*8 != encKeyBits[enc] {
		return nil, nil, nil, fmt.Errorf("%s needs a %d-bit key, got %d bits", enc, encKeyBits[enc], len(cek)*8)
	}
	return cek[:len(cek)/2], cek[len(cek)/2:], h, nil
}

func cbcHSTag(h func() hash.Hash, macKey, aad, iv, ct []byte) []byte {
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aad))*8)
	m := hmac.New(h, macKey)
	m.Write(aad)
	m.Write(iv)
	m.Write(ct)
	m.Write(al)
	sum := m.Sum(nil)
	return sum[:len(macKey)]
}

func contentEncrypt(enc string, cek, plain, aad []byte) (iv, ct, tag []byte, err error) {
	if strings.HasSuffix(enc, "GCM") {
		block, err := aes.NewCipher(cek)
		if err != nil {
			return nil, nil, nil, err
		}
		gcm, _ := cipher.NewGCM(block)
		iv = make([]byte, 12)
		rand.Read(iv)
		sealed := gcm.Seal(nil, iv, plain, aad)
		return iv, sealed[:len(sealed)-16], sealed[len(sealed)-16:], nil
	}
	macKey, encKey, h, err := cbcHSKeys(enc, cek)
	if err != nil {
		return nil, nil, nil, err
	}
	block, _ := aes.NewCipher(encKey)
	iv = make([]byte, aes.BlockSize)
	rand.Read(iv)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	ct = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return iv, ct, cbcHSTag(h, macKey, aad, iv, ct), nil
}

// ---- decrypt ----

type jweParts struct {
	Header                      M
	B64Header                   string
	EncKey, IV, Ciphertext, Tag []byte
}

func parseJWE(s string) (*jweParts, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("not a compact JWE: expected 5 parts, found %d", len(parts))
	}
	p := &jweParts{B64Header: parts[0]}
	hb, err := b64urlDecode(parts[0])
	if err != nil || json.Unmarshal(hb, &p.Header) != nil {
		return nil, errors.New("the protected header is not base64url JSON")
	}
	dec := []*[]byte{&p.EncKey, &p.IV, &p.Ciphertext, &p.Tag}
	for i, d := range dec {
		if *d, err = b64urlDecode(parts[i+1]); err != nil {
			return nil, fmt.Errorf("part %d is not base64url", i+2)
		}
	}
	return p, nil
}

// unwrapCEK recovers the content encryption key for alg.
func unwrapCEK(p *jweParts, key any, password string) ([]byte, error) {
	alg, enc := str(p.Header["alg"]), str(p.Header["enc"])
	switch {
	case alg == "dir":
		k, ok := key.([]byte)
		if !ok {
			return nil, errors.New("dir needs a symmetric (oct) key")
		}
		return k, nil
	case alg == "RSA1_5" || strings.HasPrefix(alg, "RSA-OAEP"):
		rk, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s needs an RSA private key", alg)
		}
		switch alg {
		case "RSA1_5":
			return rsa.DecryptPKCS1v15(nil, rk, p.EncKey)
		case "RSA-OAEP":
			return rsa.DecryptOAEP(sha1.New(), nil, rk, p.EncKey, nil)
		case "RSA-OAEP-256":
			return rsa.DecryptOAEP(sha256.New(), nil, rk, p.EncKey, nil)
		case "RSA-OAEP-384":
			return rsa.DecryptOAEP(sha512.New384(), nil, rk, p.EncKey, nil)
		case "RSA-OAEP-512":
			return rsa.DecryptOAEP(sha512.New(), nil, rk, p.EncKey, nil)
		}
	case strings.HasPrefix(alg, "ECDH-ES"):
		priv, err := toECDHPrivate(key)
		if err != nil {
			return nil, err
		}
		epkM, _ := p.Header["epk"].(map[string]any)
		epk, err := epkPublic(epkM)
		if err != nil {
			return nil, err
		}
		z, err := priv.ECDH(epk)
		if err != nil {
			return nil, err
		}
		apu, _ := b64urlDecode(str(p.Header["apu"]))
		apv, _ := b64urlDecode(str(p.Header["apv"]))
		if alg == "ECDH-ES" {
			return concatKDF(z, enc, apu, apv, encKeyBits[enc]), nil
		}
		return aesKeyUnwrap(concatKDF(z, alg, apu, apv, kwBits(alg)), p.EncKey)
	case strings.HasSuffix(alg, "GCMKW"):
		kek, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%s needs a symmetric (oct) key", alg)
		}
		iv, _ := b64urlDecode(str(p.Header["iv"]))
		tag, _ := b64urlDecode(str(p.Header["tag"]))
		block, err := aes.NewCipher(kek)
		if err != nil {
			return nil, err
		}
		gcm, _ := cipher.NewGCM(block)
		if len(iv) != gcm.NonceSize() || len(tag) != gcm.Overhead() {
			return nil, fmt.Errorf("%s needs a %d-byte iv and a %d-byte tag in the header", alg, gcm.NonceSize(), gcm.Overhead())
		}
		return gcm.Open(nil, iv, append(append([]byte{}, p.EncKey...), tag...), nil)
	case strings.HasPrefix(alg, "PBES2-"):
		if password == "" {
			return nil, fmt.Errorf("%s needs password", alg)
		}
		salt, _ := b64urlDecode(str(p.Header["p2s"]))
		count, _ := p.Header["p2c"].(float64)
		h := map[string]func() hash.Hash{"PBES2-HS256+A128KW": sha256.New, "PBES2-HS384+A192KW": sha512.New384, "PBES2-HS512+A256KW": sha512.New}[alg]
		if h == nil || count < 1 {
			return nil, fmt.Errorf("bad %s parameters", alg)
		}
		if count > maxPBES2Count {
			return nil, fmt.Errorf("p2c=%.0f exceeds the %d iterations idpdbg will run (a hostile token could otherwise stall it)", count, maxPBES2Count)
		}
		fullSalt := append(append([]byte(alg), 0), salt...)
		kek, err := pbkdf2.Key(h, password, fullSalt, int(count), kwBits(alg)/8)
		if err != nil {
			return nil, err
		}
		return aesKeyUnwrap(kek, p.EncKey)
	case strings.HasSuffix(alg, "KW"):
		kek, ok := key.([]byte)
		if !ok {
			return nil, fmt.Errorf("%s needs a symmetric (oct) key", alg)
		}
		return aesKeyUnwrap(kek, p.EncKey)
	}
	return nil, fmt.Errorf("unsupported alg %q", alg)
}

func runJWEDecrypt(c *Ctx) (M, error) {
	p, err := parseJWE(c.Str("token"))
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{"header": p.Header}
	defer func() { out["checks"] = cs }()
	alg, enc := str(p.Header["alg"]), str(p.Header["enc"])
	switch {
	case alg == "RSA1_5":
		cs.add("key management algorithm", "warn", "RSA1_5 is open to padding-oracle attacks; use RSA-OAEP-256 or ECDH-ES", "RFC 8725 §3.2")
	case alg == "RSA-OAEP":
		cs.add("key management algorithm", "info", "RSA-OAEP uses SHA-1; RSA-OAEP-256 is preferred", "RFC 7518 §4.3")
	case strings.HasPrefix(alg, "PBES2-"):
		if n, _ := p.Header["p2c"].(float64); n < 1000 {
			cs.add("PBES2 iteration count", "warn", fmt.Sprintf("p2c=%v is low; RFC 7518 recommends at least 1000", p.Header["p2c"]), "RFC 7518 §4.8.1.2")
		}
	}
	if _, ok := encKeyBits[enc]; !ok {
		cs.add("content encryption algorithm", "fail", "unsupported enc "+enc, "RFC 7518 §5.1")
		return out, nil
	}
	var key any
	if k := c.Str("key"); k != "" {
		if key, err = loadPrivateKey(k); err != nil {
			return out, fmt.Errorf("key: %w", err)
		}
	} else if !strings.HasPrefix(alg, "PBES2-") {
		return out, errors.New("pass key (PEM, or a private/oct JWK)")
	}
	cek, err := unwrapCEK(p, key, c.Str("password"))
	if !cs.ok(err == nil, "content key recovered ("+alg+")", detailOr(err, ""), "RFC 7516 §5.2") {
		return out, nil
	}
	plain, err := contentDecrypt(enc, cek, p.IV, p.Ciphertext, p.Tag, []byte(p.B64Header))
	if !cs.ok(err == nil, "decrypted and authenticated ("+enc+")", detailOr(err, ""), "RFC 7516 §5.2") {
		return out, nil
	}
	if str(p.Header["zip"]) == "DEF" {
		if plain, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(plain)), 16<<20)); err != nil {
			cs.add("decompression", "fail", err.Error(), "RFC 7516 §4.1.3")
			return out, nil
		}
		cs.add("compression before encryption", "info", "zip=DEF can leak plaintext length information", "RFC 8725 §3.6")
	}
	text := strings.TrimSpace(string(plain))
	var js any
	switch {
	case looksLikeJWT(text):
		jp, err := parseJWT(text)
		if err == nil {
			out["nested_jwt"] = describeJWT(jp)
			cs.add("nested JWT", "info", "the payload is a signed JWT; verify it with jwt verify", "RFC 7519 §5.2")
		}
	case json.Unmarshal(plain, &js) == nil:
		out["payload"] = js
		if m, ok := js.(map[string]any); ok {
			timeChecks(&cs, m, 60)
		}
	default:
		out["payload_text"] = string(plain)
	}
	return out, nil
}

// ---- encrypt ----

func runJWEEncrypt(c *Ctx) (M, error) {
	alg, enc := c.Str("alg"), c.Str("enc")
	if _, ok := encKeyBits[enc]; !ok {
		return nil, fmt.Errorf("unsupported enc %q", enc)
	}
	header := M{"alg": alg, "enc": enc}
	if kid := c.Str("kid"); kid != "" {
		header["kid"] = kid
	}
	if cty := c.Str("cty"); cty != "" {
		header["cty"] = cty
	}
	var key any
	var err error
	if alg == "dir" || strings.HasSuffix(alg, "KW") && !strings.HasPrefix(alg, "ECDH-ES") && !strings.HasPrefix(alg, "PBES2") {
		if key, err = loadPrivateKey(c.Str("key")); err != nil {
			return nil, fmt.Errorf("key: %w", err)
		}
	} else if !strings.HasPrefix(alg, "PBES2") {
		if key, err = loadPublicKeyAny(c.Str("key")); err != nil {
			return nil, fmt.Errorf("key: %w", err)
		}
	}
	cek := make([]byte, encKeyBits[enc]/8)
	rand.Read(cek)
	var encKey []byte
	switch {
	case alg == "dir":
		k, ok := key.([]byte)
		if !ok || len(k) != len(cek) {
			return nil, fmt.Errorf("dir with %s needs a %d-byte oct key", enc, len(cek))
		}
		cek = k
	case strings.HasPrefix(alg, "RSA-OAEP"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s needs an RSA public key", alg)
		}
		h := map[string]hash.Hash{"RSA-OAEP": sha1.New(), "RSA-OAEP-256": sha256.New(), "RSA-OAEP-384": sha512.New384(), "RSA-OAEP-512": sha512.New()}[alg]
		if h == nil {
			return nil, fmt.Errorf("unsupported alg %q", alg)
		}
		if encKey, err = rsa.EncryptOAEP(h, rand.Reader, pub, cek, nil); err != nil {
			return nil, err
		}
	case strings.HasPrefix(alg, "ECDH-ES"):
		pub, err := toECDHPublic(key)
		if err != nil {
			return nil, err
		}
		eph, err := pub.Curve().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		z, err := eph.ECDH(pub)
		if err != nil {
			return nil, err
		}
		header["epk"] = ecdhJWK(eph.PublicKey())
		if alg == "ECDH-ES" {
			cek = concatKDF(z, enc, nil, nil, encKeyBits[enc])
		} else if encKey, err = aesKeyWrap(concatKDF(z, alg, nil, nil, kwBits(alg)), cek); err != nil {
			return nil, err
		}
	case strings.HasPrefix(alg, "PBES2-"):
		h := map[string]func() hash.Hash{"PBES2-HS256+A128KW": sha256.New, "PBES2-HS384+A192KW": sha512.New384, "PBES2-HS512+A256KW": sha512.New}[alg]
		if h == nil || c.Str("password") == "" {
			return nil, fmt.Errorf("%s needs a supported alg and password", alg)
		}
		salt := make([]byte, 16)
		rand.Read(salt)
		header["p2s"], header["p2c"] = b64url(salt), 600000
		kek, err := pbkdf2.Key(h, c.Str("password"), append(append([]byte(alg), 0), salt...), 600000, kwBits(alg)/8)
		if err != nil {
			return nil, err
		}
		if encKey, err = aesKeyWrap(kek, cek); err != nil {
			return nil, err
		}
	case strings.HasSuffix(alg, "KW") && !strings.HasSuffix(alg, "GCMKW"):
		k, ok := key.([]byte)
		if !ok || len(k)*8 != kwBits(alg) {
			return nil, fmt.Errorf("%s needs a %d-bit oct key", alg, kwBits(alg))
		}
		if encKey, err = aesKeyWrap(k, cek); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported alg %q for encryption", alg)
	}
	hb, _ := json.Marshal(header)
	b64h := b64url(hb)
	payload := []byte(c.Str("payload"))
	if c.Has("claims") {
		claims, _ := c.Args["claims"].(map[string]any)
		if claims != nil && c.Bool("iat_now") {
			if _, ok := claims["iat"]; !ok {
				claims["iat"] = time.Now().Unix()
			}
		}
		payload, _ = json.Marshal(c.Args["claims"])
	}
	if len(payload) == 0 {
		return nil, errors.New("pass payload or claims")
	}
	iv, ct, tag, err := contentEncrypt(enc, cek, payload, []byte(b64h))
	if err != nil {
		return nil, err
	}
	token := strings.Join([]string{b64h, b64url(encKey), b64url(iv), b64url(ct), b64url(tag)}, ".")
	return M{"token": token, "header": header}, nil
}

// ---- jwt sign ----

func runJWTSign(c *Ctx) (M, error) {
	claims, _ := c.Args["claims"].(map[string]any)
	if claims == nil {
		return nil, errors.New("claims must be a JSON object")
	}
	now := time.Now().Unix()
	if c.Bool("iat_now") {
		if _, ok := claims["iat"]; !ok {
			claims["iat"] = now
		}
	}
	if n := c.Int("expires_in"); n > 0 {
		claims["exp"] = now + int64(n)
	}
	header := M{"typ": "JWT"}
	if h, ok := c.Args["header"].(map[string]any); ok {
		for k, v := range h {
			header[k] = v
		}
	}
	if kid := c.Str("kid"); kid != "" {
		header["kid"] = kid
	}
	var tok string
	if sec := c.Str("secret"); sec != "" {
		alg := c.Str("alg")
		if alg == "" {
			alg = "HS256"
		}
		if !strings.HasPrefix(alg, "HS") {
			return nil, errors.New("a secret signs only HS256/HS384/HS512")
		}
		delete(header, "alg")
		tok = signHS([]byte(sec), alg, header, claims)
	} else {
		if c.Str("key") == "" {
			return nil, errors.New("pass key (PEM or private JWK) or secret")
		}
		k, err := loadPrivateKey(c.Str("key"))
		if err != nil {
			return nil, fmt.Errorf("key: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("the key cannot sign (oct keys need secret)")
		}
		alg, err := signerAlg(signer, c.Str("alg"))
		if err != nil {
			return nil, err
		}
		if c.Bool("embed_jwk") {
			jwk, err := publicJWK(signer.Public())
			if err != nil {
				return nil, err
			}
			header["jwk"] = jwk
		}
		if tok, err = signJWS(signer, alg, header, claims); err != nil {
			return nil, err
		}
	}
	p, _ := parseJWT(tok)
	out := describeJWT(p)
	out["token"] = tok
	return out, nil
}

// publicKeyPEM is used by tests and by webauthn output.
func publicKeyPEM(pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func init() {
	register(
		&Op{
			Name:    "jwe.decrypt",
			Summary: "Decrypt a compact JWE with every registered algorithm: RSA-OAEP(-256/384/512), RSA1_5, ECDH-ES (+A128/192/256KW, P-256/384/521 and X25519), AES key wrap, AES-GCM key wrap, PBES2 and dir; content A128/192/256GCM and A128CBC-HS256/A192CBC-HS384/A256CBC-HS512; zip=DEF. Shows the header, the payload or nested JWT, and flags weak choices.",
			Params: []Param{
				{Name: "token", Type: "string", Required: true, File: true, Desc: "The compact JWE (CLI: @file or - for stdin)"},
				{Name: "key", Type: "string", Path: true, Explicit: true, Desc: "Decryption key: PEM private key, or a private or oct JWK"},
				{Name: "password", Type: "string", Secret: true, Explicit: true, Desc: "Password for PBES2 (prefer env IDPDBG_PASSWORD)"}},
			Run: runJWEDecrypt,
		},
		&Op{
			Name:    "jwe.encrypt",
			Summary: "Encrypt a payload or JSON claims into a compact JWE for a recipient key (public PEM/JWK, or an oct JWK for dir and AES key wrap, or a password for PBES2). For producing test tokens.",
			Params: []Param{
				{Name: "alg", Type: "string", Desc: "Key management: RSA-OAEP-256, RSA-OAEP, ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A256KW, A128KW, A256KW, dir, PBES2-HS256+A128KW…", Default: "RSA-OAEP-256"},
				{Name: "enc", Type: "string", Enum: []string{"A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"}, Desc: "Content encryption", Default: "A256GCM"},
				{Name: "key", Type: "string", Path: true, Desc: "Recipient key: public PEM or certificate, a public JWK, or an oct JWK"},
				{Name: "password", Type: "string", Secret: true, Explicit: true, Desc: "Password for PBES2"},
				{Name: "payload", Type: "string", File: true, Desc: "Plaintext to encrypt (or use claims)"},
				{Name: "claims", Type: "json", Desc: "JSON claims to encrypt"},
				{Name: "iat_now", Type: "bool", Desc: "Add iat to claims when missing", Default: true},
				{Name: "kid", Type: "string", Desc: "kid header"},
				{Name: "cty", Type: "string", Desc: "cty header, e.g. JWT for a nested token"}},
			Run: runJWEEncrypt,
		},
		&Op{
			Name:    "jwt.sign",
			Summary: "Create a signed JWT from JSON claims with a private key (PEM or JWK; RS/PS/ES/EdDSA) or a shared secret (HS256/384/512). Adds iat and, with expires_in, exp. For producing test tokens.",
			Params: []Param{
				{Name: "claims", Type: "json", Required: true, Desc: `JSON claims, e.g. {"iss":"https://issuer","sub":"alice","aud":"api"}`},
				{Name: "key", Type: "string", Path: true, Explicit: true, Desc: "Signing key: PEM private key or private JWK"},
				{Name: "secret", Type: "string", Secret: true, Explicit: true, Desc: "Shared secret for HS256/384/512"},
				{Name: "alg", Type: "string", Desc: "Algorithm; default follows the key (RS256, ES256/384/512, EdDSA) or HS256; PS256/384/512 for RSA-PSS"},
				{Name: "kid", Type: "string", Desc: "kid header"},
				{Name: "header", Type: "json", Desc: "Extra header members as a JSON object"},
				{Name: "embed_jwk", Type: "bool", Desc: "Put the public key in the header as jwk"},
				{Name: "iat_now", Type: "bool", Desc: "Add iat when missing", Default: true},
				{Name: "expires_in", Type: "int", Desc: "Set exp this many seconds from now"}},
			Run: runJWTSign,
		},
	)
}
