package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

type jwtParts struct {
	Header       M
	Claims       M // nil when the payload is not a JSON object
	Payload      []byte
	Sig          []byte
	SigningInput string
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func looksLikeJWT(s string) bool {
	return strings.Count(s, ".") == 2 && strings.HasPrefix(s, "eyJ")
}

func parseJWT(tok string) (*jwtParts, error) {
	tok = strings.TrimSpace(tok)
	tok = strings.TrimPrefix(strings.TrimPrefix(tok, "Bearer "), "bearer ")
	parts := strings.Split(tok, ".")
	if len(parts) == 5 {
		return nil, errors.New("this is a JWE (5 parts, encrypted): use jwe decrypt with the recipient key")
	}
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT: expected 3 dot-separated parts, found %d", len(parts))
	}
	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header is not base64url: %w", err)
	}
	p := &jwtParts{SigningInput: parts[0] + "." + parts[1]}
	if err := json.Unmarshal(hb, &p.Header); err != nil {
		return nil, fmt.Errorf("header is not JSON: %w", err)
	}
	if p.Payload, err = b64urlDecode(parts[1]); err != nil {
		return nil, fmt.Errorf("payload is not base64url: %w", err)
	}
	_ = json.Unmarshal(p.Payload, &p.Claims)
	if p.Sig, err = b64urlDecode(parts[2]); err != nil {
		return nil, fmt.Errorf("signature is not base64url: %w", err)
	}
	return p, nil
}

func claimTime(claims M, name string) (time.Time, bool) {
	f, ok := claims[name].(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0).UTC(), true
}

// audList normalises the aud claim, which may be a string or an array.
func audList(claims M) []string {
	switch a := claims["aud"].(type) {
	case string:
		return []string{a}
	case []any:
		out := []string{}
		for _, v := range a {
			out = append(out, fmt.Sprint(v))
		}
		return out
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// describeJWT is the decoded view shared by every operation that shows a token.
func describeJWT(p *jwtParts) M {
	out := M{"header": p.Header}
	if p.Claims == nil {
		out["payload_raw"] = string(p.Payload)
		return out
	}
	out["claims"] = p.Claims
	times := M{}
	for _, n := range []string{"iat", "nbf", "exp", "auth_time", "updated_at"} {
		if t, ok := claimTime(p.Claims, n); ok {
			times[n] = t.Format(time.RFC3339) + " (" + relTime(t) + ")"
		}
	}
	if len(times) > 0 {
		out["times"] = times
	}
	return out
}

// timeChecks covers exp / nbf / iat with a leeway in seconds.
func timeChecks(cs *Checks, claims M, leeway int) {
	lw := time.Duration(leeway) * time.Second
	now := time.Now()
	if exp, ok := claimTime(claims, "exp"); ok {
		cs.ok(now.Before(exp.Add(lw)), "exp: token not expired", "expires "+exp.Format(time.RFC3339)+" ("+relTime(exp)+")", "RFC 7519 §4.1.4")
	} else {
		cs.add("exp: present", "warn", "no exp claim, the token never expires", "RFC 7519 §4.1.4")
	}
	if nbf, ok := claimTime(claims, "nbf"); ok {
		cs.ok(!now.Add(lw).Before(nbf), "nbf: token already valid", "valid from "+nbf.Format(time.RFC3339), "RFC 7519 §4.1.5")
	}
	if iat, ok := claimTime(claims, "iat"); ok {
		cs.warn(!iat.After(now.Add(lw)), "iat: not in the future", "issued "+iat.Format(time.RFC3339)+" ("+relTime(iat)+")", "RFC 7519 §4.1.6")
	}
}

// ---- keys ----

func jwkBig(k M, name string) (*big.Int, error) {
	b, err := b64urlDecode(str(k[name]))
	if err != nil || len(b) == 0 {
		return nil, fmt.Errorf("JWK member %q missing or not base64url", name)
	}
	return new(big.Int).SetBytes(b), nil
}

// jwkPublicKey turns a JWK into *rsa.PublicKey, *ecdsa.PublicKey,
// ed25519.PublicKey or []byte (oct).
func jwkPublicKey(k M) (any, error) {
	switch str(k["kty"]) {
	case "RSA":
		n, err := jwkBig(k, "n")
		if err != nil {
			return nil, err
		}
		e, err := jwkBig(k, "e")
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch str(k["crv"]) {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", str(k["crv"]))
		}
		x, err := jwkBig(k, "x")
		if err != nil {
			return nil, err
		}
		y, err := jwkBig(k, "y")
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		if str(k["crv"]) != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", str(k["crv"]))
		}
		x, err := b64urlDecode(str(k["x"]))
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("bad Ed25519 public key")
		}
		return ed25519.PublicKey(x), nil
	case "oct":
		return b64urlDecode(str(k["k"]))
	case "AKP":
		params := mldsaAlgs[str(k["alg"])]
		if params == nil {
			return nil, fmt.Errorf("unsupported AKP alg %q (ML-DSA-44, ML-DSA-65 or ML-DSA-87)", str(k["alg"]))
		}
		pub, err := b64urlDecode(str(k["pub"]))
		if err != nil {
			return nil, errors.New("AKP member pub missing or not base64url")
		}
		return mldsa.NewPublicKey(params(), pub)
	}
	return nil, fmt.Errorf("unsupported kty %q", str(k["kty"]))
}

// jwkThumbprint is the RFC 7638 SHA-256 thumbprint.
func jwkThumbprint(k M) string {
	var members []string
	switch str(k["kty"]) {
	case "RSA":
		members = []string{"e", "kty", "n"}
	case "EC":
		members = []string{"crv", "kty", "x", "y"}
	case "OKP":
		members = []string{"crv", "kty", "x"}
	case "AKP":
		members = []string{"alg", "kty", "pub"}
	default:
		return ""
	}
	var sb strings.Builder
	sb.WriteString("{")
	for i, m := range members {
		if i > 0 {
			sb.WriteString(",")
		}
		v, _ := json.Marshal(str(k[m]))
		fmt.Fprintf(&sb, "%q:%s", m, v)
	}
	sb.WriteString("}")
	sum := sha256.Sum256([]byte(sb.String()))
	return b64url(sum[:])
}

func algHash(alg string) (crypto.Hash, func() hash.Hash) {
	switch {
	case strings.HasSuffix(alg, "384"):
		return crypto.SHA384, sha512.New384
	case strings.HasSuffix(alg, "512"), alg == "EdDSA":
		return crypto.SHA512, sha512.New
	}
	return crypto.SHA256, sha256.New
}

func verifySig(alg string, key any, signingInput string, sig []byte) error {
	ch, newHash := algHash(alg)
	h := newHash()
	h.Write([]byte(signingInput))
	digest := h.Sum(nil)
	switch {
	case alg == "none":
		return errors.New(`alg "none": the token is unsigned`)
	case strings.HasPrefix(alg, "HS"):
		secret, ok := key.([]byte)
		if !ok {
			return errors.New("HMAC algorithm needs a shared secret, not a public key")
		}
		mac := hmac.New(newHash, secret)
		mac.Write([]byte(signingInput))
		if !hmac.Equal(mac.Sum(nil), sig) {
			return errors.New("HMAC does not match")
		}
		return nil
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an RSA key", alg)
		}
		if alg[0] == 'P' {
			return rsa.VerifyPSS(pub, ch, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(pub, ch, digest, sig)
	case strings.HasPrefix(alg, "ES"):
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an EC key", alg)
		}
		if len(sig)%2 != 0 || len(sig) == 0 {
			return errors.New("malformed ECDSA signature (expected raw r||s)")
		}
		r := new(big.Int).SetBytes(sig[:len(sig)/2])
		s := new(big.Int).SetBytes(sig[len(sig)/2:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errors.New("ECDSA signature does not verify")
		}
		return nil
	case mldsaAlgs[alg] != nil:
		pub, ok := key.(*mldsa.PublicKey)
		if !ok || pub.Parameters().String() != alg {
			return fmt.Errorf("%s needs an %s key", alg, alg)
		}
		if err := mldsa.Verify(pub, []byte(signingInput), sig, nil); err != nil {
			return fmt.Errorf("%s signature does not verify", alg)
		}
		return nil
	case alg == "EdDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return errors.New("EdDSA needs an Ed25519 key")
		}
		if !ed25519.Verify(pub, []byte(signingInput), sig) {
			return errors.New("Ed25519 signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("unsupported alg %q", alg)
}

func jwksKeys(set any) []M {
	m, _ := set.(map[string]any)
	if m == nil {
		return nil
	}
	if _, single := m["kty"]; single {
		return []M{m}
	}
	arr, _ := m["keys"].([]any)
	var out []M
	for _, k := range arr {
		if km, ok := k.(map[string]any); ok {
			out = append(out, km)
		}
	}
	return out
}

// verifyWithJWKS tries the key named by kid, or every key when there is no kid.
func verifyWithJWKS(p *jwtParts, keys []M) (used string, err error) {
	alg, kid := str(p.Header["alg"]), str(p.Header["kid"])
	var candidates []M
	for _, k := range keys {
		if kid == "" || str(k["kid"]) == kid {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		var kids []string
		for _, k := range keys {
			kids = append(kids, str(k["kid"]))
		}
		return "", fmt.Errorf("no key with kid %q in the key set (available: %s)", kid, strings.Join(kids, ", "))
	}
	err = errors.New("no usable key")
	for _, k := range candidates {
		pub, kerr := jwkPublicKey(k)
		if kerr != nil {
			err = kerr
			continue
		}
		if verr := verifySig(alg, pub, p.SigningInput, p.Sig); verr != nil {
			err = verr
			continue
		}
		used = str(k["kid"])
		if used == "" {
			used = "thumbprint " + jwkThumbprint(k)
		}
		return used, nil
	}
	return "", err
}

func parsePEMCerts(b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		if blk.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				out = append(out, c)
			}
		}
	}
}

func isPEM(s string) bool { return strings.Contains(s, "-----BEGIN") }

// loadPublicKeyPEM accepts a certificate or a public key, inline or as a path.
func loadPublicKeyPEM(s string) (any, error) {
	b, err := inlineContent(s, isPEM)
	if err != nil {
		return nil, err
	}
	if certs := parsePEMCerts(b); len(certs) > 0 {
		return certs[0].PublicKey, nil
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block found")
	}
	if k, err := x509.ParsePKIXPublicKey(blk.Bytes); err == nil {
		return k, nil
	}
	return x509.ParsePKCS1PublicKey(blk.Bytes)
}

func certInfo(c *x509.Certificate) M {
	sum := sha256.Sum256(c.Raw)
	return M{
		"subject":            c.Subject.String(),
		"issuer":             c.Issuer.String(),
		"not_before":         c.NotBefore.UTC().Format(time.RFC3339),
		"not_after":          c.NotAfter.UTC().Format(time.RFC3339) + " (" + relTime(c.NotAfter) + ")",
		"sha256_fingerprint": hex.EncodeToString(sum[:]),
		"public_key":         c.PublicKeyAlgorithm.String(),
		"signature_alg":      c.SignatureAlgorithm.String(),
	}
}

func describeJWK(k M) M {
	out := M{}
	for _, n := range []string{"kid", "kty", "alg", "use", "crv", "key_ops"} {
		if v, ok := k[n]; ok {
			out[n] = v
		}
	}
	if tp := jwkThumbprint(k); tp != "" {
		out["thumbprint_sha256"] = tp
	}
	if pub, err := jwkPublicKey(k); err != nil {
		out["error"] = err.Error()
	} else if r, ok := pub.(*rsa.PublicKey); ok {
		out["bits"] = r.N.BitLen()
	} else if m, ok := pub.(*mldsa.PublicKey); ok {
		out["post_quantum"] = m.Parameters().String() + " (FIPS 204; JOSE use per draft-ietf-cose-dilithium)"
	}
	if x5c, _ := k["x5c"].([]any); len(x5c) > 0 {
		if der, err := base64.StdEncoding.DecodeString(str(x5c[0])); err == nil {
			if c, err := x509.ParseCertificate(der); err == nil {
				out["certificate"] = certInfo(c)
			}
		}
	}
	return out
}

func fetchJWKS(c *Ctx, u string) ([]M, error) {
	res, err := c.do("GET", u, map[string]string{"Accept": "application/json"}, nil)
	if err != nil {
		return nil, err
	}
	if res.Status != 200 {
		return nil, fmt.Errorf("JWKS %s returned HTTP %d", u, res.Status)
	}
	keys := jwksKeys(res.JSON)
	if len(keys) == 0 {
		return nil, fmt.Errorf("JWKS %s contains no keys", u)
	}
	return keys, nil
}

// ---- operations ----

func init() {
	tokenParam := Param{Name: "token", Type: "string", Required: true, File: true, Desc: "The JWT (CLI: @file or - for stdin)"}
	register(
		&Op{
			Name:    "jwt.decode",
			Summary: "Decode a JWT without verifying it: header, claims, readable timestamps and basic sanity checks.",
			Params: []Param{tokenParam,
				{Name: "leeway", Type: "int", Desc: "Clock skew allowance in seconds", Default: 60}},
			Run: func(c *Ctx) (M, error) {
				p, err := parseJWT(c.Str("token"))
				if err != nil {
					return nil, err
				}
				out := describeJWT(p)
				var cs Checks
				alg := str(p.Header["alg"])
				cs.ok(alg != "none" && alg != "", "alg: token is signed", "alg="+alg, "RFC 8725 §3.2")
				if strings.HasPrefix(alg, "HS") {
					cs.add("alg: symmetric", "info", "HMAC tokens can only be verified by parties holding the shared secret", "RFC 7518 §3.2")
				}
				if p.Claims != nil {
					timeChecks(&cs, p.Claims, c.Int("leeway"))
				}
				cs.add("signature", "info", "not verified; use jwt verify", "")
				out["checks"] = cs
				return out, nil
			},
		},
		&Op{
			Name:    "jwt.verify",
			Summary: "Verify a JWT signature and validate its claims. Keys come from an issuer's discovery document, a JWKS URL, an inline/file JWKS, a PEM public key or certificate, or an HMAC secret.",
			Params: []Param{tokenParam,
				{Name: "issuer", Type: "string", Desc: "Issuer URL: discover its jwks_uri and require iss to equal it"},
				{Name: "jwks_uri", Type: "string", Desc: "JWKS URL to fetch keys from"},
				{Name: "jwks", Type: "string", Path: true, Desc: "JWKS or single JWK as inline JSON, or a path to a file"},
				{Name: "pem", Type: "string", Path: true, Desc: "PEM public key or certificate, inline or a path to a file"},
				{Name: "secret", Type: "string", Secret: true, Desc: "Shared secret for HS256/384/512"},
				{Name: "audience", Type: "string", Desc: "Value that must appear in aud"},
				{Name: "nonce", Type: "string", Desc: "Value the nonce claim must equal"},
				{Name: "leeway", Type: "int", Desc: "Clock skew allowance in seconds", Default: 60}},
			Run: runJWTVerify,
		},
		&Op{
			Name:    "jwks.fetch",
			Summary: "Fetch a JWKS (directly or via an issuer's discovery document) and describe every key: kid, type, size, RFC 7638 thumbprint and any embedded certificate.",
			Params: []Param{
				{Name: "issuer", Type: "string", Desc: "Issuer URL; its jwks_uri is discovered"},
				{Name: "jwks_uri", Type: "string", Desc: "JWKS URL"}},
			Run: func(c *Ctx) (M, error) {
				u := c.Str("jwks_uri")
				if u == "" {
					if c.Str("issuer") == "" {
						return nil, errors.New("pass issuer or jwks_uri")
					}
					meta, _, err := fetchMeta(c, c.Str("issuer"))
					if err != nil {
						return nil, err
					}
					if u = str(meta["jwks_uri"]); u == "" {
						return nil, errors.New("the issuer metadata has no jwks_uri")
					}
				}
				keys, err := fetchJWKS(c, u)
				if err != nil {
					return nil, err
				}
				var cs Checks
				seen := map[string]bool{}
				descs := []M{}
				for _, k := range keys {
					d := describeJWK(k)
					descs = append(descs, d)
					kid := str(k["kid"])
					if kid == "" {
						cs.add("kid: present", "warn", "a key has no kid; clients cannot select it by header", "RFC 7517 §4.5")
					} else if seen[kid] {
						cs.add("kid: unique", "fail", "duplicate kid "+kid, "RFC 7517 §4.5")
					}
					seen[kid] = true
					if bits, ok := d["bits"].(int); ok {
						cs.warn(bits >= 2048, "RSA key size", fmt.Sprintf("kid %s is %d bits", kid, bits), "RFC 7518 §3.3")
					}
					if _, private := k["d"]; private {
						cs.add("no private key material", "fail", "kid "+kid+" exposes the private member d", "RFC 7517 §9.2")
					}
				}
				return M{"jwks_uri": u, "keys": descs, "checks": cs}, nil
			},
		},
	)
}

func runJWTVerify(c *Ctx) (M, error) {
	p, err := parseJWT(c.Str("token"))
	if err != nil {
		return nil, err
	}
	out := describeJWT(p)
	var cs Checks
	alg := str(p.Header["alg"])

	var keys []M
	var direct any
	source := ""
	switch {
	case c.Str("secret") != "" && strings.HasPrefix(alg, "HS"):
		direct, source = []byte(c.Str("secret")), "shared secret"
	case c.Str("pem") != "":
		if direct, err = loadPublicKeyPEM(c.Str("pem")); err != nil {
			return nil, fmt.Errorf("pem: %w", err)
		}
		source = "PEM key"
	case c.Str("jwks") != "":
		b, err := inlineContent(c.Str("jwks"), func(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "{") })
		if err != nil {
			return nil, err
		}
		var set any
		if err := json.Unmarshal(b, &set); err != nil {
			return nil, fmt.Errorf("jwks: %w", err)
		}
		keys, source = jwksKeys(set), "supplied JWKS"
	default:
		u := c.Str("jwks_uri")
		if u == "" {
			iss := c.Str("issuer")
			if iss == "" && p.Claims != nil {
				iss = str(p.Claims["iss"])
				if iss != "" {
					cs.add("key source", "warn", "keys were discovered from the token's own iss claim ("+iss+"); pass issuer to pin whom you trust", "RFC 8725 §3.8")
				}
			}
			if iss == "" {
				return nil, errors.New("no key source: pass issuer, jwks_uri, jwks, pem or secret")
			}
			meta, _, err := fetchMeta(c, iss)
			if err != nil {
				return nil, err
			}
			if u = str(meta["jwks_uri"]); u == "" {
				return nil, errors.New("the issuer metadata has no jwks_uri")
			}
		}
		if keys, err = fetchJWKS(c, u); err != nil {
			return nil, err
		}
		source = u
	}
	out["key_source"] = source

	if direct != nil {
		verr := verifySig(alg, direct, p.SigningInput, p.Sig)
		cs.ok(verr == nil, "signature", detailOr(verr, alg+" verified with "+source), "RFC 7515 §5.2")
	} else {
		used, verr := verifyWithJWKS(p, keys)
		cs.ok(verr == nil, "signature", detailOr(verr, alg+" verified with key "+used), "RFC 7515 §5.2")
	}
	if p.Claims != nil {
		timeChecks(&cs, p.Claims, c.Int("leeway"))
		if iss := c.Str("issuer"); iss != "" {
			cs.ok(str(p.Claims["iss"]) == iss, "iss: matches expected issuer", "iss="+str(p.Claims["iss"]), "RFC 7519 §4.1.1")
		}
		if aud := c.Str("audience"); aud != "" {
			cs.ok(contains(audList(p.Claims), aud), "aud: contains expected audience", "aud="+strings.Join(audList(p.Claims), " "), "RFC 7519 §4.1.3")
		}
		if n := c.Str("nonce"); n != "" {
			cs.ok(str(p.Claims["nonce"]) == n, "nonce: matches", "nonce="+str(p.Claims["nonce"]), "OIDC Core §3.1.3.7")
		}
	}
	out["checks"] = cs
	return out, nil
}

func detailOr(err error, okDetail string) string {
	if err != nil {
		return err.Error()
	}
	return okDetail
}
