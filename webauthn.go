package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	stdasn1 "encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// WebAuthn: client data, authenticator data, attestation objects and
// assertion signatures, with a small CBOR decoder and COSE key support.

// ---- CBOR (RFC 8949), definite lengths only ----

func cborDecode(b []byte) (any, int, error) { return cborItem(b, 0) }

// cborTag is a tagged item kept as such, with its encoded bytes (some
// formats, such as mdoc, hash a tagged item exactly as it was encoded).
type cborTag struct {
	Num uint64
	V   any
	Raw []byte
}

// cborDecodeTagged decodes like cborDecode but keeps tags as cborTag.
func cborDecodeTagged(b []byte) (any, int, error) { return cborItemOpt(b, 0, true) }

func cborItem(b []byte, depth int) (any, int, error) { return cborItemOpt(b, depth, false) }

func cborItemOpt(b []byte, depth int, keepTags bool) (any, int, error) {
	if depth > 32 {
		return nil, 0, errors.New("cbor: nested too deeply")
	}
	if len(b) == 0 {
		return nil, 0, errors.New("cbor: unexpected end of data")
	}
	major, ai := b[0]>>5, b[0]&0x1f
	var arg uint64
	n := 1
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai <= 27:
		size := 1 << (ai - 24)
		if len(b) < 1+size {
			return nil, 0, errors.New("cbor: truncated header")
		}
		for _, x := range b[1 : 1+size] {
			arg = arg<<8 | uint64(x)
		}
		n += size
	default:
		return nil, 0, errors.New("cbor: indefinite lengths are not supported")
	}
	need := func(l uint64) error {
		if l > uint64(len(b)-n) {
			return errors.New("cbor: length beyond the end of data")
		}
		return nil
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return arg, n, nil
		}
		return int64(arg), n, nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, 0, errors.New("cbor: negative integer out of range")
		}
		return -1 - int64(arg), n, nil
	case 2, 3:
		if err := need(arg); err != nil {
			return nil, 0, err
		}
		v := b[n : n+int(arg)]
		if major == 3 {
			return string(v), n + int(arg), nil
		}
		return append([]byte{}, v...), n + int(arg), nil
	case 4:
		if err := need(arg); err != nil { // each item takes at least a byte
			return nil, 0, err
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, m, err := cborItemOpt(b[n:], depth+1, keepTags)
			if err != nil {
				return nil, 0, err
			}
			out, n = append(out, v), n+m
		}
		return out, n, nil
	case 5:
		if err := need(arg * 2); err != nil {
			return nil, 0, err
		}
		out := map[any]any{}
		for i := uint64(0); i < arg; i++ {
			k, m, err := cborItemOpt(b[n:], depth+1, keepTags)
			if err != nil {
				return nil, 0, err
			}
			n += m
			v, m, err := cborItemOpt(b[n:], depth+1, keepTags)
			if err != nil {
				return nil, 0, err
			}
			n += m
			// Only scalar keys: anything else is unhashable or meaningless here.
			switch kk := k.(type) {
			case int64, uint64, string, bool, float64:
			case []byte:
				k = "h'" + hex.EncodeToString(kk) + "'"
			default:
				return nil, 0, fmt.Errorf("cbor: map keys of type %T are not supported", k)
			}
			out[k] = v
		}
		return out, n, nil
	case 6:
		v, m, err := cborItemOpt(b[n:], depth+1, keepTags)
		if err == nil && keepTags {
			return cborTag{Num: arg, V: v, Raw: append([]byte{}, b[:n+m]...)}, n + m, nil
		}
		return v, n + m, err
	}
	switch ai {
	case 20:
		return false, n, nil
	case 21:
		return true, n, nil
	case 22, 23:
		return nil, n, nil
	case 25:
		return halfFloat(uint16(arg)), n, nil
	case 26:
		return float64(math.Float32frombits(uint32(arg))), n, nil
	case 27:
		return math.Float64frombits(arg), n, nil
	}
	return int64(arg), n, nil // other simple values
}

func halfFloat(h uint16) float64 {
	exp, mant := (h>>10)&0x1f, float64(h&0x3ff)
	var v float64
	switch exp {
	case 0:
		v = mant * math.Pow(2, -24)
	case 31:
		v = math.Inf(1)
		if mant != 0 {
			v = math.NaN()
		}
	default:
		v = (mant + 1024) * math.Pow(2, float64(exp)-25)
	}
	if h&0x8000 != 0 {
		v = -v
	}
	return v
}

// cborJSON turns decoded CBOR into something JSON can show.
func cborJSON(v any) any {
	switch t := v.(type) {
	case map[any]any:
		out := M{}
		for k, val := range t {
			out[fmt.Sprint(k)] = cborJSON(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = cborJSON(t[i])
		}
		return out
	case []byte:
		return b64url(t)
	}
	return v
}

// ---- COSE keys (RFC 9052/9053) ----

var coseAlgs = map[int64]string{-7: "ES256", -35: "ES384", -36: "ES512", -8: "EdDSA", -257: "RS256", -258: "RS384", -259: "RS512", -37: "PS256", -38: "PS384", -39: "PS512", -65535: "RS1"}

func coseInt(m map[any]any, k int64) (int64, bool) {
	v, ok := m[k].(int64)
	return v, ok
}

func coseBytes(m map[any]any, k int64) []byte {
	b, _ := m[k].([]byte)
	return b
}

// coseKey returns the public key and its COSE algorithm name.
func coseKey(v any) (any, string, error) {
	m, ok := v.(map[any]any)
	if !ok {
		return nil, "", errors.New("COSE key is not a map")
	}
	kty, _ := coseInt(m, 1)
	algID, _ := coseInt(m, 3)
	alg := coseAlgs[algID]
	if alg == "" {
		alg = fmt.Sprintf("COSE alg %d", algID)
	}
	switch kty {
	case 2:
		crv, _ := coseInt(m, -1)
		curve := map[int64]elliptic.Curve{1: elliptic.P256(), 2: elliptic.P384(), 3: elliptic.P521()}[crv]
		if curve == nil {
			return nil, alg, fmt.Errorf("unsupported EC2 curve %d", crv)
		}
		x, y := new(big.Int).SetBytes(coseBytes(m, -2)), new(big.Int).SetBytes(coseBytes(m, -3))
		if !curve.IsOnCurve(x, y) {
			return nil, alg, errors.New("the EC2 point is not on its curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, alg, nil
	case 3:
		return &rsa.PublicKey{N: new(big.Int).SetBytes(coseBytes(m, -1)), E: int(new(big.Int).SetBytes(coseBytes(m, -2)).Int64())}, alg, nil
	case 1:
		crv, _ := coseInt(m, -1)
		if crv != 6 {
			return nil, alg, fmt.Errorf("unsupported OKP curve %d", crv)
		}
		x := coseBytes(m, -2)
		if len(x) != ed25519.PublicKeySize {
			return nil, alg, errors.New("bad Ed25519 key length")
		}
		return ed25519.PublicKey(x), alg, nil
	}
	return nil, alg, fmt.Errorf("unsupported COSE kty %d", kty)
}

// webauthnVerify checks a WebAuthn signature; ECDSA signatures are ASN.1 DER.
func webauthnVerify(alg string, pub any, data, sig []byte) error {
	h := crypto.SHA256
	switch {
	case strings.HasSuffix(alg, "384"):
		h = crypto.SHA384
	case strings.HasSuffix(alg, "512"):
		h = crypto.SHA512
	case alg == "RS1":
		h = crypto.SHA1
	}
	var digest []byte
	if alg != "EdDSA" {
		hh := h.New()
		hh.Write(data)
		digest = hh.Sum(nil)
	}
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, sig) {
			return errors.New("ECDSA signature does not verify")
		}
		return nil
	case *rsa.PublicKey:
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(k, h, digest, sig, nil)
		}
		return rsa.VerifyPKCS1v15(k, h, digest, sig)
	case ed25519.PublicKey:
		if !ed25519.Verify(k, data, sig) {
			return errors.New("Ed25519 signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("unsupported key type %T", pub)
}

// ---- authenticator data ----

type authData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32
	AAGUID    []byte
	CredID    []byte
	CredKey   any
	CredAlg   string
	CredCOSE  any
	Ext       any
}

func parseAuthData(b []byte) (*authData, error) {
	if len(b) < 37 {
		return nil, fmt.Errorf("authenticator data is %d bytes; at least 37 are required", len(b))
	}
	a := &authData{RPIDHash: b[:32], Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if a.Flags&0x40 != 0 {
		if len(rest) < 18 {
			return nil, errors.New("attested credential data is truncated")
		}
		a.AAGUID = rest[:16]
		l := int(binary.BigEndian.Uint16(rest[16:18]))
		if len(rest) < 18+l {
			return nil, errors.New("credential ID is truncated")
		}
		a.CredID, rest = rest[18:18+l], rest[18+l:]
		v, n, err := cborDecode(rest)
		if err != nil {
			return nil, fmt.Errorf("credential public key: %w", err)
		}
		a.CredCOSE, rest = v, rest[n:]
		if a.CredKey, a.CredAlg, err = coseKey(v); err != nil {
			return nil, fmt.Errorf("credential public key: %w", err)
		}
	}
	if a.Flags&0x80 != 0 {
		v, n, err := cborDecode(rest)
		if err != nil {
			return nil, fmt.Errorf("extensions: %w", err)
		}
		a.Ext, rest = v, rest[n:]
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%d unexpected bytes after the authenticator data", len(rest))
	}
	return a, nil
}

func uuidString(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) != 32 {
		return h
	}
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (a *authData) describe() M {
	out := M{"rp_id_hash": hex.EncodeToString(a.RPIDHash), "sign_count": a.SignCount, "flags": M{
		"user_present": a.Flags&0x01 != 0, "user_verified": a.Flags&0x04 != 0, "backup_eligible": a.Flags&0x08 != 0,
		"backed_up": a.Flags&0x10 != 0, "attested_credential_data": a.Flags&0x40 != 0, "extensions": a.Flags&0x80 != 0}}
	if a.AAGUID != nil {
		out["aaguid"], out["credential_id"] = uuidString(a.AAGUID), b64url(a.CredID)
		jwk, _ := publicJWK(a.CredKey)
		out["credential_public_key"] = M{"alg": a.CredAlg, "key": keyDescription(a.CredKey), "jwk": jwk, "pem": publicKeyPEM(a.CredKey)}
	}
	if a.Ext != nil {
		out["extensions"] = cborJSON(a.Ext)
	}
	return out
}

// ---- inputs ----

// binParam accepts base64url, base64 or (for JSON) raw text.
func binParam(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{") {
		return []byte(s), nil
	}
	if b, err := b64urlDecode(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

type webauthnInput struct {
	ClientData, AuthData, AttObj, Sig, UserHandle []byte
}

func webauthnInputs(c *Ctx) (*webauthnInput, error) {
	in := &webauthnInput{}
	fields := map[string]*[]byte{"client_data_json": &in.ClientData, "authenticator_data": &in.AuthData, "attestation_object": &in.AttObj, "signature": &in.Sig}
	if cred := c.Str("credential"); cred != "" {
		var pkc struct {
			Response map[string]string `json:"response"`
		}
		if err := json.Unmarshal([]byte(cred), &pkc); err != nil || pkc.Response == nil {
			return nil, errors.New("credential must be a PublicKeyCredential JSON object with a response member")
		}
		for name, ptr := range map[string]*[]byte{"clientDataJSON": &in.ClientData, "authenticatorData": &in.AuthData, "attestationObject": &in.AttObj, "signature": &in.Sig, "userHandle": &in.UserHandle} {
			if v := pkc.Response[name]; v != "" {
				b, err := binParam(v)
				if err != nil {
					return nil, fmt.Errorf("credential.response.%s: %w", name, err)
				}
				*ptr = b
			}
		}
	}
	for name, ptr := range fields {
		if v := c.Str(name); v != "" {
			b, err := binParam(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			*ptr = b
		}
	}
	if in.ClientData == nil && in.AuthData == nil && in.AttObj == nil {
		return nil, errors.New("pass credential, or client_data_json with attestation_object or authenticator_data")
	}
	return in, nil
}

// ---- the operation ----

func runWebAuthn(c *Ctx) (M, error) {
	in, err := webauthnInputs(c)
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{}
	defer func() { out["checks"] = cs }()
	ceremony := ""

	// Client data.
	var clientHash []byte
	if in.ClientData != nil {
		sum := sha256.Sum256(in.ClientData)
		clientHash = sum[:]
		var cd M
		if err := json.Unmarshal(in.ClientData, &cd); err != nil {
			cs.add("clientDataJSON is JSON", "fail", err.Error(), "WebAuthn §5.8.1")
		} else {
			out["client_data"] = cd
			ceremony = map[string]string{"webauthn.create": "registration", "webauthn.get": "authentication"}[str(cd["type"])]
			cs.ok(ceremony != "", "client data type", "type="+str(cd["type"]), "WebAuthn §5.8.1")
			if ch := c.Str("expected_challenge"); ch != "" {
				got, _ := b64urlDecode(str(cd["challenge"]))
				want, _ := binParam(ch)
				cs.ok(bytes.Equal(got, want) && len(want) > 0, "challenge matches", "challenge="+str(cd["challenge"]), "WebAuthn §7.1 step 8")
			}
			if o := c.Str("expected_origin"); o != "" {
				cs.ok(str(cd["origin"]) == o, "origin matches", "origin="+str(cd["origin"]), "WebAuthn §7.1 step 9")
			}
			if cd["crossOrigin"] == true {
				cs.add("same-origin ceremony", "warn", "crossOrigin=true: the ceremony ran in a cross-origin iframe (topOrigin="+str(cd["topOrigin"])+")", "WebAuthn §5.8.1")
			}
		}
	}

	// Attestation object (registration) or bare authenticator data (authentication).
	authBytes := in.AuthData
	var att map[any]any
	if in.AttObj != nil {
		v, _, err := cborDecode(in.AttObj)
		if err != nil {
			cs.add("attestation object is CBOR", "fail", err.Error(), "WebAuthn §6.5")
			return out, nil
		}
		var ok bool
		if att, ok = v.(map[any]any); !ok {
			cs.add("attestation object is a map", "fail", "", "WebAuthn §6.5")
			return out, nil
		}
		authBytes, _ = att["authData"].([]byte)
		if ceremony == "" {
			ceremony = "registration"
		}
	}
	if authBytes == nil {
		cs.add("authenticator data present", "fail", "", "WebAuthn §6.1")
		return out, nil
	}
	ad, err := parseAuthData(authBytes)
	if !cs.ok(err == nil, "authenticator data well-formed", detailOr(err, fmt.Sprintf("%d bytes", len(authBytes))), "WebAuthn §6.1") {
		return out, nil
	}
	out["authenticator_data"] = ad.describe()
	if rp := c.Str("rp_id"); rp != "" {
		sum := sha256.Sum256([]byte(rp))
		cs.ok(bytes.Equal(sum[:], ad.RPIDHash), "rpIdHash is SHA-256 of the RP ID", "rp_id="+rp, "WebAuthn §7.1 step 13")
	}
	cs.ok(ad.Flags&0x01 != 0, "user present (UP)", "", "WebAuthn §7.1 step 14")
	if ad.Flags&0x04 != 0 {
		cs.add("user verified (UV)", "pass", "", "WebAuthn §7.1 step 15")
	} else if c.Bool("require_uv") {
		cs.add("user verified (UV)", "fail", "user verification was required but not performed", "WebAuthn §7.1 step 15")
	} else {
		cs.add("user verified (UV)", "info", "not performed", "WebAuthn §7.1 step 15")
	}
	if ad.Flags&0x10 != 0 && ad.Flags&0x08 == 0 {
		cs.add("backup flags consistent", "fail", "BS is set without BE", "WebAuthn §6.1.3")
	} else if ad.Flags&0x08 != 0 {
		cs.add("credential is backup eligible", "info", "a synced passkey (BE=1, BS="+fmt.Sprint(ad.Flags&0x10 != 0)+")", "WebAuthn §6.1.3")
	}
	if c.Has("prior_sign_count") {
		prior := uint32(c.Int("prior_sign_count"))
		cs.ok(ad.SignCount == 0 && prior == 0 || ad.SignCount > prior, "signature counter increased", fmt.Sprintf("%d after %d", ad.SignCount, prior), "WebAuthn §6.1.1")
	}

	if att != nil {
		out["attestation"] = verifyAttestation(&cs, att, authBytes, clientHash, ad)
		if c.Bool("metadata") {
			stmt, _ := att["attStmt"].(map[any]any)
			out["metadata"] = mdsForAttestation(c, &cs, ad, attestationCerts(stmt), true)
		}
		return out, nil
	}

	// Authentication: the assertion signature.
	if in.Sig != nil {
		if c.Str("public_key") == "" {
			cs.add("assertion signature", "warn", "not verified: pass public_key (the credential key from registration: COSE, JWK or PEM)", "WebAuthn §7.2 step 20")
			return out, nil
		}
		if clientHash == nil {
			cs.add("assertion signature", "warn", "not verified: client_data_json is needed", "WebAuthn §7.2 step 20")
			return out, nil
		}
		pub, alg, err := webauthnPublicKey(c.Str("public_key"), c.Str("alg"))
		if err != nil {
			return out, fmt.Errorf("public_key: %w", err)
		}
		err = webauthnVerify(alg, pub, append(append([]byte{}, authBytes...), clientHash...), in.Sig)
		cs.ok(err == nil, "assertion signature", detailOr(err, alg+" over authenticatorData || SHA-256(clientDataJSON)"), "WebAuthn §7.2 step 20")
	}
	if in.UserHandle != nil {
		out["user_handle"] = b64url(in.UserHandle)
	}
	return out, nil
}

// verifyAttestation checks an attestation statement over the authenticator
// data and the client data hash (when known).
func verifyAttestation(cs *Checks, att map[any]any, authBytes, clientHash []byte, ad *authData) M {
	fmtName, _ := att["fmt"].(string)
	stmt, _ := att["attStmt"].(map[any]any)
	info := M{"fmt": fmtName, "statement": cborJSON(stmt)}
	if ad.CredKey == nil {
		cs.add("attested credential data present", "fail", "a registration must carry the new credential", "WebAuthn §7.1 step 19")
		return info
	}
	signed := append(append([]byte{}, authBytes...), clientHash...)
	certs := attestationCerts(stmt)
	if len(certs) > 0 {
		var subj []string
		for _, ce := range certs {
			subj = append(subj, ce.Subject.String())
		}
		info["certificates"] = subj
	}
	sig, _ := stmt["sig"].([]byte)
	switch fmtName {
	case "none":
		cs.add("attestation", "info", "fmt none: the authenticator's make and model are not attested", "WebAuthn §8.7")
	case "packed":
		algID, _ := stmt["alg"].(int64)
		alg := coseAlgs[algID]
		if clientHash == nil {
			cs.add("attestation signature", "warn", "not verified: client_data_json is needed", "WebAuthn §8.2")
			break
		}
		if len(certs) > 0 {
			err := webauthnVerify(alg, certs[0].PublicKey, signed, sig)
			cs.ok(err == nil, "attestation signature (packed, x5c)", detailOr(err, "by "+certs[0].Subject.String()+"; trust in that certificate is not established"), "WebAuthn §8.2")
			ou := strings.Join(certs[0].Subject.OrganizationalUnit, ",")
			cs.warn(ou == "Authenticator Attestation", "attestation certificate OU", "OU="+ou, "WebAuthn §8.2.1")
			a := certs[0]
			cs.ok(a.Version == 3, "attestation certificate is X.509 v3", fmt.Sprintf("version %d", a.Version), "WebAuthn §8.2.1")
			cs.ok(!a.IsCA, "attestation certificate is not a CA", "", "WebAuthn §8.2.1")
			for _, e := range a.Extensions {
				if e.Id.String() == "1.3.6.1.4.1.45724.1.1.4" { // id-fido-gen-ce-aaguid
					var v []byte
					_, err := stdasn1.Unmarshal(e.Value, &v)
					cs.ok(err == nil && bytes.Equal(v, ad.AAGUID) && !e.Critical, "attestation certificate AAGUID matches the authenticator data", uuidString(v), "WebAuthn §8.2.1")
				}
			}
		} else {
			cs.ok(alg == ad.CredAlg, "self attestation uses the credential's algorithm", "attStmt alg="+alg+", credential alg="+ad.CredAlg, "WebAuthn §8.2")
			err := webauthnVerify(alg, ad.CredKey, signed, sig)
			cs.ok(err == nil, "attestation signature (packed, self)", detailOr(err, "signed by the new credential itself"), "WebAuthn §8.2")
		}
	case "fido-u2f":
		ec, ok := ad.CredKey.(*ecdsa.PublicKey)
		if len(certs) == 0 || !ok || clientHash == nil {
			cs.add("attestation signature (fido-u2f)", "warn", "needs x5c, a P-256 credential and client_data_json", "WebAuthn §8.6")
			break
		}
		pt := append([]byte{4}, append(ec.X.FillBytes(make([]byte, 32)), ec.Y.FillBytes(make([]byte, 32))...)...)
		data := append(append(append(append([]byte{0}, ad.RPIDHash...), clientHash...), ad.CredID...), pt...)
		err := webauthnVerify("ES256", certs[0].PublicKey, data, sig)
		cs.ok(err == nil, "attestation signature (fido-u2f)", detailOr(err, "by "+certs[0].Subject.String()), "WebAuthn §8.6")
	default:
		cs.add("attestation signature", "info", "fmt "+fmtName+" is decoded but its signature is not verified by idpdbg", "WebAuthn §8")
	}
	if allZero(ad.AAGUID) {
		cs.add("AAGUID", "info", "all zeros: the authenticator does not identify its model", "WebAuthn §6.5.1")
	}
	return info
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// webauthnPublicKey accepts a COSE key (base64url), a JWK or PEM.
func webauthnPublicKey(s, alg string) (any, string, error) {
	if !looksLikeJSON(s) && !strings.Contains(s, "-----BEGIN") {
		b, err := binParam(s)
		if err != nil {
			return nil, "", err
		}
		v, _, err := cborDecode(b)
		if err != nil {
			return nil, "", fmt.Errorf("not a COSE key: %w", err)
		}
		return coseKey(v)
	}
	pub, err := loadPublicKeyAny(s)
	if err != nil {
		return nil, "", err
	}
	if alg == "" {
		switch pub.(type) {
		case *ecdsa.PublicKey:
			alg = "ES256"
		case ed25519.PublicKey:
			alg = "EdDSA"
		default:
			alg = "RS256"
		}
	}
	return pub, alg, nil
}

func init() {
	register(&Op{
		Name:    "webauthn.decode",
		Summary: "Decode and check WebAuthn artifacts from a registration or authentication: clientDataJSON (type, challenge, origin), authenticator data (RP ID hash, UP/UV/BE/BS flags, counter, AAGUID, credential ID and COSE public key as JWK/PEM, extensions), the attestation object (packed and fido-u2f signatures verified; none and others decoded), and assertion signatures against the registered key. Accepts a whole PublicKeyCredential JSON.",
		Params: []Param{
			{Name: "credential", Type: "string", File: true, Desc: "A PublicKeyCredential as JSON (response.clientDataJSON, attestationObject or authenticatorData/signature, base64url)"},
			{Name: "client_data_json", Type: "string", Desc: "clientDataJSON, base64url or raw JSON"},
			{Name: "attestation_object", Type: "string", Desc: "attestationObject, base64url (registration)"},
			{Name: "authenticator_data", Type: "string", Desc: "authenticatorData, base64url (authentication)"},
			{Name: "signature", Type: "string", Desc: "Assertion signature, base64url"},
			{Name: "public_key", Type: "string", File: true, Desc: "Credential public key for assertions: COSE (base64url), JWK or PEM (CLI: @file)"},
			{Name: "alg", Type: "string", Desc: "Signature algorithm when public_key is a JWK or PEM (ES256, RS256, PS256, EdDSA)"},
			{Name: "expected_challenge", Type: "string", Desc: "Challenge the RP issued (base64url)"},
			{Name: "expected_origin", Type: "string", Desc: "Origin the ceremony must come from, e.g. https://example.com"},
			{Name: "rp_id", Type: "string", Desc: "RP ID whose SHA-256 must be the rpIdHash"},
			{Name: "require_uv", Type: "bool", Desc: "Fail when user verification was not performed"},
			{Name: "prior_sign_count", Type: "int", Desc: "Last stored signature counter, to detect cloned authenticators"},
			{Name: "metadata", Type: "bool", Desc: "Check the authenticator against the FIDO Metadata Service: model, certification, security status, attestation chain to the model's root (downloads and caches the MDS3 BLOB)"}},
		Run: runWebAuthn,
	})
}
