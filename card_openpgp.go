package main

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // OpenPGP v4 fingerprints are SHA-1
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// OpenPGP card operations that need PW1 (OpenPGP card 3.4 §7.2.10-7.2.13):
// signing with the signature key (PSO: COMPUTE DIGITAL SIGNATURE),
// authentication (INTERNAL AUTHENTICATE) and decryption (PSO: DECIPHER).
// Each result is checked against the slot's public key, read from the card
// without a PIN, and that key against the fingerprint the card stores.
// No key is generated or imported, and the admin PIN is never used.

const (
	pgpRef        = "OpenPGP card 3.4"
	pgpMinRetries = 2 // never spend the last PW1 attempt
)

var pgpAID = []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}

type pgpSlot struct {
	name     string
	crt      byte // control reference template for GENERATE (read public key)
	fpOffset int  // in C5 (fingerprints) and CD (generation times)
	attrTag  uint32
	pw1Mode  byte // VERIFY P2: 81 for signing, 82 for the rest
}

var pgpSlots = map[string]pgpSlot{
	"signature":      {"signature", 0xB6, 0, 0xC1, 0x81},
	"decryption":     {"decryption", 0xB8, 1, 0xC2, 0x82},
	"authentication": {"authentication", 0xA4, 2, 0xC3, 0x82},
}

type pgpCard struct {
	conn   cardConn
	reader string
	ard    []tlv
}

func openPGPCard(c *Ctx) (*pgpCard, error) {
	reader, err := chooseReader(c)
	if err != nil {
		return nil, err
	}
	conn, info, err := connectCard(reader)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", reader, err)
	}
	sw, err := selectAID(conn, pgpAID)
	if err != nil || sw != 0x9000 {
		conn.Close()
		if err == nil {
			err = errors.New("no OpenPGP applet (" + swText(sw) + ")")
		}
		return nil, err
	}
	p := &pgpCard{conn: conn, reader: info.Reader}
	if err := p.readARD(); err != nil {
		conn.Close()
		return nil, err
	}
	return p, nil
}

func (p *pgpCard) Close() error { return p.conn.Close() }

func (p *pgpCard) getData(tag uint16) ([]byte, uint16, error) {
	return cardAPDU(p.conn, 0xCA, byte(tag>>8), byte(tag), nil)
}

func (p *pgpCard) readARD() error {
	data, sw, err := p.getData(0x006E)
	if err != nil {
		return err
	}
	if sw != 0x9000 {
		return fmt.Errorf("reading Application Related Data: %s", swText(sw))
	}
	ts, err := parseTLV(data)
	if err != nil {
		return fmt.Errorf("Application Related Data: %w", err)
	}
	if len(ts) == 1 && ts[0].Tag == 0x6E {
		ts = ts[0].Kids
	}
	p.ard = ts
	return nil
}

// find looks for a tag in the ARD, inside its 73 (Discretionary data objects) too.
func (p *pgpCard) find(tag uint32) []byte {
	if t := findTLV(p.ard, tag); t != nil {
		return t.Value
	}
	if d := findTLV(p.ard, 0x73); d != nil {
		if t := findTLV(d.Kids, tag); t != nil {
			return t.Value
		}
	}
	return nil
}

func (p *pgpCard) fingerprint(s pgpSlot) []byte {
	fp := p.find(0xC5)
	if len(fp) < 60 || allZero(fp[s.fpOffset*20:s.fpOffset*20+20]) {
		return nil
	}
	return fp[s.fpOffset*20 : s.fpOffset*20+20]
}

func (p *pgpCard) generated(s pgpSlot) uint32 {
	gd := p.find(0xCD)
	if len(gd) < 12 {
		return 0
	}
	return binary.BigEndian.Uint32(gd[s.fpOffset*4:])
}

// signatureCount is DO 93 in the Security Support Template (7A).
func (p *pgpCard) signatureCount() (int, bool) {
	data, sw, err := p.getData(0x007A)
	if err != nil || sw != 0x9000 {
		return 0, false
	}
	ts, err := parseTLV(data)
	if err != nil {
		return 0, false
	}
	if len(ts) == 1 && ts[0].Tag == 0x7A {
		ts = ts[0].Kids
	}
	c := findTLV(ts, 0x93)
	if c == nil || len(c.Value) != 3 {
		return 0, false
	}
	return int(c.Value[0])<<16 | int(c.Value[1])<<8 | int(c.Value[2]), true
}

// pgpPublic is a slot's public key as the card returns it, with what is
// needed to compute its OpenPGP fingerprint.
type pgpPublic struct {
	key      any    // *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey, *ecdh.PublicKey
	algo     byte   // OpenPGP public-key algorithm: 1 RSA, 18 ECDH, 19 ECDSA, 22 EdDSA
	oid      []byte // curve OID (ECC)
	point    []byte // the 86 data object as sent
	curve    string
	n, e     []byte
	describe string
}

var pgpCurveOIDs = map[string]string{"2A8648CE3D030107": "P-256", "2B81040022": "P-384", "2B81040023": "P-521",
	"2B060104019755010501": "Curve25519", "2B06010401DA470F01": "Ed25519"}

// readPublic reads a slot's public key (GENERATE ASYMMETRIC KEY PAIR with
// P1=81, which only reads; §7.2.14). It needs no PIN.
func (p *pgpCard) readPublic(s pgpSlot) (*pgpPublic, error) {
	data, sw, err := cardAPDU(p.conn, 0x47, 0x81, 0x00, []byte{s.crt, 0x00})
	if err != nil {
		return nil, err
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("reading the %s public key: %s", s.name, swText(sw))
	}
	ts, err := parseTLV(data)
	if err != nil || len(ts) == 0 || ts[0].Tag != 0x7F49 {
		return nil, errors.New("public key: no 7F49 template")
	}
	kt := ts[0].Kids
	attr := p.find(s.attrTag)
	if len(attr) == 0 {
		return nil, errors.New("no algorithm attributes for the slot")
	}
	pub := &pgpPublic{algo: attr[0]}
	switch attr[0] {
	case 0x01:
		n, e := findTLV(kt, 0x81), findTLV(kt, 0x82)
		if n == nil || e == nil {
			return nil, errors.New("RSA public key without modulus or exponent")
		}
		ev := new(big.Int).SetBytes(e.Value)
		if !ev.IsInt64() || ev.Int64() > 1<<31 {
			return nil, errors.New("RSA exponent out of range")
		}
		pub.n, pub.e = trimZeros(n.Value), trimZeros(e.Value)
		pub.key = &rsa.PublicKey{N: new(big.Int).SetBytes(n.Value), E: int(ev.Int64())}
		pub.describe = fmt.Sprintf("RSA %d", pub.key.(*rsa.PublicKey).N.BitLen())
	case 0x12, 0x13, 0x16:
		pub.oid = bytes.TrimSuffix(bytes.TrimSuffix(attr[1:], []byte{0xFF}), []byte{0x00})
		pub.curve = pgpCurveOIDs[strings.ToUpper(hex.EncodeToString(pub.oid))]
		pt := findTLV(kt, 0x86)
		if pt == nil {
			return nil, errors.New("EC public key without a point")
		}
		pub.point = pt.Value
		raw := bytes.TrimPrefix(pt.Value, []byte{0x40}) // native 25519 keys may carry the 0x40 prefix
		if pub.curve == "Ed25519" || pub.curve == "Curve25519" {
			if len(raw) != 32 {
				return nil, fmt.Errorf("%s point of %d bytes", pub.curve, len(raw))
			}
		}
		curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
		switch {
		case pub.algo == 0x16 && pub.curve == "Ed25519":
			pub.key = ed25519.PublicKey(raw)
		case pub.algo == 0x12 && pub.curve == "Curve25519":
			k, err := ecdh.X25519().NewPublicKey(raw)
			if err != nil {
				return nil, err
			}
			pub.key = k
		case curves[pub.curve] != nil:
			x, y := elliptic.Unmarshal(curves[pub.curve], pt.Value) //nolint:staticcheck // the card's wire format
			if x == nil {
				return nil, fmt.Errorf("%s point is not on the curve", pub.curve)
			}
			ek := &ecdsa.PublicKey{Curve: curves[pub.curve], X: x, Y: y}
			if pub.algo == 0x12 {
				k, err := ek.ECDH()
				if err != nil {
					return nil, err
				}
				pub.key = k
			} else {
				pub.key = ek
			}
		default:
			name := pub.curve
			if name == "" {
				name = "OID " + strings.ToUpper(hex.EncodeToString(pub.oid))
			}
			return nil, fmt.Errorf("curve %s is not supported here", name)
		}
		pub.describe = map[byte]string{0x12: "ECDH", 0x13: "ECDSA", 0x16: "EdDSA"}[pub.algo] + " " + pub.curve
	default:
		return nil, fmt.Errorf("algorithm id %d is not supported", attr[0])
	}
	return pub, nil
}

func trimZeros(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// mpi is an OpenPGP multiprecision integer (RFC 9580 §3.2).
func mpi(b []byte) []byte {
	b = trimZeros(b)
	bits := len(b) * 8
	if len(b) > 0 {
		for m := byte(0x80); m > 0 && b[0]&m == 0; m >>= 1 {
			bits--
		}
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(bits)), b...)
}

// pgpKDF are the ECDH KDF parameters GnuPG uses per curve (RFC 6637 §9):
// the fingerprint covers them, and the card does not store them.
var pgpKDF = map[string][]byte{"P-256": {3, 1, 8, 7}, "P-384": {3, 1, 9, 8}, "P-521": {3, 1, 10, 9}, "Curve25519": {3, 1, 8, 7}}

// v4Fingerprint is the OpenPGP v4 fingerprint of the key as created at t
// (RFC 9580 §5.5.4).
func (pub *pgpPublic) v4Fingerprint(created uint32) []byte {
	body := binary.BigEndian.AppendUint32([]byte{4}, created)
	body = append(body, pub.algo)
	switch pub.algo {
	case 0x01:
		body = append(append(body, mpi(pub.n)...), mpi(pub.e)...)
	default:
		point := pub.point
		if (pub.curve == "Ed25519" || pub.curve == "Curve25519") && len(point) == 32 {
			point = append([]byte{0x40}, point...)
		}
		body = append(append(append(body, byte(len(pub.oid))), pub.oid...), mpi(point)...)
		if pub.algo == 0x12 {
			body = append(body, pgpKDF[pub.curve]...)
		}
	}
	h := sha1.New() //nolint:gosec // the v4 fingerprint is defined with SHA-1
	h.Write(binary.BigEndian.AppendUint16([]byte{0x99}, uint16(len(body))))
	h.Write(body)
	return h.Sum(nil)
}

func (pub *pgpPublic) pemText() string {
	k := pub.key
	if x, ok := k.(*ecdh.PublicKey); ok {
		// An ECDH key on a NIST curve is shown in its ECDSA form; X25519
		// marshals as it is.
		if c := map[ecdh.Curve]elliptic.Curve{ecdh.P256(): elliptic.P256(), ecdh.P384(): elliptic.P384(), ecdh.P521(): elliptic.P521()}[x.Curve()]; c != nil {
			px, py := elliptic.Unmarshal(c, x.Bytes()) //nolint:staticcheck // the uncompressed point
			k = &ecdsa.PublicKey{Curve: c, X: px, Y: py}
		}
	}
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// slotKey reads a slot's public key and checks it against the stored
// fingerprint, adding what it found to out.
func (p *pgpCard) slotKey(cs *Checks, out M, s pgpSlot) (*pgpPublic, error) {
	fp := p.fingerprint(s)
	if fp == nil {
		cs.add(s.name+" key present", "fail", "no key in the "+s.name+" slot: generate or import one first (gpg --card-edit, or ykman openpgp)", pgpRef+" §4.4.3")
		return nil, nil
	}
	pub, err := p.readPublic(s)
	if err != nil {
		return nil, err
	}
	out["key"] = M{"slot": s.name, "algorithm": pub.describe, "fingerprint": strings.ToUpper(hex.EncodeToString(fp)), "public_key_pem": pub.pemText()}
	if gen := p.generated(s); gen != 0 {
		out["key"].(M)["generated"] = time.Unix(int64(gen), 0).UTC().Format(time.RFC3339)
		ok := bytes.Equal(pub.v4Fingerprint(gen), fp)
		detail := "the v4 fingerprint of the card's public key and generation time"
		if !ok {
			detail = "the card's public key and generation time give another v4 fingerprint: a v6 key, other ECDH KDF parameters, or the key was replaced without updating the fingerprint"
		}
		cs.warn(ok, "public key matches the stored fingerprint", detail, "RFC 9580 §5.5.4, "+pgpRef+" §4.4.3.7")
	} else {
		cs.add("public key matches the stored fingerprint", "info", "no generation time stored, so the fingerprint cannot be recomputed", pgpRef+" §4.4.3.7")
	}
	return pub, nil
}

// verifyPW1 presents the user PIN once, for signing (81) or the other keys
// (82), after checking it cannot block the card.
func (p *pgpCard) verifyPW1(c *Ctx, mode byte) error {
	status := p.find(0xC4)
	if len(status) < 7 {
		return errors.New("no PW status bytes (C4) in the Application Related Data")
	}
	if left := int(status[4]); left < pgpMinRetries {
		return fmt.Errorf("refusing to try PW1: %d attempt(s) left; unblock it with the reset code or admin PIN first", left)
	}
	if ext := p.find(0xC0); len(ext) > 0 && ext[0]&0x01 != 0 {
		if kdf, sw, err := p.getData(0x00F9); err == nil && sw == 0x9000 {
			if ts, err := parseTLV(kdf); err == nil {
				if a := findTLV(ts, 0x81); a != nil && len(a.Value) == 1 && a.Value[0] != 0 {
					return errors.New("the card hashes PINs with a KDF (DO F9), which idpdbg does not do yet")
				}
			}
		}
	}
	pin, err := secretFor(c, "openpgp_pin", "OpenPGP user PIN (PW1) for "+p.reader)
	if err != nil {
		return err
	}
	if len(pin) < 6 || len(pin) > int(status[1]) {
		return fmt.Errorf("PW1 is 6 to %d bytes", status[1])
	}
	_, sw, err := cardAPDU(p.conn, 0x20, 0x00, mode, []byte(pin))
	switch {
	case err != nil:
		return err
	case sw == 0x9000:
		return nil
	case sw == 0x6982 || sw&0xFFF0 == 0x63C0:
		left := "?"
		if p.readARD() == nil {
			if st := p.find(0xC4); len(st) >= 7 {
				left = fmt.Sprint(st[4])
			}
		}
		return fmt.Errorf("wrong PIN: %s attempt(s) left", left)
	case sw == 0x6983:
		return errors.New("PW1 is blocked")
	}
	return fmt.Errorf("VERIFY PW1: %s", swText(sw))
}

func pgpHash(name string) (crypto.Hash, error) {
	h, ok := map[string]crypto.Hash{"sha256": crypto.SHA256, "sha384": crypto.SHA384, "sha512": crypto.SHA512}[name]
	if !ok {
		return 0, fmt.Errorf("hash %q: sha256, sha384 or sha512", name)
	}
	return h, nil
}

func runOpenPGPSign(c *Ctx) (M, error) {
	s := pgpSlots[c.Str("slot")]
	if s.name == "" || s.name == "decryption" {
		return nil, errors.New("slot: signature or authentication")
	}
	h, err := pgpHash(c.Str("hash"))
	if err != nil {
		return nil, err
	}
	if err := pgpCLIOnly(c, "message"); err != nil {
		return nil, err
	}
	msg := []byte(c.Str("message"))
	if len(msg) == 0 {
		msg = []byte("idpdbg OpenPGP card test " + time.Now().UTC().Format(time.RFC3339))
	}
	hh := h.New()
	hh.Write(msg)
	digest := hh.Sum(nil)

	card, err := openPGPCard(c)
	if err != nil {
		return nil, err
	}
	defer card.Close()
	var cs Checks
	out := M{"reader": card.reader, "hash": c.Str("hash"), "digest": hex.EncodeToString(digest)}
	pub, err := card.slotKey(&cs, out, s)
	if pub == nil || err != nil {
		out["checks"] = cs
		return out, err
	}
	var input []byte
	switch pub.algo {
	case 0x01:
		input = append(append([]byte{}, digestInfoPrefix[h]...), digest...)
	case 0x13, 0x16:
		input = digest
	default:
		return nil, fmt.Errorf("the %s key (%s) does not sign", s.name, pub.describe)
	}
	before, haveCount := card.signatureCount()
	if err := card.verifyPW1(c, s.pw1Mode); err != nil {
		return nil, err
	}
	var sig []byte
	var sw uint16
	if s.name == "signature" {
		sig, sw, err = cardAPDU(card.conn, 0x2A, 0x9E, 0x9A, input)
	} else {
		sig, sw, err = cardAPDU(card.conn, 0x88, 0x00, 0x00, input)
	}
	if err != nil {
		return nil, err
	}
	op := map[string]string{"signature": "PSO: COMPUTE DIGITAL SIGNATURE", "authentication": "INTERNAL AUTHENTICATE"}[s.name]
	if !cs.ok(sw == 0x9000, "card signed ("+op+")", swText(sw), pgpRef+" §7.2.10") {
		out["checks"] = cs
		return out, nil
	}
	if c.CLI {
		out["signature"] = hex.EncodeToString(sig)
	}
	var verr error
	switch k := pub.key.(type) {
	case *rsa.PublicKey:
		verr = rsa.VerifyPKCS1v15(k, h, digest, sig)
	case *ecdsa.PublicKey:
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*n {
			verr = fmt.Errorf("signature of %d bytes, want r||s of %d", len(sig), 2*n)
		} else if !ecdsa.Verify(k, digest, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])) {
			verr = errors.New("ECDSA verification failed")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(k, digest, sig) {
			verr = errors.New("Ed25519 verification failed")
		}
	}
	cs.ok(verr == nil, "signature verifies with the slot's public key", detailOr(verr, pub.describe+", "+c.Str("hash")), pgpRef+" §7.2.10")
	if s.name == "signature" && haveCount {
		after, ok := card.signatureCount()
		cs.ok(ok && after == before+1, "signature counter went up by one", fmt.Sprintf("%d → %d", before, after), pgpRef+" §4.4.1")
		out["signature_count"] = after
	}
	if st := card.find(0xC4); s.name == "signature" && len(st) > 0 {
		if st[0] == 0 {
			cs.add("PW1 for every signature", "info", "the card asks for PW1 again before each signature (the PIN is not kept verified)", pgpRef+" §4.4.1")
		} else {
			cs.add("PW1 for every signature", "info", "one PW1 verification allows several signatures until the card is reset", pgpRef+" §4.4.1")
		}
	}
	out["checks"] = cs
	return out, nil
}

func runOpenPGPDecrypt(c *Ctx) (M, error) {
	if err := pgpCLIOnly(c, "ciphertext"); err != nil {
		return nil, err
	}
	s := pgpSlots["decryption"]
	card, err := openPGPCard(c)
	if err != nil {
		return nil, err
	}
	defer card.Close()
	var cs Checks
	out := M{"reader": card.reader}
	pub, err := card.slotKey(&cs, out, s)
	if pub == nil || err != nil {
		out["checks"] = cs
		return out, err
	}
	given, err := cardBytesOpt(c.Str("ciphertext"))
	if err != nil {
		return nil, fmt.Errorf("ciphertext: %w", err)
	}
	var input, want []byte
	switch k := pub.key.(type) {
	case *rsa.PublicKey:
		ct := given
		if ct == nil {
			want = randomBytes(32)
			if ct, err = rsa.EncryptPKCS1v15(rand.Reader, k, want); err != nil {
				return nil, err
			}
		}
		input = append([]byte{0x00}, ct...) // padding indicator byte
	case *ecdh.PublicKey:
		point := given
		if point == nil {
			eph, err := k.Curve().GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			if want, err = eph.ECDH(k); err != nil {
				return nil, err
			}
			point = eph.PublicKey().Bytes()
		}
		input = tlvBytes([]byte{0xA6}, tlvBytes([]byte{0x7F, 0x49}, tlvBytes([]byte{0x86}, point)))
	default:
		return nil, fmt.Errorf("the decryption key (%s) does not decrypt", pub.describe)
	}
	if err := card.verifyPW1(c, s.pw1Mode); err != nil {
		return nil, err
	}
	res, sw, err := cardAPDU(card.conn, 0x2A, 0x80, 0x86, input)
	if err != nil {
		return nil, err
	}
	if !cs.ok(sw == 0x9000, "card decrypted (PSO: DECIPHER)", swText(sw), pgpRef+" §7.2.11") {
		out["checks"] = cs
		return out, nil
	}
	if c.Rec != nil {
		c.Rec.secrets = append(c.Rec.secrets, hex.EncodeToString(res))
	}
	if want != nil {
		out["mode"] = "round trip: idpdbg encrypted a random value to the slot's public key"
		cs.ok(bytes.Equal(res, want), "the card's answer is the value idpdbg encrypted", pub.describe, pgpRef+" §7.2.11")
		return withChecks(out, cs), nil
	}
	if _, isRSA := pub.key.(*rsa.PublicKey); isRSA {
		out["plaintext"] = hex.EncodeToString(res)
	} else {
		out["shared_secret"] = hex.EncodeToString(res)
	}
	return withChecks(out, cs), nil
}

// pgpCLIOnly keeps the card from becoming a signing or decryption oracle
// over MCP: there a caller (a model, possibly steered by what it read) could
// otherwise have the person's key sign a commit or an email, or decrypt
// their mail. Over MCP only idpdbg's own test values are used.
func pgpCLIOnly(c *Ctx, param string) error {
	if !c.CLI && strings.TrimSpace(c.Str(param)) != "" {
		return fmt.Errorf("%s is only accepted from the CLI: over MCP the card signs and decrypts only idpdbg's own test values", param)
	}
	return nil
}

func withChecks(out M, cs Checks) M { out["checks"] = cs; return out }

// cardBytesOpt is cardBytes for an optional value.
func cardBytesOpt(s string) ([]byte, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	return cardBytes(s)
}

func init() {
	common := []Param{
		{Name: "reader", Type: "string", Desc: "Reader name or part of it; default the first reader"},
		{Name: "openpgp_pin", Type: "string", Secret: true, Desc: "The user PIN (PW1); else IDPDBG_OPENPGP_PIN or a no-echo prompt. Never tried with fewer than 2 attempts left, and never retried"},
	}
	register(
		&Op{
			Name:    "card.openpgp_sign",
			Summary: "Sign with an OpenPGP card's signature key (PSO: COMPUTE DIGITAL SIGNATURE) or authentication key (INTERNAL AUTHENTICATE), and check the signature with the slot's public key read from the card, that key against the stored fingerprint, and that the signature counter went up. Needs the user PIN (PW1).",
			Params: joinParams(common, []Param{
				{Name: "slot", Type: "string", Default: "signature", Enum: []string{"signature", "authentication"}, Desc: "Which key"},
				{Name: "message", Type: "string", File: true, Desc: "What to sign (default: a test string). CLI only: over MCP the card signs only idpdbg's test string, and the signature is not returned"},
				{Name: "hash", Type: "string", Default: "sha256", Enum: []string{"sha256", "sha384", "sha512"}, Desc: "Hash of the message the card signs"},
			}),
			Run: runOpenPGPSign,
		},
		&Op{
			Name:    "card.openpgp_decrypt",
			Summary: "Decrypt with an OpenPGP card's decryption key (PSO: DECIPHER). Without a ciphertext it is a round trip: idpdbg encrypts a random value to the slot's public key (RSA PKCS #1 v1.5, or an ephemeral ECDH key) and checks the card's answer. With one it returns the plaintext (RSA) or the ECDH shared secret. Needs the user PIN (PW1).",
			Params: joinParams(common, []Param{
				{Name: "ciphertext", Type: "string", File: true, Desc: "RSA: the PKCS #1 v1.5 ciphertext; ECDH: the sender's ephemeral public key (hex or base64). Default: a round trip. CLI only"},
			}),
			Run: runOpenPGPDecrypt,
		},
	)
}
