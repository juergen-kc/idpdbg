package main

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"golang.org/x/term"
)

// PIV (SP 800-73-4) private key operations on a smart card or YubiKey: the
// PIN, management key authentication, on-card key generation, certificate
// objects, and a crypto.Signer / crypto.Decrypter whose key never leaves
// the card. PINs and management keys are taken from a parameter, the
// environment or a no-echo terminal prompt, and never appear in output.

var pivAID = []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00}

const pivMinPINRetries = 2 // never try a PIN that could lock the card

type pivSlotInfo struct {
	key    byte
	object []byte
	name   string
}

// pivSlotFor maps "9a", "9c", "9d", "9e" and the retired "82".."95".
func pivSlotFor(s string) (pivSlotInfo, error) {
	switch strings.ToLower(s) {
	case "9a":
		return pivSlotInfo{0x9A, []byte{0x5F, 0xC1, 0x05}, "PIV Authentication"}, nil
	case "9c":
		return pivSlotInfo{0x9C, []byte{0x5F, 0xC1, 0x0A}, "Digital Signature"}, nil
	case "9d":
		return pivSlotInfo{0x9D, []byte{0x5F, 0xC1, 0x0B}, "Key Management"}, nil
	case "9e":
		return pivSlotInfo{0x9E, []byte{0x5F, 0xC1, 0x01}, "Card Authentication"}, nil
	}
	var n int
	if _, err := fmt.Sscanf(strings.ToLower(s), "%x", &n); err == nil && n >= 0x82 && n <= 0x95 && len(s) == 2 {
		return pivSlotInfo{byte(n), []byte{0x5F, 0xC1, byte(0x0D + n - 0x82)}, fmt.Sprintf("Retired Key Management %d", n-0x81)}, nil
	}
	return pivSlotInfo{}, fmt.Errorf("slot %q: use 9a, 9c, 9d, 9e or a retired slot 82-95", s)
}

// PIV algorithm identifiers (SP 800-78-4 Table 6-2).
var pivAlgorithms = map[string]byte{"rsa2048": 0x07, "eccp256": 0x11, "eccp384": 0x14}

func berLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func tlvBytes(tag []byte, v []byte) []byte {
	return append(append(append([]byte{}, tag...), berLen(len(v))...), v...)
}

type pivCard struct {
	conn   cardConn
	reader string
}

func chooseReader(c *Ctx) (string, error) {
	if listReaders == nil || connectCard == nil {
		return "", errors.New("this build has no PC/SC support (built without cgo)")
	}
	readers, err := listReaders()
	if err != nil {
		return "", fmt.Errorf("listing readers: %w", err)
	}
	want := c.Str("reader")
	for _, r := range readers {
		if want == "" || r == want || strings.Contains(strings.ToLower(r), strings.ToLower(want)) {
			return r, nil
		}
	}
	if want == "" {
		return "", errors.New("no smart-card readers found: plug in the card or token")
	}
	return "", fmt.Errorf("no reader matches %q", want)
}

func openPIV(c *Ctx) (*pivCard, error) {
	reader, err := chooseReader(c)
	if err != nil {
		return nil, err
	}
	conn, info, err := connectCard(reader)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", reader, err)
	}
	sw, err := selectAID(conn, pivAID)
	if err != nil || sw != 0x9000 {
		conn.Close()
		if err == nil {
			err = errors.New("no PIV applet (" + swText(sw) + ")")
		}
		return nil, err
	}
	return &pivCard{conn: conn, reader: info.Reader}, nil
}

func (p *pivCard) Close() error { return p.conn.Close() }

// apdu sends one command, chaining data over 255 bytes (ISO 7816-4 §5.1.1).
func (p *pivCard) apdu(ins, p1, p2 byte, data []byte) ([]byte, uint16, error) {
	for len(data) > 255 {
		_, sw, err := transmit(p.conn, append([]byte{0x10, ins, p1, p2, 255}, data[:255]...))
		if err != nil {
			return nil, 0, err
		}
		if sw != 0x9000 {
			return nil, sw, nil
		}
		data = data[255:]
	}
	cmd := []byte{0x00, ins, p1, p2}
	if len(data) > 0 {
		cmd = append(append(cmd, byte(len(data))), data...)
	}
	return transmit(p.conn, append(cmd, 0x00))
}

// pinRetries asks how many PIN attempts are left without spending one.
func (p *pivCard) pinRetries() (n int, verified bool, err error) {
	r, err := p.conn.Transmit([]byte{0x00, 0x20, 0x00, 0x80})
	if err != nil {
		return 0, false, err
	}
	if len(r) < 2 {
		return 0, false, errors.New("card returned no status word")
	}
	sw := uint16(r[len(r)-2])<<8 | uint16(r[len(r)-1])
	switch {
	case sw == 0x9000:
		return -1, true, nil
	case sw&0xFFF0 == 0x63C0:
		return int(sw & 0x0F), false, nil
	case sw == 0x6983:
		return 0, false, nil
	}
	return 0, false, fmt.Errorf("PIN status: %s", swText(sw))
}

// verifyPIN presents the PIN once, after checking it cannot lock the card.
func (p *pivCard) verifyPIN(pin string) error {
	n, verified, err := p.pinRetries()
	if err != nil || verified {
		return err
	}
	if n < pivMinPINRetries {
		return fmt.Errorf("refusing to try the PIN: %d attempt(s) left; unblock it with the PUK first", n)
	}
	if len(pin) < 6 || len(pin) > 8 {
		return errors.New("a PIV PIN is 6 to 8 characters")
	}
	b := append([]byte(pin), bytes.Repeat([]byte{0xFF}, 8-len(pin))...)
	_, sw, err := p.apdu(0x20, 0x00, 0x80, b)
	switch {
	case err != nil:
		return err
	case sw == 0x9000:
		return nil
	case sw&0xFFF0 == 0x63C0:
		return fmt.Errorf("wrong PIN: %d attempt(s) left", sw&0x0F)
	case sw == 0x6983:
		return errors.New("the PIN is blocked")
	}
	return fmt.Errorf("PIN: %s", swText(sw))
}

// managementCipher picks the management key's algorithm: from GET METADATA
// where the card has it (YubiKey 5.3 and later), else by key length, with
// 24 bytes meaning 3DES as on older YubiKeys.
func (p *pivCard) managementCipher(key []byte) (cipher.Block, byte, error) {
	alg := byte(0)
	if data, sw, err := p.apdu(0xF7, 0x00, 0x9B, nil); err == nil && sw == 0x9000 {
		if ts, err := parseTLV(data); err == nil {
			if t := findTLV(ts, 0x01); t != nil && len(t.Value) == 1 {
				alg = t.Value[0]
			}
		}
	}
	if alg == 0 {
		alg = map[int]byte{16: 0x08, 24: 0x03, 32: 0x0C}[len(key)]
	}
	switch alg {
	case 0x03:
		b, err := des.NewTripleDESCipher(key)
		return b, alg, err
	case 0x08, 0x0A, 0x0C:
		b, err := aes.NewCipher(key)
		return b, alg, err
	}
	return nil, 0, fmt.Errorf("management key: %d bytes is not a 3DES or AES key", len(key))
}

// authenticate proves the management key to the card (mutual
// authentication: decrypt the card's witness, then check its answer to our
// challenge).
func (p *pivCard) authenticate(key []byte) error {
	blk, alg, err := p.managementCipher(key)
	if err != nil {
		return err
	}
	bs := blk.BlockSize()
	data, sw, err := p.apdu(0x87, alg, 0x9B, []byte{0x7C, 0x02, 0x80, 0x00})
	if err != nil {
		return err
	}
	if sw != 0x9000 {
		return fmt.Errorf("management key: witness request: %s", swText(sw))
	}
	ts, _ := parseTLV(data)
	w := findTLV(ts, 0x80)
	if w == nil || len(w.Value) != bs {
		return errors.New("management key: the card sent no witness")
	}
	plain := make([]byte, bs)
	blk.Decrypt(plain, w.Value)
	challenge := make([]byte, bs)
	rand.Read(challenge)
	body := append(tlvBytes([]byte{0x80}, plain), tlvBytes([]byte{0x81}, challenge)...)
	data, sw, err = p.apdu(0x87, alg, 0x9B, tlvBytes([]byte{0x7C}, body))
	if err != nil {
		return err
	}
	if sw == 0x6982 {
		return errors.New("wrong management key")
	}
	if sw != 0x9000 {
		return fmt.Errorf("management key: %s", swText(sw))
	}
	ts, _ = parseTLV(data)
	resp := findTLV(ts, 0x82)
	want := make([]byte, bs)
	blk.Encrypt(want, challenge)
	if resp == nil || subtle.ConstantTimeCompare(resp.Value, want) != 1 {
		return errors.New("management key: the card's answer to our challenge is wrong")
	}
	return nil
}

// generate makes a key pair in a slot and returns its public key.
func (p *pivCard) generate(slot byte, alg byte) (crypto.PublicKey, error) {
	data, sw, err := p.apdu(0x47, 0x00, slot, tlvBytes([]byte{0xAC}, []byte{0x80, 0x01, alg}))
	if err != nil {
		return nil, err
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("generate key: %s", swText(sw))
	}
	ts, err := parseTLV(data)
	if err != nil {
		return nil, err
	}
	switch alg {
	case 0x07:
		n, e := findTLV(ts, 0x81), findTLV(ts, 0x82)
		if n == nil || e == nil {
			return nil, errors.New("generate key: no RSA public key in the answer")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n.Value), E: int(new(big.Int).SetBytes(e.Value).Int64())}, nil
	case 0x11, 0x14:
		pt := findTLV(ts, 0x86)
		curve := map[byte]elliptic.Curve{0x11: elliptic.P256(), 0x14: elliptic.P384()}[alg]
		if pt == nil {
			return nil, errors.New("generate key: no EC point in the answer")
		}
		x, y := elliptic.Unmarshal(curve, pt.Value) //nolint:staticcheck // uncompressed point from the card
		if x == nil {
			return nil, errors.New("generate key: bad EC point")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}
	return nil, fmt.Errorf("algorithm %02X not supported", alg)
}

// readCertificate reads a slot's certificate object; nil when empty.
func (p *pivCard) readCertificate(s pivSlotInfo) (*x509.Certificate, error) {
	data, sw, err := p.apdu(0xCB, 0x3F, 0xFF, tlvBytes([]byte{0x5C}, s.object))
	if err != nil {
		return nil, err
	}
	if sw == 0x6A82 {
		return nil, nil
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("read certificate: %s", swText(sw))
	}
	ts, err := parseTLV(data)
	if err != nil {
		return nil, err
	}
	ct := findTLV(ts, 0x70)
	if ct == nil || len(ct.Value) == 0 {
		return nil, nil
	}
	der := ct.Value
	if info := findTLV(ts, 0x71); info != nil && len(info.Value) > 0 && info.Value[0]&0x01 != 0 {
		zr, err := gzip.NewReader(bytes.NewReader(der))
		if err != nil {
			return nil, err
		}
		if der, err = io.ReadAll(io.LimitReader(zr, 1<<20)); err != nil {
			return nil, err
		}
	}
	return x509.ParseCertificate(der)
}

func (p *pivCard) writeCertificate(s pivSlotInfo, cert *x509.Certificate) error {
	obj := append(append(tlvBytes([]byte{0x70}, cert.Raw), 0x71, 0x01, 0x00), 0xFE, 0x00)
	_, sw, err := p.apdu(0xDB, 0x3F, 0xFF, append(tlvBytes([]byte{0x5C}, s.object), tlvBytes([]byte{0x53}, obj)...))
	if err != nil {
		return err
	}
	if sw != 0x9000 {
		return fmt.Errorf("write certificate: %s", swText(sw))
	}
	return nil
}

// generalAuthenticate runs the slot's private key over input (a signature
// or an RSA decryption) and returns the card's output.
func (p *pivCard) generalAuthenticate(alg, slot byte, input []byte) ([]byte, error) {
	body := append([]byte{0x82, 0x00}, tlvBytes([]byte{0x81}, input)...)
	data, sw, err := p.apdu(0x87, alg, slot, tlvBytes([]byte{0x7C}, body))
	if err != nil {
		return nil, err
	}
	switch sw {
	case 0x9000:
	case 0x6982:
		return nil, errors.New("the card wants the PIN (or a touch) first")
	case 0x6A80, 0x6A86:
		return nil, fmt.Errorf("the slot has no key of this kind (%s)", swText(sw))
	default:
		return nil, fmt.Errorf("private key operation: %s", swText(sw))
	}
	ts, _ := parseTLV(data)
	out := findTLV(ts, 0x82)
	if out == nil {
		return nil, errors.New("the card returned no result")
	}
	return out.Value, nil
}

// pivSigner is a key in a PIV slot.
type pivSigner struct {
	card *pivCard
	slot byte
	pub  crypto.PublicKey
}

func (s *pivSigner) Public() crypto.PublicKey { return s.pub }

// digestInfoPrefix is the DER prefix of PKCS #1 v1.5 DigestInfo per hash.
var digestInfoPrefix = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func (s *pivSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch pub := s.pub.(type) {
	case *rsa.PublicKey:
		if _, pss := opts.(*rsa.PSSOptions); pss {
			return nil, errors.New("RSA-PSS is not supported with a PIV key")
		}
		prefix, ok := digestInfoPrefix[opts.HashFunc()]
		if !ok || len(digest) != opts.HashFunc().Size() {
			return nil, fmt.Errorf("hash %v not supported", opts.HashFunc())
		}
		k := (pub.N.BitLen() + 7) / 8
		t := append(append([]byte{}, prefix...), digest...)
		if len(t)+11 > k {
			return nil, errors.New("key too small for this hash")
		}
		em := append(append([]byte{0x00, 0x01}, bytes.Repeat([]byte{0xFF}, k-len(t)-3)...), 0x00)
		return s.card.generalAuthenticate(0x07, s.slot, append(em, t...))
	case *ecdsa.PublicKey:
		n := (pub.Curve.Params().BitSize + 7) / 8
		in := digest
		if len(in) > n {
			in = in[:n]
		} else if len(in) < n {
			in = append(make([]byte, n-len(in)), in...)
		}
		alg := map[int]byte{256: 0x11, 384: 0x14}[pub.Curve.Params().BitSize]
		return s.card.generalAuthenticate(alg, s.slot, in)
	}
	return nil, fmt.Errorf("key type %T not supported", s.pub)
}

// Decrypt is RSA PKCS #1 v1.5 decryption on the card.
func (s *pivSigner) Decrypt(_ io.Reader, ct []byte, opts crypto.DecrypterOpts) ([]byte, error) {
	if _, oaep := opts.(*rsa.OAEPOptions); oaep {
		return nil, errors.New("RSA-OAEP is not supported with a PIV key")
	}
	pub, ok := s.pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("only RSA keys decrypt")
	}
	k := (pub.N.BitLen() + 7) / 8
	if len(ct) > k {
		return nil, errors.New("ciphertext longer than the modulus")
	}
	em, err := s.card.generalAuthenticate(0x07, s.slot, append(make([]byte, k-len(ct)), ct...))
	if err != nil {
		return nil, err
	}
	if len(em) != k || em[0] != 0x00 || em[1] != 0x02 {
		return nil, errors.New("decryption error")
	}
	i := bytes.IndexByte(em[2:], 0x00)
	if i < 8 {
		return nil, errors.New("decryption error")
	}
	return em[2+i+1:], nil
}

// secretFor reads a secret from its parameter (or IDPDBG_<NAME>), or from a
// no-echo prompt on the person's terminal; the value is never logged.
func secretFor(c *Ctx, param, prompt string) (string, error) {
	if v := c.Str(param); v != "" {
		return v, nil
	}
	if !c.CLI || !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("pass %s (or set IDPDBG_%s)", param, strings.ToUpper(param))
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	v := strings.TrimRight(string(b), "\r\n")
	if c.Rec != nil {
		c.Rec.secrets = append(c.Rec.secrets, v)
	}
	return v, nil
}

// unlockPIN verifies the PIN unless this session already has, asking for it
// only when needed.
func unlockPIN(c *Ctx, card *pivCard) error {
	if _, verified, err := card.pinRetries(); err != nil || verified {
		return err
	}
	pin, err := secretFor(c, "piv_pin", "PIV PIN for "+card.reader)
	if err != nil {
		return err
	}
	return card.verifyPIN(pin)
}

// Yubico's admin data object says how the management key is kept; a
// PIN-protected key lives in the PIN-protected "printed" object (the layout
// ykman uses for "change-management-key --protect").
var (
	pivAdminData = []byte{0x5F, 0xFF, 0x00}
	pivPrinted   = []byte{0x5F, 0xC1, 0x09}
)

// innerTLV parses the TLVs nested in a container that is tagged as
// primitive (Yubico's 80 and 88), which parseTLV leaves unparsed.
func innerTLV(data []byte, container uint32) ([]tlv, error) {
	ts, err := parseTLV(data)
	if err != nil {
		return nil, err
	}
	c := findTLV(ts, container)
	if c == nil {
		return nil, fmt.Errorf("no %02X container", container)
	}
	return parseTLV(c.Value)
}

// storedManagementKey reports how the card keeps its management key:
// "protected" (stored on the card behind the PIN), "derived" (the old,
// deprecated PIN-derived mode) or "" (the person holds it).
func (p *pivCard) storedManagementKey() (string, error) {
	data, sw, err := p.apdu(0xCB, 0x3F, 0xFF, tlvBytes([]byte{0x5C}, pivAdminData))
	if err != nil {
		return "", err
	}
	if sw != 0x9000 {
		return "", nil // no admin data: nothing stored
	}
	ts, err := innerTLV(data, 0x80)
	if err != nil {
		return "", nil
	}
	if findTLV(ts, 0x82) != nil {
		return "derived", nil
	}
	if f := findTLV(ts, 0x81); f != nil && len(f.Value) > 0 && f.Value[0]&0x02 != 0 {
		return "protected", nil
	}
	return "", nil
}

// readProtectedManagementKey reads the stored key; the PIN must be verified.
func (p *pivCard) readProtectedManagementKey() ([]byte, error) {
	data, sw, err := p.apdu(0xCB, 0x3F, 0xFF, tlvBytes([]byte{0x5C}, pivPrinted))
	if err != nil {
		return nil, err
	}
	if sw != 0x9000 {
		return nil, fmt.Errorf("reading the PIN-protected management key: %s", swText(sw))
	}
	ts, err := innerTLV(data, 0x88)
	if err != nil {
		return nil, err
	}
	k := findTLV(ts, 0x89)
	if k == nil || len(k.Value) == 0 {
		return nil, errors.New("the card says its management key is PIN-protected, but holds none")
	}
	return k.Value, nil
}

// managementKeyFor returns the management key: given (parameter,
// environment, prompt), or read from the card when it keeps it behind the
// PIN. It never appears in output.
func managementKeyFor(c *Ctx, card *pivCard, out M) ([]byte, error) {
	if c.Str("management_key") == "" {
		how, err := card.storedManagementKey()
		if err != nil {
			return nil, err
		}
		switch how {
		case "derived":
			return nil, errors.New("this card uses the deprecated PIN-derived management key, which idpdbg does not support: pass management_key, or move to a protected key with ykman piv access change-management-key --protect")
		case "protected":
			if err := unlockPIN(c, card); err != nil {
				return nil, err
			}
			key, err := card.readProtectedManagementKey()
			if err == nil {
				out["management_key"] = "PIN-protected on the card"
			}
			return key, err
		}
	}
	s, err := secretFor(c, "management_key", "PIV management key (hex)")
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if err != nil {
		return nil, errors.New("management_key must be hex")
	}
	out["management_key"] = "given"
	return key, nil
}

// pivSignerFor opens the card, reads the slot's certificate and unlocks the
// key with the PIN. The caller closes the card.
func pivSignerFor(c *Ctx, slotName string) (*pivSigner, *x509.Certificate, error) {
	slot, err := pivSlotFor(slotName)
	if err != nil {
		return nil, nil, err
	}
	card, err := openPIV(c)
	if err != nil {
		return nil, nil, err
	}
	cert, err := card.readCertificate(slot)
	if err == nil && cert == nil {
		err = fmt.Errorf("slot %s has no certificate", slotName)
	}
	if err == nil {
		err = unlockPIN(c, card)
	}
	if err != nil {
		card.Close()
		return nil, nil, err
	}
	return &pivSigner{card: card, slot: slot.key, pub: cert.PublicKey}, cert, nil
}

func runPIVGenerate(c *Ctx) (M, error) {
	slot, err := pivSlotFor(c.Str("slot"))
	if err != nil {
		return nil, err
	}
	alg, ok := pivAlgorithms[c.Str("algorithm")]
	if !ok {
		return nil, fmt.Errorf("algorithm %q: use rsa2048, eccp256 or eccp384", c.Str("algorithm"))
	}
	card, err := openPIV(c)
	if err != nil {
		return nil, err
	}
	defer card.Close()
	var cs Checks
	out := M{"reader": card.reader, "slot": fmt.Sprintf("%02X (%s)", slot.key, slot.name), "algorithm": c.Str("algorithm")}
	defer func() { out["checks"] = cs }()
	if old, err := card.readCertificate(slot); err != nil {
		return out, err
	} else if old != nil && !c.Bool("overwrite") {
		return out, fmt.Errorf("slot %02X already holds a certificate for %s: pass overwrite to replace its key", slot.key, old.Subject)
	}
	// The PIN is needed for the CSR; check it can be tried before changing anything.
	if n, verified, err := card.pinRetries(); err != nil {
		return out, err
	} else if !verified && n < pivMinPINRetries {
		return out, fmt.Errorf("the PIN has %d attempt(s) left: unblock it with the PUK first", n)
	}
	key, err := managementKeyFor(c, card, out)
	if err != nil {
		return out, err
	}
	if err := card.authenticate(key); err != nil {
		return out, err
	}
	cs.add("management key accepted", "pass", str(out["management_key"]), "SP 800-73-4 Part 2 §3.2.4")
	c.Log("generating the key on the card (RSA can take up to a minute)...")
	pub, err := card.generate(slot.key, alg)
	if err != nil {
		return out, err
	}
	cs.add("key pair generated on the card", "pass", "the private key cannot be exported", "SP 800-73-4 Part 2 §3.3.2")
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	out["public_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	if err := unlockPIN(c, card); err != nil {
		return out, fmt.Errorf("the key is on the card, but the CSR needs the PIN: %w", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: c.Str("common_name")}}
	if upn := c.Str("upn"); upn != "" {
		v, _ := asn1.Marshal(upn)
		san := mustDER([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: append(mustDER(oidMSUPN), mustDER(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: v})...)}})
		tmpl.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAltName, Value: san}}
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, tmpl, &pivSigner{card: card, slot: slot.key, pub: pub})
	if err != nil {
		return out, fmt.Errorf("CSR signed on the card: %w", err)
	}
	parsed, err := x509.ParseCertificateRequest(csr)
	if err == nil {
		err = parsed.CheckSignature()
	}
	if !cs.ok(err == nil, "CSR signed by the card's key", detailOr(err, ""), "RFC 2986") {
		return out, nil
	}
	out["csr"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	out["next"] = "have the CSR issued, then write the certificate to the slot with card piv_import"
	return out, nil
}

func runPIVImport(c *Ctx) (M, error) {
	slot, err := pivSlotFor(c.Str("slot"))
	if err != nil {
		return nil, err
	}
	o, err := parsePKI(c.Str("cert"))
	if err != nil || len(o.Certs) == 0 {
		return nil, fmt.Errorf("cert: no certificate (%v)", err)
	}
	cert := o.Certs[0]
	card, err := openPIV(c)
	if err != nil {
		return nil, err
	}
	defer card.Close()
	var cs Checks
	out := M{"reader": card.reader, "slot": fmt.Sprintf("%02X (%s)", slot.key, slot.name), "certificate": certDetail(cert)}
	defer func() { out["checks"] = cs }()
	// Prove the certificate belongs to the slot's key before writing it.
	if err := unlockPIN(c, card); err != nil {
		return out, err
	}
	probe := make([]byte, 32)
	rand.Read(probe)
	signer := &pivSigner{card: card, slot: slot.key, pub: cert.PublicKey}
	sig, err := signer.Sign(rand.Reader, probe, crypto.SHA256)
	if err == nil {
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, probe, sig)
		case *ecdsa.PublicKey:
			if !ecdsa.VerifyASN1(pub, probe, sig) {
				err = errors.New("signature does not verify")
			}
		default:
			err = fmt.Errorf("key type %T not supported", pub)
		}
	}
	if !cs.ok(err == nil, "certificate matches the slot's key", detailOr(err, "a test signature from the card verifies with the certificate"), "SP 800-73-4 Part 2 §3.2.4") {
		return out, nil
	}
	key, err := managementKeyFor(c, card, out)
	if err != nil {
		return out, err
	}
	if err := card.authenticate(key); err != nil {
		return out, err
	}
	if err := card.writeCertificate(slot, cert); err != nil {
		return out, err
	}
	back, err := card.readCertificate(slot)
	cs.ok(err == nil && back != nil && bytes.Equal(back.Raw, cert.Raw), "certificate written to the slot", detailOr(err, "read back unchanged"), "SP 800-73-4 Part 1 Table 15")
	return out, nil
}

func init() {
	cardSecrets := []Param{
		{Name: "reader", Type: "string", Desc: "Reader name or part of it; default the first reader"},
		{Name: "slot", Type: "string", Default: "9a", Desc: "PIV slot: 9a, 9c, 9d, 9e or a retired slot 82-95"},
		{Name: "piv_pin", Type: "string", Secret: true, Desc: "PIV PIN; else IDPDBG_PIV_PIN or a no-echo prompt. Never tried with fewer than 2 attempts left, and never retried"},
		{Name: "management_key", Type: "string", Secret: true, Desc: "PIV management key in hex; else IDPDBG_MANAGEMENT_KEY, the card's PIN-protected key (ykman --protect), or a no-echo prompt"},
	}
	register(
		&Op{
			Name:     "card.piv_generate",
			Mutating: true,
			Summary:  "Generate a key pair in a PIV slot of a smart card or YubiKey (the private key never leaves the card) and return a CSR the card signs, for example with a UPN for smart card logon or PKINIT. Refuses a slot that already holds a certificate unless overwrite is set. Needs the management key and the PIN.",
			Params: joinParams(cardSecrets, []Param{
				{Name: "algorithm", Type: "string", Default: "rsa2048", Enum: []string{"rsa2048", "eccp256", "eccp384"}, Desc: "Key type"},
				{Name: "common_name", Type: "string", Required: true, Desc: "Subject common name for the CSR"},
				{Name: "upn", Type: "string", Desc: "User principal name to put in the CSR's subject alternative name (Microsoft UPN otherName)"},
				{Name: "overwrite", Type: "bool", Desc: "Replace the key of a slot that already holds a certificate"},
			}),
			Run: runPIVGenerate,
		},
		&Op{
			Name:     "card.piv_import",
			Mutating: true,
			Summary:  "Write a certificate into a PIV slot, after checking with a signature from the card that it belongs to the slot's key. Needs the PIN and the management key.",
			Params: joinParams(cardSecrets, []Param{
				{Name: "cert", Type: "string", Path: true, Required: true, Desc: "The certificate (PEM)"},
			}),
			Run: runPIVImport,
		},
	)
}
