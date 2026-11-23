package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Kerberos FAST (RFC 6113): the AS exchange runs inside a tunnel keyed by an
// armor ticket, so the password-derived pre-authentication cannot be attacked
// offline, and KDC errors come back integrity protected.

const (
	paFXCookie           int32 = 133
	paFXFast             int32 = 136
	paFXError            int32 = 137
	paEncryptedChallenge int32 = 138

	usageFastReqChecksum    = 50
	usageFastEnc            = 51
	usageFastRep            = 52
	usageFastFinished       = 53
	usageEncChallengeClnt   = 54
	usageEncChallengeKDC    = 55
	fxFastArmorAPRequest    = 1
	usageAPReqAuthenticator = 11
)

var paTypeNames = map[int32]string{
	2: "PA-ENC-TIMESTAMP", 3: "PA-PW-SALT", 11: "PA-ETYPE-INFO", 15: "PA-PK-AS-REP_OLD", 16: "PA-PK-AS-REQ", 17: "PA-PK-AS-REP",
	19: "PA-ETYPE-INFO2", 128: "PA-PAC-REQUEST", 129: "PA-FOR-USER", 133: "PA-FX-COOKIE", 136: "PA-FX-FAST",
	137: "PA-FX-ERROR", 138: "PA-ENCRYPTED-CHALLENGE", 141: "PA-OTP-CHALLENGE", 147: "PA-PKINIT-KX",
	149: "PA-REQ-ENC-PA-REP", 150: "PA-AS-FRESHNESS", 151: "PA-SPAKE", 165: "PA-SUPPORTED-ENCTYPES", 167: "PA-PAC-OPTIONS",
}

func paTypeName(t int32) string {
	if n, ok := paTypeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("padata-%d", t)
}

// ---- RFC 3961 pseudo-random() and KRB-FX-CF2 ----

// krbPRF is the enctype's pseudo-random function: aes-ecb(DK(key, "prf"),
// trunc128(sha-1(input))) for the RFC 3962 types, KDF-HMAC-SHA2 for RFC
// 8009, HMAC-SHA1 for RC4 (RFC 4757).
func krbPRF(key types.EncryptionKey, in []byte) ([]byte, error) {
	switch key.KeyType {
	case 17, 18:
		et, err := crypto.GetEtype(key.KeyType)
		if err != nil {
			return nil, err
		}
		kp, err := et.DeriveKey(key.KeyValue, []byte("prf"))
		if err != nil {
			return nil, err
		}
		blk, err := aes.NewCipher(kp)
		if err != nil {
			return nil, err
		}
		h := sha1.Sum(in)
		out := make([]byte, 16)
		blk.Encrypt(out, h[:16])
		return out, nil
	case 19:
		return kdfHMACSHA2(sha256.New, key.KeyValue, "prf", in, 256), nil
	case 20:
		return kdfHMACSHA2(sha512.New384, key.KeyValue, "prf", in, 384), nil
	case 23, 24:
		m := hmac.New(sha1.New, key.KeyValue)
		m.Write(in)
		return m.Sum(nil), nil
	}
	return nil, fmt.Errorf("no pseudo-random function for %s", etypeName(key.KeyType))
}

// kdfHMACSHA2 is RFC 8009's KDF-HMAC-SHA2(key, label, context, k).
func kdfHMACSHA2(h func() hash.Hash, key []byte, label string, context []byte, bits int) []byte {
	m := hmac.New(h, key)
	m.Write([]byte{0, 0, 0, 1})
	m.Write([]byte(label))
	m.Write([]byte{0})
	m.Write(context)
	binary.Write(m, binary.BigEndian, uint32(bits))
	return m.Sum(nil)[:bits/8]
}

// krbKeyLen is the protocol key length. gokrb5's GetKeyByteSize says 24
// for aes256-cts-hmac-sha384-192, whose keys are 32 bytes (RFC 8009 §5).
func krbKeyLen(etype int32) (int, error) {
	switch etype {
	case 17, 19, 23, 24:
		return 16, nil
	case 18, 20:
		return 32, nil
	}
	return 0, fmt.Errorf("unsupported encryption type %s", etypeName(etype))
}

func prfPlus(key types.EncryptionKey, pepper []byte, n int) ([]byte, error) {
	var out []byte
	for i := 1; len(out) < n; i++ {
		b, err := krbPRF(key, append([]byte{byte(i)}, pepper...))
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out[:n], nil
}

// krbCF2 is KRB-FX-CF2(k1, k2, pepper1, pepper2) (RFC 6113 §5.1); the result
// has k1's enctype.
func krbCF2(k1, k2 types.EncryptionKey, pepper1, pepper2 string) (types.EncryptionKey, error) {
	n, err := krbKeyLen(k1.KeyType)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	a, err := prfPlus(k1, []byte(pepper1), n)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	b, err := prfPlus(k2, []byte(pepper2), n)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	for i := range a {
		a[i] ^= b[i]
	}
	// random-to-key is the identity for every enctype krbPRF supports (AES,
	// RFC 4757 RC4); gokrb5's RC4 RandomToKey hashes with MD4, which is wrong.
	return types.EncryptionKey{KeyType: k1.KeyType, KeyValue: a}, nil
}

// ---- FAST structures (RFC 6113 §5.4) ----

type krbFastArmor struct {
	ArmorType  int32  `asn1:"explicit,tag:0"`
	ArmorValue []byte `asn1:"explicit,tag:1"`
}

type krbFastArmoredReq struct {
	Armor       krbFastArmor        `asn1:"explicit,optional,tag:0"`
	ReqChecksum types.Checksum      `asn1:"explicit,tag:1"`
	EncFastReq  types.EncryptedData `asn1:"explicit,tag:2"`
}

type krbFastReq struct {
	FastOptions asn1.BitString       `asn1:"explicit,tag:0"`
	PAData      types.PADataSequence `asn1:"explicit,tag:1"`
	ReqBody     asn1.RawValue        `asn1:"explicit,tag:2"`
}

type krbFastArmoredRep struct {
	EncFastRep types.EncryptedData `asn1:"explicit,tag:0"`
}

type krbFastFinished struct {
	Timestamp      time.Time           `asn1:"generalized,explicit,tag:0"`
	Usec           int                 `asn1:"explicit,tag:1"`
	CRealm         string              `asn1:"generalstring,explicit,tag:2"`
	CName          types.PrincipalName `asn1:"explicit,tag:3"`
	TicketChecksum types.Checksum      `asn1:"explicit,tag:4"`
}

type krbFastResponse struct {
	PAData        types.PADataSequence `asn1:"explicit,tag:0"`
	StrengthenKey types.EncryptionKey  `asn1:"explicit,optional,tag:1"`
	Finished      krbFastFinished      `asn1:"explicit,optional,tag:2"`
	Nonce         int64                `asn1:"explicit,tag:3"`
}

// fastTunnel is one armor key, with the armor that names it (absent for
// the implicit armor of a TGS request).
type fastTunnel struct {
	armor    krbFastArmor
	armorKey types.EncryptionKey
}

func keyedChecksum(key types.EncryptionKey, data []byte, usage uint32) (types.Checksum, error) {
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return types.Checksum{}, err
	}
	ck, err := et.GetChecksumHash(key.KeyValue, data, usage)
	if err != nil {
		return types.Checksum{}, err
	}
	return types.Checksum{CksumType: et.GetHashID(), Checksum: ck}, nil
}

func verifyKeyedChecksum(key types.EncryptionKey, data []byte, ck types.Checksum, usage uint32) bool {
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil || ck.CksumType != et.GetHashID() {
		return false
	}
	return et.VerifyChecksum(key.KeyValue, data, ck.Checksum, usage)
}

// wrap builds PA-FX-FAST around the inner padata and request body. The
// checksum binds it to the outer request: the outer body for AS, the
// PA-TGS-REQ AP-REQ for TGS.
func (f *fastTunnel) wrap(checksumOver []byte, inner types.PADataSequence, body []byte) (types.PAData, error) {
	if inner == nil {
		inner = types.PADataSequence{}
	}
	fr, err := asn1.Marshal(krbFastReq{FastOptions: types.NewKrbFlags(), PAData: inner,
		ReqBody: asn1.RawValue{Class: asn1.ClassContextSpecific, IsCompound: true, Tag: 2, Bytes: body}})
	if err != nil {
		return types.PAData{}, err
	}
	enc, err := crypto.GetEncryptedData(fr, f.armorKey, usageFastEnc, 0)
	if err != nil {
		return types.PAData{}, err
	}
	ck, err := keyedChecksum(f.armorKey, checksumOver, usageFastReqChecksum)
	if err != nil {
		return types.PAData{}, err
	}
	ar, err := asn1.Marshal(krbFastArmoredReq{Armor: f.armor, ReqChecksum: ck, EncFastReq: enc})
	if err != nil {
		return types.PAData{}, err
	}
	v, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, IsCompound: true, Tag: 0, Bytes: ar})
	if err != nil {
		return types.PAData{}, err
	}
	return types.PAData{PADataType: paFXFast, PADataValue: v}, nil
}

// unwrap finds PA-FX-FAST in a reply's padata and decrypts the response.
// It returns nil, nil when the KDC sent none.
func (f *fastTunnel) unwrap(pas types.PADataSequence) (*krbFastResponse, error) {
	for _, pa := range pas {
		if pa.PADataType != paFXFast {
			continue
		}
		var outer asn1.RawValue
		if _, err := asn1.Unmarshal(pa.PADataValue, &outer); err != nil {
			return nil, fmt.Errorf("PA-FX-FAST-REPLY: %w", err)
		}
		if outer.Class != asn1.ClassContextSpecific || outer.Tag != 0 {
			return nil, errors.New("PA-FX-FAST-REPLY: not armored-data [0]")
		}
		var rep krbFastArmoredRep
		if _, err := asn1.Unmarshal(outer.Bytes, &rep); err != nil {
			return nil, fmt.Errorf("KrbFastArmoredRep: %w", err)
		}
		b, err := crypto.DecryptEncPart(rep.EncFastRep, f.armorKey, usageFastRep)
		if err != nil {
			return nil, fmt.Errorf("KrbFastResponse does not decrypt with the armor key: %w", err)
		}
		var r krbFastResponse
		if _, err := asn1.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("KrbFastResponse: %w", err)
		}
		return &r, nil
	}
	return nil, nil
}

func findPA(pas types.PADataSequence, t int32) (types.PAData, bool) {
	for _, pa := range pas {
		if pa.PADataType == t {
			return pa, true
		}
	}
	return types.PAData{}, false
}

func describePAData(pas types.PADataSequence) []M {
	var out []M
	for _, pa := range pas {
		m := M{"type": pa.PADataType, "name": paTypeName(pa.PADataType)}
		if pa.PADataType == patype.PA_ETYPE_INFO2 {
			if info, err := pa.GetETypeInfo2(); err == nil {
				var es []M
				for _, i := range info {
					es = append(es, M{"etype": etypeName(i.EType), "salt": i.Salt})
				}
				m["etype_info2"] = es
			}
		}
		out = append(out, m)
	}
	return out
}

// rawTicket returns the ticket's DER exactly as the KDC sent it in a KDC-REP
// (field [5]), which the KrbFastFinished checksum covers.
func rawTicket(reply []byte) ([]byte, error) {
	var app, seq asn1.RawValue
	if _, err := asn1.Unmarshal(reply, &app); err != nil {
		return nil, err
	}
	if _, err := asn1.Unmarshal(app.Bytes, &seq); err != nil {
		return nil, err
	}
	rest := seq.Bytes
	for len(rest) > 0 {
		var f asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &f); err != nil {
			return nil, err
		}
		if f.Class == asn1.ClassContextSpecific && f.Tag == 5 {
			return f.Bytes, nil
		}
	}
	return nil, errors.New("no ticket in the reply")
}

// krbSendAny sends to the pinned KDCs in turn until one answers.
func krbSendAny(c *Ctx, s *krbSetup, b []byte) ([]byte, error) {
	var lastErr error
	for _, kdc := range s.kdcs {
		reply, err := krbSend(c, kdc, b)
		if err == nil {
			return reply, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no KDC answered: %w", lastErr)
}

// fastError reads a KRB-ERROR to a FAST request: the armored response in
// its e-data and the authenticated error inside (PA-FX-ERROR).
func fastError(f *fastTunnel, ke messages.KRBError, nonce int, cs *Checks, step string) (*krbFastResponse, M) {
	info := describeKRBError(ke)
	var md types.PADataSequence
	if len(ke.EData) == 0 || md.Unmarshal(ke.EData) != nil {
		cs.add(step+": error is armored", "fail", "the KDC answered "+errorcode.Lookup(ke.ErrorCode)+" without PA-FX-FAST: it ignored or rejected the armor, so the error is not integrity protected", "RFC 6113 §5.4.4")
		return nil, info
	}
	fr, err := f.unwrap(md)
	if fr == nil {
		detail := "the KDC answered " + errorcode.Lookup(ke.ErrorCode) + " without PA-FX-FAST: it ignored or rejected the armor, so the error is not integrity protected"
		if err != nil {
			detail = err.Error()
		}
		cs.add(step+": error is armored", "fail", detail, "RFC 6113 §5.4.4")
		return nil, info
	}
	cs.add(step+": error is armored", "pass", "KRB-ERROR carries a KrbFastResponse that decrypts with the armor key", "RFC 6113 §5.4.4")
	cs.ok(fr.Nonce == int64(nonce), step+": FAST response nonce matches the request", "", "RFC 6113 §5.4.3")
	cs.ok(fr.StrengthenKey.KeyType == 0, step+": no strengthen-key in an error", "", "RFC 6113 §5.4.3")
	info["fast_pa_data"] = describePAData(fr.PAData)
	if pa, ok := findPA(fr.PAData, paFXError); ok {
		var inner messages.KRBError
		if inner.Unmarshal(pa.PADataValue) == nil {
			info["authenticated_error"] = describeKRBError(inner)
			cs.ok(inner.ErrorCode == ke.ErrorCode, step+": PA-FX-ERROR matches the outer error", errorcode.Lookup(inner.ErrorCode), "RFC 6113 §5.4.4")
			cs.ok(len(inner.EData) == 0, step+": PA-FX-ERROR has no e-data", "", "RFC 6113 §5.4.4")
		}
	} else {
		cs.add(step+": PA-FX-ERROR present", "fail", "the armored response has no PA-FX-ERROR", "RFC 6113 §5.4.4")
	}
	return fr, info
}

// verifyFinished checks KrbFastFinished against the ticket the KDC sent.
func verifyFinished(f *fastTunnel, fr *krbFastResponse, reply []byte, cs *Checks, step string) M {
	if fr.Finished.TicketChecksum.CksumType == 0 {
		cs.add(step+": KrbFastFinished present", "fail", "the reply carries no finished field, so the ticket is not bound to the armor", "RFC 6113 §5.4.3")
		return nil
	}
	raw, err := rawTicket(reply)
	cs.ok(err == nil && verifyKeyedChecksum(f.armorKey, raw, fr.Finished.TicketChecksum, usageFastFinished),
		step+": ticket checksum in KrbFastFinished verifies", detailOr(err, "keyed with the armor key"), "RFC 6113 §5.4.3")
	return M{"kdc_time": krbTime(fr.Finished.Timestamp), "client": principalString(fr.Finished.CName, fr.Finished.CRealm)}
}

// ---- armor ----

// armorTicket gets the TGT that armors the AS request and builds the
// FX_FAST_ARMOR_AP_REQUEST armor with a fresh subkey.
func armorTicket(c *Ctx, s *krbSetup, cs *Checks, out M) (*fastTunnel, error) {
	cl, err := s.client(c)
	who := principalString(s.cname, s.realm)
	note := "armored with the client's own TGT from an ordinary AS exchange: this exercises the KDC's FAST handling, but in real use the armor comes from a machine account or anonymous PKINIT, which is what keeps the password exchange from being attacked offline"
	if c.Bool("armor_anonymous") {
		if c.Str("armor_principal") != "" {
			return nil, errors.New("pass armor_principal or armor_anonymous, not both")
		}
		info, t := pkinitExchange(c, s, nil, "dh", nil, cs)
		out["armor_pkinit"] = info
		if t == nil {
			return nil, nil
		}
		cs.add("armor TGT issued", "pass", "anonymous PKINIT: "+principalString(t.rep.CName, t.rep.CRealm), "RFC 6113 §5.4.1.1")
		for _, ck := range *cs {
			if strings.HasPrefix(ck.Name, "anonymous PKINIT: KDC certificate chain verifies") && ck.Status == "fail" {
				cs.add("armor authenticates the KDC", "warn", "the KDC's certificate did not verify, so this armor does not keep an attacker posing as the KDC from attacking the password exchange (pass the KDC's CA as ca_cert)", "RFC 8062 §4.1")
			}
		}
		return armorFromTGT(t.rep.CName, t.rep.CRealm, t.rep.Ticket, t.rep.DecryptedEncPart.Key, out, "WELLKNOWN/ANONYMOUS (anonymous PKINIT)")
	}
	if ap := c.Str("armor_principal"); ap != "" {
		name, realm := ap, s.realm
		if i := strings.LastIndex(ap, "@"); i > 0 {
			name, realm = ap[:i], ap[i+1:]
		}
		if realm != s.realm {
			return nil, fmt.Errorf("armor_principal is in realm %s: cross-realm armor is not supported, use a principal in %s", realm, s.realm)
		}
		as := &krbSetup{cfg: s.cfg, realm: s.realm, user: name, kdcs: s.kdcs}
		if k := c.Str("armor_keytab"); k != "" {
			if as.kt, err = loadKeytab(k); err != nil {
				return nil, fmt.Errorf("armor_keytab: %w", err)
			}
		}
		ac := &Ctx{Args: M{"password": c.Str("armor_password")}}
		if as.kt == nil && c.Str("armor_password") == "" {
			return nil, errors.New("pass armor_keytab or armor_password with armor_principal")
		}
		cl, err = as.client(ac)
		who, note = name+"@"+s.realm, ""
	}
	if err != nil {
		return nil, err
	}
	req, err := messages.NewASReqForTGT(s.realm, s.cfg, cl.Credentials.CName())
	if err != nil {
		return nil, err
	}
	rep, err := cl.ASExchange(s.realm, req, 0)
	if !cs.ok(err == nil, "armor TGT issued", detailOr(err, who), "RFC 6113 §5.4.1.1") {
		return nil, nil
	}
	if note != "" {
		cs.add("armor source", "info", note, "RFC 6113 §5.4.1.1")
	}
	return armorFromTGT(cl.Credentials.CName(), s.realm, rep.Ticket, rep.DecryptedEncPart.Key, out, who)
}

// armorFromTGT builds the FAST armor (an AP-REQ with a fresh subkey) and
// the armor key from a TGT and its session key.
func armorFromTGT(cname types.PrincipalName, crealm string, tgt messages.Ticket, sk types.EncryptionKey, out M, who string) (*fastTunnel, error) {
	klen, err := krbKeyLen(sk.KeyType)
	if err != nil {
		return nil, err
	}
	auth, err := types.NewAuthenticator(crealm, cname)
	if err != nil {
		return nil, err
	}
	if err := auth.GenerateSeqNumberAndSubKey(sk.KeyType, klen); err != nil {
		return nil, err
	}
	ap, err := messages.NewAPReq(tgt, sk, auth)
	if err != nil {
		return nil, err
	}
	// gokrb5 picks the PA-TGS-REQ key usage for a TGT; armor is a plain AP-REQ.
	ab, err := auth.Marshal()
	if err != nil {
		return nil, err
	}
	if ap.EncryptedAuthenticator, err = crypto.GetEncryptedData(ab, sk, usageAPReqAuthenticator, 0); err != nil {
		return nil, err
	}
	apb, err := ap.Marshal()
	if err != nil {
		return nil, err
	}
	key, err := krbCF2(auth.SubKey, sk, "subkeyarmor", "ticketarmor")
	if err != nil {
		return nil, err
	}
	out["armor"] = M{"principal": who, "ticket_etype": etypeName(tgt.EncPart.EType), "armor_key_etype": etypeName(key.KeyType)}
	return &fastTunnel{armor: krbFastArmor{ArmorType: fxFastArmorAPRequest, ArmorValue: apb}, armorKey: key}, nil
}

// ---- the armored AS exchange ----

// fastASRequest sends one armored AS-REQ and returns the raw reply.
func fastASRequest(c *Ctx, s *krbSetup, f *fastTunnel, inner types.PADataSequence) (messages.ASReq, []byte, error) {
	req, err := messages.NewASReqForTGT(s.realm, s.cfg, s.cname)
	if err != nil {
		return req, nil, err
	}
	body, err := req.ReqBody.Marshal()
	if err != nil {
		return req, nil, err
	}
	fx, err := f.wrap(body, append(append(types.PADataSequence{}, req.PAData...), inner...), body)
	if err != nil {
		return req, nil, err
	}
	req.PAData = types.PADataSequence{fx}
	b, err := req.Marshal()
	if err != nil {
		return req, nil, err
	}
	reply, err := krbSendAny(c, s, b)
	return req, reply, err
}

// longTermKey derives or looks up the client's key for the enctype the
// KDC chose (first PA-ETYPE-INFO2 entry).
func longTermKey(c *Ctx, s *krbSetup, pas types.PADataSequence) (types.EncryptionKey, error) {
	etype := int32(0)
	if pa, ok := findPA(pas, patype.PA_ETYPE_INFO2); ok {
		if info, err := pa.GetETypeInfo2(); err == nil && len(info) > 0 {
			etype = info[0].EType
		}
	}
	if etype == 0 {
		if len(s.cfg.LibDefaults.DefaultTktEnctypeIDs) == 0 {
			return types.EncryptionKey{}, errors.New("the KDC sent no PA-ETYPE-INFO2")
		}
		etype = s.cfg.LibDefaults.DefaultTktEnctypeIDs[0]
	}
	if s.kt != nil {
		k, _, err := s.kt.GetEncryptionKey(s.cname, s.realm, 0, etype)
		return k, err
	}
	if c.Str("password") == "" {
		return types.EncryptionKey{}, errors.New("pass password (or IDPDBG_PASSWORD) or keytab")
	}
	k, _, err := crypto.GetKeyFromPassword(c.Str("password"), s.cname, s.realm, etype, pas)
	return k, err
}

func fastHint(code int32) string {
	switch code {
	case errorcode.KDC_ERR_PREAUTH_FAILED:
		return "wrong password or key, or the KDC could not use the armor"
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return "the KDC does not know the client"
	case errorcode.KDC_ERR_ETYPE_NOSUPP:
		return "no common encryption type"
	case errorcode.KRB_AP_ERR_SKEW:
		return "clock skew too large"
	case errorcode.KDC_ERR_POLICY:
		return "refused by policy (on Active Directory: FAST may be disabled for the domain controllers, or an authentication policy applies)"
	case 93:
		return "the KDC does not understand a critical FAST option"
	}
	return ""
}

func runFAST(c *Ctx) (M, error) {
	s, err := krbPrepare(c)
	if err != nil {
		return nil, err
	}
	if s.user == "" {
		return nil, errors.New("pass principal")
	}
	var cs Checks
	out := M{"realm": s.realm, "kdcs": s.kdcs, "client": principalString(s.cname, s.realm)}
	if s.found != nil {
		out["kdc_discovery"] = s.found
	}
	defer func() { out["checks"] = cs }()

	// Does the KDC advertise FAST to an unarmored client?
	notAdvertised := -1 // index of the "KDC advertises FAST" warning, if any
	if plain, err := messages.NewASReqForTGT(s.realm, s.cfg, s.cname); err == nil {
		if b, err := plain.Marshal(); err == nil {
			reply, err := krbSendAny(c, s, b)
			if err == nil && len(reply) > 0 && reply[0] == 0x6b {
				cs.add("KDC advertises FAST", "info", "the KDC issued a TGT to an unarmored request without pre-authentication, so it had no reason to advertise FAST", "RFC 6113 §5.4.2")
			}
			if err == nil && len(reply) > 0 && reply[0] == 0x7e {
				var ke messages.KRBError
				if ke.Unmarshal(reply) == nil {
					var md types.PADataSequence
					advertised := len(ke.EData) > 0 && md.Unmarshal(ke.EData) == nil && md.Contains(paFXFast)
					if advertised {
						cs.add("KDC advertises FAST", "pass", "PA-FX-FAST in the PREAUTH_REQUIRED method data", "RFC 6113 §5.4.2")
					} else {
						notAdvertised = len(cs)
						cs.add("KDC advertises FAST", "warn", fmt.Sprintf("%s without PA-FX-FAST: the KDC may not support FAST (Active Directory: enable \"KDC support for claims, compound authentication and Kerberos armoring\")", errorcode.Lookup(ke.ErrorCode)), "RFC 6113 §5.4.2")
					}
					out["unarmored_probe"] = describeKRBError(ke)
				}
			}
		}
	}

	f, err := armorTicket(c, s, &cs, out)
	if err != nil || f == nil {
		return out, err
	}

	// First armored request, without a factor: the KDC answers with an
	// armored PREAUTH_REQUIRED that names the methods and the salt.
	req1, reply, err := fastASRequest(c, s, f, nil)
	if err != nil {
		return out, err
	}
	var methods types.PADataSequence
	if len(reply) > 0 && reply[0] == 0x7e {
		var ke messages.KRBError
		if err := ke.Unmarshal(reply); err != nil {
			return out, fmt.Errorf("KRB-ERROR: %w", err)
		}
		fr, info := fastError(f, ke, req1.ReqBody.Nonce, &cs, "armored AS-REQ")
		out["armored_preauth_required"] = info
		if fr == nil {
			return out, nil
		}
		if ke.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
			cs.add("armored AS exchange", "fail", errorcode.Lookup(ke.ErrorCode)+" "+fastHint(ke.ErrorCode), "RFC 6113 §5.4.4")
			return out, nil
		}
		methods = fr.PAData
		_, offered := findPA(methods, paEncryptedChallenge)
		cs.warn(offered, "encrypted challenge offered", "PA-ENCRYPTED-CHALLENGE among the methods", "RFC 6113 §5.4.6")
	} else {
		cs.add("pre-authentication required inside FAST", "warn", "the KDC issued a ticket to an armored request without any factor", "RFC 6113 §5.4.6")
		return out, nil
	}

	// Second request: encrypted challenge in the client challenge key,
	// with the cookie copied back.
	long, err := longTermKey(c, s, methods)
	if !cs.ok(err == nil, "client long-term key", detailOr(err, etypeNameOK(err, long)), "RFC 4120 §3.1.3") {
		return out, nil
	}
	ck, err := krbCF2(f.armorKey, long, "clientchallengearmor", "challengelongterm")
	if err != nil {
		return out, err
	}
	ts, err := types.GetPAEncTSEncAsnMarshalled()
	if err != nil {
		return out, err
	}
	ed, err := crypto.GetEncryptedData(ts, ck, usageEncChallengeClnt, 0)
	if err != nil {
		return out, err
	}
	edb, err := ed.Marshal()
	if err != nil {
		return out, err
	}
	inner := types.PADataSequence{}
	if cookie, ok := findPA(methods, paFXCookie); ok {
		inner = append(inner, cookie)
		cs.add("PA-FX-COOKIE", "info", fmt.Sprintf("%d bytes, returned to the KDC unchanged", len(cookie.PADataValue)), "RFC 6113 §5.2")
	}
	inner = append(inner, types.PAData{PADataType: paEncryptedChallenge, PADataValue: edb})
	req2, reply, err := fastASRequest(c, s, f, inner)
	if err != nil {
		return out, err
	}
	if len(reply) > 0 && reply[0] == 0x7e {
		var ke messages.KRBError
		if err := ke.Unmarshal(reply); err != nil {
			return out, fmt.Errorf("KRB-ERROR: %w", err)
		}
		_, info := fastError(f, ke, req2.ReqBody.Nonce, &cs, "encrypted challenge")
		out["encrypted_challenge_error"] = info
		cs.add("encrypted challenge accepted (TGT issued)", "fail", errorcode.Lookup(ke.ErrorCode)+" "+fastHint(ke.ErrorCode), "RFC 6113 §5.4.6")
		return out, nil
	}
	var rep messages.ASRep
	if err := rep.Unmarshal(reply); err != nil {
		return out, fmt.Errorf("AS-REP: %w", err)
	}
	cs.add("encrypted challenge accepted (TGT issued)", "pass", "krbtgt/"+s.realm, "RFC 6113 §5.4.6")
	if notAdvertised >= 0 {
		// Supported, just not advertised. Active Directory does this unless
		// the KDC policy is set to "Always provide claims"; Windows clients
		// learn that the domain supports armoring from the DC locator instead.
		cs[notAdvertised].Status = "info"
		cs[notAdvertised].Detail = "the KDC accepted armor without advertising PA-FX-FAST in PREAUTH_REQUIRED (Active Directory only advertises it when \"KDC support for claims, compound authentication and Kerberos armoring\" is set to \"Always provide claims\"; with \"Supported\" clients learn it from the domain's capabilities)"
	}
	fr, err := f.unwrap(rep.PAData)
	if fr == nil {
		cs.add("AS-REP carries PA-FX-FAST", "fail", detailOr(err, "the reply is not armored: a client must reject it, since it could have been stripped of FAST"), "RFC 6113 §5.4.3")
		return out, nil
	}
	cs.add("AS-REP carries PA-FX-FAST", "pass", "KrbFastResponse decrypts with the armor key", "RFC 6113 §5.4.3")
	cs.ok(fr.Nonce == int64(req2.ReqBody.Nonce), "FAST response nonce matches the request", "", "RFC 6113 §5.4.3")
	out["fast_pa_data"] = describePAData(fr.PAData)
	if fin := verifyFinished(f, fr, reply, &cs, "AS-REP"); fin != nil {
		out["finished"] = fin
		cs.ok(fr.Finished.CName.Equal(s.cname) && strings.EqualFold(fr.Finished.CRealm, s.realm), "KrbFastFinished names the client", fin["client"].(string), "RFC 6113 §5.4.3")
	}
	// The KDC proves it knows the client's key with its own challenge.
	if pa, ok := findPA(fr.PAData, paEncryptedChallenge); ok {
		kk, err := krbCF2(f.armorKey, long, "kdcchallengearmor", "challengelongterm")
		var ked types.EncryptedData
		var kts types.PAEncTSEnc
		if err == nil {
			if err = ked.Unmarshal(pa.PADataValue); err == nil {
				var b []byte
				if b, err = crypto.DecryptEncPart(ked, kk, usageEncChallengeKDC); err == nil {
					err = kts.Unmarshal(b)
				}
			}
		}
		if cs.ok(err == nil, "KDC encrypted challenge verifies (KDC authenticated)", detailOr(err, "KDC time "+krbTime(kts.PATimestamp)), "RFC 6113 §5.4.6") {
			skew := time.Since(kts.PATimestamp)
			if skew < 0 {
				skew = -skew
			}
			cs.warn(skew <= 5*time.Minute, "KDC challenge timestamp within clock skew", skew.Round(time.Second).String(), "RFC 6113 §5.4.6")
		}
	} else {
		cs.add("KDC encrypted challenge verifies (KDC authenticated)", "fail", "the KDC sent no PA-ENCRYPTED-CHALLENGE back, so it did not prove it knows the client's key", "RFC 6113 §5.4.6")
	}
	replyKey := long
	if fr.StrengthenKey.KeyType != 0 {
		cs.add("reply key strengthened", "pass", etypeName(fr.StrengthenKey.KeyType), "RFC 6113 §5.4.3")
		if replyKey, err = krbCF2(fr.StrengthenKey, long, "strengthenkey", "replykey"); err != nil {
			return out, err
		}
	} else {
		cs.add("reply key strengthened", "fail", "no strengthen-key: with encrypted challenge the KDC MUST strengthen the reply key", "RFC 6113 §5.4.6")
	}
	b, err := crypto.DecryptEncPart(rep.EncPart, replyKey, keyusage.AS_REP_ENCPART)
	if err == nil {
		err = rep.DecryptedEncPart.Unmarshal(b)
	}
	if !cs.ok(err == nil, "AS-REP decrypts with the strengthened reply key", detailOr(err, ""), "RFC 6113 §5.4.3") {
		return out, nil
	}
	d := rep.DecryptedEncPart
	cs.ok(d.Nonce == req2.ReqBody.Nonce, "AS-REP nonce matches the request", "", "RFC 4120 §3.1.5")
	out["ticket"] = describeTicket(rep.Ticket)
	out["tgt"] = M{"flags": flagList(d.Flags), "session_key_type": etypeName(d.Key.KeyType), "auth_time": krbTime(d.AuthTime),
		"end_time": krbTime(d.EndTime), "server": d.SName.PrincipalNameString() + "@" + d.SRealm}
	etypeCheck(&cs, "TGT session key", d.Key.KeyType)
	etypeCheck(&cs, "TGT", rep.Ticket.EncPart.EType)

	if spn := c.Str("target_spn"); spn != "" {
		out["service_ticket"] = fastTGS(c, s, rep.Ticket, d.Key, spn, &cs)
	}
	return out, nil
}

func etypeNameOK(err error, k types.EncryptionKey) string {
	if err != nil {
		return ""
	}
	return etypeName(k.KeyType)
}

// fastTGS asks for a service ticket inside FAST with implicit armor: the
// armor key comes from the PA-TGS-REQ authenticator's subkey and the TGT
// session key (RFC 6113 §5.4.1).
func fastTGS(c *Ctx, s *krbSetup, tgt messages.Ticket, sk types.EncryptionKey, spn string, cs *Checks) M {
	out := M{"spn": spn}
	fail := func(err error) M {
		cs.add("FAST TGS exchange", "fail", err.Error(), "RFC 6113 §5.4.1")
		return out
	}
	sname, _ := types.ParseSPNString(spn)
	req, err := messages.NewTGSReq(s.cname, s.realm, s.cfg, tgt, sk, sname, false)
	if err != nil {
		return fail(err)
	}
	body, err := req.ReqBody.Marshal()
	if err != nil {
		return fail(err)
	}
	klen, err := krbKeyLen(sk.KeyType)
	if err != nil {
		return fail(err)
	}
	bck, err := keyedChecksum(sk, body, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		return fail(err)
	}
	auth, err := types.NewAuthenticator(s.realm, s.cname)
	if err != nil {
		return fail(err)
	}
	auth.Cksum = bck
	if err := auth.GenerateSeqNumberAndSubKey(sk.KeyType, klen); err != nil {
		return fail(err)
	}
	ap, err := messages.NewAPReq(tgt, sk, auth)
	if err != nil {
		return fail(err)
	}
	apb, err := ap.Marshal()
	if err != nil {
		return fail(err)
	}
	key, err := krbCF2(auth.SubKey, sk, "subkeyarmor", "ticketarmor")
	if err != nil {
		return fail(err)
	}
	f := &fastTunnel{armorKey: key}
	fx, err := f.wrap(apb, nil, body)
	if err != nil {
		return fail(err)
	}
	req.PAData = types.PADataSequence{{PADataType: patype.PA_TGS_REQ, PADataValue: apb}, fx}
	b, err := req.Marshal()
	if err != nil {
		return fail(err)
	}
	reply, err := krbSendAny(c, s, b)
	if err != nil {
		return fail(err)
	}
	if len(reply) > 0 && reply[0] == 0x7e {
		var ke messages.KRBError
		if err := ke.Unmarshal(reply); err != nil {
			return fail(err)
		}
		_, info := fastError(f, ke, req.ReqBody.Nonce, cs, "FAST TGS-REQ")
		out["error"] = info
		cs.add("FAST TGS exchange (service ticket issued)", "fail", errorcode.Lookup(ke.ErrorCode)+" "+s4uHint(ke.ErrorCode, ""), "RFC 6113 §5.4.1")
		return out
	}
	var rep messages.TGSRep
	if err := rep.Unmarshal(reply); err != nil {
		return fail(fmt.Errorf("TGS-REP: %w", err))
	}
	cs.add("FAST TGS exchange (service ticket issued)", "pass", spn, "RFC 6113 §5.4.1")
	fr, err := f.unwrap(rep.PAData)
	if fr == nil {
		cs.add("TGS-REP carries PA-FX-FAST", "fail", detailOr(err, "the reply is not armored"), "RFC 6113 §5.4.3")
		return out
	}
	cs.add("TGS-REP carries PA-FX-FAST", "pass", "KrbFastResponse decrypts with the implicit armor key", "RFC 6113 §5.4.3")
	cs.ok(fr.Nonce == int64(req.ReqBody.Nonce), "TGS FAST response nonce matches the request", "", "RFC 6113 §5.4.3")
	if fin := verifyFinished(f, fr, reply, cs, "TGS-REP"); fin != nil {
		out["finished"] = fin
	}
	replyKey := auth.SubKey
	if fr.StrengthenKey.KeyType == 0 {
		cs.add("TGS reply key strengthened", "fail", "no strengthen-key: it MUST be present in a TGS reply, or an attacker could strip FAST from it", "RFC 6113 §5.4.3")
	} else {
		cs.add("TGS reply key strengthened", "pass", etypeName(fr.StrengthenKey.KeyType), "RFC 6113 §5.4.3")
		if replyKey, err = krbCF2(fr.StrengthenKey, auth.SubKey, "strengthenkey", "replykey"); err != nil {
			return fail(err)
		}
	}
	db, err := crypto.DecryptEncPart(rep.EncPart, replyKey, keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY)
	if err == nil {
		err = rep.DecryptedEncPart.Unmarshal(db)
	}
	if !cs.ok(err == nil, "TGS-REP decrypts with the strengthened reply key", detailOr(err, ""), "RFC 6113 §5.4.3") {
		return out
	}
	cs.ok(rep.DecryptedEncPart.Nonce == req.ReqBody.Nonce, "TGS-REP nonce matches the request", "", "RFC 4120 §3.3.3")
	info := describeTicket(rep.Ticket)
	info["flags"] = flagList(rep.DecryptedEncPart.Flags)
	out["ticket"] = info
	etypeCheck(cs, "service ticket", rep.Ticket.EncPart.EType)
	return out
}

func init() {
	register(&Op{
		Name: "krb.fast",
		Summary: "Get a TGT inside Kerberos FAST armoring (RFC 6113): checks the KDC advertises FAST, armors the AS exchange with a TGT (a machine account's, one from anonymous PKINIT, or the client's own), " +
			"authenticates with the encrypted challenge factor and verifies the armored replies: integrity-protected errors, the KDC's own challenge, the strengthened reply key and the ticket checksum. " +
			"With target_spn it also gets a service ticket with FAST and implicit armor. Returns ticket descriptions only, never usable tickets or keys.",
		Params: joinParams(krbParams, []Param{
			{Name: "armor_principal", Type: "string", Desc: "Principal whose TGT armors the request, usually a machine account (host/client.example.com, or CLIENT$ on Active Directory); default: the client itself"},
			{Name: "armor_keytab", Type: "string", Path: true, Desc: "Keytab of armor_principal (a path, or base64)"},
			{Name: "armor_password", Type: "string", Secret: true, Desc: "Password of armor_principal"},
			{Name: "armor_anonymous", Type: "bool", Desc: "Armor with a TGT from anonymous PKINIT (RFC 8062) instead: no machine account needed, and the KDC is authenticated by its certificate (pass its CA as ca_cert)"},
			{Name: "target_spn", Type: "string", Desc: "Also get a service ticket for this SPN inside FAST, e.g. HTTP/web.example.com"},
		}),
		Run: runFAST,
	})
}
