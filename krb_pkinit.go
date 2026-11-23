package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	forkasn1 "github.com/jcmturner/gofork/encoding/asn1"
	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// PKINIT (RFC 4556): the AS exchange with a certificate and its private key
// instead of a password. The client signs an AuthPack with its key (CMS
// SignedData); the KDC answers with the reply key either agreed by
// Diffie-Hellman (signed by the KDC) or encrypted to the client's RSA key
// (EnvelopedData around a signed ReplyKeyPack). Both are checked here,
// together with the KDC's own certificate, which the client must verify.

const (
	paPKASReq          int32 = 16
	paPKASRep          int32 = 17
	paASFreshness      int32 = 150 // RFC 8070
	paPKINITKX         int32 = 147 // RFC 8062 §7
	usagePKInitASReqCk       = 6   // RFC 4556 §3.2.3.2: asChecksum
	usagePKINITKX            = 44  // RFC 8062 §7
	// RFC 6112 §5: the request-anonymous KDC option and the anonymous
	// ticket flag are both bit 16 (gokrb5's flags.RequestAnonymous is an
	// older draft's 12).
	kdcOptRequestAnonymous = 16
	tktFlagAnonymous       = 16
	ntWellknown            = 11 // RFC 6111 §3
)

// anonymousSetup is s with the anonymous client of RFC 8062:
// WELLKNOWN/ANONYMOUS in the realm whose KDC it talks to.
func anonymousSetup(s *krbSetup) *krbSetup {
	a := *s
	a.user, a.kt = "WELLKNOWN/ANONYMOUS", nil
	a.cname = types.PrincipalName{NameType: ntWellknown, NameString: []string{"WELLKNOWN", "ANONYMOUS"}}
	return &a
}

// pkinitTGT is what a PKINIT exchange yields beyond its report: the
// decrypted AS-REP, for armoring FAST with it.
type pkinitTGT struct {
	rep messages.ASRep
}

var (
	oidPKINITAuthData     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}
	oidPKINITDHKeyData    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}
	oidPKINITRKeyData     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 3}
	oidPKINITKPClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4}
	oidPKINITKPKdc        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}
	oidPKINITSAN          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}
	oidMSSmartcardLogon   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	oidMSUPN              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
	oidDHPublicNumber     = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}
	oidSubjectAltName     = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// MODP groups: RFC 2409 §6.2 (group 2) and RFC 3526 §3 (group 14), g = 2.
var modpGroups = map[int]string{
	2:  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
	14: "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
}

func modpPrime(group int) (*big.Int, error) {
	h, ok := modpGroups[group]
	if !ok {
		return nil, fmt.Errorf("dh_group %d: use 14 (2048-bit) or 2 (1024-bit)", group)
	}
	p, _ := new(big.Int).SetString(h, 16)
	return p, nil
}

type pkAuthenticator struct {
	Cusec          int       `asn1:"explicit,tag:0"`
	Ctime          time.Time `asn1:"generalized,explicit,tag:1"`
	Nonce          int64     `asn1:"explicit,tag:2"`
	PAChecksum     []byte    `asn1:"explicit,optional,tag:3"`
	FreshnessToken []byte    `asn1:"explicit,optional,tag:4"`
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkinitAuthPack struct {
	PKAuthenticator   pkAuthenticator            `asn1:"explicit,tag:0"`
	ClientPublicValue subjectPublicKeyInfo       `asn1:"explicit,optional,tag:1"`
	SupportedCMSTypes []pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:2"`
}

type paPKASReqValue struct {
	SignedAuthPack []byte `asn1:"tag:0"`
}

type dhDomainParameters struct {
	P, G, Q *big.Int
}

type dhRepInfo struct {
	DHSignedData  []byte        `asn1:"tag:0"`
	ServerDHNonce []byte        `asn1:"explicit,optional,tag:1"`
	KDF           asn1.RawValue `asn1:"explicit,optional,tag:2"`
}

type kdcDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"explicit,tag:0"`
	Nonce            *big.Int       `asn1:"explicit,tag:1"`
	DHKeyExpiration  time.Time      `asn1:"generalized,explicit,optional,tag:2"`
}

type krbEncryptionKeyASN struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

type krbChecksumASN struct {
	CksumType int32  `asn1:"explicit,tag:0"`
	Checksum  []byte `asn1:"explicit,tag:1"`
}

type replyKeyPack struct {
	ReplyKey   krbEncryptionKeyASN `asn1:"explicit,tag:0"`
	ASChecksum krbChecksumASN      `asn1:"explicit,tag:1"`
}

// krb5PrincipalNameSAN is the id-pkinit-san otherName (RFC 4556 §3.2.2).
type krb5PrincipalNameSAN struct {
	Realm string              `asn1:"generalstring,explicit,tag:0"`
	Name  types.PrincipalName `asn1:"explicit,tag:1"`
}

// pkinitSANs lists a certificate's Kerberos principal names (id-pkinit-san)
// and Microsoft UPNs.
func pkinitSANs(c *x509.Certificate) (principals, upns []string) {
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			continue
		}
		var seq asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &seq); err != nil {
			return
		}
		for rest := seq.Bytes; len(rest) > 0; {
			var gn asn1.RawValue
			var err error
			if rest, err = asn1.Unmarshal(rest, &gn); err != nil {
				return
			}
			if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 {
				continue
			}
			var on struct {
				ID    asn1.ObjectIdentifier
				Value asn1.RawValue `asn1:"explicit,tag:0"`
			}
			if _, err := asn1.UnmarshalWithParams(gn.FullBytes, &on, "tag:0"); err != nil {
				continue
			}
			switch {
			case on.ID.Equal(oidPKINITSAN):
				var kp krb5PrincipalNameSAN
				if _, err := forkasn1.Unmarshal(on.Value.Bytes, &kp); err == nil {
					principals = append(principals, kp.Name.PrincipalNameString()+"@"+kp.Realm)
				}
			case on.ID.Equal(oidMSUPN):
				var s string
				if _, err := asn1.Unmarshal(on.Value.Bytes, &s); err == nil {
					upns = append(upns, s)
				}
			}
		}
	}
	return
}

func hasOID(list []asn1.ObjectIdentifier, o asn1.ObjectIdentifier) bool {
	for _, x := range list {
		if x.Equal(o) {
			return true
		}
	}
	return false
}

// octetString2Key is RFC 4556 §3.2.3.1: SHA-1 of a counter byte and the
// input, concatenated and cut to the key length. For AES and RC4 keys
// random-to-key is the identity.
func octetString2Key(x []byte, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		h := sha1.New()
		h.Write([]byte{byte(i)})
		h.Write(x)
		out = h.Sum(out)
	}
	return out[:n]
}

// pkinitErrorNames covers the RFC 4556 error codes gokrb5 does not name.
var pkinitErrorNames = map[int32]string{
	62: "KDC_ERR_CLIENT_NOT_TRUSTED", 63: "KDC_ERR_KDC_NOT_TRUSTED", 64: "KDC_ERR_INVALID_SIG",
	65: "KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED", 70: "KDC_ERR_CANT_VERIFY_CERTIFICATE", 71: "KDC_ERR_INVALID_CERTIFICATE",
	72: "KDC_ERR_REVOKED_CERTIFICATE", 73: "KDC_ERR_REVOCATION_STATUS_UNKNOWN", 74: "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE",
	75: "KDC_ERR_CLIENT_NAME_MISMATCH", 76: "KDC_ERR_KDC_NAME_MISMATCH", 77: "KDC_ERR_INCONSISTENT_KEY_PURPOSE",
	78: "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED", 79: "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED",
	80: "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED", 81: "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED",
}

var pkinitErrorHints = map[int32]string{
	6:  "the KDC does not know this principal",
	16: "the KDC does not support PKINIT (Active Directory needs a domain controller certificate with KDC Authentication)",
	62: "the KDC does not trust the client certificate: its issuing CA must be trusted for client authentication by the KDC (on Active Directory, in the NTAuth store, as enterprise CAs are) and the chain must verify there, revocation included",
	64: "the KDC could not verify the signature on the AuthPack",
	65: "the KDC does not accept this Diffie-Hellman group: try the other dh_group",
	70: "the KDC cannot build or verify the chain of the client certificate",
	71: "the KDC finds the client certificate unusable (validity, key usage)",
	72: "the client certificate is revoked",
	73: "the KDC cannot check whether the client certificate is revoked (CRL or OCSP unreachable from the KDC)",
	75: "the certificate does not map to this principal. Active Directory requires a strong mapping: the SID extension in the certificate, or altSecurityIdentities with issuer and serial number, subject key identifier or public key hash",
	77: "the client certificate has no client authentication purpose (Client Authentication, Smart Card Logon or id-pkinit-KPClientAuth)",
	79: "the KDC requires paChecksum in the PKAuthenticator",
	81: "the KDC does not do RSA key transport: use mode dh",
}

func pkinitErrorName(code int32) string {
	if n, ok := pkinitErrorNames[code]; ok {
		return fmt.Sprintf("(%d) %s", code, n)
	}
	return errorcode.Lookup(code)
}

// windowsExtError reads Active Directory's KERB-ERROR-DATA with an NTSTATUS
// (KERB_ERR_TYPE_EXTENDED, MS-KILE §2.2.1).
func windowsExtError(edata []byte) M {
	var ed struct {
		DataType  int32  `asn1:"explicit,tag:1"`
		DataValue []byte `asn1:"explicit,optional,tag:2"`
	}
	if _, err := asn1.Unmarshal(edata, &ed); err != nil || ed.DataType != 3 || len(ed.DataValue) < 4 {
		return nil
	}
	st := binary.LittleEndian.Uint32(ed.DataValue)
	names := map[uint32]string{0xC000006D: "STATUS_LOGON_FAILURE", 0xC000006E: "STATUS_ACCOUNT_RESTRICTION", 0xC0000072: "STATUS_ACCOUNT_DISABLED",
		0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT", 0xC0000320: "STATUS_PKINIT_FAILURE"}
	out := M{"ntstatus": fmt.Sprintf("0x%08X", st)}
	if n, ok := names[st]; ok {
		out["ntstatus_name"] = n
	}
	return out
}

type pkinitClient struct {
	chain  []*x509.Certificate
	signer crypto.Signer
	close  func() error // releases a card
	source string       // where the private key is
}

func loadPKINITClient(c *Ctx) (*pkinitClient, error) {
	if slot := c.Str("pkinit_piv_slot"); slot != "" {
		if c.Str("pkinit_key") != "" {
			return nil, errors.New("pass pkinit_piv_slot or pkinit_key, not both")
		}
		signer, cert, err := pivSignerFor(c, slot)
		if err != nil {
			return nil, fmt.Errorf("PIV slot %s: %w", slot, err)
		}
		chain := []*x509.Certificate{cert}
		if extra := c.Str("pkinit_cert"); extra != "" { // intermediates the card does not hold
			o, err := parsePKI(extra)
			if err != nil {
				signer.card.Close()
				return nil, fmt.Errorf("pkinit_cert: %w", err)
			}
			for _, ic := range o.Certs {
				if !bytes.Equal(ic.Raw, cert.Raw) {
					chain = append(chain, ic)
				}
			}
		}
		return &pkinitClient{chain: chain, signer: signer, close: signer.card.Close, source: "PIV slot " + strings.ToUpper(slot) + " on " + signer.card.reader}, nil
	}
	if c.Str("pkinit_cert") == "" || c.Str("pkinit_key") == "" {
		return nil, errors.New("pass pkinit_cert and pkinit_key, or pkinit_piv_slot")
	}
	o, err := parsePKI(c.Str("pkinit_cert"))
	if err != nil || len(o.Certs) == 0 {
		return nil, fmt.Errorf("pkinit_cert: no certificate (%v)", err)
	}
	k, err := loadPrivateKey(c.Str("pkinit_key"))
	if err != nil {
		return nil, fmt.Errorf("pkinit_key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("pkinit_key: not a signing key")
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(o.Certs[0].PublicKey) {
		return nil, errors.New("pkinit_key does not belong to the first certificate in pkinit_cert")
	}
	return &pkinitClient{chain: o.Certs, signer: signer, source: "pkinit_key"}, nil
}

func pkinitClientChecks(cl *pkinitClient, cs *Checks) M {
	cert := cl.chain[0]
	now := time.Now()
	cs.ok(now.After(cert.NotBefore) && now.Before(cert.NotAfter), "client certificate valid now",
		fmt.Sprintf("%s to %s", cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339)), "RFC 5280 §4.1.2.5")
	switch {
	case hasOID(cert.UnknownExtKeyUsage, oidPKINITKPClientAuth):
		cs.add("client certificate purpose", "pass", "id-pkinit-KPClientAuth", "RFC 4556 §3.2.2")
	case hasOID(cert.UnknownExtKeyUsage, oidMSSmartcardLogon):
		cs.add("client certificate purpose", "pass", "Smart Card Logon", "MS-PKCA §3.1.5.2.1.1")
	case len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0:
		cs.add("client certificate purpose", "warn", "no extended key usage: KDCs differ on whether they accept it", "RFC 4556 §3.2.2")
	default:
		ok := false
		for _, u := range cert.ExtKeyUsage {
			ok = ok || u == x509.ExtKeyUsageClientAuth || u == x509.ExtKeyUsageAny
		}
		cs.ok(ok, "client certificate purpose", map[bool]string{true: "Client Authentication (Active Directory accepts it; RFC 4556 KDCs may want id-pkinit-KPClientAuth)", false: "no client authentication purpose: KDCs refuse it (KDC_ERR_INCONSISTENT_KEY_PURPOSE)"}[ok], "RFC 4556 §3.2.2")
	}
	principals, upns := pkinitSANs(cert)
	info := certDetail(cert)
	if len(principals) > 0 {
		info["pkinit_san"] = principals
	}
	if len(upns) > 0 {
		info["upn"] = upns
	}
	return info
}

// pkinitFreshness asks for an RFC 8070 freshness token with an empty
// PA-AS-FRESHNESS, and reads what the KDC offers for pre-authentication.
func pkinitFreshness(c *Ctx, s *krbSetup, cs *Checks, out M) []byte {
	req, err := messages.NewASReqForTGT(s.realm, s.cfg, s.cname)
	if err != nil {
		return nil
	}
	req.PAData = append(req.PAData, types.PAData{PADataType: paASFreshness, PADataValue: []byte{}})
	b, err := req.Marshal()
	if err != nil {
		return nil
	}
	reply, err := krbSendAny(c, s, b)
	if err != nil {
		cs.add("KDC reachable", "fail", err.Error(), "RFC 4120 §7.2.2")
		return nil
	}
	if len(reply) == 0 || reply[0] != 0x7e {
		cs.add("KDC asks for pre-authentication", "warn", "the KDC answered without pre-authentication (the account does not require it)", "RFC 4120 §5.2.7")
		return nil
	}
	var ke messages.KRBError
	if ke.Unmarshal(reply) != nil {
		return nil
	}
	if ke.ErrorCode != errorcode.KDC_ERR_PREAUTH_REQUIRED {
		info := describeKRBError(ke)
		info["error"] = pkinitErrorName(ke.ErrorCode)
		out["preauth_error"] = info
		cs.add("KDC asks for pre-authentication", "fail", pkinitErrorName(ke.ErrorCode)+" "+pkinitErrorHints[ke.ErrorCode], "RFC 4120 §5.2.7")
		return nil
	}
	var pas types.PADataSequence
	if len(ke.EData) > 0 {
		_ = pas.Unmarshal(ke.EData)
	}
	out["preauth_offered"] = describePAData(pas)
	_, offered := findPA(pas, paPKASReq)
	cs.ok(offered, "KDC offers PKINIT", map[bool]string{true: "PA-PK-AS-REQ among the methods", false: "PA-PK-AS-REQ not among the methods: the KDC may lack a certificate"}[offered], "RFC 4556 §3.2.1")
	if pa, ok := findPA(pas, paASFreshness); ok && len(pa.PADataValue) > 0 {
		cs.add("KDC issues freshness tokens", "pass", fmt.Sprintf("%d-byte token, signed into the AuthPack", len(pa.PADataValue)), "RFC 8070 §4")
		return pa.PADataValue
	}
	cs.add("KDC issues freshness tokens", "info", "no PA-AS-FRESHNESS token: the request relies on ctime and the nonce alone (on Active Directory, the KDC policy \"KDC support for PKInit Freshness Extension\")", "RFC 8070 §4")
	return nil
}

// pkinitExchange runs one AS exchange in the given mode ("dh" or "rsa").
// pkinitExchange runs one PKINIT AS exchange. Without a client (cl nil)
// it is anonymous PKINIT (RFC 8062): an unsigned AuthPack from
// WELLKNOWN/ANONYMOUS, Diffie-Hellman only, and the KDC's key exchange
// (PA_PKINIT_KX) checked against the session key.
func pkinitExchange(c *Ctx, s *krbSetup, cl *pkinitClient, mode string, token []byte, cs *Checks) (M, *pkinitTGT) {
	anon := cl == nil
	label := map[string]string{"dh": "DH", "rsa": "RSA"}[mode]
	if anon {
		label, mode, s = "anonymous PKINIT", "dh", anonymousSetup(s)
	}
	out := M{}
	fail := func(check string, err error, ref string) (M, *pkinitTGT) {
		cs.add(label+": "+check, "fail", err.Error(), ref)
		return out, nil
	}
	req, err := messages.NewASReqForTGT(s.realm, s.cfg, s.cname)
	if err != nil {
		return fail("AS-REQ", err, "RFC 4120 §5.4.1")
	}
	if anon {
		types.SetFlag(&req.ReqBody.KDCOptions, kdcOptRequestAnonymous)
	}
	body, err := req.ReqBody.Marshal()
	if err != nil {
		return fail("AS-REQ", err, "RFC 4120 §5.4.1")
	}
	paCk := sha1.Sum(body)
	var nb [4]byte
	rand.Read(nb[:])
	nonce := int64(binary.BigEndian.Uint32(nb[:]) &^ 0x80000000)
	now := time.Now().UTC()
	ap := pkinitAuthPack{
		PKAuthenticator: pkAuthenticator{Cusec: now.Nanosecond() / 1000, Ctime: now.Truncate(time.Second), Nonce: nonce, PAChecksum: paCk[:], FreshnessToken: token},
		SupportedCMSTypes: []pkix.AlgorithmIdentifier{
			{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue}, {Algorithm: oidECDSAWithSHA256},
			{Algorithm: oidAES256CBC}, {Algorithm: oidAES128CBC}, {Algorithm: oidDESEDE3CBC},
		},
	}
	var p, x *big.Int
	if mode == "dh" {
		group := c.Int("dh_group")
		if group == 0 { // operations without the parameter, such as krb.fast
			group = 14
		}
		if p, err = modpPrime(group); err != nil {
			return fail("Diffie-Hellman group", err, "RFC 4556 §3.2.3.1")
		}
		q := new(big.Int).Rsh(p, 1) // (p-1)/2: the MODP primes are safe primes
		if x, err = rand.Int(rand.Reader, new(big.Int).Sub(q, big.NewInt(2))); err != nil {
			return fail("Diffie-Hellman key", err, "RFC 4556 §3.2.3.1")
		}
		x.Add(x, big.NewInt(2))
		y := new(big.Int).Exp(big.NewInt(2), x, p)
		ap.ClientPublicValue = subjectPublicKeyInfo{
			Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidDHPublicNumber, Parameters: asn1.RawValue{FullBytes: mustDER(dhDomainParameters{P: p, G: big.NewInt(2), Q: q})}},
			PublicKey: asn1.BitString{Bytes: mustDER(y), BitLength: 8 * len(mustDER(y))},
		}
		out["dh_group"] = fmt.Sprintf("MODP group %d (%d-bit)", group, p.BitLen())
		if p.BitLen() < 2048 {
			cs.add(label+": Diffie-Hellman group", "warn", fmt.Sprintf("%d-bit MODP is too weak for new use; prefer group 14", p.BitLen()), "RFC 8247 §2.4")
		}
	}
	apDER, err := asn1.Marshal(ap)
	if err != nil {
		return fail("AuthPack", err, "RFC 4556 §3.2.1")
	}
	var signed []byte
	if anon {
		signed, err = cmsUnsigned(oidPKINITAuthData, apDER)
	} else {
		signed, err = cmsSign(oidPKINITAuthData, apDER, cl.chain, cl.signer)
	}
	if err != nil {
		return fail("signed AuthPack", err, "RFC 4556 §3.2.1")
	}
	req.PAData = append(req.PAData, types.PAData{PADataType: paPKASReq, PADataValue: mustDER(paPKASReqValue{SignedAuthPack: signed})})
	reqDER, err := req.Marshal()
	if err != nil || !bytes.Contains(reqDER, body) {
		return fail("AS-REQ", fmt.Errorf("the request body changed after paChecksum was taken (%v)", err), "RFC 4556 §3.2.1")
	}
	reply, err := krbSendAny(c, s, reqDER)
	if err != nil {
		return fail("KDC reachable", err, "RFC 4120 §7.2.2")
	}
	if len(reply) > 0 && reply[0] == 0x7e {
		var ke messages.KRBError
		if err := ke.Unmarshal(reply); err != nil {
			return fail("KDC reply", err, "RFC 4120 §5.9.1")
		}
		info := describeKRBError(ke)
		info["error"] = pkinitErrorName(ke.ErrorCode)
		if w := windowsExtError(ke.EData); w != nil {
			info["windows"] = w
		}
		out["error"] = info
		hint := pkinitErrorHints[ke.ErrorCode]
		if mode == "rsa" && ke.ErrorCode == errorcode.KDC_ERR_ETYPE_NOSUPP {
			// Seen on Windows Server 2022 whatever the Kerberos and CMS
			// encryption types offered, while Diffie-Hellman works.
			hint = "Active Directory (Windows Server 2022) answers public-key encryption mode this way whatever encryption types are offered; Diffie-Hellman (mode dh), which Windows clients use, works"
		}
		if anon {
			hint = "(the KDC may not allow anonymous PKINIT: MIT krb5 needs a WELLKNOWN/ANONYMOUS principal and pkinit settings on the KDC; Active Directory does not support it)"
		}
		cs.add(label+": PKINIT accepted (TGT issued)", "fail", strings.TrimSpace(pkinitErrorName(ke.ErrorCode)+" "+hint), "RFC 4556 §3.2.2")
		return out, nil
	}
	var rep messages.ASRep
	if err := rep.Unmarshal(reply); err != nil {
		return fail("KDC reply", err, "RFC 4120 §5.4.2")
	}
	cs.add(label+": PKINIT accepted (TGT issued)", "pass", "krbtgt/"+s.realm, "RFC 4556 §3.2.3")
	pa, ok := findPA(rep.PAData, paPKASRep)
	if !ok {
		return fail("AS-REP carries PA-PK-AS-REP", errors.New("missing"), "RFC 4556 §3.2.3")
	}
	var choice asn1.RawValue
	if _, err := asn1.Unmarshal(pa.PADataValue, &choice); err != nil || choice.Class != asn1.ClassContextSpecific {
		return fail("PA-PK-AS-REP", fmt.Errorf("not a PA-PK-AS-REP (%v)", err), "RFC 4556 §3.2.3")
	}

	etype := rep.EncPart.EType
	var replyKey types.EncryptionKey
	var kdcSigned *cmsVerified
	switch {
	case choice.Tag == 0: // dhInfo
		out["reply"] = "Diffie-Hellman"
		if mode != "dh" {
			return fail("reply mode", errors.New("the KDC answered with Diffie-Hellman to a request without a DH public value"), "RFC 4556 §3.2.3")
		}
		var dh dhRepInfo
		if _, err := asn1.Unmarshal(choice.Bytes, &dh); err != nil {
			return fail("DHRepInfo", err, "RFC 4556 §3.2.3.1")
		}
		if len(dh.KDF.FullBytes) > 0 {
			return fail("key derivation", errors.New("the KDC chose an RFC 8636 KDF, which this client did not offer"), "RFC 8636 §6")
		}
		v, err := cmsVerify(dh.DHSignedData)
		if !cs.ok(err == nil, label+": KDC signature on its DH key", detailOr(err, ""), "RFC 4556 §3.2.3.1") {
			return out, nil
		}
		kdcSigned = v
		cs.ok(v.EContentType.Equal(oidPKINITDHKeyData), label+": signed content is KDCDHKeyInfo", v.EContentType.String(), "RFC 4556 §3.2.3.1")
		var info kdcDHKeyInfo
		if _, err := asn1.Unmarshal(v.Content, &info); err != nil {
			return fail("KDCDHKeyInfo", err, "RFC 4556 §3.2.3.1")
		}
		switch {
		case info.Nonce != nil && info.Nonce.Cmp(big.NewInt(nonce)) == 0:
			cs.add(label+": KDCDHKeyInfo nonce matches the PKAuthenticator", "pass", "", "RFC 4556 §3.2.3.1")
		case info.Nonce != nil && info.Nonce.Cmp(big.NewInt(int64(req.ReqBody.Nonce))) == 0:
			cs.add(label+": KDCDHKeyInfo nonce matches the PKAuthenticator", "warn", "the KDC signed the request's nonce instead of the PKAuthenticator's (MIT krb5 does this). Clients that use one value for both never notice", "RFC 4556 §3.2.3.1")
		default:
			got := "absent"
			if info.Nonce != nil {
				got = info.Nonce.String()
			}
			cs.add(label+": KDCDHKeyInfo nonce matches the PKAuthenticator", "fail", fmt.Sprintf("KDCDHKeyInfo nonce %s, PKAuthenticator nonce %d, request nonce %d", got, nonce, req.ReqBody.Nonce), "RFC 4556 §3.2.3.1")
		}
		var ky *big.Int
		if _, err := asn1.Unmarshal(info.SubjectPublicKey.Bytes, &ky); err != nil {
			return fail("KDC DH public value", err, "RFC 4556 §3.2.3.1")
		}
		pm1 := new(big.Int).Sub(p, big.NewInt(1))
		if !cs.ok(ky.Cmp(big.NewInt(1)) > 0 && ky.Cmp(pm1) < 0, label+": KDC DH public value in range", "", "RFC 4556 §3.2.3.1") {
			return out, nil
		}
		z := new(big.Int).Exp(ky, x, p).FillBytes(make([]byte, (p.BitLen()+7)/8))
		n, err := krbKeyLen(etype)
		if err != nil {
			return fail("reply key", err, "RFC 4556 §3.2.3.1")
		}
		if len(dh.ServerDHNonce) > 0 {
			out["server_dh_nonce"] = true
		}
		replyKey = types.EncryptionKey{KeyType: etype, KeyValue: octetString2Key(append(z, dh.ServerDHNonce...), n)}
		if !info.DHKeyExpiration.IsZero() {
			out["dh_key_expiration"] = krbTime(info.DHKeyExpiration)
		}
	case choice.Tag == 1: // encKeyPack
		out["reply"] = "public-key encryption"
		if anon {
			return fail("reply mode", errors.New("the KDC encrypted the reply key, which anonymous PKINIT has no certificate for"), "RFC 8062 §4.1")
		}
		if mode != "rsa" {
			cs.add(label+": reply mode", "warn", "the KDC ignored the Diffie-Hellman value and encrypted the reply key to the certificate instead", "RFC 4556 §3.2.3")
		}
		dec, ok := cl.signer.(crypto.Decrypter)
		if !ok {
			return fail("reply key", errors.New("the KDC encrypted the reply key, but pkinit_key cannot decrypt"), "RFC 4556 §3.2.3.2")
		}
		enc, err := octetContent(choice)
		if err != nil {
			return fail("encKeyPack", err, "RFC 4556 §3.2.3.2")
		}
		opened, err := cmsDecrypt(enc, cl.chain[0], dec)
		if !cs.ok(err == nil, label+": reply key envelope decrypts", detailOr(err, ""), "RFC 4556 §3.2.3.2") {
			return out, nil
		}
		out["key_transport"], out["content_encryption"] = opened.KeyAlg, opened.ContentAlg
		if opened.ContentAlg == "3DES-CBC" {
			cs.add(label+": content encryption", "warn", "3DES: offer AES (the request lists AES first)", "RFC 8429")
		}
		// The envelope holds SignedData; some KDCs wrap it in a ContentInfo.
		v, err := cmsVerify(opened.Content)
		if err != nil {
			v, err = cmsVerify(mustDER(cmsContentInfo{ContentType: oidCMSSignedData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: opened.Content}}))
		}
		if !cs.ok(err == nil, label+": KDC signature on the reply key", detailOr(err, ""), "RFC 4556 §3.2.3.2") {
			return out, nil
		}
		kdcSigned = v
		cs.ok(v.EContentType.Equal(oidPKINITRKeyData), label+": signed content is ReplyKeyPack", v.EContentType.String(), "RFC 4556 §3.2.3.2")
		var rk replyKeyPack
		if _, err := asn1.Unmarshal(v.Content, &rk); err != nil {
			return fail("ReplyKeyPack", err, "RFC 4556 §3.2.3.2")
		}
		replyKey = types.EncryptionKey{KeyType: rk.ReplyKey.KeyType, KeyValue: rk.ReplyKey.KeyValue}
		ck := types.Checksum{CksumType: rk.ASChecksum.CksumType, Checksum: rk.ASChecksum.Checksum}
		cs.ok(verifyKeyedChecksum(replyKey, reqDER, ck, usagePKInitASReqCk), label+": asChecksum binds the reply to this AS-REQ", "", "RFC 4556 §3.2.3.2")
	default:
		return fail("PA-PK-AS-REP", fmt.Errorf("unknown choice [%d]", choice.Tag), "RFC 4556 §3.2.3")
	}
	out["kdc_certificate"] = pkinitKDCChecks(c, s, kdcSigned, label, cs)
	out["kdc_signature"] = M{"digest": kdcSigned.DigestAlg, "algorithm": kdcSigned.SignatureAlg}
	if kdcSigned.DigestAlg == "SHA-1" {
		cs.add(label+": KDC signature digest", "warn", "SHA-1, although the request offered SHA-256 first", "RFC 8636 §2")
	}

	b, err := krbcrypto.DecryptEncPart(rep.EncPart, replyKey, keyusage.AS_REP_ENCPART)
	if err == nil {
		err = rep.DecryptedEncPart.Unmarshal(b)
	}
	if !cs.ok(err == nil, label+": AS-REP decrypts with the reply key", detailOr(err, etypeName(replyKey.KeyType)), "RFC 4556 §3.2.3") {
		return out, nil
	}
	// The PKAuthenticator nonce need not equal the request's (RFC 4556
	// §3.2.1), and this client keeps them apart to see which one comes back.
	switch got := int64(rep.DecryptedEncPart.Nonce); {
	case got == int64(req.ReqBody.Nonce):
		cs.add(label+": AS-REP nonce matches the request", "pass", "", "RFC 4120 §5.4.2")
	case got == nonce:
		cs.add(label+": AS-REP nonce matches the request", "warn", "the KDC returned the PKAuthenticator's nonce instead of the request's (Active Directory does this). Clients that check the nonce, as RFC 4120 requires, then fail unless they use one value for both, as MIT and Windows clients do", "RFC 4120 §5.4.2")
	default:
		cs.add(label+": AS-REP nonce matches the request", "fail", fmt.Sprintf("sent %d, got %d", req.ReqBody.Nonce, got), "RFC 4120 §5.4.2")
	}
	if anon && !anonymousChecks(cs, label, rep, out) {
		return out, nil
	}
	if out["reply"] == "Diffie-Hellman" && !kdcContributionCheck(cs, label, rep, replyKey, anon) {
		return out, nil
	}
	tgt := describeTicket(rep.Ticket)
	tgt["flags"] = flagList(rep.DecryptedEncPart.Flags)
	tgt["session_key_type"] = etypeName(rep.DecryptedEncPart.Key.KeyType)
	tgt["end_time"] = krbTime(rep.DecryptedEncPart.EndTime)
	out["tgt"] = tgt
	return out, &pkinitTGT{rep: rep}
}

// anonymousChecks checks the anonymous client name and ticket flag of an
// anonymous AS-REP.
func anonymousChecks(cs *Checks, label string, rep messages.ASRep, out M) bool {
	out["client"] = principalString(rep.CName, rep.CRealm)
	named := cs.ok(len(rep.CName.NameString) == 2 && rep.CName.NameString[0] == "WELLKNOWN" && rep.CName.NameString[1] == "ANONYMOUS",
		label+": the ticket names the anonymous client", principalString(rep.CName, rep.CRealm), "RFC 8062 §3")
	flagged := cs.ok(types.IsFlagSet(&rep.DecryptedEncPart.Flags, tktFlagAnonymous), label+": the ticket is flagged anonymous", "", "RFC 8062 §3")
	return named && flagged
}

// kdcContributionCheck checks PA_PKINIT_KX: the KDC's contribution to the
// session key, so that a client that chose the Diffie-Hellman exchange
// alone cannot set the ticket's session key. It must be there for
// anonymous PKINIT and should be for Diffie-Hellman generally.
func kdcContributionCheck(cs *Checks, label string, rep messages.ASRep, replyKey types.EncryptionKey, required bool) bool {
	pa, ok := findPA(rep.PAData, paPKINITKX)
	if !ok {
		if required {
			cs.add(label+": the KDC contributes to the session key (PA_PKINIT_KX)", "fail", "absent: an anonymous AS-REP must carry it", "RFC 8062 §7")
			return false
		}
		cs.add(label+": the KDC contributes to the session key (PA_PKINIT_KX)", "info", "absent: RFC 8062 says a KDC should send it with Diffie-Hellman too (MIT krb5 sends it only for anonymous PKINIT)", "RFC 8062 §7")
		return true
	}
	cs.add(label+": the KDC contributes to the session key (PA_PKINIT_KX)", "pass", "", "RFC 8062 §7")
	var ed types.EncryptedData
	if err := ed.Unmarshal(pa.PADataValue); err != nil {
		cs.add(label+": PA_PKINIT_KX", "fail", err.Error(), "RFC 8062 §7")
		return false
	}
	b, err := krbcrypto.DecryptEncPart(ed, replyKey, usagePKINITKX)
	var kx types.EncryptionKey
	if err == nil {
		_, err = forkasn1.Unmarshal(b, &kx)
	}
	if err != nil {
		cs.add(label+": PA_PKINIT_KX", "fail", err.Error(), "RFC 8062 §7")
		return false
	}
	want, err := krbCF2(kx, replyKey, "PKINIT", "KEYEXCHANGE")
	sk := rep.DecryptedEncPart.Key
	return cs.ok(err == nil && want.KeyType == sk.KeyType && bytes.Equal(want.KeyValue, sk.KeyValue),
		label+": session key = KRB-FX-CF2(KDC contribution, reply key, \"PKINIT\", \"KEYEXCHANGE\")", detailOr(err, ""), "RFC 8062 §7")
}

// pkinitKDCChecks judges the certificate the KDC signed with: chain, purpose
// and whether it names this KDC.
func pkinitKDCChecks(c *Ctx, s *krbSetup, v *cmsVerified, label string, cs *Checks) M {
	kc := v.Signer
	inter := x509.NewCertPool()
	for _, ic := range v.Certs {
		if ic != kc {
			inter.AddCert(ic)
		}
	}
	opts := x509.VerifyOptions{Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	from := "the system trust store"
	if c.TLS != nil && c.TLS.RootCAs != nil {
		opts.Roots = c.TLS.RootCAs
		if c.Str("ca_cert") != "" {
			from = "the system trust store and ca_cert"
		}
	}
	_, err := kc.Verify(opts)
	hint := ""
	if err != nil && c.Str("ca_cert") == "" {
		hint = " (pass the domain's CA as ca_cert)"
	}
	cs.ok(err == nil, label+": KDC certificate chain verifies against "+from, detailOr(err, kc.Subject.String())+hint, "RFC 4556 §3.2.4")
	if hasOID(kc.UnknownExtKeyUsage, oidPKINITKPKdc) {
		cs.add(label+": KDC certificate purpose", "pass", "KDC Authentication (id-pkinit-KPKdc)", "RFC 4556 §3.2.4")
	} else {
		cs.add(label+": KDC certificate purpose", "warn", "no id-pkinit-KPKdc: RFC 4556 clients reject it unless told otherwise (older Active Directory \"Domain Controller\" certificates lack it)", "RFC 4556 §3.2.4")
	}
	principals, _ := pkinitSANs(kc)
	want := "krbtgt/" + s.realm + "@" + s.realm
	named := false
	for _, p := range principals {
		named = named || strings.EqualFold(p, want)
	}
	if named {
		cs.add(label+": KDC certificate names the realm's KDC", "pass", want+" (id-pkinit-san)", "RFC 4556 §3.2.4")
	} else {
		var hosts []string
		for _, k := range s.kdcs {
			h, _, _ := net.SplitHostPort(k)
			hosts = append(hosts, h)
		}
		dnsOK := false
		for _, h := range hosts {
			dnsOK = dnsOK || kc.VerifyHostname(h) == nil
		}
		if dnsOK {
			cs.add(label+": KDC certificate names the realm's KDC", "pass", "no id-pkinit-san; its DNS name matches the KDC contacted (Active Directory clients accept that)", "MS-PKCA §3.1.5.2.1.2")
		} else {
			cs.add(label+": KDC certificate names the realm's KDC", "warn", fmt.Sprintf("neither %s (id-pkinit-san) nor the KDC host %s: an attacker's KDC with any certificate from this CA would pass", want, strings.Join(hosts, ", ")), "RFC 4556 §3.2.4")
		}
	}
	return certDetail(kc)
}

func runPKINIT(c *Ctx) (M, error) {
	s, err := krbPrepare(c)
	if err != nil {
		return nil, err
	}
	if c.Bool("anonymous") {
		var cs Checks
		out := M{"realm": s.realm, "kdcs": s.kdcs}
		if s.found != nil {
			out["kdc_discovery"] = s.found
		}
		out["anonymous"], _ = pkinitExchange(c, s, nil, "dh", nil, &cs)
		out["checks"] = cs
		return out, nil
	}
	cl, err := loadPKINITClient(c)
	if err != nil {
		return nil, err
	}
	if cl.close != nil {
		defer cl.close()
	}
	var cs Checks
	out := M{"realm": s.realm, "kdcs": s.kdcs, "client": principalString(s.cname, s.realm)}
	if s.found != nil {
		out["kdc_discovery"] = s.found
	}
	defer func() { out["checks"] = cs }()
	out["client_certificate"] = pkinitClientChecks(cl, &cs)
	out["private_key"] = cl.source
	var token []byte
	if c.Bool("freshness") {
		token = pkinitFreshness(c, s, &cs, out)
	}
	modes := []string{"dh", "rsa"}
	switch c.Str("mode") {
	case "dh":
		modes = []string{"dh"}
	case "rsa":
		modes = []string{"rsa"}
	}
	for _, m := range modes {
		if m == "rsa" {
			if _, isRSA := cl.signer.Public().(*rsa.PublicKey); !isRSA {
				cs.add("RSA: skipped", "info", "public-key encryption needs an RSA key", "RFC 4556 §3.2.3.2")
				continue
			}
		}
		out[map[string]string{"dh": "diffie_hellman", "rsa": "public_key_encryption"}[m]], _ = pkinitExchange(c, s, cl, m, token, &cs)
	}
	return out, nil
}

func init() {
	var base []Param
	for _, p := range krbParams {
		if p.Name != "password" && p.Name != "keytab" {
			base = append(base, p)
		}
	}
	register(&Op{
		Name:    "krb.pkinit",
		Summary: "Get a TGT with a certificate (PKINIT, RFC 4556): sign the AuthPack with the certificate's key and check the KDC's answer in Diffie-Hellman mode and in public-key encryption (RSA) mode: the KDC's signature, its certificate's chain, purpose and name, the nonce, the reply key binding (asChecksum) and the decrypted AS-REP. Also asks for a freshness token (RFC 8070) first and explains KDC refusals, including Active Directory's certificate mapping rules. With anonymous, runs anonymous PKINIT (RFC 8062) instead and checks the anonymous ticket and the KDC's key exchange (PA_PKINIT_KX).",
		Params: joinParams(base, []Param{
			{Name: "pkinit_cert", Type: "string", Path: true, Desc: "Client certificate (PEM), followed by any intermediates; with pkinit_piv_slot, only intermediates the card does not hold"},
			{Name: "pkinit_key", Type: "string", Path: true, Desc: "The certificate's private key (PEM; RSA or ECDSA)"},
			{Name: "pkinit_piv_slot", Type: "string", Desc: "Use the key and certificate in this PIV slot of a smart card or YubiKey instead (9a, 9c, 9d, 9e, 82-95); the key never leaves the card"},
			{Name: "reader", Type: "string", Desc: "With pkinit_piv_slot: reader name or part of it; default the first reader"},
			{Name: "piv_pin", Type: "string", Secret: true, Desc: "With pkinit_piv_slot: the PIV PIN; else IDPDBG_PIV_PIN or a no-echo prompt. Never tried with fewer than 2 attempts left, and never retried"},
			{Name: "mode", Type: "string", Default: "both", Enum: []string{"both", "dh", "rsa"}, Desc: "Reply key delivery to try: Diffie-Hellman, public-key encryption (RSA keys only), or both"},
			{Name: "dh_group", Type: "int", Default: 14, Desc: "MODP group for Diffie-Hellman: 14 (2048-bit) or 2 (1024-bit)"},
			{Name: "freshness", Type: "bool", Default: true, Desc: "Ask the KDC for a freshness token first (RFC 8070) and sign it into the AuthPack"},
			{Name: "anonymous", Type: "bool", Desc: "Anonymous PKINIT (RFC 8062): get a TGT for WELLKNOWN/ANONYMOUS with no client certificate, only authenticating the KDC (Diffie-Hellman). Needs the realm, not a principal"},
		}),
		Run: runPKINIT,
	})
}
