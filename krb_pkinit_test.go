package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	forkasn1 "github.com/jcmturner/gofork/encoding/asn1"
	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// mockPKINIT is the KDC side of PKINIT for mockKDC: it checks the client's
// signed AuthPack and answers in Diffie-Hellman or RSA mode, signing with a
// KDC certificate. The knobs reproduce what real KDCs do.
type mockPKINIT struct {
	kdcChain        []*x509.Certificate
	kdcKey          crypto.Signer
	clientRoots     *x509.CertPool
	token           []byte // freshness token handed out (RFC 8070)
	echoPKAuthNonce bool   // put the PKAuthenticator nonce in the AS-REP, as Active Directory does
	sawToken        []byte
	anonKX          string // anonymous PKINIT: "" (conforming), "omit" or "wrong" PA_PKINIT_KX
	anonRefuse      bool   // refuse anonymous PKINIT, as a KDC without WELLKNOWN/ANONYMOUS does
}

// unsignedContent returns the content of a SignedData without signers.
func unsignedContent(ci []byte) ([]byte, bool) {
	var outer cmsContentInfo
	if _, err := asn1.Unmarshal(ci, &outer); err != nil {
		return nil, false
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(outer.Content.Bytes, &sd); err != nil || len(sd.SignerInfos) != 0 {
		return nil, false
	}
	var content []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &content); err != nil {
		return nil, false
	}
	return content, true
}

func (k *mockKDC) pkinitAS(req messages.ASReq, raw []byte) []byte {
	pk := k.pk
	tgs := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+k.realm)
	pa, ok := findPA(req.PAData, paPKASReq)
	if !ok {
		if _, fresh := findPA(req.PAData, paASFreshness); fresh {
			edata, _ := asn1.Marshal(types.PADataSequence{{PADataType: paPKASReq, PADataValue: []byte{}}, {PADataType: paASFreshness, PADataValue: pk.token}})
			return k.krbErr(tgs, errorcode.KDC_ERR_PREAUTH_REQUIRED, edata)
		}
		return nil
	}
	var v paPKASReqValue
	if _, err := asn1.Unmarshal(pa.PADataValue, &v); err != nil {
		return k.krbErr(tgs, errorcode.KDC_ERR_PREAUTH_FAILED, nil)
	}
	anon := types.IsFlagSet(&req.ReqBody.KDCOptions, kdcOptRequestAnonymous)
	var signed *cmsVerified
	var content []byte
	if anon {
		if pk.anonRefuse {
			return k.krbErr(tgs, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, nil)
		}
		c, ok := unsignedContent(v.SignedAuthPack)
		if !ok || req.ReqBody.CName.NameType != ntWellknown || req.ReqBody.CName.PrincipalNameString() != "WELLKNOWN/ANONYMOUS" {
			return k.krbErr(tgs, errorcode.KDC_ERR_PREAUTH_FAILED, nil)
		}
		content = c
	} else {
		var err error
		if signed, err = cmsVerify(v.SignedAuthPack); err != nil {
			return k.krbErr(tgs, 64, nil) // KDC_ERR_INVALID_SIG
		}
		inter := x509.NewCertPool()
		for _, c := range signed.Certs[1:] {
			inter.AddCert(c)
		}
		if _, err := signed.Signer.Verify(x509.VerifyOptions{Roots: pk.clientRoots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return k.krbErr(tgs, 62, nil) // KDC_ERR_CLIENT_NOT_TRUSTED
		}
		content = signed.Content
	}
	var ap pkinitAuthPack
	if _, err := asn1.Unmarshal(content, &ap); err != nil {
		return k.krbErr(tgs, errorcode.KDC_ERR_PREAUTH_FAILED, nil)
	}
	body, _ := req.ReqBody.Marshal()
	if sum := sha1.Sum(body); !bytes.Equal(sum[:], ap.PKAuthenticator.PAChecksum) {
		return k.krbErr(tgs, 79, nil) // KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED
	}
	pk.sawToken = ap.PKAuthenticator.FreshnessToken

	var replyKey types.EncryptionKey
	var paRep []byte
	if len(ap.ClientPublicValue.PublicKey.Bytes) > 0 {
		var params dhDomainParameters
		var y *big.Int
		asn1.Unmarshal(ap.ClientPublicValue.Algorithm.Parameters.FullBytes, &params)
		asn1.Unmarshal(ap.ClientPublicValue.PublicKey.Bytes, &y)
		x, _ := rand.Int(rand.Reader, params.Q)
		ky := new(big.Int).Exp(params.G, x, params.P)
		z := new(big.Int).Exp(y, x, params.P).FillBytes(make([]byte, (params.P.BitLen()+7)/8))
		replyKey = types.EncryptionKey{KeyType: 18, KeyValue: octetString2Key(z, 32)}
		info := mustDER(kdcDHKeyInfo{SubjectPublicKey: asn1.BitString{Bytes: mustDER(ky), BitLength: 8 * len(mustDER(ky))}, Nonce: big.NewInt(ap.PKAuthenticator.Nonce)})
		sd, _ := cmsSign(oidPKINITDHKeyData, info, pk.kdcChain, pk.kdcKey)
		paRep = mustDER(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustDER(dhRepInfo{DHSignedData: sd})})
	} else {
		kv := make([]byte, 32)
		rand.Read(kv)
		replyKey = types.EncryptionKey{KeyType: 18, KeyValue: kv}
		et, _ := krbcrypto.GetEtype(18)
		ck, _ := et.GetChecksumHash(kv, raw, usagePKInitASReqCk)
		rk := mustDER(replyKeyPack{ReplyKey: krbEncryptionKeyASN{KeyType: 18, KeyValue: kv}, ASChecksum: krbChecksumASN{CksumType: et.GetHashID(), Checksum: ck}})
		sd, _ := cmsSign(oidPKINITRKeyData, rk, pk.kdcChain, pk.kdcKey)
		env := testEnvelope(sd, signed.Signer)
		paRep = mustDER(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: env})
	}

	now := time.Now().UTC().Truncate(time.Second)
	f := k.ticketFlags(true)
	crealm := k.realm
	padata := []types.PAData{{PADataType: paPKASRep, PADataValue: paRep}}
	if anon {
		types.SetFlag(&f, tktFlagAnonymous)
		crealm = "WELLKNOWN:ANONYMOUS"
	}
	tkt, sess, err := messages.NewTicket(req.ReqBody.CName, crealm, tgs, k.realm, f, k.kt, 18, 1, now, now, now.Add(10*time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		return nil
	}
	if anon { // RFC 8062 §7: the session key mixes in a key the KDC sends
		kv := make([]byte, 32)
		rand.Read(kv)
		kx := types.EncryptionKey{KeyType: 18, KeyValue: kv}
		sess, _ = krbCF2(kx, replyKey, "PKINIT", "KEYEXCHANGE")
		if pk.anonKX == "wrong" {
			rand.Read(kx.KeyValue)
		}
		kb, _ := forkasn1.Marshal(kx)
		ed, _ := krbcrypto.GetEncryptedData(kb, replyKey, usagePKINITKX, 0)
		eb, _ := ed.Marshal()
		if pk.anonKX != "omit" {
			padata = append(padata, types.PAData{PADataType: paPKINITKX, PADataValue: eb})
		}
	}
	nonce := req.ReqBody.Nonce
	if pk.echoPKAuthNonce {
		nonce = int(ap.PKAuthenticator.Nonce)
	}
	enc := messages.EncKDCRepPart{Key: sess, LastReqs: []messages.LastReq{{LRType: 0, LRValue: now}}, Nonce: nonce, Flags: f,
		AuthTime: now, StartTime: now, EndTime: now.Add(10 * time.Hour), RenewTill: now.Add(7 * 24 * time.Hour), SRealm: k.realm, SName: tgs}
	eb, _ := enc.Marshal()
	ed, _ := krbcrypto.GetEncryptedData(eb, replyKey, keyusage.AS_REP_ENCPART, 0)
	rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 11, PAData: padata,
		CRealm: crealm, CName: req.ReqBody.CName, Ticket: tkt, EncPart: ed}}
	rb, _ := rep.Marshal()
	return rb
}

// testEnvelope encrypts content (a ContentInfo, as Windows does) to cert's
// RSA key with AES-256-CBC: the KDC side of public-key encryption mode.
func testEnvelope(content []byte, cert *x509.Certificate) []byte {
	cek, iv := make([]byte, 32), make([]byte, 16)
	rand.Read(cek)
	rand.Read(iv)
	pad := 16 - len(content)%16
	plain := append(append([]byte{}, content...), bytes.Repeat([]byte{byte(pad)}, pad)...)
	block, _ := aes.NewCipher(cek)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plain)
	ek, _ := rsa.EncryptPKCS1v15(rand.Reader, cert.PublicKey.(*rsa.PublicKey), cek)
	ri := mustDER(cmsKeyTransRecipient{Version: 0, RID: asn1.RawValue{FullBytes: mustDER(cmsIssuerAndSerial{Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, Serial: cert.SerialNumber})},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue}, EncryptedKey: ek})
	ed := mustDER(cmsEnvelopedData{Version: 0, RecipientInfos: []asn1.RawValue{{FullBytes: ri}},
		EncryptedContentInfo: cmsEncryptedContentInfo{ContentType: oidCMSSignedData,
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidAES256CBC, Parameters: asn1.RawValue{FullBytes: mustDER(iv)}},
			EncryptedContent:           asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: ct}}})
	return mustDER(cmsContentInfo{ContentType: oidCMSEnvelopedData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: ed}})
}

type testPKI struct {
	caCert            *x509.Certificate
	caKey             crypto.Signer
	caPEM             string
	kdcCert, kdcPlain *x509.Certificate // with and without id-pkinit-KPKdc
	kdcKey            crypto.Signer
	clientCert        *x509.Certificate
	clientKey         *rsa.PrivateKey
	clientPEM, keyPEM string
}

func issueTestCert(t *testing.T, tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func newTestPKI(t *testing.T) *testPKI {
	p := &testPKI{}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.caKey = caKey
	window := func(tmpl *x509.Certificate) *x509.Certificate {
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		return tmpl
	}
	caTmpl := window(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Domain CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign})
	p.caCert = issueTestCert(t, caTmpl, caTmpl, caKey.Public(), caKey)
	p.caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.caCert.Raw}))
	kdcKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p.kdcKey = kdcKey
	p.kdcCert = issueTestCert(t, window(&x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "dc1.idpdbg.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidPKINITKPKdc}, KeyUsage: x509.KeyUsageDigitalSignature}), p.caCert, kdcKey.Public(), caKey)
	p.kdcPlain = issueTestCert(t, window(&x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "dc1.idpdbg.test"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}), p.caCert, kdcKey.Public(), caKey)
	p.clientKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	p.clientCert = issueTestCert(t, window(&x509.Certificate{SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "alice"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}), p.caCert, &p.clientKey.PublicKey, caKey)
	p.clientPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.clientCert.Raw}))
	kb, _ := x509.MarshalPKCS8PrivateKey(p.clientKey)
	p.keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
	return p
}

func TestPKINIT(t *testing.T) {
	pki := newTestPKI(t)
	kdc := newMockKDC(t, "IDPDBG.TEST")
	roots := x509.NewCertPool()
	roots.AddCert(pki.caCert)
	kdc.pk = &mockPKINIT{kdcChain: []*x509.Certificate{pki.kdcCert}, kdcKey: pki.kdcKey, clientRoots: roots, token: []byte("fresh-123")}
	args := func(extra M) M {
		a := M{"principal": "alice@IDPDBG.TEST", "kdc": kdc.addr, "pkinit_cert": pki.clientPEM, "pkinit_key": pki.keyPEM, "ca_cert": pki.caPEM}
		for k, v := range extra {
			a[k] = v
		}
		return a
	}

	t.Run("both modes against a conforming KDC", func(t *testing.T) {
		res := run(t, "krb.pkinit", args(nil), nil)
		noFailures(t, res)
		if dh := res["diffie_hellman"].(M); dh["reply"] != "Diffie-Hellman" || dh["tgt"] == nil {
			t.Errorf("DH: %v", dh)
		}
		if pke := res["public_key_encryption"].(M); pke["reply"] != "public-key encryption" || pke["content_encryption"] != "AES-256-CBC" || pke["tgt"] == nil {
			t.Errorf("RSA: %v", pke)
		}
		wantStatus(t, res, "KDC issues freshness tokens", "pass")
		if string(kdc.pk.sawToken) != "fresh-123" {
			t.Errorf("freshness token not signed into the AuthPack: %q", kdc.pk.sawToken)
		}
		wantStatus(t, res, "RSA: asChecksum binds the reply", "pass")
		wantStatus(t, res, "DH: KDC certificate names the realm's KDC", "pass")
	})

	t.Run("a KDC that returns the PKAuthenticator nonce", func(t *testing.T) {
		kdc.pk.echoPKAuthNonce = true
		defer func() { kdc.pk.echoPKAuthNonce = false }()
		res := run(t, "krb.pkinit", args(M{"mode": "dh"}), nil)
		wantStatus(t, res, "DH: AS-REP nonce matches the request", "warn")
	})

	t.Run("the KDC certificate is checked", func(t *testing.T) {
		res := run(t, "krb.pkinit", args(M{"mode": "dh", "ca_cert": ""}), nil)
		wantStatus(t, res, "DH: KDC certificate chain verifies", "fail")
		kdc.pk.kdcChain = []*x509.Certificate{pki.kdcPlain}
		defer func() { kdc.pk.kdcChain = []*x509.Certificate{pki.kdcCert} }()
		wantStatus(t, run(t, "krb.pkinit", args(M{"mode": "dh"}), nil), "DH: KDC certificate purpose", "warn")
	})

	t.Run("an untrusted client is refused with a reason", func(t *testing.T) {
		kdc.pk.clientRoots = x509.NewCertPool()
		defer func() { kdc.pk.clientRoots = roots }()
		res := run(t, "krb.pkinit", args(M{"mode": "dh"}), nil)
		if c := checkOf(res, "DH: PKINIT accepted"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "KDC_ERR_CLIENT_NOT_TRUSTED") || !strings.Contains(c.Detail, "NTAuth") {
			t.Errorf("refusal: %+v", c)
		}
	})

	t.Run("anonymous PKINIT", func(t *testing.T) {
		anon := M{"realm": "IDPDBG.TEST", "kdc": kdc.addr, "ca_cert": pki.caPEM, "anonymous": true}
		res := run(t, "krb.pkinit", anon, nil)
		noFailures(t, res)
		for _, n := range []string{"PKINIT accepted", "KDC signature on its DH key", "KDC certificate chain verifies", "the ticket names the anonymous client",
			"the ticket is flagged anonymous", "the KDC contributes to the session key", "session key = KRB-FX-CF2"} {
			wantStatus(t, res, "anonymous PKINIT: "+n, "pass")
		}
		if a := res["anonymous"].(M); a["client"] != "WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS" || a["tgt"] == nil {
			t.Errorf("anonymous: %v", a)
		}
		// Only the KDC is authenticated, so its certificate must verify.
		delete(anon, "ca_cert")
		wantStatus(t, run(t, "krb.pkinit", anon, nil), "anonymous PKINIT: KDC certificate chain verifies", "fail")
		anon["ca_cert"] = pki.caPEM
		for knob, check := range map[string]string{"omit": "the KDC contributes to the session key", "wrong": "session key = KRB-FX-CF2"} {
			kdc.pk.anonKX = knob
			wantStatus(t, run(t, "krb.pkinit", anon, nil), "anonymous PKINIT: "+check, "fail")
		}
		kdc.pk.anonKX = ""
		kdc.pk.anonRefuse = true
		defer func() { kdc.pk.anonRefuse = false }()
		if c := checkOf(run(t, "krb.pkinit", anon, nil), "anonymous PKINIT: PKINIT accepted"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "WELLKNOWN/ANONYMOUS principal") {
			t.Errorf("refusal: %+v", c)
		}
	})

	t.Run("key and certificate must belong together", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		kb, _ := x509.MarshalPKCS8PrivateKey(other)
		if _, err := runOp(t.Context(), findOp("krb.pkinit"), args(M{"pkinit_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))}), false, nil); err == nil {
			t.Error("a key for another certificate was accepted")
		}
	})
}

func TestModpGroupsAreSafePrimes(t *testing.T) {
	for group, bits := range map[int]int{2: 1024, 14: 2048} {
		p, err := modpPrime(group)
		if err != nil || p.BitLen() != bits || !p.ProbablyPrime(20) || !new(big.Int).Rsh(p, 1).ProbablyPrime(20) {
			t.Errorf("group %d: not a %d-bit safe prime", group, bits)
		}
	}
	if _, err := modpPrime(5); err == nil {
		t.Error("unknown group accepted")
	}
}

func TestOctetString2Key(t *testing.T) {
	x := []byte("shared secret")
	h0, h1 := sha1.Sum(append([]byte{0}, x...)), sha1.Sum(append([]byte{1}, x...))
	if want := append(h0[:], h1[:]...)[:32]; !bytes.Equal(octetString2Key(x, 32), want) {
		t.Error("octetstring2key does not follow RFC 4556 §3.2.3.1")
	}
	if len(octetString2Key(x, 16)) != 16 {
		t.Error("AES-128 key length")
	}
}

func TestCMSSignVerifyAndDecrypt(t *testing.T) {
	pki := newTestPKI(t)
	sd, err := cmsSign(oidPKINITAuthData, []byte("auth pack"), []*x509.Certificate{pki.clientCert}, pki.clientKey)
	if err != nil {
		t.Fatal(err)
	}
	v, err := cmsVerify(sd)
	if err != nil || string(v.Content) != "auth pack" || v.Signer.SerialNumber.Int64() != 4 || !v.EContentType.Equal(oidPKINITAuthData) {
		t.Fatalf("verify: %v %+v", err, v)
	}
	// Any change to the signer info is caught: signed attributes, signature,
	// and the version and algorithms it names. (The embedded certificate's
	// own signature is the chain check's business, not this one's.)
	start := bytes.Index(sd, pki.clientCert.Raw) + len(pki.clientCert.Raw)
	for i := start; i < len(sd); i++ {
		bad := append([]byte{}, sd...)
		bad[i] ^= 0x01
		if _, err := cmsVerify(bad); err == nil {
			t.Errorf("tampered signer info byte +%d accepted", i-start)
		}
	}
	// So is a change to the content.
	if i := bytes.Index(sd, []byte("auth pack")); i < 0 {
		t.Fatal("content not found")
	} else {
		bad := append([]byte{}, sd...)
		bad[i] ^= 0x01
		if _, err := cmsVerify(bad); err == nil {
			t.Error("tampered content accepted")
		}
	}
	// ECDSA signers too.
	if sd2, err := cmsSign(oidPKINITDHKeyData, []byte("dh"), []*x509.Certificate{pki.kdcCert}, pki.kdcKey); err != nil {
		t.Fatal(err)
	} else if _, err := cmsVerify(sd2); err != nil {
		t.Errorf("ECDSA: %v", err)
	}

	env := testEnvelope(sd, pki.clientCert)
	opened, err := cmsDecrypt(env, pki.clientCert, pki.clientKey)
	if err != nil || !bytes.Equal(opened.Content, sd) || opened.ContentAlg != "AES-256-CBC" || opened.KeyAlg != "RSA (PKCS #1 v1.5)" {
		t.Fatalf("decrypt: %v %+v", err, opened)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := cmsDecrypt(env, pki.clientCert, other); err == nil {
		t.Error("decrypted with the wrong key")
	}
	if _, err := cmsDecrypt(env, pki.kdcCert, pki.clientKey); err == nil {
		t.Error("decrypted for a certificate that is not a recipient")
	}
}

func TestPKINITSANs(t *testing.T) {
	pki := newTestPKI(t)
	kp, _ := forkasn1.Marshal(krb5PrincipalNameSAN{Realm: "IDPDBG.TEST", Name: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/IDPDBG.TEST")})
	upn, _ := asn1.Marshal("alice@idpdbg.test")
	other := func(id asn1.ObjectIdentifier, v []byte) asn1.RawValue {
		b := mustDER(id)
		b = append(b, mustDER(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: v})...)
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: b}
	}
	san := mustDER([]asn1.RawValue{other(oidPKINITSAN, kp), other(oidMSUPN, upn)})
	c := issueTestCert(t, &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "kdc"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Value: san}}}, pki.caCert, pki.kdcKey.Public(), pki.caKey)
	principals, upns := pkinitSANs(c)
	if len(principals) != 1 || principals[0] != "krbtgt/IDPDBG.TEST@IDPDBG.TEST" || len(upns) != 1 || upns[0] != "alice@idpdbg.test" {
		t.Errorf("SANs: %v %v", principals, upns)
	}
}
