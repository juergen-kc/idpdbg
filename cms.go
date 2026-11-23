package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sort"
)

// A minimal CMS (RFC 5652): SignedData with signed attributes, signed with an
// RSA or ECDSA key and verified with the signer's certificate, and the
// recipient side of EnvelopedData with key transport (RSA). This is what
// PKINIT (RFC 4556) needs, and no more.

var (
	oidCMSData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidCMSSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidCMSEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidAttrContentType  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMsgDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAESOAEP       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

var cmsAlgNames = map[string]string{
	oidSHA1.String(): "SHA-1", oidSHA256.String(): "SHA-256", oidSHA384.String(): "SHA-384", oidSHA512.String(): "SHA-512",
	oidRSAEncryption.String(): "RSA (PKCS #1 v1.5)", oidRSAESOAEP.String(): "RSA-OAEP",
	oidSHA1WithRSA.String(): "sha1WithRSAEncryption", oidSHA256WithRSA.String(): "sha256WithRSAEncryption",
	oidSHA384WithRSA.String(): "sha384WithRSAEncryption", oidSHA512WithRSA.String(): "sha512WithRSAEncryption",
	oidECDSAWithSHA256.String(): "ecdsa-with-SHA256", oidECDSAWithSHA384.String(): "ecdsa-with-SHA384", oidECDSAWithSHA512.String(): "ecdsa-with-SHA512",
	oidAES128CBC.String(): "AES-128-CBC", oidAES192CBC.String(): "AES-192-CBC", oidAES256CBC.String(): "AES-256-CBC", oidDESEDE3CBC.String(): "3DES-CBC",
}

func cmsAlgName(o asn1.ObjectIdentifier) string {
	if n, ok := cmsAlgNames[o.String()]; ok {
		return n
	}
	return o.String()
}

type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type cmsEncapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type cmsSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type cmsSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo cmsEncapContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []cmsSignerInfo `asn1:"set"`
}

type cmsIssuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

func mustDER(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// cmsSign wraps content of type eContentType in a SignedData signed by key,
// carrying the certificate chain, as a ContentInfo.
func cmsSign(eContentType asn1.ObjectIdentifier, content []byte, chain []*x509.Certificate, key crypto.Signer) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("no signing certificate")
	}
	digest := sha256.Sum256(content)
	attr := func(t asn1.ObjectIdentifier, value []byte) []byte {
		return mustDER(cmsAttribute{t, asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: value}})
	}
	attrs := [][]byte{attr(oidAttrContentType, mustDER(eContentType)), attr(oidAttrMsgDigest, mustDER(digest[:]))}
	sort.Slice(attrs, func(i, j int) bool { return bytes.Compare(attrs[i], attrs[j]) < 0 }) // DER SET OF order
	setBody := bytes.Join(attrs, nil)
	// The signature covers the attributes as a DER SET OF.
	h := sha256.Sum256(mustDER(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: setBody}))

	var sigAlg pkix.AlgorithmIdentifier
	var sig []byte
	var err error
	switch k := key.Public().(type) {
	case *rsa.PublicKey:
		_ = k
		sigAlg = pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue}
		sig, err = key.Sign(rand.Reader, h[:], crypto.SHA256)
	case *ecdsa.PublicKey:
		sigAlg = pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}
		sig, err = key.Sign(rand.Reader, h[:], crypto.SHA256)
	default:
		return nil, fmt.Errorf("unsupported signing key %T (RSA or ECDSA)", k)
	}
	if err != nil {
		return nil, err
	}
	signer := chain[0]
	sid := mustDER(cmsIssuerAndSerial{Issuer: asn1.RawValue{FullBytes: signer.RawIssuer}, Serial: signer.SerialNumber})
	var certs []byte
	for _, c := range chain {
		certs = append(certs, c.Raw...)
	}
	sd := cmsSignedData{
		Version:          3, // eContentType is not id-data
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: oidSHA256}},
		EncapContentInfo: cmsEncapContentInfo{EContentType: eContentType,
			EContent: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustDER(content)}},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: certs},
		SignerInfos: []cmsSignerInfo{{
			Version:            1,
			SID:                asn1.RawValue{FullBytes: sid},
			DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: oidSHA256},
			SignedAttrs:        asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: setBody},
			SignatureAlgorithm: sigAlg,
			Signature:          sig,
		}},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(cmsContentInfo{ContentType: oidCMSSignedData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER}})
}

// cmsUnsigned wraps content in a SignedData without signers, as anonymous
// PKINIT sends its AuthPack (RFC 8062 §4.1).
func cmsUnsigned(eContentType asn1.ObjectIdentifier, content []byte) ([]byte, error) {
	sd := cmsSignedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{},
		EncapContentInfo: cmsEncapContentInfo{EContentType: eContentType,
			EContent: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustDER(content)}},
		SignerInfos: []cmsSignerInfo{},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(cmsContentInfo{ContentType: oidCMSSignedData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sdDER}})
}

// cmsVerified is a SignedData whose signature checked out against the
// certificate it names. The chain is not judged here.
type cmsVerified struct {
	EContentType asn1.ObjectIdentifier
	Content      []byte
	Signer       *x509.Certificate
	Certs        []*x509.Certificate
	DigestAlg    string
	SignatureAlg string
}

func cmsHash(o asn1.ObjectIdentifier) (crypto.Hash, hash.Hash, error) {
	switch {
	case o.Equal(oidSHA1):
		return crypto.SHA1, sha1.New(), nil
	case o.Equal(oidSHA256):
		return crypto.SHA256, sha256.New(), nil
	case o.Equal(oidSHA384):
		return crypto.SHA384, sha512.New384(), nil
	case o.Equal(oidSHA512):
		return crypto.SHA512, sha512.New(), nil
	}
	return 0, nil, fmt.Errorf("digest algorithm %s not supported", o)
}

// octetContent returns the bytes of an OCTET STRING, joining the pieces of a
// BER constructed one.
func octetContent(r asn1.RawValue) ([]byte, error) {
	if !r.IsCompound {
		return r.Bytes, nil
	}
	var out []byte
	rest := r.Bytes
	for len(rest) > 0 {
		var part asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &part); err != nil {
			return nil, err
		}
		b, err := octetContent(part)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return out, nil
}

// cmsVerify parses a ContentInfo holding SignedData and checks its single
// signer's signature, and with signed attributes the content type and
// message digest.
func cmsVerify(der []byte) (*cmsVerified, error) {
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("not a CMS ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidCMSSignedData) {
		return nil, fmt.Errorf("content type %s, not SignedData", ci.ContentType)
	}
	var sd cmsSignedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("SignedData: %w", err)
	}
	content, err := octetContent(sd.EncapContentInfo.EContent)
	if err != nil || len(content) == 0 {
		return nil, errors.New("SignedData carries no content")
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("SignedData certificates: %w", err)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("%d signers, want 1", len(sd.SignerInfos))
	}
	si := sd.SignerInfos[0]
	var signer *x509.Certificate
	if si.SID.Class == asn1.ClassUniversal {
		var ias cmsIssuerAndSerial
		if _, err := asn1.Unmarshal(si.SID.FullBytes, &ias); err != nil {
			return nil, fmt.Errorf("signer identifier: %w", err)
		}
		for _, c := range certs {
			if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
				signer = c
			}
		}
	} else {
		for _, c := range certs {
			if bytes.Equal(c.SubjectKeyId, si.SID.Bytes) {
				signer = c
			}
		}
	}
	if signer == nil {
		return nil, errors.New("the signer's certificate is not in the SignedData")
	}
	if want := map[bool]int{true: 1, false: 3}[si.SID.Class == asn1.ClassUniversal]; si.Version != want {
		return nil, fmt.Errorf("SignerInfo version %d, want %d for this signer identifier", si.Version, want)
	}
	hashAlg, h, err := cmsHash(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if err := cmsCheckSigAlg(si.SignatureAlgorithm, hashAlg, signer.PublicKey); err != nil {
		return nil, err
	}
	signed := content
	if len(si.SignedAttrs.FullBytes) > 0 {
		var gotType asn1.ObjectIdentifier
		var gotDigest []byte
		rest := si.SignedAttrs.Bytes
		for len(rest) > 0 {
			var a cmsAttribute
			if rest, err = asn1.Unmarshal(rest, &a); err != nil {
				return nil, fmt.Errorf("signed attributes: %w", err)
			}
			switch {
			case a.Type.Equal(oidAttrContentType):
				_, err = asn1.Unmarshal(a.Values.Bytes, &gotType)
			case a.Type.Equal(oidAttrMsgDigest):
				_, err = asn1.Unmarshal(a.Values.Bytes, &gotDigest)
			}
			if err != nil {
				return nil, fmt.Errorf("signed attribute %s: %w", a.Type, err)
			}
		}
		h.Write(content)
		if !bytes.Equal(h.Sum(nil), gotDigest) {
			return nil, errors.New("message digest attribute does not match the content")
		}
		if !gotType.Equal(sd.EncapContentInfo.EContentType) {
			return nil, errors.New("content type attribute does not match the content")
		}
		signed = append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...) // signed as a SET OF
		h.Reset()
	}
	h.Write(signed)
	sum := h.Sum(nil)
	switch pub := signer.PublicKey.(type) {
	case *rsa.PublicKey:
		err = rsa.VerifyPKCS1v15(pub, hashAlg, sum, si.Signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, sum, si.Signature) {
			err = errors.New("ECDSA signature does not verify")
		}
	default:
		err = fmt.Errorf("signer key %T not supported", pub)
	}
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	return &cmsVerified{EContentType: sd.EncapContentInfo.EContentType, Content: content, Signer: signer, Certs: certs,
		DigestAlg: cmsAlgName(si.DigestAlgorithm.Algorithm), SignatureAlg: cmsAlgName(si.SignatureAlgorithm.Algorithm)}, nil
}

var oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// cmsCheckSigAlg makes sure the signature algorithm a SignerInfo names fits
// the signer's key and the digest algorithm.
func cmsCheckSigAlg(ai pkix.AlgorithmIdentifier, digest crypto.Hash, pub crypto.PublicKey) error {
	alg, params := ai.Algorithm, ai.Parameters
	absentOrNull := len(params.FullBytes) == 0 || (params.Class == asn1.ClassUniversal && params.Tag == asn1.TagNull && len(params.Bytes) == 0)
	rsaAlgs := map[string]crypto.Hash{oidSHA1WithRSA.String(): crypto.SHA1, oidSHA256WithRSA.String(): crypto.SHA256,
		oidSHA384WithRSA.String(): crypto.SHA384, oidSHA512WithRSA.String(): crypto.SHA512}
	ecAlgs := map[string]crypto.Hash{oidECDSAWithSHA256.String(): crypto.SHA256, oidECDSAWithSHA384.String(): crypto.SHA384, oidECDSAWithSHA512.String(): crypto.SHA512}
	var h crypto.Hash
	var known bool
	switch pub.(type) {
	case *rsa.PublicKey:
		if !absentOrNull {
			return fmt.Errorf("signature algorithm %s has parameters it should not have", cmsAlgName(alg))
		}
		if alg.Equal(oidRSAEncryption) {
			return nil // the digest algorithm alone says which hash
		}
		h, known = rsaAlgs[alg.String()]
	case *ecdsa.PublicKey:
		if alg.Equal(oidECPublicKey) {
			return nil
		}
		if len(params.FullBytes) != 0 {
			return fmt.Errorf("signature algorithm %s must have no parameters", cmsAlgName(alg))
		}
		h, known = ecAlgs[alg.String()]
	}
	if !known {
		return fmt.Errorf("signature algorithm %s does not fit a %T", cmsAlgName(alg), pub)
	}
	if h != digest {
		return fmt.Errorf("signature algorithm %s disagrees with the digest algorithm", cmsAlgName(alg))
	}
	return nil
}

type cmsEncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
}

type cmsEnvelopedData struct {
	Version              int
	OriginatorInfo       asn1.RawValue   `asn1:"optional,tag:0"`
	RecipientInfos       []asn1.RawValue `asn1:"set"`
	EncryptedContentInfo cmsEncryptedContentInfo
	UnprotectedAttrs     asn1.RawValue `asn1:"optional,tag:1"`
}

type cmsKeyTransRecipient struct {
	Version                int
	RID                    asn1.RawValue
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// cmsOpened is a decrypted EnvelopedData.
type cmsOpened struct {
	Content       []byte
	ContentType   asn1.ObjectIdentifier
	KeyAlg        string
	ContentAlg    string
	RecipientInfo int
}

// cmsDecrypt opens a ContentInfo holding EnvelopedData addressed to cert
// with an RSA key transport recipient.
func cmsDecrypt(der []byte, cert *x509.Certificate, key crypto.Decrypter) (*cmsOpened, error) {
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("not a CMS ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidCMSEnvelopedData) {
		return nil, fmt.Errorf("content type %s, not EnvelopedData", ci.ContentType)
	}
	var ed cmsEnvelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, fmt.Errorf("EnvelopedData: %w", err)
	}
	var cek []byte
	var keyAlg string
	for _, ri := range ed.RecipientInfos {
		if ri.Class != asn1.ClassUniversal || ri.Tag != asn1.TagSequence {
			continue // not key transport
		}
		var kt cmsKeyTransRecipient
		if _, err := asn1.Unmarshal(ri.FullBytes, &kt); err != nil {
			continue
		}
		mine := false
		if kt.RID.Class == asn1.ClassUniversal {
			var ias cmsIssuerAndSerial
			if _, err := asn1.Unmarshal(kt.RID.FullBytes, &ias); err == nil {
				mine = bytes.Equal(ias.Issuer.FullBytes, cert.RawIssuer) && ias.Serial.Cmp(cert.SerialNumber) == 0
			}
		} else {
			mine = bytes.Equal(kt.RID.Bytes, cert.SubjectKeyId)
		}
		if !mine {
			continue
		}
		keyAlg = cmsAlgName(kt.KeyEncryptionAlgorithm.Algorithm)
		var err error
		switch {
		case kt.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAEncryption):
			cek, err = key.Decrypt(rand.Reader, kt.EncryptedKey, &rsa.PKCS1v15DecryptOptions{})
		case kt.KeyEncryptionAlgorithm.Algorithm.Equal(oidRSAESOAEP):
			// Default parameters (SHA-1, MGF1 with SHA-1) are the common case.
			cek, err = key.Decrypt(rand.Reader, kt.EncryptedKey, &rsa.OAEPOptions{Hash: crypto.SHA1})
		default:
			err = fmt.Errorf("key encryption %s not supported", keyAlg)
		}
		if err != nil {
			return nil, fmt.Errorf("content key: %w", err)
		}
		break
	}
	if cek == nil {
		return nil, errors.New("no key transport recipient for this certificate")
	}
	eci := ed.EncryptedContentInfo
	enc, err := octetContent(eci.EncryptedContent)
	if err != nil {
		return nil, err
	}
	var iv []byte
	if _, err := asn1.Unmarshal(eci.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("content encryption IV: %w", err)
	}
	var block cipher.Block
	alg := eci.ContentEncryptionAlgorithm.Algorithm
	switch {
	case alg.Equal(oidAES128CBC), alg.Equal(oidAES192CBC), alg.Equal(oidAES256CBC):
		block, err = aes.NewCipher(cek)
	case alg.Equal(oidDESEDE3CBC):
		block, err = des.NewTripleDESCipher(cek)
	default:
		err = fmt.Errorf("content encryption %s not supported", alg)
	}
	if err != nil {
		return nil, err
	}
	if len(iv) != block.BlockSize() || len(enc) == 0 || len(enc)%block.BlockSize() != 0 {
		return nil, errors.New("encrypted content has the wrong length")
	}
	plain := make([]byte, len(enc))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, enc)
	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > block.BlockSize() || !bytes.Equal(plain[len(plain)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errors.New("bad padding: wrong content key")
	}
	return &cmsOpened{Content: plain[:len(plain)-pad], ContentType: eci.ContentType, KeyAlg: keyAlg, ContentAlg: cmsAlgName(alg)}, nil
}
