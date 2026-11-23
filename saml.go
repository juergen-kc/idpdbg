package main

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

const (
	nsSAMLP        = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsSAML         = "urn:oasis:names:tc:SAML:2.0:assertion"
	bindRedirect   = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	bindPOST       = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	samlStatusOK   = "urn:oasis:names:tc:SAML:2.0:status:Success"
	samlTimeLayout = "2006-01-02T15:04:05Z"
	samlCore       = "SAML Core"
	samlProfiles   = "SAML Profiles §4.1.4.2"
)

// ---- namespace-agnostic XML helpers ----

func kids(el *etree.Element, local string) []*etree.Element {
	var out []*etree.Element
	if el == nil {
		return out
	}
	for _, ch := range el.ChildElements() {
		if ch.Tag == local {
			out = append(out, ch)
		}
	}
	return out
}

func kid(el *etree.Element, path ...string) *etree.Element {
	for _, p := range path {
		k := kids(el, p)
		if len(k) == 0 {
			return nil
		}
		el = k[0]
	}
	return el
}

// It joins all of the element's character data, skipping comments, which is
// what a signature over the canonical form covers. etree's Text() stops at
// the first comment: a NameID "admin@example.com<!---->.evil.com" would read
// as admin@example.com while the signed value is admin@example.com.evil.com
// (the CVE-2017-11427 class of attack).
func text(el *etree.Element) string {
	if el == nil {
		return ""
	}
	var b strings.Builder
	for _, t := range el.Child {
		if cd, ok := t.(*etree.CharData); ok {
			b.WriteString(cd.Data)
		}
	}
	return strings.TrimSpace(b.String())
}

// hasComment reports whether an element holds an XML comment among its
// text, where a careless parser reads a truncated value.
func hasComment(el *etree.Element) bool {
	if el == nil {
		return false
	}
	for _, t := range el.Child {
		if _, ok := t.(*etree.Comment); ok {
			return true
		}
	}
	return false
}

func findAll(el *etree.Element, local string, out *[]*etree.Element) {
	for _, ch := range el.ChildElements() {
		if ch.Tag == local {
			*out = append(*out, ch)
		}
		findAll(ch, local, out)
	}
}

func prettyXML(el *etree.Element) string {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	doc.Indent(2)
	s, _ := doc.WriteToString()
	return s
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// ---- inputs ----

func isXML(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "<") }

func parseCertB64(s string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

type idpMeta struct {
	EntityID    string
	SSO         map[string]string // binding -> location
	SLO         map[string]string
	ARS         map[int]string // ArtifactResolutionService index -> location
	NameIDs     []string
	Certs       []*x509.Certificate
	WantsSigned bool
	Root        *etree.Element
}

// loadIDPMetadata accepts a URL, inline XML or a file path.
func loadIDPMetadata(c *Ctx, src string) (*idpMeta, error) {
	var b []byte
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		res, err := c.do("GET", src, map[string]string{"Accept": "application/samlmetadata+xml, application/xml, text/xml"}, nil)
		if err != nil {
			return nil, err
		}
		if res.Status != 200 {
			return nil, fmt.Errorf("metadata %s returned HTTP %d", src, res.Status)
		}
		b = res.Body
	} else {
		var err error
		if b, err = inlineContent(src, isXML); err != nil {
			return nil, err
		}
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b); err != nil || doc.Root() == nil {
		return nil, fmt.Errorf("metadata is not XML: %v", err)
	}
	var descs []*etree.Element
	if doc.Root().Tag == "EntityDescriptor" {
		descs = []*etree.Element{doc.Root()}
	}
	findAll(doc.Root(), "EntityDescriptor", &descs)
	for _, ed := range descs {
		idp := kid(ed, "IDPSSODescriptor")
		if idp == nil {
			continue
		}
		m := &idpMeta{EntityID: ed.SelectAttrValue("entityID", ""), SSO: map[string]string{}, SLO: map[string]string{}, ARS: map[int]string{}, Root: ed,
			WantsSigned: idp.SelectAttrValue("WantAuthnRequestsSigned", "false") == "true"}
		for _, s := range kids(idp, "SingleSignOnService") {
			m.SSO[s.SelectAttrValue("Binding", "")] = s.SelectAttrValue("Location", "")
		}
		for _, s := range kids(idp, "SingleLogoutService") {
			m.SLO[s.SelectAttrValue("Binding", "")] = s.SelectAttrValue("Location", "")
		}
		for _, s := range kids(idp, "ArtifactResolutionService") {
			if i, err := strconv.Atoi(s.SelectAttrValue("index", "")); err == nil && s.SelectAttrValue("Binding", "") == bindSOAP {
				m.ARS[i] = s.SelectAttrValue("Location", "")
			}
		}
		for _, n := range kids(idp, "NameIDFormat") {
			m.NameIDs = append(m.NameIDs, text(n))
		}
		for _, kd := range kids(idp, "KeyDescriptor") {
			if use := kd.SelectAttrValue("use", "signing"); use != "signing" {
				continue
			}
			var certEls []*etree.Element
			findAll(kd, "X509Certificate", &certEls)
			for _, ce := range certEls {
				if cert, err := parseCertB64(text(ce)); err == nil {
					m.Certs = append(m.Certs, cert)
				}
			}
		}
		return m, nil
	}
	return nil, errors.New("no EntityDescriptor with an IDPSSODescriptor found in the metadata")
}

func loadRSAKey(s string) (*rsa.PrivateKey, error) {
	b, err := inlineContent(s, isPEM)
	if err != nil {
		return nil, err
	}
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, errors.New("no RSA private key found in the PEM")
		}
		if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
			if rk, ok := k.(*rsa.PrivateKey); ok {
				return rk, nil
			}
		}
	}
}

func loadCerts(s string) ([]*x509.Certificate, error) {
	b, err := inlineContent(s, isPEM)
	if err != nil {
		return nil, err
	}
	certs := parsePEMCerts(b)
	if len(certs) == 0 {
		return nil, errors.New("no certificate found in the PEM")
	}
	return certs, nil
}

// decodeSAMLInput accepts raw XML, base64 (POST binding), deflate+base64
// (Redirect binding), URL-encoded forms of those, or a whole redirect URL.
func decodeSAMLInput(s string) ([]byte, string, error) {
	s = strings.TrimSpace(s)
	if isXML(s) {
		return []byte(s), "raw XML", nil
	}
	if i := strings.Index(s, "?"); i >= 0 && strings.Contains(s, "SAML") {
		s = s[i+1:]
	}
	if strings.Contains(s, "SAMLRequest=") || strings.Contains(s, "SAMLResponse=") {
		q, err := url.ParseQuery(s)
		if err != nil {
			return nil, "", err
		}
		if s = q.Get("SAMLResponse"); s == "" {
			s = q.Get("SAMLRequest")
		}
	} else if strings.Contains(s, "%") {
		if u, err := url.QueryUnescape(s); err == nil {
			s = u
		}
	}
	s = strings.Join(strings.Fields(s), "")
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err != nil {
			return nil, "", fmt.Errorf("input is neither XML nor base64: %w", err)
		}
	}
	if isXML(string(raw)) {
		return raw, "base64 (HTTP-POST binding)", nil
	}
	inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 16<<20))
	if err != nil || !isXML(string(inflated)) {
		return nil, "", errors.New("base64 decoded, but the content is neither XML nor DEFLATE-compressed XML")
	}
	return inflated, "DEFLATE + base64 (HTTP-Redirect binding)", nil
}

// ---- signatures and encryption ----

// checkSignature validates the enveloped signature directly under el.
func checkSignature(cs *Checks, what string, el *etree.Element, trusted []*x509.Certificate) (signed, valid bool) {
	return checkSignatureID(cs, what, el, trusted, "ID")
}

// checkSignatureID is checkSignature for elements whose identifier attribute
// is not ID (SAML 1.1 assertions use AssertionID).
func checkSignatureID(cs *Checks, what string, el *etree.Element, trusted []*x509.Certificate, idAttr string) (signed, valid bool) {
	const ref = "SAML Core §5.4"
	sig := kid(el, "Signature")
	if sig == nil {
		return false, false
	}
	name := what + ": signature"
	var embedded *x509.Certificate
	if ce := kid(sig, "KeyInfo", "X509Data", "X509Certificate"); ce != nil {
		embedded, _ = parseCertB64(text(ce))
	}
	roots, trustKnown := trusted, len(trusted) > 0
	if !trustKnown {
		if embedded == nil {
			cs.add(name, "warn", "signed, but there is no embedded certificate and no IdP certificate was supplied, so it cannot be verified", ref)
			return true, false
		}
		roots = []*x509.Certificate{embedded}
	}
	nsCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		cs.add(name, "fail", err.Error(), ref)
		return true, false
	}
	detached, err := etreeutils.NSDetatch(nsCtx, el)
	if err != nil {
		cs.add(name, "fail", err.Error(), ref)
		return true, false
	}
	// A signature without KeyInfo names no certificate; goxmldsig then needs
	// exactly one candidate, so during key rollover try each trusted one.
	candidates := [][]*x509.Certificate{roots}
	if embedded == nil && len(roots) > 1 {
		candidates = nil
		for _, r := range roots {
			candidates = append(candidates, []*x509.Certificate{r})
		}
	}
	var signer *x509.Certificate
	for _, cand := range candidates {
		s := embedded
		if s == nil {
			s = cand[0]
		}
		vctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: cand})
		vctx.IdAttribute = idAttr
		// Certificate validity is reported as its own check, so judge the
		// signature at an instant when the certificate was valid.
		vctx.Clock = dsig.NewFakeClockAt(s.NotBefore.Add(time.Second))
		if _, err = vctx.Validate(detached); err == nil {
			signer = s
			break
		}
	}
	if signer == nil {
		detail := err.Error()
		if embedded != nil && trustKnown {
			detail += " (signing certificate sha256 " + fingerprint(embedded) + ")"
		}
		cs.add(name, "fail", detail, ref)
		return true, false
	}
	method := ""
	if sm := kid(sig, "SignedInfo", "SignatureMethod"); sm != nil {
		method = sm.SelectAttrValue("Algorithm", "")
	}
	if trustKnown {
		cs.add(name, "pass", "valid, signed by the trusted IdP certificate "+signer.Subject.String()+" using "+method, ref)
	} else {
		cs.add(name, "warn", "cryptographically valid against the certificate embedded in the message, but trust is not established: pass idp_metadata or idp_cert", ref)
	}
	if strings.HasSuffix(method, "rsa-sha1") || strings.HasSuffix(method, "dsa-sha1") {
		cs.add(what+": signature algorithm", "warn", "SHA-1 based signature ("+method+")", "SAML Security Considerations")
	}
	now := time.Now()
	cs.warn(now.After(signer.NotBefore) && now.Before(signer.NotAfter), what+": signing certificate within its validity period",
		"not after "+signer.NotAfter.UTC().Format(time.RFC3339)+" ("+relTime(signer.NotAfter)+")", "")
	return true, trustKnown
}

// decryptAssertion decrypts a SAML EncryptedAssertion, or a bare
// xenc:EncryptedData as WS-* security token services send it.
func decryptAssertion(enc *etree.Element, key *rsa.PrivateKey) (*etree.Element, error) {
	data := enc
	if enc.Tag != "EncryptedData" {
		if data = kid(enc, "EncryptedData"); data == nil {
			return nil, errors.New("EncryptedAssertion has no EncryptedData")
		}
	}
	var encKeys []*etree.Element
	findAll(enc, "EncryptedKey", &encKeys)
	if len(encKeys) == 0 {
		return nil, errors.New("no EncryptedKey found")
	}
	cipherValue := func(el *etree.Element) ([]byte, error) {
		return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text(kid(el, "CipherData", "CipherValue"))), ""))
	}
	// An IdP may encrypt the key once per SP encryption certificate (key
	// rollover): use the first EncryptedKey this private key can unwrap.
	var cek []byte
	var err error
	for _, ek := range encKeys {
		if cek, err = unwrapEncryptedKey(ek, key, cipherValue); err == nil {
			break
		}
	}
	if err != nil {
		var to []string
		for _, ek := range encKeys {
			if r := encryptedKeyRecipient(ek); r != "" {
				to = append(to, r)
			}
		}
		if len(to) > 0 {
			err = fmt.Errorf("%w; the key was encrypted for %s", err, strings.Join(to, ", "))
		}
		if len(encKeys) > 1 {
			return nil, fmt.Errorf("none of the %d EncryptedKey elements unwraps with the private key; last error: %w", len(encKeys), err)
		}
		return nil, err
	}
	ct, err := cipherValue(data)
	if err != nil {
		return nil, fmt.Errorf("EncryptedData CipherValue: %w", err)
	}
	return decryptContent(data, cek, ct)
}

// encryptedKeyRecipient says which certificate an EncryptedKey names in
// its KeyInfo (a certificate, its SHA-1 thumbprint, or issuer and serial),
// so a wrong decryption key can be told from a broken token.
func encryptedKeyRecipient(ek *etree.Element) string {
	ki := kid(ek, "KeyInfo")
	if ki == nil {
		return ""
	}
	var els []*etree.Element
	findAll(ki, "X509Certificate", &els)
	for _, e := range els {
		if der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(text(e)), "")); err == nil {
			if c, err := x509.ParseCertificate(der); err == nil {
				return fmt.Sprintf("the certificate %s (SHA-1 %X)", c.Subject, sha1.Sum(c.Raw))
			}
		}
	}
	els = nil
	findAll(ki, "KeyIdentifier", &els)
	for _, e := range els {
		if strings.HasSuffix(e.SelectAttrValue("ValueType", ""), "ThumbprintSHA1") {
			if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text(e))); err == nil {
				return fmt.Sprintf("the certificate with SHA-1 thumbprint %X", b)
			}
		}
	}
	els = nil
	findAll(ki, "X509IssuerSerial", &els)
	for _, e := range els {
		return fmt.Sprintf("the certificate issued by %s with serial %s", text(kid(e, "X509IssuerName")), text(kid(e, "X509SerialNumber")))
	}
	return ""
}

func unwrapEncryptedKey(ek *etree.Element, key *rsa.PrivateKey, cipherValue func(*etree.Element) ([]byte, error)) ([]byte, error) {
	wrapped, err := cipherValue(ek)
	if err != nil {
		return nil, fmt.Errorf("EncryptedKey CipherValue: %w", err)
	}
	em := kid(ek, "EncryptionMethod")
	keyAlg := ""
	if em != nil {
		keyAlg = em.SelectAttrValue("Algorithm", "")
	}
	var cek []byte
	switch {
	case strings.HasSuffix(keyAlg, "rsa-1_5"):
		cek, err = rsa.DecryptPKCS1v15(rand.Reader, key, wrapped)
	case strings.Contains(keyAlg, "rsa-oaep"):
		opts := &rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1}
		pick := func(alg string) crypto.Hash {
			switch {
			case strings.HasSuffix(alg, "sha256"):
				return crypto.SHA256
			case strings.HasSuffix(alg, "sha384"):
				return crypto.SHA384
			case strings.HasSuffix(alg, "sha512"):
				return crypto.SHA512
			}
			return crypto.SHA1
		}
		if dm := kid(em, "DigestMethod"); dm != nil {
			opts.Hash = pick(dm.SelectAttrValue("Algorithm", ""))
		}
		if mgf := kid(em, "MGF"); mgf != nil {
			opts.MGFHash = pick(mgf.SelectAttrValue("Algorithm", ""))
		}
		cek, err = key.Decrypt(rand.Reader, wrapped, opts)
	default:
		return nil, fmt.Errorf("unsupported key transport algorithm %q", keyAlg)
	}
	if err != nil {
		return nil, fmt.Errorf("could not unwrap the content key with the SP private key (%s): %w", keyAlg, err)
	}
	return cek, nil
}

func decryptContent(data *etree.Element, cek, ct []byte) (*etree.Element, error) {
	dataAlg := ""
	if m := kid(data, "EncryptionMethod"); m != nil {
		dataAlg = m.SelectAttrValue("Algorithm", "")
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	var plain []byte
	switch {
	case strings.HasSuffix(dataAlg, "-cbc"):
		if len(ct) < 2*aes.BlockSize || len(ct)%aes.BlockSize != 0 {
			return nil, errors.New("ciphertext has the wrong length for AES-CBC")
		}
		plain = make([]byte, len(ct)-aes.BlockSize)
		cipher.NewCBCDecrypter(block, ct[:aes.BlockSize]).CryptBlocks(plain, ct[aes.BlockSize:])
		pad := int(plain[len(plain)-1])
		if pad < 1 || pad > aes.BlockSize {
			return nil, errors.New("bad padding after decryption (wrong key?)")
		}
		plain = plain[:len(plain)-pad]
	case strings.HasSuffix(dataAlg, "-gcm"):
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		if len(ct) < gcm.NonceSize() {
			return nil, errors.New("ciphertext too short for AES-GCM")
		}
		if plain, err = gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], nil); err != nil {
			return nil, fmt.Errorf("AES-GCM authentication failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported data encryption algorithm %q", dataAlg)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plain); err != nil || doc.Root() == nil {
		return nil, fmt.Errorf("decrypted content is not XML: %v", err)
	}
	return doc.Root(), nil
}

// ---- analysis ----

type samlExpect struct {
	Trusted      []*x509.Certificate
	SPKey        *rsa.PrivateKey
	Audience     string
	ACS          string
	InResponseTo string
	Leeway       time.Duration
	KeyWithheld  string // why SPKey is not used, when it is withheld
}

func samlTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

func describeAssertion(cs *Checks, a *etree.Element, ex *samlExpect) M {
	out := M{"id": a.SelectAttrValue("ID", ""), "issuer": text(kid(a, "Issuer")), "issue_instant": a.SelectAttrValue("IssueInstant", "")}
	now := time.Now()
	if nid := kid(a, "Subject", "NameID"); nid != nil {
		out["name_id"] = M{"value": text(nid), "format": nid.SelectAttrValue("Format", ""), "sp_name_qualifier": nid.SelectAttrValue("SPNameQualifier", "")}
		if hasComment(nid) {
			cs.add("NameID free of XML comments", "warn", "the NameID contains a comment; idpdbg reads it whole ("+text(nid)+"), but service providers that stop at the comment read a different identity", "CVE-2017-11427")
		}
	} else if kid(a, "Subject", "EncryptedID") != nil {
		out["name_id"] = "EncryptedID (not decrypted)"
	}
	bearer := false
	for _, sc := range kids(kid(a, "Subject"), "SubjectConfirmation") {
		if sc.SelectAttrValue("Method", "") != "urn:oasis:names:tc:SAML:2.0:cm:bearer" {
			continue
		}
		bearer = true
		d := kid(sc, "SubjectConfirmationData")
		if d == nil {
			cs.add("assertion: SubjectConfirmationData present", "fail", "bearer confirmation without data", samlProfiles)
			continue
		}
		out["subject_confirmation"] = M{"recipient": d.SelectAttrValue("Recipient", ""), "not_on_or_after": d.SelectAttrValue("NotOnOrAfter", ""), "in_response_to": d.SelectAttrValue("InResponseTo", "")}
		if t, ok := samlTime(d.SelectAttrValue("NotOnOrAfter", "")); ok {
			cs.ok(now.Before(t.Add(ex.Leeway)), "assertion: SubjectConfirmation not expired", "NotOnOrAfter "+t.Format(time.RFC3339)+" ("+relTime(t)+")", samlProfiles)
		} else {
			cs.add("assertion: SubjectConfirmationData NotOnOrAfter present", "fail", "", samlProfiles)
		}
		if ex.ACS != "" {
			cs.ok(d.SelectAttrValue("Recipient", "") == ex.ACS, "assertion: Recipient is the ACS URL", "Recipient="+d.SelectAttrValue("Recipient", ""), samlProfiles)
		}
		if ex.InResponseTo != "" {
			cs.ok(d.SelectAttrValue("InResponseTo", "") == ex.InResponseTo, "assertion: InResponseTo matches the request", "InResponseTo="+d.SelectAttrValue("InResponseTo", ""), samlProfiles)
		}
	}
	if kid(a, "Subject") != nil && !bearer {
		cs.add("assertion: bearer SubjectConfirmation present", "warn", "no bearer confirmation; Web Browser SSO requires one", samlProfiles)
	}
	if cond := kid(a, "Conditions"); cond != nil {
		var auds []string
		for _, ar := range kids(cond, "AudienceRestriction") {
			for _, au := range kids(ar, "Audience") {
				auds = append(auds, text(au))
			}
		}
		out["conditions"] = M{"not_before": cond.SelectAttrValue("NotBefore", ""), "not_on_or_after": cond.SelectAttrValue("NotOnOrAfter", ""), "audiences": auds}
		if t, ok := samlTime(cond.SelectAttrValue("NotBefore", "")); ok {
			cs.ok(!now.Add(ex.Leeway).Before(t), "assertion: Conditions NotBefore reached", "NotBefore "+t.Format(time.RFC3339), "SAML Core §2.5.1")
		}
		if t, ok := samlTime(cond.SelectAttrValue("NotOnOrAfter", "")); ok {
			cs.ok(now.Before(t.Add(ex.Leeway)), "assertion: Conditions not expired", "NotOnOrAfter "+t.Format(time.RFC3339)+" ("+relTime(t)+")", "SAML Core §2.5.1")
		}
		if ex.Audience != "" {
			cs.ok(contains(auds, ex.Audience), "assertion: audience includes the SP entity ID", "audiences="+strings.Join(auds, " "), "SAML Core §2.5.1.4")
		} else if len(auds) == 0 {
			cs.add("assertion: AudienceRestriction present", "warn", "no audience restriction", samlProfiles)
		}
	}
	if as := kid(a, "AuthnStatement"); as != nil {
		out["authn_statement"] = M{"authn_instant": as.SelectAttrValue("AuthnInstant", ""), "session_index": as.SelectAttrValue("SessionIndex", ""),
			"session_not_on_or_after": as.SelectAttrValue("SessionNotOnOrAfter", ""), "authn_context_class_ref": text(kid(as, "AuthnContext", "AuthnContextClassRef"))}
	}
	attrs := M{}
	for _, st := range kids(a, "AttributeStatement") {
		for _, at := range kids(st, "Attribute") {
			vals := []string{}
			for _, v := range kids(at, "AttributeValue") {
				vals = append(vals, text(v))
			}
			attrs[at.SelectAttrValue("Name", "")] = vals
		}
	}
	if len(attrs) > 0 {
		out["attributes"] = attrs
	}
	return out
}

func analyzeSAML(xmlBytes []byte, ex *samlExpect) (M, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(xmlBytes); err != nil || doc.Root() == nil {
		return nil, fmt.Errorf("not well-formed XML: %v", err)
	}
	root := doc.Root()
	var cs Checks
	out := M{"message_type": root.Tag, "xml": prettyXML(root)}
	attrs := M{}
	for _, a := range root.Attr {
		if a.Space != "xmlns" && a.Key != "xmlns" {
			attrs[a.Key] = a.Value
		}
	}
	out["attributes"] = attrs
	if iss := kid(root, "Issuer"); iss != nil {
		out["issuer"] = text(iss)
	}
	defer func() { out["checks"] = cs }()

	switch root.Tag {
	case "Response":
		code := kid(root, "Status", "StatusCode")
		status := M{}
		if code != nil {
			status["code"] = code.SelectAttrValue("Value", "")
			if sub := kid(code, "StatusCode"); sub != nil {
				status["sub_code"] = sub.SelectAttrValue("Value", "")
			}
		}
		if m := text(kid(root, "Status", "StatusMessage")); m != "" {
			status["message"] = m
		}
		out["status"] = status
		detail := fmt.Sprint(status["code"])
		if status["sub_code"] != nil {
			detail += " / " + fmt.Sprint(status["sub_code"])
		}
		if status["message"] != nil {
			detail += ": " + fmt.Sprint(status["message"])
		}
		cs.ok(status["code"] == samlStatusOK, "response: status is Success", detail, "SAML Core §3.2.2.2")
		cs.ok(root.SelectAttrValue("Version", "") == "2.0", "response: Version is 2.0", "", "SAML Core §3.2.2")
		if ex.ACS != "" {
			cs.ok(root.SelectAttrValue("Destination", "") == ex.ACS, "response: Destination is the ACS URL", "Destination="+root.SelectAttrValue("Destination", ""), "SAML Bindings §3.5.5.2")
		}
		if ex.InResponseTo != "" {
			cs.ok(root.SelectAttrValue("InResponseTo", "") == ex.InResponseTo, "response: InResponseTo matches the request", "InResponseTo="+root.SelectAttrValue("InResponseTo", ""), samlProfiles)
		}
		respSigned, respValid := checkSignature(&cs, "response", root, ex.Trusted)
		assertions := kids(root, "Assertion")
		decrypted := map[*etree.Element]bool{} // came from an EncryptedAssertion child of the Response
		for _, enc := range kids(root, "EncryptedAssertion") {
			encryptionAlgChecks(&cs, enc)
			if ex.SPKey == nil {
				why := "the assertion is encrypted; pass sp_key to decrypt it"
				if ex.KeyWithheld != "" {
					why = ex.KeyWithheld
				}
				cs.add("assertion: decryption", "warn", why, "SAML Core §2.3.4")
				continue
			}
			a, err := decryptAssertion(enc, ex.SPKey)
			if err != nil {
				cs.add("assertion: decryption", "fail", err.Error(), "SAML Core §2.3.4")
				continue
			}
			cs.add("assertion: decryption", "pass", "decrypted with the SP private key", "SAML Core §2.3.4")
			out["decrypted_assertion_xml"] = prettyXML(a)
			assertions = append(assertions, a)
			decrypted[a] = true
		}
		anySigned, allCovered := respSigned, len(assertions) > 0
		list := []M{}
		for _, a := range assertions {
			aSigned, aValid := checkSignature(&cs, "assertion", a, ex.Trusted)
			anySigned = anySigned || aSigned
			if !(aValid || (respValid && (a.Parent() == root || decrypted[a]))) {
				allCovered = false
			}
			list = append(list, describeAssertion(&cs, a, ex))
		}
		out["assertions"] = list
		if status["code"] == samlStatusOK {
			cs.ok(len(assertions) > 0 || len(kids(root, "EncryptedAssertion")) > 0, "response: contains an assertion", "", samlProfiles)
			if !anySigned {
				cs.add("response or assertion is signed", "fail", "neither the Response nor any Assertion carries a signature", "SAML Profiles §4.1.3.5")
			} else if len(ex.Trusted) > 0 {
				cs.ok(allCovered, "every assertion is covered by a trusted signature", "", "SAML Profiles §4.1.3.5")
			}
		}
	case "Assertion":
		if signed, _ := checkSignature(&cs, "assertion", root, ex.Trusted); !signed {
			cs.add("assertion: signed", "fail", "a bare assertion without a signature proves nothing", "SAML Profiles §4.1.3.5")
		}
		out["assertions"] = []M{describeAssertion(&cs, root, ex)}
	case "AuthnRequest":
		req := M{}
		if p := kid(root, "NameIDPolicy"); p != nil {
			req["name_id_policy"] = M{"format": p.SelectAttrValue("Format", ""), "allow_create": p.SelectAttrValue("AllowCreate", "")}
		}
		if rac := kid(root, "RequestedAuthnContext"); rac != nil {
			var refs []string
			for _, r := range kids(rac, "AuthnContextClassRef") {
				refs = append(refs, text(r))
			}
			req["requested_authn_context"] = M{"comparison": rac.SelectAttrValue("Comparison", "exact"), "class_refs": refs}
		}
		out["request"] = req
		cs.ok(root.SelectAttrValue("ID", "") != "", "request: ID present", "", "SAML Core §3.2.1")
		cs.ok(root.SelectAttrValue("Version", "") == "2.0", "request: Version is 2.0", "", "SAML Core §3.2.1")
		cs.ok(kid(root, "Issuer") != nil, "request: Issuer present", "", "SAML Profiles §4.1.4.1")
		if signed, _ := checkSignature(&cs, "request", root, ex.Trusted); !signed {
			cs.add("request: signature", "info", "no enveloped signature (with the Redirect binding the signature travels in the query string)", "SAML Bindings §3.4.4.1")
		}
	case "LogoutRequest", "LogoutResponse":
		if nid := kid(root, "NameID"); nid != nil {
			out["name_id"] = M{"value": text(nid), "format": nid.SelectAttrValue("Format", "")}
		}
		if code := kid(root, "Status", "StatusCode"); code != nil {
			out["status"] = M{"code": code.SelectAttrValue("Value", "")}
		}
		if root.Tag == "LogoutResponse" {
			code := ""
			if sc := kid(root, "Status", "StatusCode"); sc != nil {
				code = sc.SelectAttrValue("Value", "")
				if sub := kid(sc, "StatusCode"); sub != nil {
					code += " / " + sub.SelectAttrValue("Value", "")
				}
			}
			cs.ok(strings.HasPrefix(code, samlStatusOK), "logout response: status is Success", code, "SAML Core §3.7.2")
			if strings.Contains(code, "PartialLogout") {
				cs.add("logout response: complete", "warn", "PartialLogout: not every session participant was logged out", "SAML Core §3.2.2.2")
			}
			if ex.InResponseTo != "" {
				cs.ok(root.SelectAttrValue("InResponseTo", "") == ex.InResponseTo, "logout response: InResponseTo matches the request", "InResponseTo="+root.SelectAttrValue("InResponseTo", ""), "SAML Core §3.2.2")
			}
			if ex.ACS != "" {
				cs.ok(root.SelectAttrValue("Destination", "") == ex.ACS, "logout response: Destination is the SP SingleLogoutService", "Destination="+root.SelectAttrValue("Destination", ""), "SAML Bindings §3.4.5.2")
			}
		}
		if signed, _ := checkSignature(&cs, strings.ToLower(root.Tag), root, ex.Trusted); !signed {
			cs.add(strings.ToLower(root.Tag)+": signature", "info", "no enveloped signature (with the Redirect binding the signature travels in the query string)", "SAML Bindings §3.4.4.1")
		}
	default:
		cs.add("message type", "info", "unrecognised root element "+root.Tag+"; showing the XML only", "")
	}
	return out, nil
}

// ---- building requests ----

type spConfig struct {
	EntityID string
	ACS      string
	SLO      string
	Key      *rsa.PrivateKey
	Cert     *x509.Certificate
}

func loadSP(c *Ctx) (*spConfig, error) {
	sp := &spConfig{EntityID: c.Str("sp_entity_id"), ACS: c.Str("acs_url"), SLO: c.Str("slo_url")}
	var err error
	if s := c.Str("sp_key"); s != "" {
		if sp.Key, err = loadRSAKey(s); err != nil {
			return nil, fmt.Errorf("sp_key: %w", err)
		}
	}
	if s := c.Str("sp_cert"); s != "" {
		certs, err := loadCerts(s)
		if err != nil {
			return nil, fmt.Errorf("sp_cert: %w", err)
		}
		sp.Cert = certs[0]
	}
	return sp, nil
}

type builtRequest struct {
	ID, XML, Binding, Destination, Encoded, RelayState string
	Param                                              string // SAMLRequest or SAMLResponse
	RedirectURL                                        string // Redirect binding
	Signed                                             bool
}

func buildAuthnRequest(c *Ctx, sp *spConfig, ssoURL, binding string) (*builtRequest, error) {
	if err := c.allowDestination("the AuthnRequest", ssoURL); err != nil {
		return nil, err
	}
	r := &builtRequest{ID: newSAMLID(), Binding: binding, Destination: ssoURL, RelayState: c.Str("relay_state"), Param: "SAMLRequest"}
	doc := etree.NewDocument()
	el := doc.CreateElement("samlp:AuthnRequest")
	el.CreateAttr("xmlns:samlp", nsSAMLP)
	el.CreateAttr("xmlns:saml", nsSAML)
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", time.Now().UTC().Format(samlTimeLayout))
	el.CreateAttr("Destination", ssoURL)
	if c.Str("response_binding") == "artifact" {
		el.CreateAttr("ProtocolBinding", bindArtifact)
	} else {
		el.CreateAttr("ProtocolBinding", bindPOST)
	}
	if sp.ACS != "" {
		el.CreateAttr("AssertionConsumerServiceURL", sp.ACS)
	}
	if c.Bool("force_authn") {
		el.CreateAttr("ForceAuthn", "true")
	}
	if c.Bool("is_passive") {
		el.CreateAttr("IsPassive", "true")
	}
	el.CreateElement("saml:Issuer").SetText(sp.EntityID)
	if f := c.Str("name_id_format"); f != "" {
		p := el.CreateElement("samlp:NameIDPolicy")
		p.CreateAttr("Format", f)
		p.CreateAttr("AllowCreate", "true")
	}
	if ac := c.Str("authn_context"); ac != "" {
		rac := el.CreateElement("samlp:RequestedAuthnContext")
		rac.CreateAttr("Comparison", "exact")
		rac.CreateElement("saml:AuthnContextClassRef").SetText(ac)
	}
	return finishMessage(sp, doc, el, r, c.Bool("sign"))
}

func (r *builtRequest) postForm() string {
	relay := ""
	if r.RelayState != "" {
		relay = `<input type="hidden" name="RelayState" value="` + html.EscapeString(r.RelayState) + `">`
	}
	return `<!doctype html><meta charset="utf-8"><title>idpdbg</title><body onload="document.forms[0].submit()">
<form method="post" action="` + html.EscapeString(r.Destination) + `"><input type="hidden" name="` + r.Param + `" value="` + r.Encoded + `">` + relay + `
<noscript><button>Continue to the identity provider</button></noscript></form></body>`
}

func (r *builtRequest) describe() M {
	out := M{"id": r.ID, "binding": r.Binding, "destination": r.Destination, "xml": r.XML, "encoded": r.Encoded, "signed": r.Signed}
	if r.RedirectURL != "" {
		out["redirect_url"] = r.RedirectURL
	} else {
		out["post_form_html"] = r.postForm()
	}
	return out
}

// resolveIDP works out where to send the request and whom to trust.
func resolveIDP(c *Ctx) (ssoURL, binding string, meta *idpMeta, trusted []*x509.Certificate, err error) {
	if src := c.Str("idp_metadata"); src != "" {
		if meta, err = loadIDPMetadata(c, src); err != nil {
			return
		}
		trusted = meta.Certs
	}
	if s := c.Str("idp_cert"); s != "" {
		var certs []*x509.Certificate
		if certs, err = loadCerts(s); err != nil {
			err = fmt.Errorf("idp_cert: %w", err)
			return
		}
		trusted = append(trusted, certs...)
	}
	binding = map[string]string{"redirect": bindRedirect, "post": bindPOST}[c.Str("binding")]
	ssoURL = c.Str("sso_url")
	if ssoURL == "" && meta != nil {
		if ssoURL = meta.SSO[binding]; ssoURL == "" {
			for _, b := range []string{bindRedirect, bindPOST} {
				if meta.SSO[b] != "" {
					ssoURL, binding = meta.SSO[b], b
					break
				}
			}
		}
	}
	return
}

// samlExpectFrom is what a response must satisfy. supplied says the
// response came from the caller rather than from an exchange idpdbg ran;
// over MCP a stored sp_key does not decrypt such a response, so a tool
// call cannot use the person's SP key to decrypt whatever it is handed.
func samlExpectFrom(c *Ctx, trusted []*x509.Certificate, supplied bool) (*samlExpect, error) {
	ex := &samlExpect{Trusted: trusted, Audience: c.Str("sp_entity_id"), ACS: c.Str("acs_url"), InResponseTo: c.Str("in_response_to"),
		Leeway: time.Duration(c.Int("leeway")) * time.Second}
	if supplied && !c.CLI && c.stored["sp_key"] != "" {
		ex.KeyWithheld = "the assertion is encrypted; over MCP the sp_key from the " + c.stored["sp_key"] + " does not decrypt a supplied response: pass sp_key in the call"
	} else if s := c.Str("sp_key"); s != "" {
		k, err := loadRSAKey(s)
		if err != nil {
			return nil, fmt.Errorf("sp_key: %w", err)
		}
		ex.SPKey = k
	}
	return ex, nil
}

func spMetadataXML(sp *spConfig, signed bool) string {
	key := ""
	if sp.Cert != nil {
		b := base64.StdEncoding.EncodeToString(sp.Cert.Raw)
		for _, use := range []string{"signing", "encryption"} {
			key += `
    <md:KeyDescriptor use="` + use + `"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>` + b + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
		}
	}
	slo := ""
	if sp.SLO != "" {
		for _, b := range []string{bindRedirect, bindPOST} {
			slo += `
    <md:SingleLogoutService Binding="` + b + `" Location="` + html.EscapeString(sp.SLO) + `"/>`
		}
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + html.EscapeString(sp.EntityID) + `">
  <md:SPSSODescriptor AuthnRequestsSigned="` + fmt.Sprint(signed) + `" WantAssertionsSigned="true" protocolSupportEnumeration="` + nsSAMLP + `">` + key + slo + `
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:AssertionConsumerService Binding="` + bindPOST + `" Location="` + html.EscapeString(sp.ACS) + `" index="0" isDefault="true"/>
    <md:AssertionConsumerService Binding="` + bindArtifact + `" Location="` + html.EscapeString(sp.ACS) + `" index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
`
}

// ---- operations ----

// The SAML service-provider and IdP-trust parameters every SAML operation shares.
var (
	samlSPParams = []Param{
		{Name: "sp_entity_id", Type: "string", Desc: "Entity ID this tool presents as the service provider", Default: "idpdbg"},
		{Name: "sp_key", Type: "string", Path: true, Desc: "SP RSA private key (PEM inline or a path) for signing requests and decrypting assertions"},
		{Name: "sp_cert", Type: "string", Path: true, Desc: "SP certificate (PEM inline or a path)"},
	}
	samlIDPParams = []Param{
		{Name: "idp_metadata", Type: "string", Path: true, Desc: "IdP metadata: a URL, a file path or inline XML"},
		{Name: "idp_cert", Type: "string", Path: true, Desc: "IdP signing certificate (PEM inline or a path), instead of or in addition to metadata"},
	}
)

func init() {
	spParams, idpParams := samlSPParams, samlIDPParams
	requestParams := []Param{
		{Name: "sso_url", Type: "string", Desc: "IdP SSO URL, overriding metadata"},
		{Name: "binding", Type: "string", Enum: []string{"redirect", "post"}, Desc: "Binding used to send the AuthnRequest", Default: "redirect"},
		{Name: "name_id_format", Type: "string", Desc: "Requested NameID format URI"},
		{Name: "authn_context", Type: "string", Desc: "Requested AuthnContextClassRef URI"},
		{Name: "force_authn", Type: "bool", Desc: "Set ForceAuthn=true"},
		{Name: "is_passive", Type: "bool", Desc: "Set IsPassive=true"},
		{Name: "relay_state", Type: "string", Desc: "RelayState to send"},
		{Name: "sign", Type: "bool", Desc: "Sign the request with sp_key"},
		{Name: "response_binding", Type: "string", Enum: []string{"post", "artifact"}, Desc: "Binding the IdP should answer with: post, or artifact (resolved over SOAP)", Default: "post"},
	}
	join := joinParams
	leeway := Param{Name: "leeway", Type: "int", Desc: "Clock skew allowance in seconds", Default: 120}

	register(
		&Op{
			Name:    "saml.metadata",
			Summary: "Load and summarise SAML IdP metadata: entity ID, SSO and SLO endpoints per binding, NameID formats and signing certificates with expiry.",
			Params:  []Param{{Name: "idp_metadata", Type: "string", Path: true, Required: true, Desc: "IdP metadata: a URL, a file path or inline XML"}},
			Run: func(c *Ctx) (M, error) {
				m, err := loadIDPMetadata(c, c.Str("idp_metadata"))
				if err != nil {
					return nil, err
				}
				var cs Checks
				if cs.ok(m.EntityID != "", "entityID present", m.EntityID, "SAML Metadata §2.3.2") {
					entityIDCheck(&cs, m.EntityID)
				}
				cs.ok(len(m.SSO) > 0, "SingleSignOnService present", fmt.Sprintf("%d binding(s)", len(m.SSO)), "SAML Metadata §2.4.3")
				cs.ok(len(m.Certs) > 0, "signing certificate present", fmt.Sprintf("%d certificate(s)", len(m.Certs)), "SAML Metadata §2.4.1.1")
				certs := []M{}
				for _, cert := range m.Certs {
					certs = append(certs, certInfo(cert))
					certChecks(&cs, cert, "signing")
				}
				for b, loc := range m.SSO {
					if !strings.HasPrefix(loc, "https://") {
						cs.add("SSO endpoint uses https", "warn", b+" -> "+loc, "")
					}
				}
				checkSignature(&cs, "metadata", m.Root, nil)
				return M{"entity_id": m.EntityID, "sso_services": m.SSO, "slo_services": m.SLO, "name_id_formats": m.NameIDs,
					"want_authn_requests_signed": m.WantsSigned, "signing_certificates": certs, "checks": cs}, nil
			},
		},
		&Op{
			Name:    "saml.authn_request",
			Summary: "Build (and optionally sign) a SAML 2.0 AuthnRequest without sending it. Returns the XML, the encoded form and a ready redirect URL or auto-submitting POST form.",
			Params: join(idpParams[:1], requestParams, spParams,
				[]Param{{Name: "acs_url", Type: "string", Desc: "Assertion Consumer Service URL to ask the IdP to respond to"}}),
			Run: func(c *Ctx) (M, error) {
				ssoURL, binding, _, _, err := resolveIDP(c)
				if err != nil {
					return nil, err
				}
				if ssoURL == "" {
					return nil, errors.New("pass idp_metadata or sso_url")
				}
				sp, err := loadSP(c)
				if err != nil {
					return nil, err
				}
				r, err := buildAuthnRequest(c, sp, ssoURL, binding)
				if err != nil {
					return nil, err
				}
				return r.describe(), nil
			},
		},
		&Op{
			Name:    "saml.login",
			Browser: true,
			Summary: "Run SP-initiated SAML SSO end to end: listen on a local Assertion Consumer Service, send an AuthnRequest through the browser, capture the SAMLResponse and verify its signature, conditions, audience and recipient. Blocks until the person finishes signing in. Register the ACS URL and SP entity ID with the IdP first (see saml sp_metadata).",
			Params: join(idpParams, requestParams, spParams, []Param{
				{Name: "acs_port", Type: "int", Desc: "Loopback port for the local ACS", Default: 8766},
				{Name: "ars_url", Type: "string", Desc: "ArtifactResolutionService URL, overriding metadata (artifact responses)"},
				{Name: "mtls_cert", Type: "string", Path: true, Desc: "Client certificate for mutual TLS to the resolution service"},
				{Name: "mtls_key", Type: "string", Path: true, Desc: "Private key for mtls_cert"},
				{Name: "acs_path", Type: "string", Desc: "Path of the local ACS", Default: "/saml/acs"},
				leeway}, browserParams),
			Run: runSAMLLogin,
		},
		&Op{
			Name:    "saml.decode",
			Summary: "Decode and inspect a SAML message (Response, Assertion, AuthnRequest, Logout messages): raw XML, base64, DEFLATE+base64 or a whole redirect URL. Given the IdP metadata or certificate it verifies signatures; given the SP details it checks audience, recipient and timing, and decrypts encrypted assertions.",
			Params: join([]Param{{Name: "message", Type: "string", Required: true, File: true, Desc: "The SAML message in any encoding (CLI: @file or - for stdin)"}},
				idpParams, []Param{
					{Name: "sp_entity_id", Type: "string", Desc: "Expected audience (the SP entity ID)"},
					{Name: "acs_url", Type: "string", Desc: "Expected Destination / Recipient (the ACS URL)"},
					{Name: "in_response_to", Type: "string", Desc: "ID of the AuthnRequest the response must answer"},
					{Name: "sp_key", Type: "string", Path: true, Desc: "SP RSA private key (PEM inline or a path) to decrypt an EncryptedAssertion; over MCP it must be passed in the call, not taken from a profile"},
					leeway}),
			Run: func(c *Ctx) (M, error) {
				// A signed Redirect URL is parsed once; the signature is checked
				// over, and the message decoded from, the same values.
				var redirect *redirectMsg
				input := c.Str("message")
				if q := redirectQuery(input); q != "" {
					m, err := parseRedirect(q)
					if err != nil {
						return nil, err
					}
					redirect, input = m, m.Message
				}
				xmlBytes, enc, err := decodeSAMLInput(input)
				if err != nil {
					return nil, err
				}
				if redirect != nil {
					enc = "DEFLATE + base64 (HTTP-Redirect binding, signed)"
				}
				_, _, _, trusted, err := resolveIDP(c)
				if err != nil {
					return nil, err
				}
				ex, err := samlExpectFrom(c, trusted, true)
				if err != nil {
					return nil, err
				}
				out, err := analyzeSAML(xmlBytes, ex)
				if out != nil {
					out["encoding"] = enc
					if redirect != nil {
						var pre Checks
						checkRedirectSignature(&pre, redirect, trusted)
						out["checks"] = append(pre, out["checks"].(Checks)...)
					}
				}
				return out, err
			},
		},
		&Op{
			Name:    "saml.sp_metadata",
			Summary: "Generate SP metadata XML for this tool, to register it with an IdP before running saml login.",
			Params: join(spParams[:1], spParams[2:], []Param{
				{Name: "acs_url", Type: "string", Desc: "ACS URL", Default: "http://localhost:8766/saml/acs"},
				{Name: "slo_url", Type: "string", Desc: "SingleLogoutService URL (empty to leave it out)", Default: "http://localhost:8766/saml/slo"},
				{Name: "sign", Type: "bool", Desc: "Declare AuthnRequestsSigned=true"},
				{Name: "out", Type: "string", Desc: "Write the XML to this file as well"}}),
			Run: func(c *Ctx) (M, error) {
				sp, err := loadSP(c)
				if err != nil {
					return nil, err
				}
				x := spMetadataXML(sp, c.Bool("sign"))
				out := M{"entity_id": sp.EntityID, "acs_url": sp.ACS, "slo_url": sp.SLO, "xml": x}
				if p := c.Str("out"); p != "" {
					if !c.CLI {
						return nil, errors.New("out is only available from the CLI; over MCP the XML is returned in the result")
					}
					if err := os.WriteFile(p, []byte(x), 0o644); err != nil {
						return nil, err
					}
					out["written_to"] = p
				}
				return out, nil
			},
		},
	)
}

func runSAMLLogin(c *Ctx) (M, error) {
	ssoURL, binding, meta, trusted, err := resolveIDP(c)
	if err != nil {
		return nil, err
	}
	if ssoURL == "" {
		return nil, errors.New("pass idp_metadata or sso_url")
	}
	sp, err := loadSP(c)
	if err != nil {
		return nil, err
	}
	port, path := c.Int("acs_port"), c.Str("acs_path")
	sp.ACS = fmt.Sprintf("http://localhost:%d%s", port, path)
	r, err := buildAuthnRequest(c, sp, ssoURL, binding)
	if err != nil {
		return nil, err
	}
	ch := make(chan url.Values, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if req.Form.Get("SAMLResponse") == "" && req.Form.Get("SAMLart") == "" {
			http.Error(w, "idpdbg: expected a SAMLResponse or SAMLart", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, donePage)
		select {
		case ch <- req.Form:
		default:
		}
	})
	start := r.RedirectURL
	if binding == bindPOST {
		mux.HandleFunc("/saml/start", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, r.postForm())
		})
		start = fmt.Sprintf("http://localhost:%d/saml/start", port)
	}
	stop, err := serveLoopback(port, mux)
	if err != nil {
		return nil, err
	}
	defer stop()
	c.Log("Local ACS listening on %s (SP entity ID %q); both must be registered with the IdP", sp.ACS, sp.EntityID)
	vals, err := awaitBrowser(c, start, ch)
	if err != nil {
		return nil, err
	}
	var pre Checks
	var xmlBytes []byte
	var enc string
	var artInfo M
	if art := vals.Get("SAMLart"); art != "" {
		if c.Str("response_binding") != "artifact" {
			pre.add("response binding", "info", "the IdP answered with an artifact although HTTP-POST was requested", "SAML Profiles §4.1.4.1")
		}
		xmlBytes, artInfo, err = resolveArtifact(c, sp, meta, trusted, art, &pre)
		if err != nil {
			artInfo["checks"] = pre
			return artInfo, err
		}
		enc = "HTTP-Artifact (resolved over SOAP)"
	} else {
		if c.Str("response_binding") == "artifact" {
			pre.add("response binding", "warn", "an artifact was requested but the IdP posted the Response directly", "SAML Profiles §4.1.4.1")
		}
		if xmlBytes, enc, err = decodeSAMLInput(vals.Get("SAMLResponse")); err != nil {
			return nil, err
		}
	}
	ex := &samlExpect{Trusted: trusted, SPKey: sp.Key, Audience: sp.EntityID, ACS: sp.ACS, InResponseTo: r.ID, Leeway: time.Duration(c.Int("leeway")) * time.Second}
	out, err := analyzeSAML(xmlBytes, ex)
	if err != nil {
		return nil, err
	}
	out["checks"] = append(pre, out["checks"].(Checks)...)
	for k, v := range artInfo {
		out[k] = v
	}
	out["encoding"] = enc
	out["request"] = r.describe()
	out["acs_url"] = sp.ACS
	if rs := vals.Get("RelayState"); rs != "" || r.RelayState != "" {
		out["relay_state"] = rs
		cs := out["checks"].(Checks)
		cs.ok(rs == r.RelayState, "RelayState echoed unchanged", "RelayState="+rs, "SAML Bindings §3.5.3")
		out["checks"] = cs
	}
	if meta != nil {
		if iss, _ := out["issuer"].(string); iss != "" {
			cs := out["checks"].(Checks)
			cs.ok(iss == meta.EntityID, "response: Issuer is the IdP entity ID", "Issuer="+iss, samlProfiles)
			out["checks"] = cs
		}
	}
	return out, nil
}

var _ = samlCore

// entityIDCheck warns about entity IDs that are not absolute URIs (SAML
// Core §8.3.6): SPs and federations key trust on this string, and a
// placeholder left from a console form usually means a half-configured app.
func entityIDCheck(cs *Checks, id string) {
	u, err := url.Parse(id)
	switch {
	case err != nil || u.Scheme == "" || strings.ContainsAny(id, " \t\n"):
		cs.add("entityID is an absolute URI", "warn", fmt.Sprintf("%q is not a URI; it looks like a placeholder", id), "SAML Core §8.3.6")
	case len(id) > 1024:
		cs.add("entityID is an absolute URI", "warn", fmt.Sprintf("%d characters; the limit is 1024", len(id)), "SAML Core §8.3.6")
	default:
		cs.add("entityID is an absolute URI", "pass", "", "SAML Core §8.3.6")
	}
}
