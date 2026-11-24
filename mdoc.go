package main

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"sort"
	"strings"
	"time"
)

// mdoc (ISO/IEC 18013-5, the mobile driving licence and EUDI wallet
// credential format): the issuer-signed part. The issuer signs a Mobile
// Security Object (MSO) in a COSE_Sign1 with its document signer (DS)
// certificate; the MSO holds a digest of every data element, the device
// key the holder proves possession of, and the validity. Each data element
// travels on its own, wrapped in CBOR tag 24, and is checked against its
// digest. Device authentication (the holder's signature over the session)
// is decoded but not verified: it needs the session transcript.

const mdocRef = "ISO/IEC 18013-5"

var (
	oidMdlDS = asn1.ObjectIdentifier{1, 0, 18013, 5, 1, 2} // id-mdl-kp-mdlDS
)

// mdocBytes reads the input in any of the encodings it arrives in.
func mdocBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(s)%2 == 0 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not hex or base64")
}

// untag unwraps tags; tag 24 (embedded CBOR) is decoded.
func untag(v any) any {
	for {
		t, ok := v.(cborTag)
		if !ok {
			return v
		}
		if t.Num == 24 {
			if b, ok := t.V.([]byte); ok {
				if inner, _, err := cborDecodeTagged(b); err == nil {
					v = inner
					continue
				}
			}
		}
		v = t.V
	}
}

// mdocJSON shows an element value: dates as strings, embedded CBOR decoded,
// long byte strings (portraits) summarised.
func mdocJSON(v any) any {
	switch t := v.(type) {
	case cborTag:
		switch t.Num {
		case 0, 1004:
			return t.V
		case 24:
			return mdocJSON(untag(t))
		}
		return mdocJSON(t.V)
	case map[any]any:
		out := M{}
		for k, x := range t {
			out[fmt.Sprint(k)] = mdocJSON(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = mdocJSON(t[i])
		}
		return out
	case []byte:
		if len(t) > 96 {
			return fmt.Sprintf("<%d bytes, sha256 %x…>", len(t), sha256.Sum256(t))
		}
		return b64url(t)
	}
	return v
}

func mapOf(v any) map[any]any { m, _ := untag(v).(map[any]any); return m }

// mdocTime reads a tdate (tag 0) or a plain RFC 3339 string.
func mdocTime(v any) (time.Time, bool) {
	s, ok := untag(v).(string)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

type coseSign1 struct {
	Protected   []byte
	Unprotected map[any]any
	Payload     []byte
	Signature   []byte
	Alg         int64
	Chain       []*x509.Certificate
}

func parseCOSESign1(v any) (*coseSign1, error) {
	arr, ok := untag(v).([]any)
	if !ok || len(arr) != 4 {
		return nil, errors.New("not a COSE_Sign1 (an array of four)")
	}
	s := &coseSign1{}
	s.Protected, _ = arr[0].([]byte)
	s.Unprotected, _ = arr[1].(map[any]any)
	s.Payload, _ = arr[2].([]byte)
	s.Signature, _ = arr[3].([]byte)
	if len(s.Protected) > 0 {
		ph, _, err := cborDecode(s.Protected)
		if err != nil {
			return nil, fmt.Errorf("protected header: %w", err)
		}
		if m, ok := ph.(map[any]any); ok {
			s.Alg, _ = m[int64(1)].(int64)
		}
	}
	// x5chain (label 33): one certificate, or an array of them.
	var ders [][]byte
	switch x := s.Unprotected[int64(33)].(type) {
	case []byte:
		ders = [][]byte{x}
	case []any:
		for _, e := range x {
			if b, ok := e.([]byte); ok {
				ders = append(ders, b)
			}
		}
	}
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			return nil, fmt.Errorf("x5chain certificate: %w", err)
		}
		s.Chain = append(s.Chain, c)
	}
	return s, nil
}

// verify checks the COSE_Sign1 signature (RFC 9052 §4.4) with pub; ECDSA
// signatures are r||s, not DER.
func (s *coseSign1) verify(pub crypto.PublicKey) error {
	toBeSigned := cborEncode([]any{"Signature1", s.Protected, []byte{}, s.Payload})
	switch s.Alg {
	case -7, -35, -36:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("an ECDSA algorithm with a non-EC key")
		}
		h := map[int64]crypto.Hash{-7: crypto.SHA256, -35: crypto.SHA384, -36: crypto.SHA512}[s.Alg].New()
		h.Write(toBeSigned)
		n := (k.Curve.Params().BitSize + 7) / 8
		if len(s.Signature) != 2*n {
			return fmt.Errorf("signature is %d bytes, want %d (r||s)", len(s.Signature), 2*n)
		}
		r, ss := new(big.Int).SetBytes(s.Signature[:n]), new(big.Int).SetBytes(s.Signature[n:])
		if !ecdsa.Verify(k, h.Sum(nil), r, ss) {
			return errors.New("signature does not verify")
		}
		return nil
	case -8:
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("EdDSA with a non-Ed25519 key")
		}
		if !ed25519.Verify(k, toBeSigned, s.Signature) {
			return errors.New("signature does not verify")
		}
		return nil
	}
	return fmt.Errorf("unsupported COSE algorithm %d", s.Alg)
}

func mdocHash(name string) (hash.Hash, bool) {
	switch name {
	case "SHA-256":
		return sha256.New(), true
	case "SHA-384":
		return sha512.New384(), true
	case "SHA-512":
		return sha512.New(), true
	}
	return nil, false
}

// checkIssuerSigned checks one document's IssuerSigned and describes it.
func checkIssuerSigned(cs *Checks, p string, issuerSigned map[any]any, docType string, roots *x509.CertPool, now time.Time, leeway time.Duration) M {
	out := M{}
	auth, err := parseCOSESign1(issuerSigned["issuerAuth"])
	if !cs.ok(err == nil, p+"issuerAuth is a COSE_Sign1", detailOr(err, ""), mdocRef+" §9.1.2.4") {
		return out
	}
	out["signature_alg"] = coseAlgs[auth.Alg]
	cs.ok(auth.Alg == -7 || auth.Alg == -35 || auth.Alg == -36 || auth.Alg == -8, p+"issuerAuth algorithm", fmt.Sprintf("%s (%d)", coseAlgs[auth.Alg], auth.Alg), mdocRef+" §9.1.3.6")

	// The document signer certificate.
	if !cs.ok(len(auth.Chain) > 0, p+"document signer certificate in x5chain", "", mdocRef+" §9.1.2.4") {
		return out
	}
	ds := auth.Chain[0]
	out["document_signer"] = certDetail(ds)
	if err := auth.verify(ds.PublicKey); err != nil {
		cs.add(p+"issuer signature", "fail", err.Error(), mdocRef+" §9.1.2.4")
		return out
	}
	cs.add(p+"issuer signature", "pass", "by "+ds.Subject.String(), mdocRef+" §9.1.2.4")
	if hasOID(ds.UnknownExtKeyUsage, oidMdlDS) {
		cs.add(p+"document signer certificate purpose", "pass", "id-mdl-kp-mdlDS", mdocRef+" Annex B.1.4")
	} else {
		cs.add(p+"document signer certificate purpose", "warn", "no id-mdl-kp-mdlDS extended key usage", mdocRef+" Annex B.1.4")
	}
	if roots != nil {
		inter := x509.NewCertPool()
		for _, c := range auth.Chain[1:] {
			inter.AddCert(c)
		}
		_, err := ds.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		cs.ok(err == nil, p+"document signer chains to a trusted IACA", detailOr(err, ds.Issuer.String()), mdocRef+" §9.3.3")
	} else {
		cs.add(p+"document signer chains to a trusted IACA", "warn", "not checked: pass the issuing authority's IACA certificate as trust_anchors", mdocRef+" §9.3.3")
	}

	// The Mobile Security Object.
	payload, _, err := cborDecodeTagged(auth.Payload)
	mso := mapOf(payload)
	if !cs.ok(err == nil && mso != nil, p+"MSO decodes", detailOr(err, ""), mdocRef+" §9.1.2.4") {
		return out
	}
	alg, _ := mso["digestAlgorithm"].(string)
	msoDoc, _ := mso["docType"].(string)
	info := M{"version": mso["version"], "digest_algorithm": alg, "doc_type": msoDoc}
	out["mso"] = info
	cs.ok(mso["version"] == "1.0", p+"MSO version 1.0", fmt.Sprint(mso["version"]), mdocRef+" §9.1.2.4")
	if docType != "" {
		cs.ok(msoDoc == docType, p+"MSO docType is the document's", "MSO "+msoDoc+", document "+docType, mdocRef+" §9.3.1")
	}
	h, okAlg := mdocHash(alg)
	cs.ok(okAlg, p+"digest algorithm", alg, mdocRef+" §9.1.2.5")

	vi := mapOf(mso["validityInfo"])
	signed, okS := mdocTime(vi["signed"])
	from, okF := mdocTime(vi["validFrom"])
	until, okU := mdocTime(vi["validUntil"])
	info["validity"] = mdocJSON(vi)
	if cs.ok(okS && okF && okU, p+"MSO validity present", "", mdocRef+" §9.1.2.4") {
		cs.ok(!now.Add(leeway).Before(from), p+"MSO valid from", "valid from "+relTime(from), mdocRef+" §9.3.1")
		cs.ok(now.Add(-leeway).Before(until), p+"MSO not expired", "valid until "+relTime(until), mdocRef+" §9.3.1")
		cs.ok(!signed.Before(ds.NotBefore) && !signed.After(ds.NotAfter), p+"MSO signed while the document signer certificate was valid",
			"signed "+signed.UTC().Format(time.RFC3339), mdocRef+" §9.3.1")
	}
	if dki := mapOf(mso["deviceKeyInfo"]); dki != nil {
		if pub, _, err := coseKey(untag(dki["deviceKey"])); err == nil {
			jwk, _ := publicJWK(pub)
			info["device_key"] = jwk
			cs.add(p+"device key present", "pass", "the holder proves possession of it when presenting", mdocRef+" §9.1.2.4")
		} else {
			cs.add(p+"device key present", "fail", err.Error(), mdocRef+" §9.1.2.4")
		}
	} else {
		cs.add(p+"device key present", "fail", "no deviceKeyInfo", mdocRef+" §9.1.2.4")
	}

	// Every data element against its digest.
	digests := mapOf(mso["valueDigests"])
	nss := M{}
	elements, bad := 0, 0
	nsMap := mapOf(issuerSigned["nameSpaces"])
	for _, nsKey := range sortedAnyKeys(nsMap) {
		ns := fmt.Sprint(nsKey)
		items, _ := untag(nsMap[nsKey]).([]any)
		want := mapOf(digests[nsKey])
		seen := map[int64]bool{}
		claims := M{}
		for _, it := range items {
			tag, ok := it.(cborTag)
			item := mapOf(it)
			if !ok || tag.Num != 24 || item == nil {
				cs.add(p+ns+": element is tag-24 encoded", "fail", "an IssuerSignedItem must be wrapped in tag 24", mdocRef+" §8.3.2.1.2.2")
				bad++
				continue
			}
			id, _ := item["digestID"].(int64)
			name := fmt.Sprint(item["elementIdentifier"])
			elements++
			if seen[id] {
				cs.add(p+ns+"/"+name+": digest ID unique", "fail", fmt.Sprintf("digestID %d appears twice", id), mdocRef+" §9.1.2.5")
				bad++
			}
			seen[id] = true
			exp, _ := want[id].([]byte)
			if okAlg {
				h.Reset()
				h.Write(tag.Raw)
				if exp == nil || !bytes.Equal(h.Sum(nil), exp) {
					why := "the digest differs from the MSO's: the element was changed"
					if exp == nil {
						why = fmt.Sprintf("the MSO has no digest %d in this namespace", id)
					}
					cs.add(p+ns+"/"+name+": digest", "fail", why, mdocRef+" §9.3.1")
					bad++
					continue
				}
			}
			claims[name] = mdocJSON(item["elementValue"])
		}
		nss[ns] = claims
	}
	out["namespaces"] = nss
	if okAlg {
		cs.ok(bad == 0, p+"every data element matches its MSO digest", fmt.Sprintf("%d element(s)", elements), mdocRef+" §9.3.1")
	}
	return out
}

// deviceAuthenticationBytes builds DeviceAuthenticationBytes (§9.1.3.4)
// from the raw SessionTranscript and DeviceNameSpacesBytes, so that both
// keep the encoding the device signed.
func deviceAuthenticationBytes(transcript []byte, docType string, nameSpacesRaw []byte) []byte {
	da := append([]byte{0x84}, cborEncode("DeviceAuthentication")...)
	da = append(da, transcript...)
	da = append(da, cborEncode(docType)...)
	da = append(da, nameSpacesRaw...)
	return cborEncode(cborTag{Num: 24, V: da})
}

// checkDeviceAuth verifies the device's signature or MAC over the session
// (§9.1.3): DeviceAuthentication = [“DeviceAuthentication”,
// SessionTranscript, DocType, DeviceNameSpacesBytes].
func checkDeviceAuth(cs *Checks, p string, deviceSigned map[any]any, docType string, devicePub crypto.PublicKey, transcript, transcriptBytes []byte, readerKey *ecdh.PrivateKey) {
	ref := mdocRef + " §9.1.3"
	nsTag, ok := deviceSigned["nameSpaces"].(cborTag)
	if !ok || nsTag.Num != 24 {
		cs.add(p+"device namespaces are tag-24 encoded", "fail", "", ref)
		return
	}
	dab := deviceAuthenticationBytes(transcript, docType, nsTag.Raw)
	auth := mapOf(deviceSigned["deviceAuth"])
	switch {
	case auth["deviceSignature"] != nil:
		sig, err := parseCOSESign1(auth["deviceSignature"])
		if err != nil {
			cs.add(p+"device signature", "fail", err.Error(), ref)
			return
		}
		if len(sig.Payload) > 0 {
			cs.add(p+"device signature payload detached", "warn", "the payload should be detached (nil) and rebuilt by the reader", ref+".4")
		}
		sig.Payload = dab
		if err := sig.verify(devicePub); err != nil {
			cs.add(p+"device signature", "fail", err.Error()+" (with this session transcript)", ref)
			return
		}
		cs.add(p+"device signature", "pass", "by the MSO's device key over this session transcript", ref)
	case auth["deviceMac"] != nil:
		if readerKey == nil {
			cs.add(p+"device MAC", "info", "not verified: a MAC needs the reader's ephemeral private key (reader_key)", ref)
			return
		}
		arr, _ := untag(auth["deviceMac"]).([]any)
		if len(arr) != 4 {
			cs.add(p+"device MAC", "fail", "not a COSE_Mac0", ref)
			return
		}
		protected, _ := arr[0].([]byte)
		tag, _ := arr[3].([]byte)
		ph, _, _ := cborDecode(protected)
		if alg, _ := mapOf(ph)[int64(1)].(int64); alg != 5 {
			cs.add(p+"device MAC algorithm", "fail", fmt.Sprintf("COSE algorithm %d, want 5 (HMAC 256/256)", alg), ref+".5")
			return
		}
		ecPub, ok := devicePub.(*ecdsa.PublicKey)
		if !ok {
			cs.add(p+"device MAC", "fail", "the device key is not an EC key", ref)
			return
		}
		dk, err := ecPub.ECDH()
		var z []byte
		if err == nil {
			z, err = readerKey.ECDH(dk)
		}
		if err != nil {
			cs.add(p+"device MAC", "fail", "ECDH with the device key: "+err.Error(), ref)
			return
		}
		salt := sha256.Sum256(transcriptBytes)
		key, err := hkdf.Key(sha256.New, z, salt[:], "EMacKey", 32)
		if err != nil {
			cs.add(p+"device MAC", "fail", err.Error(), ref)
			return
		}
		mac := hmac.New(sha256.New, key)
		mac.Write(cborEncode([]any{"MAC0", protected, []byte{}, dab}))
		if !hmac.Equal(mac.Sum(nil), tag) {
			cs.add(p+"device MAC", "fail", "the MAC does not verify with this session transcript and reader key", ref)
			return
		}
		cs.add(p+"device MAC", "pass", "EMacKey from the reader key and the MSO's device key, over this session transcript", ref)
	default:
		cs.add(p+"device authentication present", "fail", "deviceAuth has neither deviceSignature nor deviceMac", ref)
	}
}

// parseReaderKey reads the reader's ephemeral P-256 private key: PEM, a
// private JWK, or the 32-byte scalar in hex.
func parseReaderKey(s string) (*ecdh.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return ecdh.P256().NewPrivateKey(b)
	}
	k, err := loadPrivateKey(s)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("a %T, not an EC private key", k)
	}
	return ek.ECDH()
}

// sessionTranscript reads a SessionTranscript, or SessionTranscriptBytes
// (the same wrapped in tag 24), and returns both encodings.
func sessionTranscript(s string) (transcript, transcriptBytes []byte, err error) {
	b, err := mdocBytes(s)
	if err != nil {
		return nil, nil, err
	}
	v, n, err := cborDecodeTagged(b)
	if err != nil || n != len(b) {
		return nil, nil, fmt.Errorf("not one CBOR item (%v)", err)
	}
	if t, ok := v.(cborTag); ok && t.Num == 24 {
		inner, _ := t.V.([]byte)
		return inner, b, nil
	}
	return b, cborEncode(cborTag{Num: 24, V: b}), nil
}

func sortedAnyKeys(m map[any]any) []any {
	keys := make([]any, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j]) })
	return keys
}

func runMdocDecode(c *Ctx) (M, error) {
	b, err := mdocBytes(c.Str("credential"))
	if err != nil {
		return nil, fmt.Errorf("credential: %w", err)
	}
	top, n, err := cborDecodeTagged(b)
	if err != nil {
		return nil, fmt.Errorf("credential is not CBOR: %w", err)
	}
	var cs Checks
	out := M{}
	cs.ok(n == len(b), "nothing after the CBOR item", fmt.Sprintf("%d trailing bytes", len(b)-n), "RFC 8949")
	var roots *x509.CertPool
	if s := c.Str("trust_anchors"); s != "" {
		certs, err := loadCerts(s)
		if err != nil {
			return nil, fmt.Errorf("trust_anchors: %w", err)
		}
		roots = x509.NewCertPool()
		for _, ce := range certs {
			roots.AddCert(ce)
		}
	}
	now := time.Now()
	if at := c.Str("at"); at != "" {
		if now, err = time.Parse(time.RFC3339, at); err != nil {
			return nil, fmt.Errorf("at: %w", err)
		}
	}
	leeway := time.Duration(c.Int("leeway")) * time.Second
	var transcript, transcriptBytes []byte
	if s := c.Str("session_transcript"); s != "" {
		if transcript, transcriptBytes, err = sessionTranscript(s); err != nil {
			return nil, fmt.Errorf("session_transcript: %w", err)
		}
	}
	var readerKey *ecdh.PrivateKey
	if s := c.Str("reader_key"); s != "" {
		if readerKey, err = parseReaderKey(s); err != nil {
			return nil, fmt.Errorf("reader_key: %w", err)
		}
	}

	m := mapOf(top)
	if m == nil {
		return nil, errors.New("credential is not a CBOR map")
	}
	type doc struct {
		docType      string
		issuerSigned map[any]any
		deviceSigned map[any]any
	}
	var docs []doc
	switch {
	case m["documents"] != nil:
		out["kind"] = "DeviceResponse"
		out["version"] = m["version"]
		if st, ok := m["status"].(int64); ok {
			out["status"] = st
			cs.ok(st == 0, "DeviceResponse status OK", fmt.Sprintf("status %d", st), mdocRef+" §8.3.2.1.2.3")
		}
		list, _ := m["documents"].([]any)
		for _, d := range list {
			dm := mapOf(d)
			dt, _ := dm["docType"].(string)
			docs = append(docs, doc{dt, mapOf(dm["issuerSigned"]), mapOf(dm["deviceSigned"])})
		}
		if errs, ok := m["documentErrors"].([]any); ok && len(errs) > 0 {
			cs.add("document errors", "info", fmt.Sprint(mdocJSON(errs)), mdocRef+" §8.3.2.1.2.3")
		}
	case m["issuerSigned"] != nil:
		out["kind"] = "Document"
		dt, _ := m["docType"].(string)
		docs = append(docs, doc{dt, mapOf(m["issuerSigned"]), mapOf(m["deviceSigned"])})
	case m["issuerAuth"] != nil:
		out["kind"] = "IssuerSigned"
		docs = append(docs, doc{c.Str("doc_type"), m, nil})
	default:
		return nil, errors.New("not an mdoc: expected a DeviceResponse, a Document or IssuerSigned")
	}
	if !cs.ok(len(docs) > 0, "documents present", "", mdocRef+" §8.3.2.1.2.2") {
		out["checks"] = cs
		return out, nil
	}
	var list []M
	for i, d := range docs {
		p := ""
		if len(docs) > 1 {
			p = fmt.Sprintf("document %d: ", i+1)
		}
		if want := c.Str("doc_type"); want != "" && d.docType != "" {
			cs.ok(d.docType == want, p+"docType is the expected one", d.docType, mdocRef+" §8.3.2.1.2.2")
		}
		if d.issuerSigned == nil {
			cs.add(p+"issuerSigned present", "fail", "", mdocRef+" §8.3.2.1.2.2")
			continue
		}
		e := checkIssuerSigned(&cs, p, d.issuerSigned, d.docType, roots, now, leeway)
		if d.docType != "" {
			e["doc_type"] = d.docType
		} else if mso, _ := e["mso"].(M); mso != nil {
			e["doc_type"] = mso["doc_type"]
		}
		if d.deviceSigned != nil {
			auth := mapOf(d.deviceSigned["deviceAuth"])
			kind := "deviceSignature"
			if auth["deviceMac"] != nil {
				kind = "deviceMac"
			}
			e["device_signed"] = M{"device_auth": kind, "namespaces": mdocJSON(d.deviceSigned["nameSpaces"])}
			var devicePub crypto.PublicKey
			if mso, _ := e["mso"].(M); mso != nil {
				if jwk, _ := mso["device_key"].(M); jwk != nil {
					devicePub, _ = jwkPublicKey(map[string]any(jwk))
				}
			}
			dt := d.docType
			if dt == "" {
				dt, _ = e["doc_type"].(string)
			}
			switch {
			case transcript == nil:
				cs.add(p+"device authentication", "info", kind+" present, not verified: pass session_transcript (for OID4VP, vp present builds it)", mdocRef+" §9.1.3")
			case devicePub == nil:
				cs.add(p+"device authentication", "fail", "no device key in the MSO to verify it with", mdocRef+" §9.1.3")
			default:
				checkDeviceAuth(&cs, p, d.deviceSigned, dt, devicePub, transcript, transcriptBytes, readerKey)
			}
		}
		list = append(list, e)
	}
	out["documents"] = list
	out["checks"] = cs
	return out, nil
}

func init() {
	register(&Op{
		Name: "mdoc.decode",
		Summary: "Decode and check an mdoc (ISO/IEC 18013-5: mobile driving licence, EUDI PID in mso_mdoc format): IssuerSigned as OID4VCI returns it, a Document, or a DeviceResponse as an OID4VP vp_token carries it. " +
			"Checks the issuer's COSE_Sign1 signature with the document signer certificate (its purpose, and its chain to an IACA given as trust_anchors), the Mobile Security Object (version, docType, digest algorithm, validity, device key) and every data element against its digest, and shows the elements by namespace. With session_transcript it also verifies device authentication: the device signature, or with reader_key the device MAC.",
		Params: []Param{
			{Name: "credential", Type: "string", Required: true, File: true, Desc: "The mdoc, CBOR as base64url, base64 or hex (CLI: @file or - for stdin)"},
			{Name: "trust_anchors", Type: "string", Path: true, Desc: "IACA certificates (PEM) the document signer must chain to"},
			{Name: "doc_type", Type: "string", Desc: "Expected docType, e.g. org.iso.18013.5.1.mDL or eu.europa.ec.eudi.pid.1"},
			{Name: "at", Type: "string", Desc: "Judge validity at this time (RFC 3339) instead of now, e.g. for published sample documents"},
			{Name: "session_transcript", Type: "string", File: true, Desc: "SessionTranscript (or SessionTranscriptBytes), CBOR as hex or base64, to verify the device's signature or MAC over"},
			{Name: "reader_key", Type: "string", Path: true, Explicit: true, Desc: "The reader's ephemeral private key (PEM, private JWK, or the P-256 scalar in hex), to verify a device MAC"},
			{Name: "leeway", Type: "int", Desc: "Clock skew allowance in seconds", Default: 60},
		},
		Run: runMdocDecode,
	})
}
