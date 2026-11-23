package main

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// SAML Single Logout, the Artifact binding, and Redirect-binding signatures.

const (
	bindArtifact = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
	bindSOAP     = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
	nsSOAP       = "http://schemas.xmlsoap.org/soap/envelope/"
	samlBindings = "SAML Bindings"
)

func newSAMLID() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "_" + hex.EncodeToString(b)
}

func samlNow() string { return time.Now().UTC().Format(samlTimeLayout) }

// signEnvelopedAfterIssuer signs el and moves ds:Signature directly after
// saml:Issuer, where the protocol schemas want it.
func signEnvelopedAfterIssuer(sp *spConfig, el *etree.Element) (*etree.Element, error) {
	if sp.Key == nil || sp.Cert == nil {
		return nil, errors.New("signing an XML message requires sp_key and sp_cert")
	}
	sctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{sp.Cert.Raw}, PrivateKey: sp.Key}))
	sctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := sctx.SignEnveloped(el)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	// SignEnveloped appends the signature without setting its parent, so take
	// it out of the child list by hand before re-inserting it.
	if sig := kid(signed, "Signature"); sig != nil {
		rest := make([]etree.Token, 0, len(signed.Child))
		for _, tok := range signed.Child {
			if tok != etree.Token(sig) {
				rest = append(rest, tok)
			}
		}
		signed.Child = rest
		signed.InsertChildAt(1, sig)
	}
	return signed, nil
}

const sigAlgRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// finishMessage encodes a protocol message for the HTTP-POST or HTTP-Redirect
// binding, signing it in the way that binding requires.
func finishMessage(sp *spConfig, doc *etree.Document, el *etree.Element, r *builtRequest, sign bool) (*builtRequest, error) {
	if r.Param == "" {
		r.Param = "SAMLRequest"
	}
	if sign && sp.Key == nil {
		return nil, errors.New("sign requires sp_key (and sp_cert for the POST binding)")
	}
	if r.Binding == bindPOST {
		if sign {
			if sp.Cert == nil {
				return nil, errors.New("signing a POST-binding message requires sp_cert")
			}
			signed, err := signEnvelopedAfterIssuer(sp, el)
			if err != nil {
				return nil, err
			}
			doc.SetRoot(signed)
			r.Signed = true
		}
		xmlStr, err := doc.WriteToString()
		if err != nil {
			return nil, err
		}
		r.XML, r.Encoded = xmlStr, base64.StdEncoding.EncodeToString([]byte(xmlStr))
		return r, nil
	}
	xmlStr, err := doc.WriteToString()
	if err != nil {
		return nil, err
	}
	r.XML = xmlStr
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	fw.Write([]byte(xmlStr))
	fw.Close()
	r.Encoded = base64.StdEncoding.EncodeToString(buf.Bytes())
	query := r.Param + "=" + url.QueryEscape(r.Encoded)
	if r.RelayState != "" {
		query += "&RelayState=" + url.QueryEscape(r.RelayState)
	}
	if sign {
		query += "&SigAlg=" + url.QueryEscape(sigAlgRSASHA256)
		digest := sha256.Sum256([]byte(query))
		sig, err := rsa.SignPKCS1v15(rand.Reader, sp.Key, crypto.SHA256, digest[:])
		if err != nil {
			return nil, err
		}
		query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
		r.Signed = true
	}
	sep := "?"
	if strings.Contains(r.Destination, "?") {
		sep = "&"
	}
	r.RedirectURL = r.Destination + sep + query
	return r, nil
}

// ---- Redirect-binding signatures ----

// redirectQuery returns the raw query of a Redirect-binding URL when it
// carries a detached signature, or "".
func redirectQuery(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "?"); i >= 0 {
		s = s[i+1:]
	}
	if strings.Contains(s, "SigAlg=") && strings.Contains(s, "Signature=") {
		return s
	}
	return ""
}

var redirectSigAlgs = map[string]crypto.Hash{
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":          crypto.SHA1,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":   crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":   crypto.SHA384,
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":   crypto.SHA512,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256": crypto.SHA256,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384": crypto.SHA384,
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512": crypto.SHA512,
}

// redirectMsg is one parse of an HTTP-Redirect query. The signature is
// verified over raw, and the message analysed is decoded from the same raw
// value, so the two can never disagree.
type redirectMsg struct {
	Param      string            // SAMLRequest or SAMLResponse
	raw        map[string]string // values exactly as encoded on the wire
	Message    string            // decoded message parameter
	RelayState string
	HasRelay   bool
}

// parseRedirect refuses queries that different parsers could read
// differently: repeated parameters, encoded parameter names, or both kinds of
// message at once.
func parseRedirect(rawQuery string) (*redirectMsg, error) {
	m := &redirectMsg{raw: map[string]string{}}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if strings.ContainsAny(k, "%+;") {
			return nil, fmt.Errorf("refusing an ambiguous query: parameter name %q is encoded", k)
		}
		if _, dup := m.raw[k]; dup {
			return nil, fmt.Errorf("refusing an ambiguous query: parameter %q appears more than once", k)
		}
		m.raw[k] = v
	}
	_, isReq := m.raw["SAMLRequest"]
	_, isResp := m.raw["SAMLResponse"]
	if isReq == isResp {
		return nil, errors.New("the query must carry exactly one of SAMLRequest and SAMLResponse")
	}
	m.Param = "SAMLRequest"
	if isResp {
		m.Param = "SAMLResponse"
	}
	var err error
	if m.Message, err = url.QueryUnescape(m.raw[m.Param]); err != nil {
		return nil, fmt.Errorf("%s is not URL-encoded correctly: %w", m.Param, err)
	}
	if rs, ok := m.raw["RelayState"]; ok {
		m.HasRelay = true
		if m.RelayState, err = url.QueryUnescape(rs); err != nil {
			return nil, fmt.Errorf("RelayState is not URL-encoded correctly: %w", err)
		}
	}
	return m, nil
}

// checkRedirectSignature verifies the detached signature of the HTTP-Redirect
// binding. The signed octets are the parameters exactly as they were
// URL-encoded on the wire, in the order the specification fixes.
func checkRedirectSignature(cs *Checks, m *redirectMsg, trusted []*x509.Certificate) bool {
	const name, ref = "redirect binding signature", "SAML Bindings §3.4.4.1"
	if _, ok := m.raw["SigAlg"]; !ok {
		return false
	}
	signed := m.Param + "=" + m.raw[m.Param]
	if m.HasRelay {
		signed += "&RelayState=" + m.raw["RelayState"]
	}
	signed += "&SigAlg=" + m.raw["SigAlg"]
	alg, _ := url.QueryUnescape(m.raw["SigAlg"])
	sigB64, _ := url.QueryUnescape(m.raw["Signature"])
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) == 0 {
		cs.add(name, "fail", "Signature is missing or not base64", ref)
		return false
	}
	h, ok := redirectSigAlgs[alg]
	if !ok {
		cs.add(name, "fail", "unsupported SigAlg "+alg, ref)
		return false
	}
	if len(trusted) == 0 {
		cs.add(name, "warn", "signed with "+alg+", but no certificate was supplied to verify it (pass idp_metadata or idp_cert)", ref)
		return false
	}
	hh := h.New()
	hh.Write([]byte(signed))
	digest := hh.Sum(nil)
	for _, cert := range trusted {
		var verr error
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			verr = rsa.VerifyPKCS1v15(pub, h, digest, sig)
		case *ecdsa.PublicKey:
			if len(sig)%2 != 0 {
				verr = errors.New("bad ECDSA signature length")
			} else if !ecdsa.Verify(pub, digest, new(big.Int).SetBytes(sig[:len(sig)/2]), new(big.Int).SetBytes(sig[len(sig)/2:])) {
				verr = errors.New("ECDSA signature does not verify")
			}
		default:
			verr = errors.New("unsupported key type")
		}
		if verr == nil {
			cs.add(name, "pass", "valid "+alg+" signature by "+cert.Subject.String(), ref)
			if h == crypto.SHA1 {
				cs.add("redirect binding signature algorithm", "warn", "SHA-1 based signature ("+alg+")", "SAML Security Considerations")
			}
			return true
		}
	}
	cs.add(name, "fail", "the query-string signature does not verify against any trusted certificate", ref)
	return false
}

// ---- encryption algorithm hygiene ----

func encryptionAlgChecks(cs *Checks, enc *etree.Element) {
	var methods []*etree.Element
	findAll(enc, "EncryptionMethod", &methods)
	for _, m := range methods {
		alg := m.SelectAttrValue("Algorithm", "")
		switch {
		case strings.HasSuffix(alg, "rsa-1_5"):
			cs.add("assertion: key transport algorithm", "warn", "RSA PKCS#1 v1.5 key transport is open to padding-oracle attacks; use RSA-OAEP", "XML Encryption 1.1 §5.5.1")
		case strings.HasSuffix(alg, "-cbc"):
			cs.add("assertion: data encryption algorithm", "warn", "AES-CBC ("+alg+") is malleable and has been broken in XML Encryption; use AES-GCM", "XML Encryption 1.1 §5.2.4")
		case strings.HasSuffix(alg, "-gcm"):
			cs.add("assertion: data encryption algorithm", "pass", alg, "XML Encryption 1.1 §5.2.4")
		}
	}
}

// ---- Artifact binding ----

type samlArtifact struct {
	TypeCode, Index  int
	SourceID, Handle []byte
}

func parseArtifact(s string) (*samlArtifact, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("artifact is not base64: %w", err)
	}
	if len(b) < 4 {
		return nil, errors.New("artifact is too short")
	}
	a := &samlArtifact{TypeCode: int(binary.BigEndian.Uint16(b[0:2]))}
	if a.TypeCode == 4 {
		if len(b) != 44 {
			return nil, fmt.Errorf("a type 0x0004 artifact is 44 bytes, this one is %d", len(b))
		}
		a.Index = int(binary.BigEndian.Uint16(b[2:4]))
		a.SourceID, a.Handle = b[4:24], b[24:44]
	}
	return a, nil
}

// resolveArtifact checks an artifact, resolves it over the SOAP binding and
// returns the protocol message it stood for.
func resolveArtifact(c *Ctx, sp *spConfig, meta *idpMeta, trusted []*x509.Certificate, artifact string, cs *Checks) ([]byte, M, error) {
	info := M{}
	a, err := parseArtifact(artifact)
	if err != nil {
		cs.add("artifact: well-formed", "fail", err.Error(), "SAML Bindings §3.6.4")
		return nil, info, err
	}
	info["artifact"] = M{"type_code": fmt.Sprintf("0x%04x", a.TypeCode), "endpoint_index": a.Index, "source_id": hex.EncodeToString(a.SourceID)}
	if !cs.ok(a.TypeCode == 4, "artifact: type code 0x0004", fmt.Sprintf("0x%04x", a.TypeCode), "SAML Bindings §3.6.4") {
		return nil, info, errors.New("only type 0x0004 artifacts can be resolved")
	}
	ars := c.Str("ars_url")
	if meta != nil {
		sum := sha1.Sum([]byte(meta.EntityID))
		cs.ok(bytes.Equal(sum[:], a.SourceID), "artifact: SourceID is the IdP entity ID", "SHA-1 of "+meta.EntityID, "SAML Bindings §3.6.4")
		if ars == "" {
			if ars = meta.ARS[a.Index]; ars == "" {
				cs.add("artifact: endpoint index known", "fail", fmt.Sprintf("the metadata has no ArtifactResolutionService with index %d", a.Index), "SAML Bindings §3.6.4")
				return nil, info, errors.New("no artifact resolution service for this artifact; pass ars_url")
			}
			cs.add("artifact: endpoint index known", "pass", fmt.Sprintf("index %d -> %s", a.Index, ars), "SAML Bindings §3.6.4")
		}
	}
	if ars == "" {
		return nil, info, errors.New("pass idp_metadata or ars_url")
	}
	if err := c.allowDestination("the ArtifactResolve", ars); err != nil {
		return nil, info, err
	}

	id := newSAMLID()
	doc := etree.NewDocument()
	env := doc.CreateElement("SOAP-ENV:Envelope")
	env.CreateAttr("xmlns:SOAP-ENV", nsSOAP)
	body := env.CreateElement("SOAP-ENV:Body")
	reqDoc := etree.NewDocument()
	req := reqDoc.CreateElement("samlp:ArtifactResolve")
	req.CreateAttr("xmlns:samlp", nsSAMLP)
	req.CreateAttr("xmlns:saml", nsSAML)
	req.CreateAttr("ID", id)
	req.CreateAttr("Version", "2.0")
	req.CreateAttr("IssueInstant", samlNow())
	req.CreateAttr("Destination", ars)
	req.CreateElement("saml:Issuer").SetText(sp.EntityID)
	req.CreateElement("samlp:Artifact").SetText(strings.TrimSpace(artifact))
	if sp.Key != nil && sp.Cert != nil {
		if req, err = signEnvelopedAfterIssuer(sp, req); err != nil {
			return nil, info, err
		}
		info["artifact_resolve_signed"] = true
	} else {
		cs.add("ArtifactResolve signed", "info", "not signed (no sp_key/sp_cert); many IdPs require a signed request or mutual TLS", "SAML Bindings §3.6.5.1")
	}
	body.AddChild(req)
	payload, err := doc.WriteToString()
	if err != nil {
		return nil, info, err
	}
	res, err := c.do("POST", ars, map[string]string{"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "http://www.oasis-open.org/committees/security"}, []byte(payload))
	if err != nil {
		return nil, info, err
	}
	info["ars_url"], info["ars_status"] = ars, res.Status
	if !cs.ok(res.Status == http.StatusOK, "artifact resolution: HTTP 200", fmt.Sprintf("HTTP %d", res.Status), "SAML Bindings §3.2.3.3") {
		return nil, info, fmt.Errorf("artifact resolution returned HTTP %d", res.Status)
	}
	rdoc := etree.NewDocument()
	if err := rdoc.ReadFromBytes(res.Body); err != nil || rdoc.Root() == nil {
		cs.add("artifact resolution: SOAP response", "fail", "not XML", "SAML Bindings §3.2.3")
		return nil, info, errors.New("the artifact resolution response is not XML")
	}
	var found []*etree.Element
	findAll(rdoc.Root(), "ArtifactResponse", &found)
	if !cs.ok(len(found) == 1, "artifact resolution: ArtifactResponse present", "", "SAML Core §3.5.2") {
		return nil, info, errors.New("no ArtifactResponse in the SOAP body")
	}
	ar := found[0]
	code := kid(ar, "Status", "StatusCode")
	status := ""
	if code != nil {
		status = code.SelectAttrValue("Value", "")
	}
	cs.ok(status == samlStatusOK, "artifact response: status is Success", status, "SAML Core §3.5.2")
	cs.ok(ar.SelectAttrValue("InResponseTo", "") == id, "artifact response: InResponseTo matches the ArtifactResolve", "InResponseTo="+ar.SelectAttrValue("InResponseTo", ""), "SAML Core §3.2.2")
	if meta != nil {
		cs.ok(text(kid(ar, "Issuer")) == meta.EntityID, "artifact response: Issuer is the IdP entity ID", "Issuer="+text(kid(ar, "Issuer")), "SAML Core §3.2.2")
	}
	if signed, _ := checkSignature(cs, "artifact response", ar, trusted); !signed {
		cs.add("artifact response: signature", "info", "not signed; its integrity rests on the TLS connection to the resolution service", "SAML Bindings §3.6.5.2")
	}
	var msg *etree.Element
	for _, ch := range ar.ChildElements() {
		if ch.Tag != "Issuer" && ch.Tag != "Signature" && ch.Tag != "Status" && ch.Tag != "Extensions" {
			msg = ch
			break
		}
	}
	if !cs.ok(msg != nil, "artifact response: carries a message", "", "SAML Core §3.5.2") {
		return nil, info, errors.New("the artifact resolved to no message (already used or expired?)")
	}
	nsCtx, err := etreeutils.NSBuildParentContext(msg)
	if err != nil {
		return nil, info, err
	}
	detached, err := etreeutils.NSDetatch(nsCtx, msg)
	if err != nil {
		return nil, info, err
	}
	out := etree.NewDocument()
	out.SetRoot(detached)
	b, err := out.WriteToBytes()
	return b, info, err
}

// ---- Single Logout ----

func runSAMLLogout(c *Ctx) (M, error) {
	var meta *idpMeta
	var trusted []*x509.Certificate
	var err error
	if src := c.Str("idp_metadata"); src != "" {
		if meta, err = loadIDPMetadata(c, src); err != nil {
			return nil, err
		}
		trusted = meta.Certs
	}
	if s := c.Str("idp_cert"); s != "" {
		certs, err := loadCerts(s)
		if err != nil {
			return nil, fmt.Errorf("idp_cert: %w", err)
		}
		trusted = append(trusted, certs...)
	}
	binding := map[string]string{"redirect": bindRedirect, "post": bindPOST}[c.Str("binding")]
	slo := c.Str("slo_url")
	if slo == "" && meta != nil {
		if slo = meta.SLO[binding]; slo == "" {
			for _, b := range []string{bindRedirect, bindPOST} {
				if meta.SLO[b] != "" {
					slo, binding = meta.SLO[b], b
					break
				}
			}
		}
	}
	if slo == "" {
		return nil, errors.New("the IdP offers no SingleLogoutService; pass slo_url")
	}
	if err := c.allowDestination("the LogoutRequest", slo); err != nil {
		return nil, err
	}
	sp, err := loadSP(c)
	if err != nil {
		return nil, err
	}
	port, path := c.Int("slo_port"), c.Str("slo_path")
	spSLO := fmt.Sprintf("http://localhost:%d%s", port, path)

	r := &builtRequest{ID: newSAMLID(), Binding: binding, Destination: slo, RelayState: c.Str("relay_state"), Param: "SAMLRequest"}
	doc := etree.NewDocument()
	el := doc.CreateElement("samlp:LogoutRequest")
	el.CreateAttr("xmlns:samlp", nsSAMLP)
	el.CreateAttr("xmlns:saml", nsSAML)
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", samlNow())
	el.CreateAttr("Destination", slo)
	el.CreateElement("saml:Issuer").SetText(sp.EntityID)
	nid := el.CreateElement("saml:NameID")
	if f := c.Str("name_id_format"); f != "" {
		nid.CreateAttr("Format", f)
	}
	nid.SetText(c.Str("name_id"))
	if si := c.Str("session_index"); si != "" {
		el.CreateElement("samlp:SessionIndex").SetText(si)
	}
	if r, err = finishMessage(sp, doc, el, r, c.Bool("sign")); err != nil {
		return nil, err
	}

	type capture struct {
		vals     url.Values
		rawQuery string
	}
	ch := make(chan capture, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
		// The Redirect binding carries the message in the query, the POST
		// binding in the body. Take it from exactly one of them.
		var got capture
		switch req.Method {
		case http.MethodGet:
			got = capture{req.URL.Query(), req.URL.RawQuery}
		case http.MethodPost:
			if err := req.ParseForm(); err != nil {
				http.Error(w, "idpdbg: unreadable form", http.StatusBadRequest)
				return
			}
			if req.URL.Query().Has("SAMLResponse") {
				http.Error(w, "idpdbg: SAMLResponse in both the query and the body; refusing an ambiguous message", http.StatusBadRequest)
				return
			}
			got = capture{req.PostForm, ""}
		default:
			http.Error(w, "idpdbg: method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if got.vals.Get("SAMLResponse") == "" {
			http.Error(w, "idpdbg: expected a SAMLResponse", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, donePage)
		select {
		case ch <- got:
		default:
		}
	})
	start := r.RedirectURL
	if binding == bindPOST {
		mux.HandleFunc("/saml/slo-start", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, r.postForm())
		})
		start = fmt.Sprintf("http://localhost:%d/saml/slo-start", port)
	}
	stop, err := serveLoopback(port, mux)
	if err != nil {
		return nil, err
	}
	defer stop()
	c.Log("Local SingleLogoutService listening on %s; it must be registered with the IdP", spSLO)

	resultCh := make(chan url.Values, 1)
	var got capture
	go func() {
		select {
		case got = <-ch:
			resultCh <- got.vals
		case <-c.Done():
		}
	}()
	if _, err := awaitBrowser(c, start, resultCh); err != nil {
		return M{"request": r.describe()}, err
	}

	var pre Checks
	pre.warn(r.Signed, "LogoutRequest signed", map[bool]string{true: "signed with sp_key", false: "the request was not signed (pass sign with sp_key); most IdPs reject unsigned logout requests"}[r.Signed], "SAML Profiles §4.4.4.1")
	redirectSigned := false
	message, relay := got.vals.Get("SAMLResponse"), got.vals.Get("RelayState")
	if got.rawQuery != "" {
		m, err := parseRedirect(got.rawQuery)
		if err != nil {
			pre.add("redirect binding: unambiguous query", "fail", err.Error(), "SAML Bindings §3.4.4.1")
			return M{"checks": pre, "request": r.describe()}, err
		}
		message, relay = m.Message, m.RelayState
		redirectSigned = checkRedirectSignature(&pre, m, trusted)
	}
	xmlBytes, enc, err := decodeSAMLInput(message)
	if err != nil {
		return nil, err
	}
	ex := &samlExpect{Trusted: trusted, ACS: spSLO, InResponseTo: r.ID, Leeway: time.Duration(c.Int("leeway")) * time.Second}
	out, err := analyzeSAML(xmlBytes, ex)
	if err != nil {
		return nil, err
	}
	cs := append(pre, out["checks"].(Checks)...)
	cs.ok(out["message_type"] == "LogoutResponse", "response is a LogoutResponse", fmt.Sprint(out["message_type"]), "SAML Core §3.7.2")
	if meta != nil {
		cs.ok(out["issuer"] == meta.EntityID, "response: Issuer is the IdP entity ID", fmt.Sprint(out["issuer"]), "SAML Profiles §4.4.4.2")
	}
	enveloped := false
	for _, ck := range cs {
		if ck.Name == "logoutresponse: signature" && ck.Status == "pass" {
			enveloped = true
		}
	}
	if !redirectSigned && !enveloped {
		cs.add("LogoutResponse signed", "warn", "no verified signature on the LogoutResponse", "SAML Profiles §4.4.4.2")
	}
	if r.RelayState != "" {
		cs.ok(relay == r.RelayState, "RelayState echoed unchanged", "RelayState="+relay, "SAML Bindings §3.4.3")
	}
	out["checks"], out["encoding"], out["request"], out["sp_slo_url"] = cs, enc, r.describe(), spSLO
	return out, nil
}

// ---- operations ----

func init() {
	join := joinParams
	idp, sp := samlIDPParams, samlSPParams
	leeway := Param{Name: "leeway", Type: "int", Desc: "Clock skew allowance in seconds", Default: 120}
	register(
		&Op{
			Name:    "saml.logout",
			Browser: true,
			Summary: "Run SP-initiated SAML Single Logout: send a LogoutRequest through the browser (Redirect or POST binding), capture the LogoutResponse on a local SingleLogoutService and check its status, InResponseTo, issuer and signature (enveloped or Redirect-binding). Use the NameID and SessionIndex from a saml login.",
			Params: join(idp, sp, []Param{
				{Name: "slo_url", Type: "string", Desc: "IdP SingleLogoutService URL, overriding metadata"},
				{Name: "binding", Type: "string", Enum: []string{"redirect", "post"}, Desc: "Binding used to send the LogoutRequest", Default: "redirect"},
				{Name: "name_id", Type: "string", Required: true, Desc: "NameID of the session to end"},
				{Name: "name_id_format", Type: "string", Desc: "Format of that NameID"},
				{Name: "session_index", Type: "string", Desc: "SessionIndex from the AuthnStatement"},
				{Name: "sign", Type: "bool", Desc: "Sign the LogoutRequest with sp_key (recommended)"},
				{Name: "relay_state", Type: "string", Desc: "RelayState to send"},
				{Name: "slo_port", Type: "int", Desc: "Loopback port for the local SingleLogoutService", Default: 8766},
				{Name: "slo_path", Type: "string", Desc: "Path of the local SingleLogoutService", Default: "/saml/slo"},
				leeway}, browserParams),
			Run: runSAMLLogout,
		},
		&Op{
			Name:    "saml.resolve_artifact",
			Summary: "Resolve a SAML artifact (HTTP-Artifact binding): decode it, check its SourceID against the IdP, send a (signed) ArtifactResolve over SOAP to the IdP's ArtifactResolutionService, and analyse the message it returns like saml decode. Artifacts are single-use.",
			Params: join([]Param{{Name: "artifact", Type: "string", Required: true, Desc: "The SAMLart value"},
				{Name: "ars_url", Type: "string", Desc: "ArtifactResolutionService URL, overriding metadata"}},
				idp, sp, []Param{
					{Name: "mtls_cert", Type: "string", Path: true, Desc: "Client certificate for mutual TLS to the resolution service"},
					{Name: "mtls_key", Type: "string", Path: true, Desc: "Private key for mtls_cert"},
					{Name: "acs_url", Type: "string", Desc: "Expected Destination / Recipient of the resolved Response"},
					{Name: "in_response_to", Type: "string", Desc: "ID of the AuthnRequest the resolved Response must answer"},
					leeway}),
			Run: func(c *Ctx) (M, error) {
				var meta *idpMeta
				var trusted []*x509.Certificate
				var err error
				if src := c.Str("idp_metadata"); src != "" {
					if meta, err = loadIDPMetadata(c, src); err != nil {
						return nil, err
					}
					trusted = meta.Certs
				}
				if s := c.Str("idp_cert"); s != "" {
					certs, err := loadCerts(s)
					if err != nil {
						return nil, fmt.Errorf("idp_cert: %w", err)
					}
					trusted = append(trusted, certs...)
				}
				sp, err := loadSP(c)
				if err != nil {
					return nil, err
				}
				var pre Checks
				xmlBytes, info, err := resolveArtifact(c, sp, meta, trusted, c.Str("artifact"), &pre)
				if err != nil {
					info["checks"] = pre
					return info, err
				}
				ex, err := samlExpectFrom(c, trusted, false)
				if err != nil {
					return nil, err
				}
				out, err := analyzeSAML(xmlBytes, ex)
				if err != nil {
					return nil, err
				}
				for k, v := range info {
					out[k] = v
				}
				out["checks"] = append(pre, out["checks"].(Checks)...)
				return out, nil
			},
		},
	)
}
