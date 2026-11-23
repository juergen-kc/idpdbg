package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// WS-Federation passive requestor profile and WS-Trust: SOAP, RSTR analysis,
// SAML 1.1 and 2.0 tokens.

const (
	nsSAML11       = "urn:oasis:names:tc:SAML:1.0:assertion"
	nsTrust13      = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
	nsTrust2005    = "http://schemas.xmlsoap.org/ws/2005/02/trust"
	nsSOAP12       = "http://www.w3.org/2003/05/soap-envelope"
	nsSOAP11       = "http://schemas.xmlsoap.org/soap/envelope/"
	nsWSA          = "http://www.w3.org/2005/08/addressing"
	nsWSSE         = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
	nsWSU          = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
	nsWSP          = "http://schemas.xmlsoap.org/ws/2004/09/policy"
	tokenSAML2     = "urn:oasis:names:tc:SAML:2.0:assertion"
	tokenSAML11    = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"
	wsfedRef       = "WS-Federation 1.2 §13"
	saml11CMBearer = "urn:oasis:names:tc:SAML:1.0:cm:bearer"
)

// ---- SAML 1.1 assertions ----

func describeSAML11(cs *Checks, a *etree.Element, ex *samlExpect) M {
	const ref = "SAML 1.1 Core"
	out := M{"version": "SAML 1.1", "id": a.SelectAttrValue("AssertionID", ""), "issuer": a.SelectAttrValue("Issuer", ""), "issue_instant": a.SelectAttrValue("IssueInstant", "")}
	cs.ok(a.SelectAttrValue("MajorVersion", "") == "1" && a.SelectAttrValue("MinorVersion", "") == "1", "assertion: SAML 1.1", "", ref+" §2.3.2")
	if signed, _ := checkSignatureID(cs, "assertion", a, ex.Trusted, "AssertionID"); !signed {
		cs.add("assertion: signed", "fail", "the token carries no signature, so nothing vouches for it", ref+" §5")
	}
	now := time.Now()
	if cond := kid(a, "Conditions"); cond != nil {
		var auds []string
		for _, arc := range kids(cond, "AudienceRestrictionCondition") {
			for _, au := range kids(arc, "Audience") {
				auds = append(auds, text(au))
			}
		}
		out["conditions"] = M{"not_before": cond.SelectAttrValue("NotBefore", ""), "not_on_or_after": cond.SelectAttrValue("NotOnOrAfter", ""), "audiences": auds}
		if t, ok := samlTime(cond.SelectAttrValue("NotBefore", "")); ok {
			cs.ok(!now.Add(ex.Leeway).Before(t), "assertion: Conditions NotBefore reached", t.Format(time.RFC3339), ref+" §2.4.2")
		}
		if t, ok := samlTime(cond.SelectAttrValue("NotOnOrAfter", "")); ok {
			cs.ok(now.Before(t.Add(ex.Leeway)), "assertion: Conditions not expired", t.Format(time.RFC3339)+" ("+relTime(t)+")", ref+" §2.4.2")
		}
		if ex.Audience != "" {
			cs.ok(contains(auds, ex.Audience), "assertion: audience includes the realm", "audiences="+strings.Join(auds, " "), ref+" §2.4.3")
		}
	} else {
		cs.add("assertion: Conditions present", "warn", "no validity window or audience", ref+" §2.4")
	}
	var subj *etree.Element
	for _, st := range []string{"AuthenticationStatement", "AttributeStatement"} {
		if s := kid(a, st, "Subject"); s != nil && subj == nil {
			subj = s
		}
	}
	if nid := kid(subj, "NameIdentifier"); nid != nil {
		out["name_id"] = M{"value": text(nid), "format": nid.SelectAttrValue("Format", "")}
	}
	if cm := text(kid(subj, "SubjectConfirmation", "ConfirmationMethod")); cm != "" {
		out["confirmation_method"] = cm
		if cm != saml11CMBearer {
			cs.add("assertion: bearer confirmation", "info", "confirmation method "+cm+": the holder must prove possession of a key", ref+" §2.4.2.3")
		}
	}
	if as := kid(a, "AuthenticationStatement"); as != nil {
		out["authentication"] = M{"method": as.SelectAttrValue("AuthenticationMethod", ""), "instant": as.SelectAttrValue("AuthenticationInstant", "")}
	}
	attrs := M{}
	for _, st := range kids(a, "AttributeStatement") {
		for _, at := range kids(st, "Attribute") {
			var vals []string
			for _, v := range kids(at, "AttributeValue") {
				vals = append(vals, text(v))
			}
			name := at.SelectAttrValue("AttributeName", "")
			if ns := at.SelectAttrValue("AttributeNamespace", ""); ns != "" {
				name = ns + "/" + name
			}
			attrs[name] = vals
		}
	}
	if len(attrs) > 0 {
		out["attributes"] = attrs
	}
	return out
}

// ---- RequestSecurityTokenResponse ----

func wsuTime(el *etree.Element) (time.Time, bool) { return samlTime(text(el)) }

// analyzeRSTR checks a RequestSecurityTokenResponse and the token inside it.
func analyzeRSTR(cs *Checks, root *etree.Element, ex *samlExpect, ref string) (M, error) {
	var rstrs []*etree.Element
	if root.Tag == "RequestSecurityTokenResponse" {
		rstrs = []*etree.Element{root}
	}
	findAll(root, "RequestSecurityTokenResponse", &rstrs)
	if len(rstrs) == 0 {
		return nil, errors.New("no RequestSecurityTokenResponse found")
	}
	r := rstrs[0]
	out := M{"trust_namespace": r.NamespaceURI()}
	if v := text(kid(r, "TokenType")); v != "" {
		out["token_type"] = v
	}
	if v := text(kid(r, "KeyType")); v != "" {
		out["key_type"] = v
	}
	now := time.Now()
	if lt := kid(r, "Lifetime"); lt != nil {
		created, _ := wsuTime(kid(lt, "Created"))
		expires, ok := wsuTime(kid(lt, "Expires"))
		out["lifetime"] = M{"created": text(kid(lt, "Created")), "expires": text(kid(lt, "Expires"))}
		if ok {
			cs.ok(now.Before(expires.Add(ex.Leeway)) && !now.Add(ex.Leeway).Before(created), "RSTR lifetime covers now", "expires "+relTime(expires), ref)
		}
	}
	if addr := text(kid(r, "AppliesTo", "EndpointReference", "Address")); addr != "" || ex.Audience != "" {
		out["applies_to"] = addr
		if ex.Audience != "" {
			cs.ok(addr == ex.Audience, "RSTR AppliesTo is the requested realm", "AppliesTo="+addr, ref)
		}
	}
	rst := kid(r, "RequestedSecurityToken")
	if !cs.ok(rst != nil && len(rst.ChildElements()) > 0, "RSTR carries a token", "", ref) {
		return out, nil
	}
	describeToken(cs, rst.ChildElements()[0], ex, ref, out, true)
	return out, nil
}

// describeToken checks the token in an RSTR; an encrypted token is
// decrypted with the relying party's key and checked in turn.
func describeToken(cs *Checks, tok *etree.Element, ex *samlExpect, ref string, out M, outer bool) {
	switch {
	case tok.Tag == "Assertion" && tok.NamespaceURI() == nsSAML11:
		out["token"] = describeSAML11(cs, tok, ex)
	case tok.Tag == "Assertion":
		nsCtx, err := etreeutils.NSBuildParentContext(tok)
		if err != nil {
			cs.add("token", "fail", err.Error(), ref)
			return
		}
		det, err := etreeutils.NSDetatch(nsCtx, tok)
		if err != nil {
			cs.add("token", "fail", err.Error(), ref)
			return
		}
		d := etree.NewDocument()
		d.SetRoot(det)
		b, _ := d.WriteToBytes()
		a, err := analyzeSAML(b, ex)
		if err != nil {
			cs.add("token", "fail", err.Error(), ref)
			return
		}
		*cs = append(*cs, a["checks"].(Checks)...)
		out["token"] = a["assertions"]
	case outer && (tok.Tag == "EncryptedData" || tok.Tag == "EncryptedAssertion"):
		out["token_encrypted"] = true
		encryptionAlgChecks(cs, tok)
		if ex.SPKey == nil {
			cs.add("token: decryption", "warn", "the token is encrypted to the relying party; pass rp_key (its private key) to decrypt and check it", "XML Encryption 1.1 §4")
			return
		}
		a, err := decryptAssertion(tok, ex.SPKey)
		if err != nil {
			cs.add("token: decryption", "fail", err.Error(), "XML Encryption 1.1 §4")
			return
		}
		cs.add("token: decryption", "pass", "decrypted with the relying party's private key", "XML Encryption 1.1 §4")
		out["decrypted_token_xml"] = prettyXML(a)
		describeToken(cs, a, ex, ref, out, false)
	default:
		cs.add("token type", "info", "token element "+tok.Tag+" is shown but not analysed", ref)
	}
}

// ---- WS-Federation ----

type fedMeta struct {
	EntityID, Passive, STS string
	Certs                  []*x509.Certificate
	TokenTypes             []string
	Root                   *etree.Element
}

func loadFedMetadata(c *Ctx, src string) (*fedMeta, error) {
	var b []byte
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		res, err := c.do("GET", src, map[string]string{"Accept": "application/samlmetadata+xml, application/xml"}, nil)
		if err != nil {
			return nil, err
		}
		if res.Status != 200 {
			return nil, fmt.Errorf("metadata %s returned HTTP %d", src, res.Status)
		}
		b = res.Body
	} else {
		b = []byte(src)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(b); err != nil || doc.Root() == nil {
		return nil, fmt.Errorf("metadata is not XML: %v", err)
	}
	ed := doc.Root()
	m := &fedMeta{EntityID: ed.SelectAttrValue("entityID", ""), Root: ed}
	for _, rd := range kids(ed, "RoleDescriptor") {
		if !strings.Contains(rd.SelectAttrValue("xsi:type", rd.SelectAttrValue("type", "")), "SecurityTokenServiceType") {
			continue
		}
		m.Passive = text(kid(rd, "PassiveRequestorEndpoint", "EndpointReference", "Address"))
		m.STS = text(kid(rd, "SecurityTokenServiceEndpoint", "EndpointReference", "Address"))
		for _, t := range kids(kid(rd, "TokenTypesOffered"), "TokenType") {
			m.TokenTypes = append(m.TokenTypes, t.SelectAttrValue("Uri", ""))
		}
		for _, kd := range kids(rd, "KeyDescriptor") {
			if kd.SelectAttrValue("use", "signing") != "signing" {
				continue
			}
			var ce []*etree.Element
			findAll(kd, "X509Certificate", &ce)
			for _, x := range ce {
				if cert, err := parseCertB64(text(x)); err == nil {
					m.Certs = append(m.Certs, cert)
				}
			}
		}
	}
	if m.Passive == "" && m.STS == "" {
		return nil, errors.New("no SecurityTokenServiceType RoleDescriptor with a passive or STS endpoint in the metadata")
	}
	return m, nil
}

func wsfedTrust(c *Ctx) (*fedMeta, []*x509.Certificate, error) {
	var meta *fedMeta
	var trusted []*x509.Certificate
	var err error
	if src := c.Str("metadata"); src != "" {
		if meta, err = loadFedMetadata(c, src); err != nil {
			return nil, nil, err
		}
		trusted = meta.Certs
	}
	if s := c.Str("sts_cert"); s != "" {
		certs, err := loadCerts(s)
		if err != nil {
			return nil, nil, fmt.Errorf("sts_cert: %w", err)
		}
		trusted = append(trusted, certs...)
	}
	return meta, trusted, nil
}

// wsExpect is what a token for audience must satisfy, with the relying
// party's key to decrypt it.
func wsExpect(c *Ctx, trusted []*x509.Certificate, audience string) (*samlExpect, error) {
	ex := &samlExpect{Trusted: trusted, Audience: audience, Leeway: time.Duration(c.Int("leeway")) * time.Second}
	if s := c.Str("rp_key"); s != "" {
		k, err := loadRSAKey(s)
		if err != nil {
			return nil, fmt.Errorf("rp_key: %w", err)
		}
		ex.SPKey = k
	}
	return ex, nil
}

func runWSFedLogin(c *Ctx) (M, error) {
	meta, trusted, err := wsfedTrust(c)
	if err != nil {
		return nil, err
	}
	sts := c.Str("sts_url")
	if sts == "" && meta != nil {
		sts = meta.Passive
	}
	if sts == "" {
		return nil, errors.New("pass metadata or sts_url")
	}
	port, path := c.Int("reply_port"), c.Str("reply_path")
	wreply := fmt.Sprintf("http://localhost:%d%s", port, path)
	wctx := randToken(12)
	u, err := url.Parse(sts)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("wa", "wsignin1.0")
	q.Set("wtrealm", c.Str("wtrealm"))
	q.Set("wreply", wreply)
	q.Set("wctx", wctx)
	q.Set("wct", time.Now().UTC().Format(samlTimeLayout))
	for _, n := range []string{"whr", "wauth", "wfresh"} {
		if v := c.Str(n); v != "" {
			q.Set(n, v)
		}
	}
	u.RawQuery = q.Encode()
	ch := make(chan url.Values, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.ParseForm() != nil || r.PostForm.Get("wresult") == "" {
			http.Error(w, "idpdbg: expected a POST with wresult", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, donePage)
		select {
		case ch <- r.PostForm:
		default:
		}
	})
	stop, err := serveLoopback(port, mux)
	if err != nil {
		return nil, err
	}
	defer stop()
	c.Log("Listening for the token on %s (realm %q); register both with the STS", wreply, c.Str("wtrealm"))
	vals, err := awaitBrowser(c, u.String(), ch)
	if err != nil {
		return M{"signin_url": u.String()}, err
	}
	var cs Checks
	cs.ok(vals.Get("wa") == "wsignin1.0", "wa is wsignin1.0", "wa="+vals.Get("wa"), wsfedRef)
	cs.ok(vals.Get("wctx") == wctx, "wctx returned unchanged", "", wsfedRef)
	ex, err := wsExpect(c, trusted, c.Str("wtrealm"))
	if err != nil {
		return nil, err
	}
	out, err := analyzeWResult(&cs, vals.Get("wresult"), ex)
	if out == nil {
		out = M{}
	}
	out["signin_url"], out["wreply"] = u.String(), wreply
	if meta != nil {
		if tok, ok := out["token"].(M); ok {
			cs.ok(tok["issuer"] == meta.EntityID, "token issuer is the STS entity ID", fmt.Sprint(tok["issuer"]), wsfedRef)
		}
	}
	out["checks"] = cs
	return out, err
}

func analyzeWResult(cs *Checks, wresult string, ex *samlExpect) (M, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(wresult); err != nil || doc.Root() == nil {
		cs.add("wresult is XML", "fail", fmt.Sprint(err), wsfedRef)
		return nil, nil
	}
	out, err := analyzeRSTR(cs, doc.Root(), ex, wsfedRef)
	if out != nil {
		if a, ok := out["token"].([]M); ok && len(a) == 1 {
			out["token"] = a[0]
		}
		out["wresult_xml"] = prettyXML(doc.Root())
	}
	return out, err
}

// ---- WS-Trust ----

type trustVersion struct {
	NS, IssueAction, ValidateAction, Bearer, StatusType string
}

var trustVersions = map[string]trustVersion{
	"1.3":  {nsTrust13, nsTrust13 + "/RST/Issue", nsTrust13 + "/RST/Validate", nsTrust13 + "/Bearer", nsTrust13 + "/RSTR/Status"},
	"2005": {nsTrust2005, nsTrust2005 + "/RST/Issue", nsTrust2005 + "/RST/Validate", "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey", nsTrust2005 + "/RSTR/Status"},
}

// soapCall wraps body in a SOAP envelope with WS-Addressing and a
// WS-Security UsernameToken, posts it, and returns the response root.
func soapCall(c *Ctx, endpoint, action string, body *etree.Element) (*etree.Element, int, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, 0, err
	}
	if c.Str("username") != "" && u.Scheme != "https" && !isLoopbackHost(u.Hostname()) {
		return nil, 0, errors.New("refusing to send a UsernameToken password over plain HTTP; use the STS's https endpoint")
	}
	soapNS, ctype := nsSOAP12, "application/soap+xml; charset=utf-8; action=\""+action+"\""
	if c.Str("soap") == "1.1" {
		soapNS, ctype = nsSOAP11, "text/xml; charset=utf-8"
	}
	doc := etree.NewDocument()
	env := doc.CreateElement("s:Envelope")
	env.CreateAttr("xmlns:s", soapNS)
	env.CreateAttr("xmlns:a", nsWSA)
	env.CreateAttr("xmlns:u", nsWSU)
	hdr := env.CreateElement("s:Header")
	act := hdr.CreateElement("a:Action")
	act.CreateAttr("s:mustUnderstand", "1")
	act.SetText(action)
	hdr.CreateElement("a:MessageID").SetText("urn:uuid:" + uuid.NewString())
	hdr.CreateElement("a:ReplyTo").CreateElement("a:Address").SetText(nsWSA + "/anonymous")
	to := hdr.CreateElement("a:To")
	to.CreateAttr("s:mustUnderstand", "1")
	to.SetText(endpoint)
	sec := hdr.CreateElement("o:Security")
	sec.CreateAttr("s:mustUnderstand", "1")
	sec.CreateAttr("xmlns:o", nsWSSE)
	ts := sec.CreateElement("u:Timestamp")
	ts.CreateAttr("u:Id", "_0")
	now := time.Now().UTC()
	ts.CreateElement("u:Created").SetText(now.Format("2006-01-02T15:04:05.000Z"))
	ts.CreateElement("u:Expires").SetText(now.Add(5 * time.Minute).Format("2006-01-02T15:04:05.000Z"))
	if user := c.Str("username"); user != "" {
		ut := sec.CreateElement("o:UsernameToken")
		ut.CreateAttr("u:Id", "uuid-"+uuid.NewString())
		ut.CreateElement("o:Username").SetText(user)
		pw := ut.CreateElement("o:Password")
		pw.CreateAttr("Type", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText")
		pw.SetText(c.Str("password"))
	}
	env.CreateElement("s:Body").AddChild(body)
	payload, _ := doc.WriteToBytes()
	hdrs := map[string]string{"Content-Type": ctype}
	if c.Str("soap") == "1.1" {
		hdrs["SOAPAction"] = `"` + action + `"`
	}
	res, err := c.do("POST", endpoint, hdrs, payload)
	if err != nil {
		return nil, 0, err
	}
	rd := etree.NewDocument()
	if err := rd.ReadFromBytes(res.Body); err != nil || rd.Root() == nil {
		return nil, res.Status, fmt.Errorf("the STS answered HTTP %d with a body that is not XML", res.Status)
	}
	return rd.Root(), res.Status, nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func soapFault(root *etree.Element) string {
	var f []*etree.Element
	findAll(root, "Fault", &f)
	if len(f) == 0 {
		return ""
	}
	var parts []string
	var codes []*etree.Element
	findAll(f[0], "Value", &codes)
	for _, v := range codes {
		parts = append(parts, text(v))
	}
	if fc := text(kid(f[0], "faultcode")); fc != "" {
		parts = append(parts, fc)
	}
	var reasons []*etree.Element
	findAll(f[0], "Text", &reasons)
	for _, r := range reasons {
		parts = append(parts, text(r))
	}
	if fs := text(kid(f[0], "faultstring")); fs != "" {
		parts = append(parts, fs)
	}
	return strings.Join(parts, " | ")
}

func trustRST(v trustVersion, requestType string) *etree.Element {
	rst := etree.NewElement("trust:RequestSecurityToken")
	rst.CreateAttr("xmlns:trust", v.NS)
	rst.CreateElement("trust:RequestType").SetText(v.NS + "/" + requestType)
	return rst
}

func runWSTrustIssue(c *Ctx) (M, error) {
	v := trustVersions[c.Str("version")]
	_, trusted, err := wsfedTrust(c)
	if err != nil {
		return nil, err
	}
	rst := trustRST(v, "Issue")
	ap := rst.CreateElement("wsp:AppliesTo")
	ap.CreateAttr("xmlns:wsp", nsWSP)
	epr := ap.CreateElement("a:EndpointReference")
	epr.CreateAttr("xmlns:a", nsWSA)
	epr.CreateElement("a:Address").SetText(c.Str("applies_to"))
	rst.CreateElement("trust:KeyType").SetText(v.Bearer)
	rst.CreateElement("trust:TokenType").SetText(map[string]string{"saml2": tokenSAML2, "saml11": tokenSAML11}[c.Str("token_type")])
	root, status, err := soapCall(c, c.Str("endpoint"), v.IssueAction, rst)
	var cs Checks
	out := M{"endpoint": c.Str("endpoint"), "status": status}
	defer func() { out["checks"] = cs }()
	if err != nil {
		cs.add("STS response", "fail", err.Error(), "WS-Trust 1.3 §4")
		return out, nil
	}
	if f := soapFault(root); f != "" {
		cs.add("STS response", "fail", "SOAP fault: "+f, "WS-Trust 1.3 §11")
		return out, nil
	}
	cs.ok(status == 200, "STS response", fmt.Sprintf("HTTP %d", status), "WS-Trust 1.3 §4")
	ex, err := wsExpect(c, trusted, c.Str("applies_to"))
	if err != nil {
		return nil, err
	}
	r, err := analyzeRSTR(&cs, root, ex, "WS-Trust 1.3 §4.4")
	for k, val := range r {
		out[k] = val
	}
	if r != nil {
		cs.ok(r["trust_namespace"] == v.NS, "response uses the requested WS-Trust version", fmt.Sprint(r["trust_namespace"]), "WS-Trust 1.3 §1.4")
		if a, ok := r["token"].([]M); ok && len(a) == 1 {
			out["token"] = a[0]
		}
	}
	return out, err
}

func runWSTrustValidate(c *Ctx) (M, error) {
	v := trustVersions[c.Str("version")]
	tok := etree.NewDocument()
	if err := tok.ReadFromString(c.Str("token")); err != nil || tok.Root() == nil {
		return nil, errors.New("token must be the token XML (e.g. a SAML assertion)")
	}
	rst := trustRST(v, "Validate")
	rst.CreateElement("trust:TokenType").SetText(v.StatusType)
	rst.CreateElement("trust:ValidateTarget").AddChild(tok.Root())
	root, status, err := soapCall(c, c.Str("endpoint"), v.ValidateAction, rst)
	var cs Checks
	out := M{"endpoint": c.Str("endpoint"), "status": status}
	defer func() { out["checks"] = cs }()
	if err != nil {
		cs.add("STS response", "fail", err.Error(), "WS-Trust 1.3 §7")
		return out, nil
	}
	if f := soapFault(root); f != "" {
		cs.add("STS response", "fail", "SOAP fault: "+f, "WS-Trust 1.3 §11")
		return out, nil
	}
	var st []*etree.Element
	findAll(root, "Status", &st)
	if !cs.ok(len(st) > 0, "validation status returned", "", "WS-Trust 1.3 §7") {
		return out, nil
	}
	code := text(kid(st[0], "Code"))
	out["status_code"], out["reason"] = code, text(kid(st[0], "Reason"))
	cs.ok(strings.HasSuffix(code, "/status/valid"), "the STS says the token is valid", code+" "+text(kid(st[0], "Reason")), "WS-Trust 1.3 §7")
	return out, nil
}

func init() {
	trustAuth := []Param{
		{Name: "username", Type: "string", Desc: "UsernameToken user (e.g. user@domain for AD FS usernamemixed)"},
		{Name: "password", Type: "string", Secret: true, Desc: "UsernameToken password (prefer env IDPDBG_PASSWORD or a profile); only sent over https"},
		{Name: "version", Type: "string", Enum: []string{"1.3", "2005"}, Desc: "WS-Trust version", Default: "1.3"},
		{Name: "soap", Type: "string", Enum: []string{"1.2", "1.1"}, Desc: "SOAP version", Default: "1.2"},
	}
	stsTrust := []Param{
		{Name: "metadata", Type: "string", Path: true, Desc: "Federation metadata (URL, path or inline XML) for the STS signing certificates"},
		{Name: "sts_cert", Type: "string", Path: true, Desc: "STS signing certificate (PEM)"},
		{Name: "leeway", Type: "int", Desc: "Clock skew allowance in seconds", Default: 120},
		{Name: "rp_key", Type: "string", Path: true, Explicit: true, Desc: "Relying party RSA private key (PEM inline or a path) to decrypt a token the STS encrypted to the relying party's certificate, as AD FS does when an encryption certificate is configured"},
	}
	join := joinParams
	register(
		&Op{
			Name:    "wsfed.metadata",
			Summary: "Load WS-Federation metadata: the STS entity ID, passive requestor and STS endpoints, offered token types and signing certificates.",
			Params:  []Param{{Name: "metadata", Type: "string", Required: true, Path: true, Desc: "URL, path or inline XML (e.g. https://adfs.example.com/FederationMetadata/2007-06/FederationMetadata.xml)"}},
			Run: func(c *Ctx) (M, error) {
				m, err := loadFedMetadata(c, c.Str("metadata"))
				if err != nil {
					return nil, err
				}
				var cs Checks
				cs.ok(m.Passive != "", "passive requestor endpoint present", m.Passive, "WS-Federation 1.2 §3.1.2.3")
				cs.ok(len(m.Certs) > 0, "signing certificate present", fmt.Sprintf("%d", len(m.Certs)), "WS-Federation 1.2 §3.1.2.1")
				var certs []M
				for _, ce := range m.Certs {
					certs = append(certs, certInfo(ce))
					certChecks(&cs, ce, "signing")
				}
				checkSignature(&cs, "metadata", m.Root, nil)
				return M{"entity_id": m.EntityID, "passive_endpoint": m.Passive, "sts_endpoint": m.STS, "token_types": m.TokenTypes, "signing_certificates": certs, "checks": cs}, nil
			},
		},
		&Op{
			Name:    "wsfed.login",
			Browser: true,
			Summary: "Run WS-Federation passive sign-in (wa=wsignin1.0): send the browser to the STS, capture the token posted to a local wreply, and check wctx, the RSTR (lifetime, AppliesTo) and the SAML 1.1 or 2.0 token (signature, audience = wtrealm, validity), decrypting it with rp_key if the STS encrypted it. Blocks until the person signs in.",
			Params: join([]Param{
				{Name: "sts_url", Type: "string", Desc: "Passive requestor endpoint, overriding metadata (e.g. https://adfs.example.com/adfs/ls/)"},
				{Name: "wtrealm", Type: "string", Desc: "Realm (relying party identifier) registered at the STS", Default: "urn:idpdbg"},
				{Name: "whr", Type: "string", Desc: "Home realm hint"},
				{Name: "wauth", Type: "string", Desc: "Requested authentication method"},
				{Name: "wfresh", Type: "string", Desc: "Maximum age of the sign-in in minutes (0 forces re-authentication)"},
				{Name: "reply_port", Type: "int", Desc: "Loopback port for wreply", Default: 8767},
				{Name: "reply_path", Type: "string", Desc: "Path for wreply", Default: "/wsfed"}}, stsTrust, browserParams),
			Run: runWSFedLogin,
		},
		&Op{
			Name:    "wsfed.decode",
			Summary: "Analyse a WS-Federation wresult (RequestSecurityTokenResponse) offline: lifetime, AppliesTo, and the SAML 1.1 or 2.0 token with its signature, audience and validity; an encrypted token (xenc:EncryptedData, as AD FS sends it, or an EncryptedAssertion) is decrypted with rp_key and its algorithms checked.",
			Params: join([]Param{
				{Name: "wresult", Type: "string", Required: true, File: true, Desc: "The wresult XML (CLI: @file or - for stdin)"},
				{Name: "wtrealm", Type: "string", Desc: "Expected realm (AppliesTo and audience)"}}, stsTrust),
			Run: func(c *Ctx) (M, error) {
				_, trusted, err := wsfedTrust(c)
				if err != nil {
					return nil, err
				}
				var cs Checks
				ex, err := wsExpect(c, trusted, c.Str("wtrealm"))
				if err != nil {
					return nil, err
				}
				out, err := analyzeWResult(&cs, c.Str("wresult"), ex)
				if out == nil {
					out = M{}
				}
				out["checks"] = cs
				return out, err
			},
		},
		&Op{
			Name:    "wsfed.signout_url",
			Summary: "Build a WS-Federation sign-out URL (wa=wsignout1.0) with an optional wreply.",
			Params: []Param{
				{Name: "sts_url", Type: "string", Required: true, Desc: "Passive requestor endpoint"},
				{Name: "wtrealm", Type: "string", Desc: "Realm", Default: "urn:idpdbg"},
				{Name: "wreply", Type: "string", Desc: "Where to return after sign-out"}},
			Run: func(c *Ctx) (M, error) {
				u, err := url.Parse(c.Str("sts_url"))
				if err != nil {
					return nil, err
				}
				q := u.Query()
				q.Set("wa", "wsignout1.0")
				q.Set("wtrealm", c.Str("wtrealm"))
				if r := c.Str("wreply"); r != "" {
					q.Set("wreply", r)
				}
				u.RawQuery = q.Encode()
				return M{"signout_url": u.String(), "html_link": `<a href="` + html.EscapeString(u.String()) + `">Sign out</a>`}, nil
			},
		},
		&Op{
			Name:    "wstrust.issue",
			Summary: "Request a token from a WS-Trust STS (RST Issue over SOAP with a WS-Security UsernameToken, as AD FS usernamemixed expects) and check the response: SOAP faults, RSTR lifetime and AppliesTo, and the SAML 1.1 or 2.0 token's signature, audience and validity, decrypting it with rp_key if the STS encrypted it.",
			Params: join([]Param{
				{Name: "endpoint", Type: "string", Required: true, Desc: "STS endpoint, e.g. https://adfs.example.com/adfs/services/trust/13/usernamemixed"},
				{Name: "applies_to", Type: "string", Required: true, Desc: "Relying party identifier the token is for"},
				{Name: "token_type", Type: "string", Enum: []string{"saml2", "saml11"}, Desc: "Requested token type", Default: "saml2"}}, trustAuth, stsTrust),
			Run: runWSTrustIssue,
		},
		&Op{
			Name:    "wstrust.validate",
			Summary: "Ask a WS-Trust STS whether a token is valid (RST Validate) and report the status code and reason.",
			Params: join([]Param{
				{Name: "endpoint", Type: "string", Required: true, Desc: "STS endpoint"},
				{Name: "token", Type: "string", Required: true, File: true, Desc: "Token XML to validate (CLI: @file)"}}, trustAuth),
			Run: runWSTrustValidate,
		},
	)
}
