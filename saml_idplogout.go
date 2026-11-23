package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// IdP-initiated Single Logout (SAML Profiles §4.4): the IdP sends the SP a
// LogoutRequest, through the browser (Redirect or POST binding) or directly
// (SOAP), and the SP answers with a LogoutResponse in the same binding.

const (
	samlStatusResponder = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	samlStatusRequester = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	samlStatusPartial   = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	sloRef              = "SAML Profiles §4.4.4.1"
)

// samlIDPTrust loads the IdP's metadata, if given, and the certificates its
// messages must be signed with.
func samlIDPTrust(c *Ctx) (*idpMeta, []*x509.Certificate, error) {
	var meta *idpMeta
	var trusted []*x509.Certificate
	var err error
	if src := c.Str("idp_metadata"); src != "" {
		if meta, err = loadIDPMetadata(c, src); err != nil {
			return nil, nil, err
		}
		trusted = meta.Certs
	}
	if s := c.Str("idp_cert"); s != "" {
		certs, err := loadCerts(s)
		if err != nil {
			return nil, nil, fmt.Errorf("idp_cert: %w", err)
		}
		trusted = append(trusted, certs...)
	}
	return meta, trusted, nil
}

// idpLogout is one received LogoutRequest and what was answered.
type idpLogout struct {
	c       *Ctx
	meta    *idpMeta
	trusted []*x509.Certificate
	sp      *spConfig
	spSLO   string
}

// receive checks a LogoutRequest that arrived on the local
// SingleLogoutService and writes the LogoutResponse to w.
func (l *idpLogout) receive(w http.ResponseWriter, req *http.Request) M {
	var cs Checks
	out := M{}
	defer func() { out["checks"] = cs }()
	refuse := func(code int, msg string) M {
		cs.add("LogoutRequest received", "fail", msg, sloRef)
		http.Error(w, "idpdbg: "+msg, code)
		return out
	}

	// Which binding, and the message as XML.
	var binding, relay string
	var xmlBytes []byte
	redirectSigned := false
	ctype := req.Header.Get("Content-Type")
	switch {
	case req.Method == http.MethodGet:
		binding = bindRedirect
		m, err := parseRedirect(req.URL.RawQuery)
		if err != nil {
			return refuse(http.StatusBadRequest, err.Error())
		}
		if m.Param != "SAMLRequest" {
			return refuse(http.StatusBadRequest, "expected a SAMLRequest")
		}
		relay = m.RelayState
		redirectSigned = checkRedirectSignature(&cs, m, l.trusted)
		b, _, err := decodeSAMLInput(m.Message)
		if err != nil {
			return refuse(http.StatusBadRequest, err.Error())
		}
		xmlBytes = b
	case req.Method == http.MethodPost && strings.Contains(ctype, "xml"):
		binding = bindSOAP
		body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if err != nil {
			return refuse(http.StatusBadRequest, err.Error())
		}
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(body); err != nil || doc.Root() == nil || doc.Root().Tag != "Envelope" {
			return refuse(http.StatusBadRequest, "expected a SOAP envelope")
		}
		var lr []*etree.Element
		findAll(doc.Root(), "LogoutRequest", &lr)
		if len(lr) != 1 {
			return refuse(http.StatusBadRequest, "expected one LogoutRequest in the SOAP body")
		}
		if xmlBytes, err = detachedXML(lr[0]); err != nil {
			return refuse(http.StatusBadRequest, err.Error())
		}
	case req.Method == http.MethodPost:
		binding = bindPOST
		if err := req.ParseForm(); err != nil {
			return refuse(http.StatusBadRequest, "unreadable form")
		}
		if req.URL.Query().Has("SAMLRequest") {
			return refuse(http.StatusBadRequest, "SAMLRequest in both the query and the body; refusing an ambiguous message")
		}
		relay = req.PostForm.Get("RelayState")
		b, _, err := decodeSAMLInput(req.PostForm.Get("SAMLRequest"))
		if err != nil {
			return refuse(http.StatusBadRequest, "expected a SAMLRequest")
		}
		xmlBytes = b
	default:
		return refuse(http.StatusMethodNotAllowed, "method not allowed")
	}
	out["binding"] = map[string]string{bindRedirect: "HTTP-Redirect", bindPOST: "HTTP-POST", bindSOAP: "SOAP"}[binding]
	out["request_xml"] = string(xmlBytes)

	leeway := time.Duration(l.c.Int("leeway")) * time.Second
	a, err := analyzeSAML(xmlBytes, &samlExpect{Trusted: l.trusted, Leeway: leeway})
	if err != nil {
		return refuse(http.StatusBadRequest, err.Error())
	}
	cs = append(cs, a["checks"].(Checks)...)
	if !cs.ok(a["message_type"] == "LogoutRequest", "message is a LogoutRequest", fmt.Sprint(a["message_type"]), "SAML Core §3.7.1") {
		http.Error(w, "idpdbg: expected a LogoutRequest", http.StatusBadRequest)
		return out
	}
	doc := etree.NewDocument()
	doc.ReadFromBytes(xmlBytes)
	root := doc.Root()
	reqID := root.SelectAttrValue("ID", "")
	request := M{"id": reqID, "issuer": text(kid(root, "Issuer")), "destination": root.SelectAttrValue("Destination", ""),
		"issue_instant": root.SelectAttrValue("IssueInstant", "")}
	if v := root.SelectAttrValue("NotOnOrAfter", ""); v != "" {
		request["not_on_or_after"] = v
	}
	if v := root.SelectAttrValue("Reason", ""); v != "" {
		request["reason"] = v
	}
	out["request"] = request

	// Who sent it, to whom, and when.
	cs.ok(reqID != "", "LogoutRequest: ID present", "", "SAML Core §3.2.1")
	if l.meta != nil {
		cs.ok(request["issuer"] == l.meta.EntityID, "LogoutRequest: Issuer is the IdP entity ID", fmt.Sprint(request["issuer"]), sloRef)
	}
	if d := request["destination"].(string); d != "" || binding != bindSOAP {
		cs.ok(d == l.spSLO, "LogoutRequest: Destination is this SingleLogoutService", "Destination="+d, "SAML Bindings §3.4.5.2")
	}
	now := time.Now()
	if t, ok := samlTime(request["issue_instant"].(string)); ok {
		cs.ok(!t.After(now.Add(leeway)), "LogoutRequest: IssueInstant not in the future", relTime(t), "SAML Core §1.3.3")
	} else {
		cs.add("LogoutRequest: IssueInstant not in the future", "fail", "missing or unreadable", "SAML Core §3.2.1")
	}
	if v, ok := request["not_on_or_after"].(string); ok {
		t, okT := samlTime(v)
		cs.ok(okT && now.Before(t.Add(leeway)), "LogoutRequest: not expired (NotOnOrAfter)", v, "SAML Core §3.7.1")
	}

	// Signed: required on the front channel, where the browser carries it.
	enveloped := false
	for _, ck := range cs {
		if ck.Name == "logoutrequest: signature" && ck.Status == "pass" {
			enveloped = true
		}
	}
	switch {
	case redirectSigned || enveloped:
		cs.add("LogoutRequest signed", "pass", map[bool]string{true: "Redirect-binding signature", false: "enveloped signature"}[redirectSigned], sloRef)
	case binding == bindSOAP:
		cs.add("LogoutRequest signed", "warn", "unsigned: over SOAP only the TLS connection could authenticate the IdP, and this listener is plain http", sloRef)
	default:
		cs.add("LogoutRequest signed", "fail", "no verified signature: anyone could log the person out by sending them this link (pass idp_metadata or idp_cert to verify it)", sloRef)
	}

	// Whose session.
	nid := kid(root, "NameID")
	if enc := kid(root, "EncryptedID"); enc != nil {
		if l.sp.Key == nil {
			cs.add("LogoutRequest: NameID", "warn", "the NameID is encrypted (EncryptedID); pass sp_key to decrypt it", "SAML Core §2.2.4")
		} else if d, err := decryptAssertion(enc, l.sp.Key); err != nil {
			cs.add("LogoutRequest: NameID decrypts", "fail", err.Error(), "SAML Core §2.2.4")
		} else {
			cs.add("LogoutRequest: NameID decrypts", "pass", "EncryptedID decrypted with sp_key", "SAML Core §2.2.4")
			nid = d
		}
	}
	var sessions []string
	for _, si := range kids(root, "SessionIndex") {
		sessions = append(sessions, text(si))
	}
	if nid != nil {
		request["name_id"] = M{"value": text(nid), "format": nid.SelectAttrValue("Format", "")}
	}
	if len(sessions) > 0 {
		request["session_index"] = sessions
	}
	matched := true
	if want := l.c.Str("name_id"); want != "" {
		got := ""
		if nid != nil {
			got = text(nid)
		}
		matched = cs.ok(got == want, "LogoutRequest names the expected NameID", "NameID="+got, sloRef) && matched
	}
	if want := l.c.Str("session_index"); want != "" {
		if len(sessions) == 0 {
			cs.add("LogoutRequest names the expected session", "info", "no SessionIndex: the request ends all of this NameID's sessions", "SAML Core §3.7.1")
		} else {
			matched = cs.ok(contains(sessions, want), "LogoutRequest names the expected session", "SessionIndex="+strings.Join(sessions, ", "), "SAML Core §3.7.1") && matched
		}
	}

	// The answer.
	status := map[string]string{"success": samlStatusOK, "partial": samlStatusOK, "responder": samlStatusResponder, "requester": samlStatusRequester}[l.c.Str("status")]
	if status == "" {
		status = samlStatusOK
	}
	dest, respBinding := "", binding
	if binding != bindSOAP {
		dest, respBinding = l.responseLocation(binding)
		if dest == "" {
			cs.add("LogoutResponse sent", "fail", "the IdP's metadata names no SingleLogoutService for the response; pass slo_url", sloRef)
			http.Error(w, "idpdbg: no SingleLogoutService to answer to", http.StatusBadGateway)
			return out
		}
		if err := l.c.allowDestination("the LogoutResponse", dest); err != nil {
			cs.add("LogoutResponse sent", "fail", err.Error(), sloRef)
			http.Error(w, "idpdbg: "+err.Error(), http.StatusForbidden)
			return out
		}
	}
	rdoc := etree.NewDocument()
	el := rdoc.CreateElement("samlp:LogoutResponse")
	el.CreateAttr("xmlns:samlp", nsSAMLP)
	el.CreateAttr("xmlns:saml", nsSAML)
	r := &builtRequest{ID: newSAMLID(), Binding: respBinding, Destination: dest, RelayState: relay, Param: "SAMLResponse"}
	el.CreateAttr("ID", r.ID)
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", samlNow())
	if dest != "" {
		el.CreateAttr("Destination", dest)
	}
	el.CreateAttr("InResponseTo", reqID)
	el.CreateElement("saml:Issuer").SetText(l.sp.EntityID)
	sc := el.CreateElement("samlp:Status").CreateElement("samlp:StatusCode")
	sc.CreateAttr("Value", status)
	if l.c.Str("status") == "partial" {
		sc.CreateElement("samlp:StatusCode").CreateAttr("Value", samlStatusPartial)
	}
	if binding == bindSOAP {
		r.Binding = bindPOST // an enveloped signature, as for the POST binding
	}
	if r, err = finishMessage(l.sp, rdoc, el, r, l.c.Bool("sign")); err != nil {
		cs.add("LogoutResponse sent", "fail", err.Error(), sloRef)
		http.Error(w, "idpdbg: "+err.Error(), http.StatusInternalServerError)
		return out
	}
	out["response"] = r.describe()
	out["response_status"] = status
	if !matched {
		cs.add("LogoutResponse status", "info", "answered "+l.c.Str("status")+" although the request names another session; a real SP would answer for the session it names", sloRef)
	}
	cs.warn(r.Signed, "LogoutResponse signed", map[bool]string{true: "signed with sp_key", false: "unsigned (pass sign with sp_key and sp_cert); IdPs that require signed logout messages reject it"}[r.Signed], "SAML Profiles §4.4.4.2")
	switch binding {
	case bindRedirect:
		http.Redirect(w, req, r.RedirectURL, http.StatusFound)
	case bindPOST:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, r.postForm())
	case bindSOAP:
		w.Header().Set("Content-Type", "text/xml; charset=utf-8")
		fmt.Fprint(w, `<soap11:Envelope xmlns:soap11="`+nsSOAP11+`"><soap11:Body>`+strings.TrimPrefix(r.XML, xmlDeclaration(r.XML))+`</soap11:Body></soap11:Envelope>`)
	}
	cs.add("LogoutResponse sent", "pass", fmt.Sprintf("%s via %s", status, out["binding"]), sloRef)
	return out
}

// responseLocation is where the LogoutResponse goes: the IdP's
// SingleLogoutService ResponseLocation (else Location) for the binding the
// request came in, else for the other front-channel binding.
func (l *idpLogout) responseLocation(binding string) (string, string) {
	if u := l.c.Str("slo_url"); u != "" {
		return u, binding
	}
	if l.meta == nil {
		return "", binding
	}
	for _, b := range []string{binding, bindRedirect, bindPOST} {
		if u := l.meta.SLOResponse[b]; u != "" {
			return u, b
		}
		if u := l.meta.SLO[b]; u != "" {
			return u, b
		}
	}
	return "", binding
}

// detachedXML serialises el on its own, with the namespace declarations
// it inherits, so its signature still verifies.
func detachedXML(el *etree.Element) ([]byte, error) {
	nsCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, err
	}
	det, err := etreeutils.NSDetatch(nsCtx, el)
	if err != nil {
		return nil, err
	}
	d := etree.NewDocument()
	d.SetRoot(det)
	return d.WriteToBytes()
}

// xmlDeclaration returns the leading <?xml …?> of s, if any.
func xmlDeclaration(s string) string {
	if strings.HasPrefix(s, "<?xml") {
		if i := strings.Index(s, "?>"); i > 0 {
			return s[:i+2]
		}
	}
	return ""
}

func runSAMLIdPLogout(c *Ctx) (M, error) {
	meta, trusted, err := samlIDPTrust(c)
	if err != nil {
		return nil, err
	}
	sp, err := loadSP(c)
	if err != nil {
		return nil, err
	}
	if c.Bool("sign") && sp.Key == nil {
		return nil, errors.New("sign requires sp_key and sp_cert")
	}
	port, path := c.Int("slo_port"), c.Str("slo_path")
	l := &idpLogout{c: c, meta: meta, trusted: trusted, sp: sp, spSLO: fmt.Sprintf("http://localhost:%d%s", port, path)}

	var once sync.Once
	var result M
	done := make(chan url.Values, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, req *http.Request) {
		handled := false
		once.Do(func() {
			handled = true
			result = l.receive(w, req)
			done <- url.Values{}
		})
		if !handled {
			http.Error(w, "idpdbg: a LogoutRequest was already handled", http.StatusConflict)
		}
	})
	stop, err := serveLoopback(port, mux)
	if err != nil {
		return nil, err
	}
	defer stop()
	c.Log("Local SingleLogoutService listening on %s; it must be registered with the IdP", l.spSLO)

	if start := c.Str("start_url"); start != "" {
		_, err = awaitBrowser(c, start, done)
	} else {
		wait := time.Duration(c.Int("wait")) * time.Second
		c.Log("Sign out at the IdP now (in the browser where you signed in). Waiting up to %s for its LogoutRequest…", wait)
		select {
		case <-done:
		case <-time.After(wait):
			err = fmt.Errorf("timed out after %s waiting for the IdP's LogoutRequest", wait)
		case <-c.Done():
			err = c.Err()
		}
	}
	if err != nil {
		return M{"sp_slo_url": l.spSLO}, err
	}
	result["sp_slo_url"] = l.spSLO
	return result, nil
}

func init() {
	register(&Op{
		Name:    "saml.idp_logout",
		Browser: true,
		Summary: "Receive IdP-initiated SAML Single Logout: run a local SingleLogoutService, wait for the IdP's LogoutRequest (Redirect or POST binding through the browser, or SOAP back channel), check its signature, issuer, Destination, timestamps and the NameID and SessionIndex it names, and answer with a LogoutResponse (optionally signed, optionally not Success to see how the IdP copes). Start the logout at the IdP yourself, or pass start_url to open its logout page.",
		Params: joinParams(samlIDPParams, samlSPParams, []Param{
			{Name: "start_url", Type: "string", Desc: "Page to open to start the logout at the IdP, e.g. Keycloak's /realms/<realm>/protocol/openid-connect/logout; default: none, sign out at the IdP yourself"},
			{Name: "slo_url", Type: "string", Desc: "Where to send the LogoutResponse, overriding the IdP metadata's SingleLogoutService"},
			{Name: "name_id", Type: "string", Desc: "NameID the request should name, e.g. from a saml login"},
			{Name: "session_index", Type: "string", Desc: "SessionIndex the request should name"},
			{Name: "status", Type: "string", Enum: []string{"success", "partial", "responder", "requester"}, Default: "success", Desc: "Status to answer with: Success, Success with PartialLogout, or a Responder or Requester error"},
			{Name: "sign", Type: "bool", Desc: "Sign the LogoutResponse with sp_key (and sp_cert for the POST binding)"},
			{Name: "slo_port", Type: "int", Desc: "Loopback port for the local SingleLogoutService", Default: 8766},
			{Name: "slo_path", Type: "string", Desc: "Path of the local SingleLogoutService", Default: "/saml/slo"},
			{Name: "leeway", Type: "int", Desc: "Clock skew allowance in seconds", Default: 120},
		}, browserParams),
		Run: runSAMLIdPLogout,
	})
}
