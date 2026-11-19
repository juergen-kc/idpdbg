package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Active probes of the OAuth 2.0 Security BCP (RFC 9700): requests that a
// compliant authorization server must refuse, sent on purpose to see what it
// actually enforces.

var bcpProbeNames = []string{"redirect_uri", "implicit", "clickjacking", "pkce", "pkce_downgrade", "code_replay", "refresh_replay"}

// fapiProbeNames run in addition with fapi (unless probes names them
// explicitly). code_lifetime waits 61 seconds.
var fapiProbeNames = []string{"par_required", "par_client_auth", "par_redirect_uri", "dpop_code_binding", "code_lifetime"}

func init() {
	params := append(clientParams(authzParams...), redirectParams...)
	params = append(params, browserParams...)
	params = append(params, Param{Name: "probes", Type: "list", Default: strings.Join(bcpProbeNames, ","),
		Desc: "Probes to run: redirect_uri (exact matching of the redirect URI), implicit (response_type=token refused), clickjacking (the sign-in page cannot be framed), pkce (a wrong code_verifier is refused), pkce_downgrade (a code_verifier is refused for a code requested without code_challenge), code_replay (a code works only once), refresh_replay (a rotated refresh token stops working). The first three need no sign-in. " +
			"With fapi, also par_required (a request without PAR is refused), par_client_auth (PAR without client authentication is refused), par_redirect_uri (PAR without redirect_uri is refused), dpop_code_binding (a code bound to one DPoP key is refused with another) and code_lifetime (a code is refused after 61 seconds)."})
	register(&Op{
		Name:     "oidc.bcp_probe",
		Mutating: true,
		Browser:  true,
		Summary: "Probe what an authorization server enforces of the OAuth 2.0 Security BCP (RFC 9700) by sending requests it must refuse: redirect URIs that differ from the registered one, the implicit grant, a framed sign-in page, wrong and downgraded PKCE, a replayed authorization code and a replayed refresh token. " +
			"Uses the same client and loopback redirect URI as oidc login. The PKCE and replay probes need a sign-in each; after the first, the provider's session usually completes them without asking.",
		Params: params,
		Run:    runBCPProbe,
	})
}

// authOutcome is where an authorization request ends when a browser without
// a session sends it: an error page, a sign-in page, or a redirect away.
type authOutcome struct {
	Status   int
	Location string // set when the server redirected away from itself
	Header   http.Header
	SignIn   bool
	URL      string
}

func (o authOutcome) describe() string {
	switch {
	case o.Location != "":
		return fmt.Sprintf("HTTP %d redirect to %s", o.Status, o.Location)
	case o.SignIn:
		return fmt.Sprintf("HTTP %d sign-in page", o.Status)
	default:
		return fmt.Sprintf("HTTP %d", o.Status)
	}
}

// followAuth sends an authorization request as a browser with no session
// would, following redirects within the authorization server's origin and
// keeping the cookies it sets on the way.
func followAuth(c *Ctx, start string) (authOutcome, error) {
	jar, _ := cookiejar.New(nil)
	client := c.client()
	client.Jar = jar
	u := start
	origin := func(s string) string {
		p, err := url.Parse(s)
		if err != nil {
			return ""
		}
		return p.Scheme + "://" + p.Host
	}
	asOrigin := origin(start)
	for hop := 0; hop < 6; hop++ {
		req, err := http.NewRequestWithContext(c, "GET", u, nil)
		if err != nil {
			return authOutcome{}, err
		}
		req.Header.Set("Accept", "text/html")
		req.Header.Set("User-Agent", "idpdbg/"+version)
		resp, err := client.Do(req)
		if err != nil {
			return authOutcome{}, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		out := authOutcome{Status: resp.StatusCode, Header: resp.Header, URL: u}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			base, _ := url.Parse(u)
			next, err := base.Parse(resp.Header.Get("Location"))
			if err != nil {
				return out, err
			}
			if origin(next.String()) != asOrigin {
				out.Location = next.String()
				return out, nil
			}
			u = next.String()
			continue
		}
		out.SignIn = resp.StatusCode < 300 && strings.Contains(strings.ToLower(string(body)), `type="password"`)
		return out, nil
	}
	return authOutcome{}, fmt.Errorf("more than 6 redirects within the authorization server")
}

// withArgs runs f with some arguments replaced, then restores them.
func withArgs(c *Ctx, args M, f func() error) error {
	old := M{}
	for k, v := range args {
		if prev, ok := c.Args[k]; ok {
			old[k] = prev
		}
		c.Args[k] = v
	}
	defer func() {
		for k := range args {
			if prev, ok := old[k]; ok {
				c.Args[k] = prev
			} else {
				delete(c.Args, k)
			}
		}
	}()
	return f()
}

// sameEndpoint reports whether a redirect target is the given URI, ignoring
// the query and fragment the server adds.
func sameEndpoint(target, uri string) bool {
	t, err1 := url.Parse(target)
	u, err2 := url.Parse(uri)
	return err1 == nil && err2 == nil && t.Scheme == u.Scheme && t.Host == u.Host && t.Path == u.Path
}

type bcpProbe struct {
	c           *Ctx
	meta        M
	redirectURI string
	port        int
	path        string
	cs          Checks
	report      M
	tokens      M     // token response from code_replay, reused by refresh_replay
	parOK       *bool // whether a valid pushed request succeeds (see parWorks)
}

func runBCPProbe(c *Ctx) (M, error) {
	meta, err := getMeta(c)
	if err != nil {
		return nil, err
	}
	redirectURI, port, path, err := loginRedirect(c)
	if err != nil {
		return nil, err
	}
	want := c.List("probes")
	all := append(append([]string{}, bcpProbeNames...), fapiProbeNames...)
	for _, n := range want {
		if !contains(all, n) {
			return nil, fmt.Errorf("unknown probe %q; known: %s", n, strings.Join(all, ", "))
		}
	}
	if c.Bool("fapi") && strings.Join(want, ",") == strings.Join(bcpProbeNames, ",") {
		want = all
	}
	p := &bcpProbe{c: c, meta: meta, redirectURI: redirectURI, port: port, path: path, report: M{}}
	steps := map[string]func() error{
		"redirect_uri": p.redirectURIs, "implicit": p.implicit, "clickjacking": p.clickjacking,
		"pkce": p.pkce, "pkce_downgrade": p.pkceDowngrade, "code_replay": p.codeReplay, "refresh_replay": p.refreshReplay,
		"par_required": p.parRequired, "par_client_auth": p.parClientAuth, "par_redirect_uri": p.parRedirectURI,
		"dpop_code_binding": p.dpopCodeBinding, "code_lifetime": p.codeLifetime,
	}
	for _, n := range all {
		if !contains(want, n) {
			continue
		}
		if err := steps[n](); err != nil {
			ref := "RFC 9700"
			if contains(fapiProbeNames, n) {
				ref = fapiRef
			}
			p.cs.add("probe "+n, "warn", "could not run: "+err.Error(), ref)
		}
	}
	return M{"redirect_uri": redirectURI, "probes": p.report, "checks": p.cs}, nil
}

// parWorks reports whether a valid pushed authorization request succeeds
// (always true without par). A refusal at the PAR endpoint only means the
// server rejected the altered request if an unaltered one goes through.
func (p *bcpProbe) parWorks() bool {
	if !p.c.Bool("par") {
		return true
	}
	if p.parOK == nil {
		_, err := p.authorize(p.redirectURI, nil)
		ok := err == nil
		p.parOK = &ok
	}
	return *p.parOK
}

// refusedAtPAR records a refusal at the PAR endpoint as a pass, unless valid
// pushed requests are refused too.
func (p *bcpProbe) refusedAtPAR(name string, err error, ref string) {
	if !p.parWorks() {
		p.cs.add(name, "info", "inconclusive: the PAR endpoint refuses a valid request too ("+err.Error()+")", ref)
		return
	}
	p.cs.add(name, "pass", err.Error(), ref)
}

// afterSignIn sends an authorization request through the browser and waits
// for the response at the redirect URI's listener.
func (p *bcpProbe) afterSignIn(label string, a *authzRequest, redirectURI string) (url.Values, bool, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, false, err
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	p.c.Log("Probe %s: sign in if asked; a compliant server refuses this request", label)
	vals, err := captureRedirectScheme(p.c, a.URL, p.port, path, redirectScheme(redirectURI), a.State)
	if err != nil && strings.Contains(err.Error(), "timed out") {
		return nil, true, nil
	}
	return vals, false, err
}

// authorize builds an authorization request with the given overrides.
func (p *bcpProbe) authorize(redirectURI string, args M) (*authzRequest, error) {
	var a *authzRequest
	err := withArgs(p.c, args, func() error {
		var err error
		a, err = buildAuthURL(p.c, p.meta, redirectURI)
		return err
	})
	if err != nil && a != nil && a.PAR != nil {
		return a, fmt.Errorf("refused at the PAR endpoint: %w", err)
	}
	return a, err
}

func (p *bcpProbe) redirectURIs() error {
	u, err := url.Parse(p.redirectURI)
	if err != nil {
		return err
	}
	join := "?"
	if u.RawQuery != "" {
		join = "&"
	}
	extraPath := *u
	extraPath.Path = strings.TrimSuffix(u.Path, "/") + "/probe"
	other := *u
	other.Host = "attacker.example"
	if port := u.Port(); port != "" {
		other.Host += ":" + port
	}
	variants := []struct {
		name, uri string
		local     bool // still reaches idpdbg's loopback listener
	}{
		{"extra path segment", extraPath.String(), true},
		{"extra query parameter", p.redirectURI + join + "probe=1", true},
		{"other host", other.String(), false},
	}
	report := M{}
	for _, v := range variants {
		name := "redirect URI exact matching: " + v.name
		a, err := p.authorize(v.uri, nil)
		if err != nil {
			if a != nil && a.PAR != nil {
				p.refusedAtPAR(name, err, "RFC 9700 §2.1")
				report[v.name] = M{"redirect_uri": v.uri, "outcome": err.Error()}
				continue
			}
			return err
		}
		o, err := followAuth(p.c, a.URL)
		if err != nil {
			return err
		}
		report[v.name] = M{"redirect_uri": v.uri, "outcome": o.describe()}
		switch {
		case o.Location != "" && sameEndpoint(o.Location, v.uri):
			p.cs.add(name, "fail", "the server redirected to the altered redirect URI "+v.uri+", which an attacker could use to steal codes", "RFC 9700 §2.1")
		case o.Location != "":
			p.cs.add(name, "info", "redirected elsewhere: "+o.Location, "RFC 9700 §2.1")
		case o.SignIn && v.local:
			// The server may compare the redirect URI only after sign-in:
			// go through the browser and see where the code lands.
			p.secondLook(name, a, v.uri, report[v.name].(M))
		case o.SignIn:
			p.cs.add(name, "info", "not refused before sign-in: the server showed its sign-in page, so it may only compare the redirect URI afterwards", "RFC 9700 §2.1")
		case o.Status >= 400:
			p.cs.add(name, "pass", fmt.Sprintf("refused (HTTP %d)", o.Status), "RFC 9700 §2.1")
		default:
			p.cs.add(name, "info", "unclear outcome: "+o.describe(), "RFC 9700 §2.1")
		}
	}
	p.report["redirect_uri"] = report
	return nil
}

// secondLook sends an authorization request with an altered (but still
// loopback) redirect URI through the browser, for a server that showed its
// sign-in page instead of refusing it outright.
func (p *bcpProbe) secondLook(name string, a *authzRequest, altered string, report M) {
	vals, timedOut, err := p.afterSignIn(name, a, altered)
	// The extra-query variant shares the registered path: only a response
	// that kept the added parameter went to the altered URI.
	au, _ := url.Parse(altered)
	toAltered := vals != nil && (au == nil || au.Query().Get("probe") == "" || vals.Get("probe") != "")
	switch {
	case timedOut:
		report["after_sign_in"] = "no redirect came back"
		p.cs.add(name, "info", "the server showed its sign-in page, and no redirect to the altered URI came back afterwards; the browser should show an error", "RFC 9700 §2.1")
	case err != nil:
		p.cs.add(name, "info", "could not check after sign-in: "+err.Error(), "RFC 9700 §2.1")
	case !toAltered:
		report["after_sign_in"] = "answered at the registered redirect URI"
		p.cs.add(name, "warn", "after sign-in the server answered at the registered redirect URI instead of refusing the altered one", "RFC 6749 §4.1.2.1")
	case vals.Get("code") != "":
		report["after_sign_in"] = "code delivered to the altered redirect URI"
		p.cs.add(name, "fail", "after sign-in the server sent an authorization code to the altered redirect URI "+altered+", which an attacker could use to steal codes", "RFC 9700 §2.1")
	default:
		report["after_sign_in"] = "redirected with " + vals.Encode()
		p.cs.add(name, "fail", "after sign-in the server redirected to the altered redirect URI (error="+vals.Get("error")+"); it must not redirect to an unregistered URI at all", "RFC 6749 §4.1.2.1")
	}
}

func (p *bcpProbe) implicit() error {
	name := "implicit grant refused for this client"
	a, err := p.authorize(p.redirectURI, M{"response_type": "token", "response_mode": ""})
	if err != nil {
		if a != nil && a.PAR != nil {
			p.refusedAtPAR(name, err, "RFC 9700 §2.1.2")
			return nil
		}
		return err
	}
	o, err := followAuth(p.c, a.URL)
	if err != nil {
		return err
	}
	p.report["implicit"] = M{"outcome": o.describe()}
	errorBack := func() string {
		t, err := url.Parse(o.Location)
		if err != nil {
			return ""
		}
		if e := t.Query().Get("error"); e != "" {
			return e
		}
		frag, _ := url.ParseQuery(t.Fragment)
		return frag.Get("error")
	}
	switch {
	case o.Status >= 400:
		p.cs.add(name, "pass", fmt.Sprintf("refused (HTTP %d)", o.Status), "RFC 9700 §2.1.2")
	case o.Location != "" && sameEndpoint(o.Location, p.redirectURI) && errorBack() != "":
		p.cs.add(name, "pass", "refused with error="+errorBack(), "RFC 9700 §2.1.2")
	case o.SignIn:
		// It may still refuse after sign-in: see what comes back.
		vals, timedOut, err := p.afterSignIn("implicit", a, p.redirectURI)
		switch {
		case err != nil:
			return err
		case timedOut:
			p.cs.add(name, "info", "not refused before sign-in, and no response came back afterwards", "RFC 9700 §2.1.2")
		case vals.Get("access_token") != "":
			p.cs.bcp(false, name, "", "after sign-in the server returned an access token in the browser: the implicit grant is enabled for this client", "RFC 9700 §2.1.2", "warn")
		case vals.Get("error") != "":
			p.cs.add(name, "pass", "refused after sign-in with error="+vals.Get("error"), "RFC 9700 §2.1.2")
		default:
			p.cs.add(name, "info", "unclear response after sign-in", "RFC 9700 §2.1.2")
		}
	default:
		p.cs.add(name, "info", "unclear outcome: "+o.describe(), "RFC 9700 §2.1.2")
	}
	return nil
}

func (p *bcpProbe) clickjacking() error {
	name := "sign-in page cannot be framed"
	a, err := p.authorize(p.redirectURI, nil)
	if err != nil {
		return err
	}
	o, err := followAuth(p.c, a.URL)
	if err != nil {
		return err
	}
	xfo := o.Header.Get("X-Frame-Options")
	csp := o.Header.Get("Content-Security-Policy")
	p.report["clickjacking"] = M{"outcome": o.describe(), "x_frame_options": xfo, "content_security_policy": csp}
	if o.Status >= 300 || o.Location != "" {
		p.cs.add(name, "info", "did not reach a page to check: "+o.describe(), "RFC 9700 §4.16")
		return nil
	}
	var found []string
	if x := strings.ToUpper(strings.TrimSpace(xfo)); x == "DENY" || x == "SAMEORIGIN" {
		found = append(found, "X-Frame-Options: "+xfo)
	}
	for _, d := range strings.Split(csp, ";") {
		if d = strings.TrimSpace(d); strings.HasPrefix(strings.ToLower(d), "frame-ancestors") && restrictsFraming(d) {
			found = append(found, "CSP "+d)
		}
	}
	p.cs.bcp(len(found) > 0, name, strings.Join(found, "; "),
		"the sign-in page sends neither X-Frame-Options nor a CSP frame-ancestors directive, so another site can frame it", "RFC 9700 §4.16", "warn")
	return nil
}

// restrictsFraming reports whether a CSP frame-ancestors directive actually
// limits who may frame the page: a wildcard or a bare scheme lets anyone.
func restrictsFraming(directive string) bool {
	sources := strings.Fields(directive)[1:]
	if len(sources) == 0 {
		return false
	}
	for _, s := range sources {
		ls := strings.ToLower(s)
		if ls == "*" || strings.HasSuffix(ls, ":") || strings.HasPrefix(ls, "*") || strings.Contains(ls, "://*") {
			return false
		}
	}
	return true
}

// code runs one authorization request through the browser and returns the
// code and PKCE verifier, or the error the server answered with.
func (p *bcpProbe) code(label string, withPKCE bool) (code, verifier, authErr string, err error) {
	a, err := p.authorize(p.redirectURI, M{"pkce": withPKCE, "response_type": "code"})
	if err != nil {
		if a != nil && a.PAR != nil {
			if !p.parWorks() {
				return "", "", "", fmt.Errorf("the PAR endpoint refuses a valid request too: %w", err)
			}
			// The PAR endpoint answered for the authorization endpoint.
			resp, _ := a.PAR["response"].(map[string]any)
			return "", "", strings.TrimSpace(str(resp["error"]) + " " + str(resp["error_description"]) + " (at the PAR endpoint)"), nil
		}
		return "", "", "", err
	}
	p.c.Log("Probe %s: sign in if asked (the provider's session usually completes it on its own)", label)
	vals, err := captureRedirectScheme(p.c, a.URL, p.port, p.path, redirectScheme(p.redirectURI), a.State)
	if err != nil {
		return "", "", "", err
	}
	if e := vals.Get("error"); e != "" {
		return "", "", strings.TrimSpace(e + " " + vals.Get("error_description")), nil
	}
	if vals.Get("state") != a.State {
		return "", "", "", fmt.Errorf("the authorization response has the wrong state")
	}
	if vals.Get("code") == "" {
		return "", "", "", fmt.Errorf("the authorization response has no code")
	}
	return vals.Get("code"), a.Verifier, "", nil
}

// redeem sends a token request and returns its status and body, keeping its
// checks out of the probe results.
func (p *bcpProbe) redeem(form url.Values) (int, M, error) {
	var scratch Checks
	out, err := tokenCall(p.c, p.meta, form, &scratch, "")
	if err != nil {
		return 0, nil, err
	}
	status, _ := out["status"].(int)
	body, _ := out["response"].(map[string]any)
	return status, body, nil
}

func (p *bcpProbe) exchange(code, verifier string) (int, M, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {p.redirectURI}}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	return p.redeem(form)
}

func refusal(status int, body M) string {
	s := fmt.Sprintf("HTTP %d", status)
	if e := str(body["error"]); e != "" {
		s += " " + e
	}
	return s
}

func (p *bcpProbe) pkce() error {
	name := "PKCE enforced: wrong code_verifier refused"
	code, _, authErr, err := p.code("pkce", true)
	if err != nil {
		return err
	}
	if authErr != "" {
		return fmt.Errorf("authorization failed: %s", authErr)
	}
	status, body, err := p.exchange(code, randToken(32))
	if err != nil {
		return err
	}
	p.report["pkce"] = M{"wrong_verifier": refusal(status, body)}
	p.cs.ok(status != 200, name, map[bool]string{true: "the server issued tokens for a wrong code_verifier", false: "refused: " + refusal(status, body)}[status == 200], "RFC 7636 §4.6, RFC 9700 §2.1.1")
	return nil
}

func (p *bcpProbe) pkceDowngrade() error {
	name := "PKCE downgrade refused"
	code, _, authErr, err := p.code("pkce_downgrade", false)
	if err != nil {
		return err
	}
	if authErr != "" {
		p.report["pkce_downgrade"] = M{"authorization": authErr}
		if l := strings.ToLower(authErr); strings.Contains(l, "code_challenge") || strings.Contains(l, "pkce") {
			p.cs.add(name, "pass", "the server requires PKCE for this client and refused a request without code_challenge ("+authErr+")", "RFC 9700 §2.1.1")
		} else {
			p.cs.add(name, "info", "inconclusive: the request without code_challenge was refused for another reason ("+authErr+")", "RFC 9700 §2.1.1")
		}
		return nil
	}
	status, body, err := p.exchange(code, randToken(32))
	if err != nil {
		return err
	}
	p.report["pkce_downgrade"] = M{"authorization": "code issued without code_challenge", "token_request_with_code_verifier": refusal(status, body)}
	if status == 200 {
		p.cs.add(name, "fail", "the server accepted a code_verifier for a code requested without code_challenge, so an attacker can strip PKCE from a request", "RFC 9700 §2.1.1")
	} else {
		p.cs.add(name, "pass", "refused: "+refusal(status, body), "RFC 9700 §2.1.1")
	}
	return nil
}

func (p *bcpProbe) codeReplay() error {
	name := "authorization code works only once"
	code, verifier, authErr, err := p.code("code_replay", true)
	if err != nil {
		return err
	}
	if authErr != "" {
		return fmt.Errorf("authorization failed: %s", authErr)
	}
	status, body, err := p.exchange(code, verifier)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("the first redemption already failed: %s", refusal(status, body))
	}
	p.tokens = body
	status2, body2, err := p.exchange(code, verifier)
	if err != nil {
		return err
	}
	report := M{"first": "HTTP 200", "second": refusal(status2, body2)}
	p.report["code_replay"] = report
	if !p.cs.ok(status2 != 200, name, map[bool]string{true: "the same code was redeemed twice", false: "second redemption refused: " + refusal(status2, body2)}[status2 == 200], "RFC 6749 §4.1.2, RFC 9700 §4.5") {
		return nil
	}
	// The server should also revoke what the code already produced.
	if ep := endpointOrEmpty(p.c, p.meta, "introspection_endpoint"); ep != "" && effectiveClientAuth(p.c) != "none" {
		res, _, err := bearerCall(p.c, p.meta, "introspection_endpoint", url.Values{"token": {str(body["access_token"])}})
		if err == nil && res.Status == 200 {
			active, _ := res.obj()["active"].(bool)
			report["first_access_token_active_after_replay"] = active
			p.cs.warn(!active, "tokens from a replayed code revoked", map[bool]string{true: "the access token from the first redemption is still active", false: "the access token from the first redemption was revoked"}[active], "RFC 6749 §4.1.2")
		}
	}
	return nil
}

// freshTokens signs in once more and redeems the code.
func (p *bcpProbe) freshTokens(label string) (M, error) {
	code, verifier, authErr, err := p.code(label, true)
	if err != nil {
		return nil, err
	}
	if authErr != "" {
		return nil, fmt.Errorf("authorization failed: %s", authErr)
	}
	status, body, err := p.exchange(code, verifier)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("could not redeem the code: %s", refusal(status, body))
	}
	return body, nil
}

func (p *bcpProbe) refreshReplay() error {
	name := "rotated refresh token stops working"
	refresh := func(rt string) (int, M, error) {
		return p.redeem(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
	}
	tokens := p.tokens
	// Tokens left over from code_replay are only usable if the server did
	// not revoke them over the replay; otherwise sign in again.
	if tokens == nil || p.report["code_replay"] != nil && p.report["code_replay"].(M)["first_access_token_active_after_replay"] != true {
		var err error
		if tokens, err = p.freshTokens("refresh_replay"); err != nil {
			return err
		}
	}
	public := effectiveClientAuth(p.c) == "none"
	bound := strings.EqualFold(str(tokens["token_type"]), "DPoP")
	old := str(tokens["refresh_token"])
	if old == "" {
		p.cs.add(name, "info", "no refresh token was issued; nothing to replay", "RFC 9700 §2.2.2")
		return nil
	}
	status, body, err := refresh(old)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("the refresh token did not work: %s", refusal(status, body))
	}
	fresh := str(body["refresh_token"])
	report := M{"first_refresh": "HTTP 200", "rotated": fresh != "" && fresh != old}
	p.report["refresh_replay"] = report
	if fresh == "" || fresh == old {
		if public && !bound {
			p.cs.bcp(false, name, "", "the refresh token was not rotated and is not sender-constrained, which a public client needs", "RFC 9700 §2.2.2", "warn")
		} else {
			p.cs.add(name, "info", "the refresh token was not rotated; nothing to replay", "RFC 9700 §2.2.2")
		}
		return nil
	}
	status2, body2, err := refresh(old)
	if err != nil {
		return err
	}
	report["replay_of_old_token"] = refusal(status2, body2)
	switch {
	case status2 != 200:
		p.cs.add(name, "pass", "the old refresh token was refused after rotation: "+refusal(status2, body2), "RFC 9700 §4.14.2")
	case public && !bound:
		p.cs.bcp(false, name, "", "the old refresh token still works after rotation, so rotation does not protect this public client", "RFC 9700 §4.14.2", "warn")
	default:
		p.cs.add(name, "info", "the old refresh token still works after rotation (the client is confidential or its tokens are bound, so this is allowed)", "RFC 9700 §4.14.2")
	}
	return nil
}

// ---- FAPI 2.0 probes ----

func (p *bcpProbe) parRequired() error {
	name := "FAPI 2.0: authorization request without PAR refused"
	a, err := p.authorize(p.redirectURI, M{"par": false, "jar": false})
	if err != nil {
		return err
	}
	o, err := followAuth(p.c, a.URL)
	if err != nil {
		return err
	}
	p.report["par_required"] = M{"outcome": o.describe()}
	switch {
	case o.Status >= 400:
		p.cs.add(name, "pass", fmt.Sprintf("refused (HTTP %d)", o.Status), fapiRef+" §5.3.2.2")
	case o.Location != "" && sameEndpoint(o.Location, p.redirectURI) && strings.Contains(o.Location, "error="):
		p.cs.add(name, "pass", "refused with an error response", fapiRef+" §5.3.2.2")
	case o.SignIn:
		// It may still refuse after sign-in: see what comes back.
		vals, timedOut, err := p.afterSignIn("par_required", a, p.redirectURI)
		switch {
		case err != nil:
			return err
		case timedOut:
			p.cs.add(name, "info", "not refused before sign-in, and no response came back afterwards", fapiRef+" §5.3.2.2")
		case vals.Get("code") != "":
			p.cs.add(name, "fail", "the server issued a code for a request whose parameters went through the browser instead of PAR", fapiRef+" §5.3.2.2")
		case vals.Get("error") != "":
			p.cs.add(name, "pass", "refused after sign-in with error="+vals.Get("error"), fapiRef+" §5.3.2.2")
		default:
			p.cs.add(name, "info", "unclear response after sign-in", fapiRef+" §5.3.2.2")
		}
	default:
		p.cs.add(name, "info", "unclear outcome: "+o.describe(), fapiRef+" §5.3.2.2")
	}
	return nil
}

// parPost sends a pushed authorization request with or without client
// authentication, keeping its checks out of the probe results.
func (p *bcpProbe) parPost(withAuth bool, form url.Values) (int, M, error) {
	ep, err := endpoint(p.c, p.meta, "pushed_authorization_request_endpoint")
	if err != nil {
		return 0, nil, err
	}
	hdr := map[string]string{}
	if withAuth {
		if err := clientAuth(p.c, p.meta, ep, form, hdr); err != nil {
			return 0, nil, err
		}
	} else {
		form.Set("client_id", p.c.Str("client_id"))
	}
	res, err := p.c.postForm(ep, form, hdr)
	if err != nil {
		return 0, nil, err
	}
	return res.Status, res.obj(), nil
}

func (p *bcpProbe) parForm(withRedirect bool) url.Values {
	verifier := randToken(32)
	sum := sha256.Sum256([]byte(verifier))
	f := url.Values{"response_type": {"code"}, "client_id": {p.c.Str("client_id")}, "scope": {p.c.Str("scope")},
		"state": {randToken(16)}, "code_challenge": {b64url(sum[:])}, "code_challenge_method": {"S256"}}
	if withRedirect {
		f.Set("redirect_uri", p.redirectURI)
	}
	return f
}

// judgePAR classifies the answer to a pushed request the server must refuse.
// A refusal is a 4xx with an OAuth error, and only counts when a valid
// pushed request from the same client succeeds; a request_uri means it was
// accepted; anything else (a 5xx, a page) proves nothing.
func (p *bcpProbe) judgePAR(name, key string, status int, body M, accepted string) {
	p.report[key] = M{"outcome": refusal(status, body)}
	ref := fapiRef + " §5.3.2.2"
	switch {
	case status == 201 || status == 200 && str(body["request_uri"]) != "":
		p.cs.add(name, "fail", accepted+" ("+refusal(status, body)+")", ref)
	case status >= 400 && status < 500 && str(body["error"]) != "":
		if !p.parWorks() {
			p.cs.add(name, "info", "inconclusive: the PAR endpoint refuses a valid request from this client too", ref)
			return
		}
		p.cs.add(name, "pass", "refused: "+refusal(status, body), ref)
	default:
		p.cs.add(name, "info", "inconclusive: "+refusal(status, body), ref)
	}
}

func (p *bcpProbe) parClientAuth() error {
	name := "FAPI 2.0: PAR without client authentication refused"
	if m := effectiveClientAuth(p.c); m == "tls_client_auth" || m == "self_signed_tls_client_auth" {
		// The client certificate goes with every request on this transport.
		p.cs.add(name, "info", "not tested: this client authenticates with its TLS certificate, which every request here presents", fapiRef+" §5.3.2.2")
		return nil
	}
	status, body, err := p.parPost(false, p.parForm(true))
	if err != nil {
		return err
	}
	p.judgePAR(name, "par_client_auth", status, body, "the server issued a request_uri to an unauthenticated client")
	return nil
}

func (p *bcpProbe) parRedirectURI() error {
	name := "FAPI 2.0: PAR without redirect_uri refused"
	status, body, err := p.parPost(true, p.parForm(false))
	if err != nil {
		return err
	}
	p.judgePAR(name, "par_redirect_uri", status, body, "the server accepted a pushed request without redirect_uri")
	return nil
}

func (p *bcpProbe) dpopCodeBinding() error {
	name := "FAPI 2.0: code bound to the DPoP key"
	if !p.c.Bool("dpop") {
		p.cs.add(name, "info", "needs dpop: the authorization request then carries dpop_jkt", fapiRef+" §5.3.2.1")
		return nil
	}
	code, verifier, authErr, err := p.code("dpop_code_binding", true)
	if err != nil {
		return err
	}
	if authErr != "" {
		return fmt.Errorf("authorization failed: %s", authErr)
	}
	// Redeem with a different DPoP key than the one named by dpop_jkt.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	bound := p.c.dpop
	p.c.dpop = other // a fresh key, whatever dpop_key says
	status, body, err := p.exchange(code, verifier)
	p.c.dpop = bound
	if err != nil {
		return err
	}
	p.report["dpop_code_binding"] = M{"redeemed_with_other_key": refusal(status, body)}
	p.cs.ok(status != 200, name, map[bool]string{true: "redemption with another DPoP key refused: " + refusal(status, body), false: "the code was redeemed with a DPoP key other than the one in dpop_jkt"}[status != 200], fapiRef+" §5.3.2.1, RFC 9449 §10")
	return nil
}

func (p *bcpProbe) codeLifetime() error {
	name := "FAPI 2.0: authorization code expires within 60 s"
	code, verifier, authErr, err := p.code("code_lifetime", true)
	if err != nil {
		return err
	}
	if authErr != "" {
		return fmt.Errorf("authorization failed: %s", authErr)
	}
	p.c.Log("Probe code_lifetime: waiting 61 s before redeeming the code")
	select {
	case <-time.After(61 * time.Second):
	case <-p.c.Done():
		return p.c.Err()
	}
	status, body, err := p.exchange(code, verifier)
	if err != nil {
		return err
	}
	p.report["code_lifetime"] = M{"redeemed_after_61s": refusal(status, body)}
	p.cs.ok(status != 200, name, map[bool]string{true: "refused after 61 s: " + refusal(status, body), false: "the code still worked after 61 s"}[status != 200], fapiRef+" §5.3.2.1")
	return nil
}
