package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// fetchMeta loads OIDC discovery or RFC 8414 authorization server metadata.
func fetchMeta(c *Ctx, issuer string) (M, string, error) {
	var candidates []string
	if strings.Contains(issuer, "/.well-known/") {
		candidates = []string{issuer}
	} else {
		base := strings.TrimSuffix(issuer, "/")
		candidates = []string{base + "/.well-known/openid-configuration"}
		if u, err := url.Parse(base); err == nil && u.Host != "" {
			candidates = append(candidates, u.Scheme+"://"+u.Host+"/.well-known/oauth-authorization-server"+u.Path)
		}
		candidates = append(candidates, base+"/.well-known/oauth-authorization-server")
	}
	var lastErr error
	for _, u := range candidates {
		res, err := c.do("GET", u, map[string]string{"Accept": "application/json"}, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if m := res.obj(); res.Status == 200 && m != nil {
			return m, u, nil
		}
		lastErr = fmt.Errorf("%s returned HTTP %d", u, res.Status)
		if loc := res.Header.Get("Location"); res.Status >= 300 && res.Status < 400 {
			lastErr = fmt.Errorf("%s redirects (HTTP %d) to %s", u, res.Status, loc)
		}
	}
	return nil, "", fmt.Errorf("could not load metadata for %s: %w", issuer, lastErr)
}

func getMeta(c *Ctx) (M, error) {
	if c.Str("issuer") == "" {
		return M{}, nil
	}
	m, _, err := fetchMeta(c, c.Str("issuer"))
	return m, err
}

// endpoint prefers an explicit parameter over the discovered value.
//
// An endpoint taken from the provider's metadata must pass the stored-secret
// guard like an explicit one: otherwise a hostile or compromised discovery
// document could name another host as, say, its token endpoint and receive
// a client secret stored for this issuer. (Explicit endpoints are checked
// when the arguments are prepared; the authorization endpoint only gets
// the browser, never a credential.)
func endpoint(c *Ctx, meta M, key string) (string, error) {
	if v := c.Str(key); v != "" {
		return v, nil
	}
	fromMeta := ""
	if aliases, _ := meta["mtls_endpoint_aliases"].(map[string]any); c.Str("mtls_cert") != "" && str(aliases[key]) != "" {
		fromMeta = str(aliases[key])
	} else {
		fromMeta = str(meta[key])
	}
	if fromMeta != "" {
		if key != "authorization_endpoint" {
			if err := c.allowDestination("the request to the "+key+" from the provider's metadata", fromMeta); err != nil {
				return "", err
			}
		}
		return fromMeta, nil
	}
	if c.Str("issuer") != "" {
		return "", fmt.Errorf("the issuer metadata has no %s; pass %s explicitly", key, key)
	}
	return "", fmt.Errorf("pass issuer (for discovery) or %s", key)
}

// clientAuth adds the client's credentials to a request to ep.
func clientAuth(c *Ctx, meta M, ep string, form url.Values, hdr map[string]string) error {
	id, sec := c.Str("client_id"), c.Str("client_secret")
	mode := c.Str("client_auth")
	if mode == "" {
		mode = "none"
		if sec != "" {
			mode = "basic"
		}
	}
	switch mode {
	case "basic":
		cred := url.QueryEscape(id) + ":" + url.QueryEscape(sec)
		hdr["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(cred))
	case "post":
		form.Set("client_id", id)
		form.Set("client_secret", sec)
	case "private_key_jwt", "client_secret_jwt":
		assertion, err := clientAssertion(c, meta, ep, mode)
		if err != nil {
			return err
		}
		form.Set("client_id", id)
		form.Set("client_assertion_type", assertionType)
		form.Set("client_assertion", assertion)
	case "tls_client_auth", "self_signed_tls_client_auth":
		if c.Str("mtls_cert") == "" {
			return errors.New(mode + " needs mtls_cert and mtls_key")
		}
		form.Set("client_id", id)
	default:
		if id != "" {
			form.Set("client_id", id)
		}
	}
	return nil
}

func halfHash(alg, value string) string {
	_, newHash := algHash(alg)
	h := newHash()
	h.Write([]byte(value))
	sum := h.Sum(nil)
	return b64url(sum[:len(sum)/2])
}

// validateIDToken applies OIDC Core §3.1.3.7 and returns the decoded token.
func validateIDToken(c *Ctx, cs *Checks, meta M, idToken, accessToken, code, nonce string) M {
	const ref = "OIDC Core §3.1.3.7"
	p, err := parseJWT(idToken)
	if err != nil {
		cs.add("id_token: is a JWT", "fail", err.Error(), "OIDC Core §2")
		return nil
	}
	out := describeJWT(p)
	alg := str(p.Header["alg"])
	if jwksURI := str(meta["jwks_uri"]); jwksURI != "" && !strings.HasPrefix(alg, "HS") {
		keys, err := fetchJWKS(c, jwksURI)
		if err == nil {
			var used string
			used, err = verifyWithJWKS(p, keys)
			if err == nil {
				cs.add("id_token: signature", "pass", alg+" verified with key "+used, ref)
			}
		}
		if err != nil {
			cs.add("id_token: signature", "fail", err.Error(), ref)
		}
	} else if strings.HasPrefix(alg, "HS") && c.Str("client_secret") != "" {
		verr := verifySig(alg, []byte(c.Str("client_secret")), p.SigningInput, p.Sig)
		cs.ok(verr == nil, "id_token: signature", detailOr(verr, alg+" verified with the client secret"), ref)
	} else if strings.HasPrefix(alg, "HS") {
		cs.add("id_token: signature", "warn", "not verified: "+alg+" ID tokens are signed with the client secret; pass client_secret", ref)
	} else {
		cs.add("id_token: signature", "warn", "not verified: no jwks_uri known (pass issuer)", ref)
	}
	if p.Claims == nil {
		cs.add("id_token: claims", "fail", "payload is not a JSON object", ref)
		return out
	}
	if iss := str(meta["issuer"]); iss != "" {
		cs.ok(str(p.Claims["iss"]) == iss, "id_token: iss matches the issuer", "iss="+str(p.Claims["iss"]), ref)
	}
	auds := audList(p.Claims)
	if id := c.Str("client_id"); id != "" {
		cs.ok(contains(auds, id), "id_token: aud contains the client_id", "aud="+strings.Join(auds, " "), ref)
		if len(auds) > 1 {
			cs.ok(str(p.Claims["azp"]) == id, "id_token: azp equals the client_id (multiple audiences)", "azp="+str(p.Claims["azp"]), ref)
		}
	}
	cs.ok(str(p.Claims["sub"]) != "", "id_token: sub present", "sub="+str(p.Claims["sub"]), "OIDC Core §2")
	timeChecks(cs, p.Claims, 60)
	if nonce != "" {
		cs.ok(str(p.Claims["nonce"]) == nonce, "id_token: nonce matches the request", "nonce="+str(p.Claims["nonce"]), ref)
	}
	if ah := str(p.Claims["at_hash"]); ah != "" && accessToken != "" {
		cs.ok(ah == halfHash(alg, accessToken), "id_token: at_hash matches the access token", "", "OIDC Core §3.1.3.8")
	}
	if ch := str(p.Claims["c_hash"]); ch != "" && code != "" {
		cs.ok(ch == halfHash(alg, code), "id_token: c_hash matches the code", "", "OIDC Core §3.3.2.11")
	}
	return out
}

// tokenCall posts to the token endpoint and analyses whatever comes back. An
// error response is a result, not a Go error: showing it is the point.
func tokenCall(c *Ctx, meta M, form url.Values, cs *Checks, nonce string) (M, error) {
	ep, err := endpoint(c, meta, "token_endpoint")
	if err != nil {
		return nil, err
	}
	send := func(dpopNonce string) (*httpResult, error) {
		f := url.Values{}
		for k, v := range form {
			f[k] = v
		}
		hdr := map[string]string{}
		if err := clientAuth(c, meta, ep, f, hdr); err != nil {
			return nil, err
		}
		if c.Bool("dpop") {
			proof, err := dpopProof(c, "POST", ep, "", dpopNonce)
			if err != nil {
				return nil, err
			}
			hdr["DPoP"] = proof
		}
		return c.postForm(ep, f, hdr)
	}
	res, err := send("")
	if err != nil {
		return nil, err
	}
	if n := res.Header.Get("DPoP-Nonce"); c.Bool("dpop") && n != "" && str(res.obj()["error"]) == "use_dpop_nonce" {
		cs.add("DPoP: server-provided nonce", "info", "the server demanded a nonce; the request was repeated with it", "RFC 9449 §8")
		if res, err = send(n); err != nil {
			return nil, err
		}
	}
	out := M{"token_endpoint": ep, "grant_type": form.Get("grant_type"), "status": res.Status, "response": res.payload()}
	body := res.obj()
	if res.Status != 200 || body == nil {
		detail := fmt.Sprintf("HTTP %d", res.Status)
		if body != nil && str(body["error"]) != "" {
			detail += ": " + str(body["error"])
			if d := str(body["error_description"]); d != "" {
				detail += " (" + d + ")"
			}
		}
		cs.add("token response", "fail", detail, "RFC 6749 §5.2")
		if body != nil && str(body["error"]) == "invalid_client" && c.Str("client_secret") == "" {
			cs.add("client authentication", "info", "no client secret was sent; if the client is registered as confidential, supply client_secret (env IDPDBG_CLIENT_SECRET or a profile), or register it as a public client", "RFC 6749 §2.3")
		}
		return out, nil
	}
	cs.add("token response", "pass", "HTTP 200", "RFC 6749 §5.1")
	at := str(body["access_token"])
	if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" || at != "" {
		cs.ok(at != "", "access_token present", "", "RFC 6749 §5.1")
	}
	cs.ok(str(body["token_type"]) != "", "token_type present", "token_type="+str(body["token_type"]), "RFC 6749 §5.1")
	cs.warn(strings.Contains(res.Header.Get("Cache-Control"), "no-store"), "Cache-Control: no-store", "Cache-Control="+res.Header.Get("Cache-Control"), "RFC 6749 §5.1")
	if _, ok := body["expires_in"]; !ok {
		cs.add("expires_in present", "warn", "RECOMMENDED but missing", "RFC 6749 §5.1")
	}
	if idt := str(body["id_token"]); idt != "" {
		out["id_token"] = validateIDToken(c, cs, meta, idt, at, "", nonce)
	}
	granted := str(body["scope"])
	if granted == "" {
		granted = form.Get("scope")
	}
	refreshTokenCheck(cs, granted, body, form.Get("grant_type"))
	if c.Bool("dpop") {
		dpopTokenChecks(c, cs, body, out)
	}
	if c.Str("mtls_cert") != "" {
		mtlsTokenChecks(c, cs, body)
	}
	bcpTokenChecks(c, cs, body)
	if c.Bool("fapi") {
		fapiClient(c, cs)
		fapiTokens(cs, body)
	}
	if looksLikeJWT(at) {
		if p, err := parseJWT(at); err == nil {
			out["access_token_decoded"] = describeJWT(p)
		}
	} else if at != "" {
		cs.add("access_token format", "info", "opaque (not a JWT); use oidc introspect to look inside", "RFC 7662")
	}
	return out, nil
}

// effectiveClientAuth is the client authentication method clientAuth uses.
func effectiveClientAuth(c *Ctx) string {
	if m := c.Str("client_auth"); m != "" {
		return m
	}
	if c.Str("client_secret") != "" {
		return "basic"
	}
	return "none"
}

// bcpTokenChecks judges a successful token response against the Security
// BCP: how the client authenticated, and whether the access token is bound
// to a key and restricted to an audience.
func bcpTokenChecks(c *Ctx, cs *Checks, body M) {
	switch m := effectiveClientAuth(c); m {
	case "none":
	case "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth":
		cs.bcp(true, "asymmetric client authentication", m, "", "RFC 9700 §2.5", "info")
	default:
		cs.bcp(false, "asymmetric client authentication", "", "the client authenticated with a shared secret ("+m+"); private_key_jwt or mutual TLS is recommended", "RFC 9700 §2.5", "info")
	}
	at := str(body["access_token"])
	if at == "" {
		return
	}
	var claims M
	if looksLikeJWT(at) {
		if p, err := parseJWT(at); err == nil {
			claims = p.Claims
		}
	}
	cnf, _ := claims["cnf"].(map[string]any)
	bound := strings.EqualFold(str(body["token_type"]), "DPoP") || str(cnf["jkt"]) != "" || str(cnf["x5t#S256"]) != ""
	cs.bcp(bound, "access token is sender-constrained", "bound to a key (token_type="+str(body["token_type"])+")",
		"a bearer token: whoever holds it can use it (try dpop, or mutual TLS)", "RFC 9700 §2.2.1", "info")
	if claims != nil {
		aud := audList(claims)
		cs.bcp(len(aud) > 0, "access token is audience-restricted", "aud="+strings.Join(aud, ", "), "the access token has no aud claim, so any resource server accepts it", "RFC 9700 §2.3", "info")
	}
}

// redirectParams describe the loopback redirect URI of browser flows.
var redirectParams = []Param{
	{Name: "redirect_host", Type: "string", Desc: "Host used in the redirect URI (localhost or 127.0.0.1)", Default: "localhost"},
	{Name: "redirect_port", Type: "int", Desc: "Loopback port to listen on", Default: 8765},
	{Name: "redirect_path", Type: "string", Desc: "Path of the redirect URI", Default: "/callback"},
	{Name: "redirect_uri", Type: "string", Desc: "Full redirect URI, overriding host/port/path; must point at this machine"},
}

// ---- parameters shared by the grants ----

var (
	pIssuer        = Param{Name: "issuer", Type: "string", Desc: "Issuer URL; endpoints and keys are discovered from its metadata"}
	pClientID      = Param{Name: "client_id", Type: "string", Desc: "OAuth client identifier"}
	pClientSecret  = Param{Name: "client_secret", Type: "string", Secret: true, Desc: "Client secret (prefer env IDPDBG_CLIENT_SECRET or a profile)"}
	pClientAuth    = Param{Name: "client_auth", Type: "string", Enum: []string{"basic", "post", "none", "private_key_jwt", "client_secret_jwt", "tls_client_auth", "self_signed_tls_client_auth"}, Desc: "Client authentication method; default basic when a secret is set, otherwise none"}
	pTokenEndpoint = Param{Name: "token_endpoint", Type: "string", Desc: "Token endpoint, overriding discovery"}
	pScope         = Param{Name: "scope", Type: "string", Desc: "Space-separated scopes"}
)

func clientParams(extra ...Param) []Param {
	base := append([]Param{pIssuer, pClientID, pClientSecret, pClientAuth, pTokenEndpoint}, advancedClientParams...)
	return append(base, extra...)
}

var authzParams = []Param{
	{Name: "authorization_endpoint", Type: "string", Desc: "Authorization endpoint, overriding discovery"},
	{Name: "scope", Type: "string", Desc: "Space-separated scopes", Default: "openid profile email"},
	{Name: "response_type", Type: "string", Desc: "code (default), or an implicit/hybrid type such as 'code id_token'", Default: "code"},
	{Name: "response_mode", Type: "string", Desc: "query, fragment or form_post"},
	{Name: "pkce", Type: "bool", Desc: "Send an S256 PKCE challenge", Default: true},
	{Name: "prompt", Type: "string", Desc: "none, login, consent or select_account"},
	{Name: "login_hint", Type: "string", Desc: "Login hint passed to the provider"},
	{Name: "acr_values", Type: "string", Desc: "Requested authentication context class references"},
	{Name: "max_age", Type: "int", Desc: "Maximum authentication age in seconds"},
	{Name: "audience", Type: "string", Desc: "audience parameter (Auth0-style APIs)"},
	{Name: "resource", Type: "string", Desc: "RFC 8707 resource indicator"},
	{Name: "extra", Type: "json", Desc: `Extra authorization parameters as a JSON object, e.g. {"claims":"..."}`},
	{Name: "par", Type: "bool", Desc: "Push the authorization request to the PAR endpoint first (RFC 9126) and send only its request_uri through the browser"},
	{Name: "jar", Type: "bool", Desc: "Send the authorization parameters as a request object signed with client_key (RFC 9101)"},
	{Name: "pushed_authorization_request_endpoint", Type: "string", Desc: "PAR endpoint, overriding discovery"},
}

type authzRequest struct {
	URL, State, Nonce, Verifier, RedirectURI string
	RequestObject                            string // set with jar
	PAR                                      M      // set with par
	Checks                                   Checks
}

// describe adds what was done to build the request to a result.
func (a *authzRequest) describe(out M) {
	if a.RequestObject != "" {
		if p, err := parseJWT(a.RequestObject); err == nil {
			out["request_object"] = describeJWT(p)
		}
	}
	if a.PAR != nil {
		out["pushed_authorization_request"] = a.PAR
	}
}

func buildAuthURL(c *Ctx, meta M, redirectURI string) (*authzRequest, error) {
	ep, err := endpoint(c, meta, "authorization_endpoint")
	if err != nil {
		return nil, err
	}
	if c.Str("client_id") == "" {
		return nil, errors.New("missing required parameter \"client_id\"")
	}
	u, err := url.Parse(ep)
	if err != nil {
		return nil, err
	}
	a := &authzRequest{State: randToken(16), RedirectURI: redirectURI}
	q := u.Query()
	q.Set("response_type", c.Str("response_type"))
	q.Set("client_id", c.Str("client_id"))
	q.Set("redirect_uri", redirectURI)
	q.Set("state", a.State)
	if s := c.Str("scope"); s != "" {
		q.Set("scope", s)
		if strings.Contains(" "+s+" ", " openid ") {
			a.Nonce = randToken(16)
			q.Set("nonce", a.Nonce)
		}
	}
	if c.Bool("pkce") && strings.Contains(c.Str("response_type"), "code") {
		a.Verifier = randToken(32)
		sum := sha256.Sum256([]byte(a.Verifier))
		q.Set("code_challenge", b64url(sum[:]))
		q.Set("code_challenge_method", "S256")
	}
	for _, n := range []string{"response_mode", "prompt", "login_hint", "acr_values", "audience", "resource"} {
		if v := c.Str(n); v != "" {
			q.Set(n, v)
		}
	}
	if c.Has("max_age") {
		q.Set("max_age", strconv.Itoa(c.Int("max_age")))
	}
	if extra, ok := c.Args["extra"].(map[string]any); ok {
		for k, v := range extra {
			if s, isStr := v.(string); isStr {
				q.Set(k, s)
			} else {
				b, _ := json.Marshal(v)
				q.Set(k, string(b))
			}
		}
	}
	if c.Bool("dpop") {
		jkt, err := dpopThumbprint(c)
		if err != nil {
			return nil, err
		}
		q.Set("dpop_jkt", jkt)
	}
	if q, err = applyRequestModes(c, meta, a, q); err != nil {
		return a, err
	}
	u.RawQuery = q.Encode()
	a.URL = u.String()
	return a, nil
}

func runDiscover(c *Ctx) (M, error) {
	meta, u, err := fetchMeta(c, c.Str("issuer"))
	if err != nil {
		return nil, err
	}
	var cs Checks
	oidcDoc := strings.HasSuffix(u, "openid-configuration")
	ref := "RFC 8414 §2"
	if oidcDoc {
		ref = "OIDC Discovery §3"
	}
	if !strings.Contains(c.Str("issuer"), "/.well-known/") {
		cs.ok(str(meta["issuer"]) == c.Str("issuer"), "issuer matches the URL used for discovery exactly",
			fmt.Sprintf("metadata issuer=%q, requested=%q", str(meta["issuer"]), c.Str("issuer")), "OIDC Discovery §4.3 / RFC 8414 §3.3")
	}
	required := []string{"issuer", "response_types_supported"}
	if oidcDoc {
		required = append(required, "authorization_endpoint", "jwks_uri", "subject_types_supported", "id_token_signing_alg_values_supported")
	}
	for _, k := range required {
		_, ok := meta[k]
		cs.ok(ok, "required metadata: "+k, "", ref)
	}
	for _, k := range sortedKeys(meta) {
		if v := str(meta[k]); (strings.HasSuffix(k, "_endpoint") || k == "jwks_uri" || k == "issuer") && v != "" {
			if !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://localhost") && !strings.HasPrefix(v, "http://127.0.0.1") {
				cs.add("https: "+k, "fail", v, "RFC 8414 §2")
			}
		}
	}
	list := func(k string) []string {
		out, _ := coerce(Param{Name: k, Type: "list"}, meta[k], false)
		l, _ := out.([]string)
		return l
	}
	methods := "code_challenge_methods_supported=" + strings.Join(list("code_challenge_methods_supported"), " ")
	cs.bcp(contains(list("code_challenge_methods_supported"), "S256"), "PKCE S256 advertised", methods, methods, "RFC 9700 §2.1.1", "warn")
	if contains(list("code_challenge_methods_supported"), "plain") {
		cs.bcp(false, "PKCE plain not offered", "", "plain is advertised; S256 should be the only method", "RFC 9700 §2.1.1", "warn")
	}
	grants := list("grant_types_supported")
	if contains(grants, "password") {
		cs.bcp(false, "resource owner password grant not offered", "", "grant_types_supported includes password, which must not be used", "RFC 9700 §2.4", "warn")
	}
	if contains(grants, "implicit") {
		cs.bcp(false, "implicit grant not offered", "", "grant_types_supported includes implicit", "RFC 9700 §2.1.2", "warn")
	}
	authMethods := list("token_endpoint_auth_methods_supported")
	asym := []string{}
	for _, m := range []string{"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"} {
		if contains(authMethods, m) {
			asym = append(asym, m)
		}
	}
	cs.bcp(len(asym) > 0, "asymmetric client authentication offered", strings.Join(asym, ", "),
		"token_endpoint_auth_methods_supported has neither private_key_jwt nor mutual TLS; clients can only use shared secrets", "RFC 9700 §2.5", "info")
	constrained := []string{}
	if len(list("dpop_signing_alg_values_supported")) > 0 {
		constrained = append(constrained, "DPoP")
	}
	if meta["tls_client_certificate_bound_access_tokens"] == true {
		constrained = append(constrained, "mTLS-bound tokens")
	}
	cs.bcp(len(constrained) > 0, "sender-constrained access tokens offered", strings.Join(constrained, ", "),
		"neither DPoP (dpop_signing_alg_values_supported) nor mTLS-bound tokens are advertised", "RFC 9700 §2.2.1", "info")
	if contains(list("id_token_signing_alg_values_supported"), "none") {
		cs.add("alg none not offered for ID tokens", "warn", "id_token_signing_alg_values_supported includes none", "RFC 8725 §3.2")
	}
	for _, rt := range list("response_types_supported") {
		if contains(strings.Fields(rt), "token") {
			cs.bcp(false, "no response type issues access tokens in the front channel", "", "response_types_supported includes "+strconv.Quote(rt), "RFC 9700 §2.1.2", "warn")
			break
		}
	}
	if meta["authorization_response_iss_parameter_supported"] == true {
		cs.add("issuer identification in authorization responses", "pass", "the iss parameter is supported (mix-up defence)", "RFC 9207")
	} else {
		cs.add("issuer identification in authorization responses", "info", "authorization_response_iss_parameter_supported is not advertised", "RFC 9207")
	}
	offered := []string{}
	if str(meta["pushed_authorization_request_endpoint"]) != "" {
		offered = append(offered, "PAR")
	}
	if len(list("dpop_signing_alg_values_supported")) > 0 {
		offered = append(offered, "DPoP")
	}
	if meta["tls_client_certificate_bound_access_tokens"] == true {
		offered = append(offered, "mTLS-bound tokens")
	}
	if meta["request_parameter_supported"] == true || len(list("request_object_signing_alg_values_supported")) > 0 {
		offered = append(offered, "request objects (JAR)")
	}
	if contains(list("token_endpoint_auth_methods_supported"), "private_key_jwt") {
		offered = append(offered, "private_key_jwt")
	}
	if str(meta["end_session_endpoint"]) != "" {
		offered = append(offered, "RP-initiated logout")
	}
	cs.add("advanced features offered", "info", strings.Join(offered, ", "), "")
	if c.Bool("fapi") {
		fapiDiscover(&cs, meta, list)
	}
	out := M{"metadata_url": u, "metadata": meta}
	if jw := str(meta["jwks_uri"]); jw != "" {
		if keys, err := fetchJWKS(c, jw); err != nil {
			cs.add("jwks_uri is reachable", "fail", err.Error(), ref)
		} else {
			descs := []M{}
			for _, k := range keys {
				descs = append(descs, describeJWK(k))
			}
			out["jwks"] = descs
			cs.add("jwks_uri is reachable", "pass", fmt.Sprintf("%d key(s)", len(keys)), ref)
		}
	}
	out["checks"] = cs
	return out, nil
}

// redirectScheme is the scheme idpdbg's listener must speak for a redirect URI.
func redirectScheme(redirectURI string) string {
	if strings.HasPrefix(strings.ToLower(redirectURI), "https://") {
		return "https"
	}
	return "http"
}

// loginRedirect works out the loopback redirect URI from the redirect_*
// parameters, and the port and path to listen on.
func loginRedirect(c *Ctx) (redirectURI string, port int, path string, err error) {
	port, path = c.Int("redirect_port"), c.Str("redirect_path")
	redirectURI = c.Str("redirect_uri")
	if redirectURI == "" {
		return fmt.Sprintf("http://%s:%d%s", c.Str("redirect_host"), port, path), port, path, nil
	}
	ru, err := url.Parse(redirectURI)
	if err != nil {
		return "", 0, "", err
	}
	if h := ru.Hostname(); h != "localhost" && h != "127.0.0.1" && h != "::1" {
		return "", 0, "", fmt.Errorf("redirect_uri %s does not point at this machine, so idpdbg cannot receive the response; use localhost, or oidc auth_url and oidc exchange_code for other redirect URIs", redirectURI)
	}
	switch p, err := strconv.Atoi(ru.Port()); {
	case err == nil:
		port = p
	case ru.Scheme == "https":
		port = 443 // where the browser will go
	default:
		port = 80
	}
	if path = ru.Path; path == "" {
		path = "/"
	}
	return redirectURI, port, path, nil
}

// captureRedirect listens on the loopback port, sends the person to
// startURL and returns the parameters the provider redirects back with
// (query, form_post, or a fragment forwarded by fragmentPage).
func captureRedirect(c *Ctx, startURL string, port int, path, wantState string) (url.Values, error) {
	return captureRedirectScheme(c, startURL, port, path, "http", wantState)
}

// captureRedirectScheme is captureRedirect for an http or https redirect URI.
// For https the listener uses a throwaway self-signed certificate.
//
// Only a response carrying wantState is taken: anything else that reaches
// the listener (another local process, a web page posting to localhost, a
// late answer from an earlier request) is turned away, so it can neither
// end the run nor plant a result.
func captureRedirectScheme(c *Ctx, startURL string, port int, path, scheme, wantState string) (url.Values, error) {
	ch := make(chan url.Values, 1)
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if len(r.Form) == 0 && r.Method == http.MethodGet {
			fmt.Fprint(w, fragmentPage)
			return
		}
		if wantState != "" && r.Form.Get("state") != wantState {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "idpdbg: ignored a response that does not carry this run's state")
			return
		}
		fmt.Fprint(w, donePage)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case ch <- r.Form:
		default:
		}
	})
	var cert *tls.Certificate
	if scheme == "https" {
		var fp string
		var err error
		if cert, fp, err = loopbackCert(); err != nil {
			return nil, err
		}
		c.Log("The redirect URI uses https: the browser will warn about idpdbg's self-signed certificate for localhost (SHA-256 %s); accept it to let the response through", fp)
	}
	stop, err := serveLoopbackTLS(port, mux, cert)
	if err != nil {
		return nil, err
	}
	defer stop()
	return awaitBrowser(c, startURL, ch)
}

func runLogin(c *Ctx) (M, error) {
	meta, err := getMeta(c)
	if err != nil {
		return nil, err
	}
	redirectURI, port, path, err := loginRedirect(c)
	if err != nil {
		return nil, err
	}
	a, err := buildAuthURL(c, meta, redirectURI)
	if err != nil {
		if a != nil && a.PAR != nil {
			return M{"pushed_authorization_request": a.PAR, "checks": a.Checks}, err
		}
		return nil, err
	}
	c.Log("Listening for the redirect on %s (register this exact redirect URI with the provider)", redirectURI)
	vals, err := captureRedirectScheme(c, a.URL, port, path, redirectScheme(redirectURI), a.State)
	if err != nil {
		return nil, err
	}

	cs := a.Checks
	resp := M{}
	for k := range vals {
		resp[k] = vals.Get(k)
	}
	out := M{"authorization_url": a.URL, "redirect_uri": redirectURI, "authorization_response": resp}
	a.describe(out)
	if !c.Bool("pkce") && strings.Contains(c.Str("response_type"), "code") {
		cs.bcp(false, "PKCE used", "", "the request was sent without a code_challenge", "RFC 9700 §2.1.1", "warn")
	}
	if contains(strings.Fields(c.Str("response_type")), "token") {
		cs.bcp(false, "no access token in the front channel", "", "response_type "+strconv.Quote(c.Str("response_type"))+" returns the access token in the browser", "RFC 9700 §2.1.2", "warn")
	}
	defer func() { out["checks"] = cs }()
	if e := vals.Get("error"); e != "" {
		cs.add("authorization response", "fail", e+": "+vals.Get("error_description"), "RFC 6749 §4.1.2.1")
		return out, nil
	}
	if !cs.ok(vals.Get("state") == a.State, "state matches the request", "", "RFC 6749 §10.12") {
		return out, nil
	}
	if iss := vals.Get("iss"); iss != "" && str(meta["issuer"]) != "" {
		cs.ok(iss == str(meta["issuer"]), "iss response parameter matches the issuer", "iss="+iss, "RFC 9207 §2.4")
	} else if meta["authorization_response_iss_parameter_supported"] == true {
		cs.add("iss response parameter present", "fail", "the metadata promises an iss parameter but the response has none", "RFC 9207 §2.4")
	}
	if c.Bool("fapi") {
		fapiAuthzRequest(c, &cs, redirectURI)
		cs.ok(vals.Get("iss") != "", "FAPI 2.0: iss returned in the authorization response", "iss="+vals.Get("iss"), fapiRef+" §5.3.2.2")
	}
	code := vals.Get("code")
	if idt := vals.Get("id_token"); idt != "" {
		out["front_channel_id_token"] = validateIDToken(c, &cs, meta, idt, vals.Get("access_token"), code, a.Nonce)
	}
	if code == "" {
		if strings.Contains(c.Str("response_type"), "code") {
			cs.add("authorization code returned", "fail", "no code parameter in the response", "RFC 6749 §4.1.2")
		}
		return out, nil
	}
	cs.add("authorization code returned", "pass", "", "RFC 6749 §4.1.2")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}}
	if a.Verifier != "" {
		form.Set("code_verifier", a.Verifier)
	}
	form.Set("scope", c.Str("scope")) // only consulted by the analysis below
	tok, err := tokenCallNoScope(c, meta, form, &cs, a.Nonce)
	if err != nil {
		return out, err
	}
	out["token"] = tok
	body, _ := tok["response"].(map[string]any)
	if ep := endpointOrEmpty(c, meta, "userinfo_endpoint"); ep != "" && tok["status"] == 200 && str(body["access_token"]) != "" && hasScope(c.Str("scope"), "openid") {
		granted := str(body["scope"])
		if granted == "" {
			granted = c.Str("scope")
		}
		var idClaims M
		if idt, _ := tok["id_token"].(M); idt != nil {
			idClaims, _ = idt["claims"].(M)
		}
		ui, err := fetchUserinfo(c, ep, str(body["access_token"]), idClaims, granted, &cs)
		if err != nil {
			cs.add("userinfo: response", "fail", err.Error(), "OIDC Core §5.3")
		} else {
			out["userinfo"] = ui
		}
	}
	return out, nil
}

func endpointOrEmpty(c *Ctx, meta M, key string) string {
	ep, _ := endpoint(c, meta, key)
	return ep
}

func hasScope(scope, want string) bool {
	return contains(strings.Fields(scope), want)
}

// refreshTokenCheck flags a grant of offline_access that came back without a
// refresh token: the scope was accepted but has no effect.
func refreshTokenCheck(cs *Checks, scope string, body M, grant string) {
	if !hasScope(scope, "offline_access") || grant == "client_credentials" {
		return
	}
	if str(body["refresh_token"]) != "" {
		cs.add("refresh token issued for offline_access", "pass", "", "OIDC Core §11")
		return
	}
	cs.add("refresh token issued for offline_access", "warn",
		"offline_access was granted but the response has no refresh_token; the client may lack the refresh_token grant, or the provider may require prompt=consent", "OIDC Core §11")
}

// scopeClaims are the standard claims each scope asks for (OIDC Core §5.4).
var scopeClaims = map[string][]string{
	"profile": {"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"},
	"email":   {"email"},
	"phone":   {"phone_number"},
	"address": {"address"},
}

// scopeClaimChecks flags a granted scope that produced none of its claims.
// sources are the claim sets a client can read them from (UserInfo, ID token).
func scopeClaimChecks(cs *Checks, scope, where string, sources ...M) {
	for _, sc := range []string{"profile", "email", "phone", "address"} {
		if !hasScope(scope, sc) {
			continue
		}
		var found []string
		for _, claim := range scopeClaims[sc] {
			for _, src := range sources {
				if _, ok := src[claim]; ok {
					found = append(found, claim)
					break
				}
			}
		}
		name := "scope " + sc + " yields its claims"
		if len(found) > 0 {
			cs.add(name, "pass", strings.Join(found, ", ")+" present in "+where, "OIDC Core §5.4")
		} else {
			cs.add(name, "warn", "scope "+sc+" was granted but "+where+" contains none of its claims ("+strings.Join(scopeClaims[sc], ", ")+"); check the client's attribute or claim mapping", "OIDC Core §5.4")
		}
	}
}

// fetchUserinfo calls the UserInfo endpoint and checks the response. idClaims
// are the ID token's claims when known; scope is what was granted.
func fetchUserinfo(c *Ctx, ep, accessToken string, idClaims M, scope string, cs *Checks) (M, error) {
	call := func(dpopNonce string) (*httpResult, error) {
		hdr := map[string]string{"Authorization": "Bearer " + accessToken, "Accept": "application/json, application/jwt"}
		if c.Bool("dpop") {
			proof, err := dpopProof(c, "GET", ep, accessToken, dpopNonce)
			if err != nil {
				return nil, err
			}
			hdr["Authorization"], hdr["DPoP"] = "DPoP "+accessToken, proof
		}
		return c.do("GET", ep, hdr, nil)
	}
	res, err := call("")
	if err != nil {
		return nil, err
	}
	if n := res.Header.Get("DPoP-Nonce"); c.Bool("dpop") && res.Status == 401 && n != "" {
		if res, err = call(n); err != nil {
			return nil, err
		}
	}
	out := M{"userinfo_endpoint": ep, "status": res.Status, "response": res.payload()}
	claims := res.obj()
	if res.Status == 200 && claims == nil && looksLikeJWT(strings.TrimSpace(string(res.Body))) {
		if p, err := parseJWT(string(res.Body)); err == nil {
			out["response"] = describeJWT(p)
			claims = p.Claims
			cs.add("userinfo: response format", "info", "signed JWT (application/jwt)", "OIDC Core §5.3.2")
		}
	}
	if !cs.ok(res.Status == 200 && claims != nil, "userinfo: response", strings.TrimSpace(fmt.Sprintf("HTTP %d %s", res.Status, res.Header.Get("WWW-Authenticate"))), "OIDC Core §5.3.2") {
		return out, nil
	}
	cs.ok(str(claims["sub"]) != "", "userinfo: sub present", "sub="+str(claims["sub"]), "OIDC Core §5.3.2")
	where := "the UserInfo response"
	sources := []M{claims}
	if idClaims != nil {
		cs.ok(str(idClaims["sub"]) == str(claims["sub"]), "userinfo: sub matches the ID token", "id_token sub="+str(idClaims["sub"]), "OIDC Core §5.3.2")
		where = "the UserInfo response or the ID token"
		sources = append(sources, idClaims)
	}
	scopeClaimChecks(cs, scope, where, sources...)
	return out, nil
}

// tokenCallNoScope lets the analysis see the requested scope without sending
// it on a grant where the parameter does not belong.
func tokenCallNoScope(c *Ctx, meta M, form url.Values, cs *Checks, nonce string) (M, error) {
	scope := form.Get("scope")
	form.Del("scope")
	out, err := tokenCall(c, meta, form, cs, nonce)
	if err == nil && out["id_token"] == nil && strings.Contains(" "+scope+" ", " openid ") && out["status"] == 200 {
		cs.add("id_token present", "fail", "scope openid was requested but no id_token was returned", "OIDC Core §3.1.3.3")
	}
	if body, _ := out["response"].(map[string]any); err == nil && out["status"] == 200 && body != nil && str(body["scope"]) == "" {
		refreshTokenCheck(cs, scope, body, form.Get("grant_type"))
	}
	return out, err
}

func simpleGrant(grant string, fill func(c *Ctx, form url.Values) error) func(c *Ctx) (M, error) {
	return func(c *Ctx) (M, error) {
		meta, err := getMeta(c)
		if err != nil {
			return nil, err
		}
		form := url.Values{"grant_type": {grant}}
		for _, n := range []string{"scope", "audience", "resource"} {
			if v := c.Str(n); v != "" {
				form.Set(n, v)
			}
		}
		if fill != nil {
			if err := fill(c, form); err != nil {
				return nil, err
			}
		}
		var cs Checks
		out, err := tokenCall(c, meta, form, &cs, "")
		if out != nil {
			out["checks"] = cs
		}
		return out, err
	}
}

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

func pollDevice(c *Ctx, meta M, deviceCode, verifier string, interval int, cs *Checks) (M, error) {
	if interval <= 0 {
		interval = 5
	}
	deadline := time.Now().Add(time.Duration(c.Int("wait")) * time.Second)
	polls := 0
	for {
		var attempt Checks
		form := url.Values{"grant_type": {deviceGrant}, "device_code": {deviceCode}}
		if verifier != "" {
			form.Set("code_verifier", verifier)
		}
		out, err := tokenCall(c, meta, form, &attempt, "")
		if err != nil {
			return nil, err
		}
		polls++
		out["polls"] = polls
		body, _ := out["response"].(map[string]any)
		switch e := str(body["error"]); e {
		case "authorization_pending", "slow_down":
			if e == "slow_down" {
				interval += 5
			}
			if time.Now().Add(time.Duration(interval) * time.Second).After(deadline) {
				out["pending"] = true
				cs.add("device authorization", "info", "still pending when the wait expired; run oidc device_poll again", "RFC 8628 §3.5")
				return out, nil
			}
			select {
			case <-time.After(time.Duration(interval) * time.Second):
			case <-c.Done():
				return nil, c.Err()
			}
		default:
			*cs = append(*cs, attempt...)
			return out, nil
		}
	}
}

// inactiveHint explains an inactive introspection result where the token
// itself shows why: it expired, or (for a JWT) its audience leaves out the
// client asking, which Keycloak 26 reports as inactive.
func inactiveHint(token, clientID string) string {
	p, err := parseJWT(token)
	if err != nil || p.Claims == nil {
		return ""
	}
	if exp, ok := claimTime(p.Claims, "exp"); ok && time.Now().After(exp) {
		return fmt.Sprintf("; the token expired at %s", exp.Format(time.RFC3339))
	}
	if aud := audList(p.Claims); clientID != "" && len(aud) > 0 && !contains(aud, clientID) {
		return fmt.Sprintf("; the token's aud (%s) does not include the introspecting client %s, and some servers (Keycloak 26) report such tokens inactive to it", strings.Join(aud, ", "), clientID)
	}
	return ""
}

func bearerCall(c *Ctx, meta M, key string, form url.Values) (*httpResult, string, error) {
	ep, err := endpoint(c, meta, key)
	if err != nil {
		return nil, "", err
	}
	hdr := map[string]string{}
	if err := clientAuth(c, meta, ep, form, hdr); err != nil {
		return nil, ep, err
	}
	res, err := c.postForm(ep, form, hdr)
	return res, ep, err
}

func init() {
	loginParams := append(clientParams(authzParams...), redirectParams...)
	loginParams = append(loginParams, browserParams...)

	register(
		&Op{
			Name:    "oidc.discover",
			Summary: "Fetch an issuer's OpenID Connect discovery document (or RFC 8414 metadata), fetch its JWKS, and check both against the specifications and the OAuth 2.0 Security BCP.",
			Params:  []Param{{Name: "issuer", Type: "string", Required: true, Desc: "Issuer URL, or the full .well-known metadata URL"}},
			Run:     runDiscover,
		},
		&Op{
			Name:    "oidc.login",
			Browser: true,
			Summary: "Run the Authorization Code flow with PKCE end to end: listen on a loopback redirect URI, open the browser, capture the authorization response, exchange the code, validate the ID token and call UserInfo. Flags a granted offline_access without a refresh token and granted scopes that yield no claims. Also handles implicit and hybrid response types. Blocks until the person finishes signing in.",
			Params:  loginParams,
			Run:     runLogin,
		},
		&Op{
			Name:    "oidc.auth_url",
			Summary: "Build an authorization request URL without sending it. Returns the URL plus the state, nonce and PKCE code_verifier needed to finish by hand with oidc exchange_code.",
			Params: append(clientParams(authzParams...),
				Param{Name: "redirect_uri", Type: "string", Required: true, Desc: "Redirect URI registered with the provider"}),
			Run: func(c *Ctx) (M, error) {
				meta, err := getMeta(c)
				if err != nil {
					return nil, err
				}
				a, err := buildAuthURL(c, meta, c.Str("redirect_uri"))
				if err != nil {
					if a != nil && a.PAR != nil {
						return M{"pushed_authorization_request": a.PAR, "checks": a.Checks}, err
					}
					return nil, err
				}
				u, _ := url.Parse(a.URL)
				params := M{}
				for k, v := range u.Query() {
					params[k] = v[0]
				}
				out := M{"authorization_url": a.URL, "parameters": params, "state": a.State, "nonce": a.Nonce, "code_verifier": a.Verifier, "checks": a.Checks}
				a.describe(out)
				return out, nil
			},
		},
		&Op{
			Name:    "oidc.exchange_code",
			Summary: "Exchange an authorization code at the token endpoint and validate the tokens returned.",
			Params: clientParams(
				Param{Name: "code", Type: "string", Required: true, Desc: "Authorization code from the redirect"},
				Param{Name: "redirect_uri", Type: "string", Required: true, Desc: "The redirect URI used in the authorization request"},
				Param{Name: "code_verifier", Type: "string", Desc: "PKCE code verifier"},
				Param{Name: "nonce", Type: "string", Desc: "Nonce sent in the authorization request, to check the ID token against"}),
			Run: func(c *Ctx) (M, error) {
				meta, err := getMeta(c)
				if err != nil {
					return nil, err
				}
				form := url.Values{"grant_type": {"authorization_code"}, "code": {c.Str("code")}, "redirect_uri": {c.Str("redirect_uri")}}
				if v := c.Str("code_verifier"); v != "" {
					form.Set("code_verifier", v)
				}
				var cs Checks
				out, err := tokenCall(c, meta, form, &cs, c.Str("nonce"))
				if out != nil {
					out["checks"] = cs
				}
				return out, err
			},
		},
		&Op{
			Name:    "oidc.client_credentials",
			Summary: "Run the Client Credentials grant and decode the access token.",
			Params: clientParams(pScope,
				Param{Name: "audience", Type: "string", Desc: "audience parameter"},
				Param{Name: "resource", Type: "string", Desc: "RFC 8707 resource indicator"}),
			Run: simpleGrant("client_credentials", nil),
		},
		&Op{
			Name:    "oidc.password",
			Summary: "Run the Resource Owner Password Credentials grant (deprecated by RFC 9700; for testing legacy setups).",
			Params: clientParams(pScope,
				Param{Name: "username", Type: "string", Required: true, Desc: "Resource owner username"},
				Param{Name: "password", Type: "string", Required: true, Secret: true, Desc: "Resource owner password (prefer env IDPDBG_PASSWORD)"}),
			Run: func(c *Ctx) (M, error) {
				out, err := simpleGrant("password", func(c *Ctx, f url.Values) error {
					f.Set("username", c.Str("username"))
					f.Set("password", c.Str("password"))
					return nil
				})(c)
				if out != nil {
					cs, _ := out["checks"].(Checks)
					cs.bcp(false, "resource owner password grant not used", "", "the client handles the user's password; the BCP says this grant must not be used", "RFC 9700 §2.4", "warn")
					out["checks"] = cs
				}
				return out, err
			},
		},
		&Op{
			Name:    "oidc.refresh",
			Summary: "Redeem a refresh token and report whether it was rotated.",
			Params: clientParams(pScope,
				Param{Name: "refresh_token", Type: "string", Required: true, Secret: true, File: true, Desc: "Refresh token"}),
			Run: func(c *Ctx) (M, error) {
				out, err := simpleGrant("refresh_token", func(c *Ctx, f url.Values) error {
					f.Set("refresh_token", c.Str("refresh_token"))
					return nil
				})(c)
				if body, _ := out["response"].(map[string]any); body != nil && out["status"] == 200 {
					cs := out["checks"].(Checks)
					nrt := str(body["refresh_token"])
					rotated := nrt != "" && nrt != c.Str("refresh_token")
					why := "no new refresh token returned; the old one stays valid"
					if nrt != "" && !rotated {
						why = "the same refresh token was returned (no rotation)"
					}
					switch {
					case rotated && c.Bool("fapi"):
						cs.add("refresh token rotation", "warn", "a new refresh token was issued; FAPI 2.0 asks servers not to rotate refresh tokens except in extraordinary circumstances", fapiRef+" §5.3.2.1")
					case rotated:
						cs.add("refresh token rotation", "pass", "a new refresh token was issued", "RFC 9700 §2.2.2")
					case effectiveClientAuth(c) == "none" && !strings.EqualFold(str(body["token_type"]), "DPoP"):
						cs.bcp(false, "refresh token rotation", "", why+"; for a public client the refresh token must be rotated or sender-constrained", "RFC 9700 §2.2.2", "warn")
					default:
						cs.add("refresh token rotation", "info", why, "RFC 9700 §2.2.2")
					}
					out["checks"] = cs
				}
				return out, err
			},
		},
		&Op{
			Name:    "oidc.device",
			Summary: "Start the Device Authorization grant (RFC 8628) and return the user code and verification URL. With wait_for_user it keeps polling until the person approves; otherwise finish with oidc device_poll.",
			Params: clientParams(pScope,
				Param{Name: "device_authorization_endpoint", Type: "string", Desc: "Device authorization endpoint, overriding discovery"},
				Param{Name: "wait_for_user", Type: "bool", Desc: "Poll the token endpoint until approved or the wait expires"},
				Param{Name: "pkce", Type: "bool", Desc: "Send a PKCE code_challenge with the device authorization request and the code_verifier when polling, for servers that want it (Keycloak does for clients that require PKCE)"},
				Param{Name: "wait", Type: "int", Desc: "Seconds to keep polling", Default: 300}),
			Run: func(c *Ctx) (M, error) {
				meta, err := getMeta(c)
				if err != nil {
					return nil, err
				}
				form := url.Values{}
				if s := c.Str("scope"); s != "" {
					form.Set("scope", s)
				}
				verifier := ""
				if c.Bool("pkce") {
					verifier = randToken(32)
					sum := sha256.Sum256([]byte(verifier))
					form.Set("code_challenge", b64url(sum[:]))
					form.Set("code_challenge_method", "S256")
				}
				res, ep, err := bearerCall(c, meta, "device_authorization_endpoint", form)
				if err != nil {
					return nil, err
				}
				var cs Checks
				out := M{"device_authorization_endpoint": ep, "status": res.Status, "device_authorization": res.payload()}
				if verifier != "" {
					out["code_verifier"] = verifier
				}
				defer func() { out["checks"] = cs }()
				body := res.obj()
				detail := fmt.Sprintf("HTTP %d", res.Status)
				if e := str(body["error_description"]); verifier == "" && strings.Contains(e, "code_challenge") {
					detail += ": " + e + ". The server wants PKCE on this request (Keycloak does when the client requires PKCE); run again with pkce"
				}
				if !cs.ok(res.Status == 200 && body != nil, "device authorization response", detail, "RFC 8628 §3.2") {
					return out, nil
				}
				for _, k := range []string{"device_code", "user_code", "verification_uri", "expires_in"} {
					_, ok := body[k]
					cs.ok(ok, "required member: "+k, "", "RFC 8628 §3.2")
				}
				link := str(body["verification_uri_complete"])
				if link == "" {
					link = str(body["verification_uri"])
				}
				c.Log("Go to %s and enter the code %s", link, str(body["user_code"]))
				if c.Bool("wait_for_user") {
					interval, _ := body["interval"].(float64)
					tok, err := pollDevice(c, meta, str(body["device_code"]), verifier, int(interval), &cs)
					if err != nil {
						return out, err
					}
					out["token"] = tok
				}
				return out, nil
			},
		},
		&Op{
			Name:    "oidc.device_poll",
			Summary: "Poll the token endpoint with a device_code until the person approves, the code expires or the wait runs out.",
			Params: clientParams(
				Param{Name: "device_code", Type: "string", Required: true, Desc: "device_code from oidc device"},
				Param{Name: "code_verifier", Type: "string", Desc: "code_verifier from oidc device, when it was run with pkce"},
				Param{Name: "interval", Type: "int", Desc: "Seconds between polls", Default: 5},
				Param{Name: "wait", Type: "int", Desc: "Seconds to keep polling", Default: 60}),
			Run: func(c *Ctx) (M, error) {
				meta, err := getMeta(c)
				if err != nil {
					return nil, err
				}
				var cs Checks
				out, err := pollDevice(c, meta, c.Str("device_code"), c.Str("code_verifier"), c.Int("interval"), &cs)
				if out != nil {
					out["checks"] = cs
				}
				return out, err
			},
		},
		&Op{
			Name:    "oidc.token_exchange",
			Summary: "Exchange one token for another (RFC 8693): impersonation with a subject_token, or delegation by adding an actor_token.",
			Params: clientParams(pScope,
				Param{Name: "subject_token", Type: "string", Required: true, File: true, Desc: "Token representing the subject"},
				Param{Name: "subject_token_type", Type: "string", Desc: "Type URI of the subject token", Default: "urn:ietf:params:oauth:token-type:access_token"},
				Param{Name: "actor_token", Type: "string", File: true, Desc: "Token representing the acting party (delegation)"},
				Param{Name: "actor_token_type", Type: "string", Desc: "Type URI of the actor token", Default: "urn:ietf:params:oauth:token-type:access_token"},
				Param{Name: "requested_token_type", Type: "string", Desc: "Type URI of the token wanted back"},
				Param{Name: "audience", Type: "string", Desc: "Logical name of the target service"},
				Param{Name: "resource", Type: "string", Desc: "URI of the target service"}),
			Run: simpleGrant("urn:ietf:params:oauth:grant-type:token-exchange", func(c *Ctx, f url.Values) error {
				f.Set("subject_token", c.Str("subject_token"))
				f.Set("subject_token_type", c.Str("subject_token_type"))
				if v := c.Str("actor_token"); v != "" {
					f.Set("actor_token", v)
					f.Set("actor_token_type", c.Str("actor_token_type"))
				}
				if v := c.Str("requested_token_type"); v != "" {
					f.Set("requested_token_type", v)
				}
				return nil
			}),
		},
		&Op{
			Name:    "oidc.introspect",
			Summary: "Introspect a token (RFC 7662) and show whether it is active and what the server knows about it.",
			Params: clientParams(
				Param{Name: "token", Type: "string", Required: true, File: true, Desc: "Token to introspect"},
				Param{Name: "token_type_hint", Type: "string", Desc: "access_token or refresh_token"},
				Param{Name: "introspection_endpoint", Type: "string", Desc: "Introspection endpoint, overriding discovery"}),
			Run: func(c *Ctx) (M, error) {
				meta, err := getMeta(c)
				if err != nil {
					return nil, err
				}
				form := url.Values{"token": {c.Str("token")}}
				if h := c.Str("token_type_hint"); h != "" {
					form.Set("token_type_hint", h)
				}
				res, ep, err := bearerCall(c, meta, "introspection_endpoint", form)
				if err != nil {
					return nil, err
				}
				var cs Checks
				body := res.obj()
				if cs.ok(res.Status == 200 && body != nil, "introspection response", fmt.Sprintf("HTTP %d", res.Status), "RFC 7662 §2.2") {
					active, isBool := body["active"].(bool)
					cs.ok(isBool, "active is a boolean", "", "RFC 7662 §2.2")
					detail := fmt.Sprintf("active=%v", active)
					if !active && isBool {
						detail += inactiveHint(c.Str("token"), c.Str("client_id"))
					}
					cs.add("token is active", map[bool]string{true: "pass", false: "info"}[active], detail, "RFC 7662 §2.2")
					if active {
						timeChecks(&cs, body, 0)
					}
				}
				return M{"introspection_endpoint": ep, "status": res.Status, "response": res.payload(), "checks": cs}, nil
			},
		},
		&Op{
			Name:     "oidc.revoke",
			Mutating: true,
			Summary:  "Revoke a token (RFC 7009).",
			Params: clientParams(
				Param{Name: "token", Type: "string", Required: true, File: true, Desc: "Token to revoke"},
				Param{Name: "token_type_hint", Type: "string", Desc: "access_token or refresh_token"},
				Param{Name: "revocation_endpoint", Type: "string", Desc: "Revocation endpoint, overriding discovery"}),
			Run: func(c *Ctx) (M, error) {
				meta, err := getMeta(c)
				if err != nil {
					return nil, err
				}
				form := url.Values{"token": {c.Str("token")}}
				if h := c.Str("token_type_hint"); h != "" {
					form.Set("token_type_hint", h)
				}
				res, ep, err := bearerCall(c, meta, "revocation_endpoint", form)
				if err != nil {
					return nil, err
				}
				var cs Checks
				cs.ok(res.Status == 200, "revocation response", fmt.Sprintf("HTTP %d", res.Status), "RFC 7009 §2.2")
				return M{"revocation_endpoint": ep, "status": res.Status, "response": res.payload(), "checks": cs}, nil
			},
		},
		&Op{
			Name:    "oidc.userinfo",
			Summary: "Call the UserInfo endpoint with an access token. Given the ID token it checks that both describe the same subject; given the granted scopes it checks that each one actually yields its claims.",
			Params: []Param{pIssuer,
				{Name: "access_token", Type: "string", Required: true, File: true, Desc: "Access token with the openid scope"},
				{Name: "userinfo_endpoint", Type: "string", Desc: "UserInfo endpoint, overriding discovery"},
				{Name: "id_token", Type: "string", File: true, Desc: "ID token whose sub the response must match"},
				{Name: "scope", Type: "string", Desc: "Scopes that were granted; each of profile, email, phone and address is checked for its claims"},
				{Name: "dpop", Type: "bool", Desc: "The access token is DPoP-bound: send it with a proof"},
				{Name: "dpop_key", Type: "string", Path: true, Desc: "The DPoP private key the token is bound to (PEM inline or a path)"}},
			Run: func(c *Ctx) (M, error) {
				meta, err := getMeta(c)
				if err != nil {
					return nil, err
				}
				ep, err := endpoint(c, meta, "userinfo_endpoint")
				if err != nil {
					return nil, err
				}
				var idClaims M
				if idt := c.Str("id_token"); idt != "" {
					p, err := parseJWT(idt)
					if err != nil {
						return nil, fmt.Errorf("id_token: %w", err)
					}
					idClaims = p.Claims
				}
				var cs Checks
				out, err := fetchUserinfo(c, ep, c.Str("access_token"), idClaims, c.Str("scope"), &cs)
				if out != nil {
					out["checks"] = cs
				}
				return out, err
			},
		},
		&Op{
			Name:     "oidc.register",
			Mutating: true,
			Summary:  "Register a client with Dynamic Client Registration (RFC 7591 / OIDC DCR).",
			Params: []Param{pIssuer,
				{Name: "registration_endpoint", Type: "string", Desc: "Registration endpoint, overriding discovery"},
				{Name: "metadata", Type: "json", Required: true, Desc: `Client metadata as JSON, e.g. {"client_name":"test","redirect_uris":["http://localhost:8765/callback"]} (CLI: @file)`},
				{Name: "initial_access_token", Type: "string", Secret: true, Desc: "Initial access token, if the server requires one"}},
			Run: func(c *Ctx) (M, error) {
				meta, err := getMeta(c)
				if err != nil {
					return nil, err
				}
				ep, err := endpoint(c, meta, "registration_endpoint")
				if err != nil {
					return nil, err
				}
				body, _ := json.Marshal(c.Args["metadata"])
				hdr := map[string]string{"Content-Type": "application/json", "Accept": "application/json"}
				if t := c.Str("initial_access_token"); t != "" {
					hdr["Authorization"] = "Bearer " + t
				}
				res, err := c.do("POST", ep, hdr, body)
				if err != nil {
					return nil, err
				}
				var cs Checks
				if cs.ok(res.Status == 201, "registration response", fmt.Sprintf("HTTP %d", res.Status), "RFC 7591 §3.2.1") {
					cs.ok(str(res.obj()["client_id"]) != "", "client_id returned", "", "RFC 7591 §3.2.1")
				}
				return M{"registration_endpoint": ep, "status": res.Status, "response": res.payload(), "checks": cs}, nil
			},
		},
	)
}
