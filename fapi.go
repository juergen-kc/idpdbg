package main

import (
	"fmt"
	"net/url"
	"strings"
)

// FAPI 2.0 Security Profile (final): the requirements a run can observe.
// With --fapi, every oidc operation adds them as checks (and implies
// --strict, since the profile builds on the OAuth 2.0 Security BCP).

const fapiRef = "FAPI 2.0 SP"

var pFAPI = Param{Name: "fapi", Type: "bool", Desc: "Judge against the FAPI 2.0 Security Profile: adds its requirements as checks (PAR, PKCE S256, private_key_jwt or mutual TLS, sender-constrained tokens, the iss response parameter, PS256/ES256/EdDSA) and implies strict"}

var fapiAlgs = []string{"PS256", "ES256", "EdDSA"}

// fapiAlgList judges an advertised list of signing algorithms: one of the
// permitted ones must be there, and none must not.
func fapiAlgList(cs *Checks, name string, algs []string) {
	if len(algs) == 0 {
		return
	}
	var ok []string
	for _, a := range algs {
		if contains(fapiAlgs, a) {
			ok = append(ok, a)
		}
	}
	switch {
	case contains(algs, "none"):
		cs.add("FAPI 2.0: "+name+" excludes none", "fail", strings.Join(algs, " "), fapiRef+" §5.4.1")
	case len(ok) == 0:
		cs.add("FAPI 2.0: "+name+" offers PS256, ES256 or EdDSA", "fail", strings.Join(algs, " "), fapiRef+" §5.4.1")
	default:
		cs.add("FAPI 2.0: "+name+" offers PS256, ES256 or EdDSA", "pass", strings.Join(ok, " "), fapiRef+" §5.4.1")
	}
}

// fapiDiscover judges authorization server metadata.
func fapiDiscover(cs *Checks, meta M, list func(string) []string) {
	par := str(meta["pushed_authorization_request_endpoint"])
	switch {
	case par == "":
		cs.add("FAPI 2.0: pushed authorization requests", "fail", "no pushed_authorization_request_endpoint", fapiRef+" §5.3.2.2")
	case meta["require_pushed_authorization_requests"] == true:
		cs.add("FAPI 2.0: pushed authorization requests", "pass", "required for every client", fapiRef+" §5.3.2.2")
	default:
		cs.add("FAPI 2.0: pushed authorization requests", "info", "offered, but not required server-wide (require_pushed_authorization_requests); it may be required per client: oidc bcp_probe --fapi checks", fapiRef+" §5.3.2.2")
	}
	cs.ok(contains(list("code_challenge_methods_supported"), "S256"), "FAPI 2.0: PKCE with S256",
		"code_challenge_methods_supported="+strings.Join(list("code_challenge_methods_supported"), " "), fapiRef+" §5.3.2.2")
	var auth []string
	for _, m := range list("token_endpoint_auth_methods_supported") {
		if m == "private_key_jwt" || m == "tls_client_auth" || m == "self_signed_tls_client_auth" {
			auth = append(auth, m)
		}
	}
	cs.ok(len(auth) > 0, "FAPI 2.0: client authentication with private_key_jwt or mutual TLS",
		map[bool]string{true: strings.Join(auth, " "), false: "token_endpoint_auth_methods_supported has neither"}[len(auth) > 0], fapiRef+" §5.3.2.1")
	var sc []string
	if len(list("dpop_signing_alg_values_supported")) > 0 {
		sc = append(sc, "DPoP")
	}
	if meta["tls_client_certificate_bound_access_tokens"] == true {
		sc = append(sc, "mTLS-bound tokens")
	}
	cs.ok(len(sc) > 0, "FAPI 2.0: sender-constrained access tokens",
		map[bool]string{true: strings.Join(sc, ", "), false: "neither DPoP nor mTLS-bound tokens are advertised"}[len(sc) > 0], fapiRef+" §5.3.2.1")
	cs.ok(meta["authorization_response_iss_parameter_supported"] == true, "FAPI 2.0: iss in authorization responses",
		map[bool]string{true: "authorization_response_iss_parameter_supported", false: "authorization_response_iss_parameter_supported is not true"}[meta["authorization_response_iss_parameter_supported"] == true], fapiRef+" §5.3.2.2")
	cs.ok(contains(list("response_types_supported"), "code"), "FAPI 2.0: response_type code", "response_types_supported="+strings.Join(list("response_types_supported"), " "), fapiRef+" §5.3.2.2")
	fapiAlgList(cs, "ID token signing", list("id_token_signing_alg_values_supported"))
	fapiAlgList(cs, "client assertion signing", list("token_endpoint_auth_signing_alg_values_supported"))
	fapiAlgList(cs, "DPoP proof signing", list("dpop_signing_alg_values_supported"))
	var plain, loopback []string
	for _, k := range []string{"issuer", "jwks_uri", "authorization_endpoint", "token_endpoint", "pushed_authorization_request_endpoint", "userinfo_endpoint"} {
		switch v := str(meta[k]); {
		case v == "" || strings.HasPrefix(v, "https://"):
		case isLoopbackURL(v):
			loopback = append(loopback, k)
		default:
			plain = append(plain, k+"="+v)
		}
	}
	switch {
	case len(plain) > 0:
		cs.add("FAPI 2.0: endpoints use TLS", "fail", strings.Join(plain, ", "), fapiRef+" §5.2.1")
	case len(loopback) > 0:
		cs.add("FAPI 2.0: endpoints use TLS", "info", "plain http on loopback, accepted for testing only: "+strings.Join(loopback, ", "), fapiRef+" §5.2.1")
	default:
		cs.add("FAPI 2.0: endpoints use TLS", "pass", "", fapiRef+" §5.2.1")
	}
}

func isLoopbackURL(v string) bool {
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// fapiClient judges how this run's client was set up: FAPI clients are
// confidential, authenticate with private_key_jwt or mutual TLS, and bind
// their tokens.
func fapiClient(c *Ctx, cs *Checks) {
	switch m := effectiveClientAuth(c); m {
	case "private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth":
		cs.add("FAPI 2.0: client authentication", "pass", m, fapiRef+" §5.3.2.1")
		if m == "private_key_jwt" && c.Str("client_assertion_aud") != "" {
			cs.add("FAPI 2.0: client assertion aud is the issuer", "info", "client_assertion_aud overrides it with "+c.Str("client_assertion_aud")+"; the server must only accept its issuer identifier", fapiRef+" §5.3.3.1")
		}
	case "none":
		cs.add("FAPI 2.0: client authentication", "fail", "a public client; FAPI allows only confidential clients", fapiRef+" §5.3.2.1")
	default:
		cs.add("FAPI 2.0: client authentication", "fail", m+"; FAPI allows only private_key_jwt or mutual TLS", fapiRef+" §5.3.2.1")
	}
	cs.ok(c.Bool("dpop") || c.Str("mtls_cert") != "", "FAPI 2.0: client sender-constrains its tokens",
		map[bool]string{true: "dpop or mutual TLS", false: "neither dpop nor an mTLS certificate is in use"}[c.Bool("dpop") || c.Str("mtls_cert") != ""], fapiRef+" §5.3.3.1")
}

// fapiAuthzRequest judges how the authorization request was made.
func fapiAuthzRequest(c *Ctx, cs *Checks, redirectURI string) {
	cs.ok(c.Bool("par"), "FAPI 2.0: pushed authorization request used", map[bool]string{true: "only client_id and request_uri went through the browser", false: "the parameters went through the browser; run with par"}[c.Bool("par")], fapiRef+" §5.3.3.2")
	cs.ok(c.Bool("pkce"), "FAPI 2.0: PKCE with S256", "", fapiRef+" §5.3.3.2")
	cs.ok(c.Str("response_type") == "code", "FAPI 2.0: response_type code", "response_type="+c.Str("response_type"), fapiRef+" §5.3.2.2")
	if strings.HasPrefix(redirectURI, "http://") {
		cs.add("FAPI 2.0: https redirect URI", "info", redirectURI+" is loopback, which a FAPI server should refuse outside testing", fapiRef+" §5.3.2.2")
	}
}

// fapiPAR judges a pushed authorization response.
func fapiPAR(cs *Checks, body M) {
	exp, ok := body["expires_in"].(float64)
	if ok {
		cs.ok(exp < 600, "FAPI 2.0: request_uri expires in under 600 s", fmt.Sprintf("expires_in=%v", exp), fapiRef+" §5.3.2.2")
	}
}

// fapiTokens judges a successful token response: permitted signing
// algorithms on the ID token and a JWT access token.
func fapiTokens(cs *Checks, body M) {
	for _, k := range []string{"id_token", "access_token"} {
		tok := str(body[k])
		if !looksLikeJWT(tok) {
			continue
		}
		p, err := parseJWT(tok)
		if err != nil {
			continue
		}
		alg := str(p.Header["alg"])
		cs.ok(contains(fapiAlgs, alg), "FAPI 2.0: "+strings.ReplaceAll(k, "_", " ")+" signed with PS256, ES256 or EdDSA", "alg="+alg, fapiRef+" §5.4.1")
	}
}

// fapiSummary counts the FAPI requirements a result fails.
func fapiSummary(res M) {
	cs, ok := res["checks"].(Checks)
	if !ok {
		return
	}
	n, inconclusive := 0, 0
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case M:
			for _, k := range sortedKeys(x) {
				if checks, ok := x[k].(Checks); ok {
					for _, ch := range checks {
						if strings.HasPrefix(ch.Ref, fapiRef) && ch.Status == "fail" {
							n++
						}
						if strings.HasPrefix(ch.Ref, fapiRef) && strings.HasPrefix(ch.Name, "probe ") && ch.Status == "warn" {
							inconclusive++
						}
					}
					continue
				}
				walk(x[k])
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(res)
	switch {
	case n > 0:
		cs.add("FAPI 2.0 Security Profile", "fail", fmt.Sprintf("%d requirement(s) not met", n), fapiRef)
	case inconclusive > 0:
		cs.add("FAPI 2.0 Security Profile", "warn", fmt.Sprintf("no requirement failed, but %d probe(s) could not run", inconclusive), fapiRef)
	default:
		cs.add("FAPI 2.0 Security Profile", "pass", "0 requirement(s) not met", fapiRef)
	}
	res["checks"] = cs
}
