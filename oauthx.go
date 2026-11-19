package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client authentication beyond a shared secret, sender-constrained tokens
// (DPoP, mTLS), pushed and signed authorization requests, logout and
// registration management.

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

var advancedClientParams = []Param{
	{Name: "client_key", Type: "string", Path: true, Desc: "Client private key (PEM inline or a path) for private_key_jwt and signed request objects"},
	{Name: "client_key_id", Type: "string", Desc: "kid to put in the header of JWTs signed with client_key"},
	{Name: "signing_alg", Type: "string", Desc: "JWS algorithm for client_key; default follows the key type (RS256, ES256, EdDSA); use PS256 for RSA-PSS"},
	{Name: "client_assertion_aud", Type: "string", Desc: "aud of the client assertion; default is the issuer, else the endpoint being called"},
	{Name: "mtls_cert", Type: "string", Path: true, Desc: "Client certificate (PEM inline or a path) for mutual TLS"},
	{Name: "mtls_key", Type: "string", Path: true, Desc: "Private key for mtls_cert (PEM inline or a path)"},
	{Name: "dpop", Type: "bool", Desc: "Send DPoP proofs (RFC 9449) so issued tokens are bound to a key"},
	{Name: "dpop_key", Type: "string", Path: true, Desc: "DPoP private key (PEM inline or a path); default is a fresh P-256 key that lasts for this run only"},
}

// clientAssertion builds the JWT for private_key_jwt / client_secret_jwt.
func clientAssertion(c *Ctx, meta M, ep, mode string) (string, error) {
	id := c.Str("client_id")
	if id == "" {
		return "", errors.New(mode + " needs client_id")
	}
	aud := c.Str("client_assertion_aud")
	if aud == "" {
		if aud = str(meta["issuer"]); aud == "" {
			aud = ep
		}
	}
	now := time.Now().Unix()
	claims := M{"iss": id, "sub": id, "aud": aud, "jti": randToken(16), "iat": now, "nbf": now, "exp": now + 60}
	if mode == "client_secret_jwt" {
		if c.Str("client_secret") == "" {
			return "", errors.New("client_secret_jwt needs client_secret")
		}
		return signHS([]byte(c.Str("client_secret")), "HS256", M{"typ": "JWT"}, claims), nil
	}
	signer, alg, header, err := clientSigner(c)
	if err != nil {
		return "", err
	}
	return signJWS(signer, alg, header, claims)
}

func clientSigner(c *Ctx) (crypto.Signer, string, M, error) {
	if c.Str("client_key") == "" {
		return nil, "", nil, errors.New("this needs client_key (the client's private key)")
	}
	signer, err := loadSigner(c.Str("client_key"))
	if err != nil {
		return nil, "", nil, fmt.Errorf("client_key: %w", err)
	}
	alg, err := signerAlg(signer, c.Str("signing_alg"))
	if err != nil {
		return nil, "", nil, err
	}
	header := M{"typ": "JWT"}
	if kid := c.Str("client_key_id"); kid != "" {
		header["kid"] = kid
	}
	return signer, alg, header, nil
}

// ---- DPoP ----

func (c *Ctx) dpopSigner() (crypto.Signer, error) {
	if c.dpop != nil {
		return c.dpop, nil
	}
	var err error
	if k := c.Str("dpop_key"); k != "" {
		if c.dpop, err = loadSigner(k); err != nil {
			return nil, fmt.Errorf("dpop_key: %w", err)
		}
	} else if c.dpop, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, err
	}
	return c.dpop, nil
}

func dpopThumbprint(c *Ctx) (string, error) {
	s, err := c.dpopSigner()
	if err != nil {
		return "", err
	}
	jwk, err := publicJWK(s.Public())
	if err != nil {
		return "", err
	}
	return jwkThumbprint(jwk), nil
}

// dpopProof signs a proof for one request. accessToken is set when the proof
// accompanies a token at a resource server; nonce when the server asked for one.
func dpopProof(c *Ctx, method, target, accessToken, nonce string) (string, error) {
	s, err := c.dpopSigner()
	if err != nil {
		return "", err
	}
	alg, err := signerAlg(s, "")
	if err != nil {
		return "", err
	}
	jwk, err := publicJWK(s.Public())
	if err != nil {
		return "", err
	}
	htu := target
	if u, err := url.Parse(target); err == nil {
		u.RawQuery, u.Fragment = "", ""
		htu = u.String()
	}
	claims := M{"jti": randToken(16), "htm": method, "htu": htu, "iat": time.Now().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = b64url(sum[:])
	}
	return signJWS(s, alg, M{"typ": "dpop+jwt", "jwk": jwk}, claims)
}

// dpopTokenChecks reports whether the issued token is actually bound to the key.
func dpopTokenChecks(c *Ctx, cs *Checks, body M, out M) {
	jkt, err := dpopThumbprint(c)
	if err != nil {
		return
	}
	info := M{"jkt": jkt, "key": "dpop_key"}
	if c.Str("dpop_key") == "" {
		info["key"] = "ephemeral P-256 key generated for this run; pass dpop_key to keep using the token afterwards"
	}
	out["dpop"] = info
	tt := str(body["token_type"])
	if strings.EqualFold(tt, "DPoP") {
		cs.add("DPoP: token_type is DPoP", "pass", "", "RFC 9449 §5")
	} else {
		cs.add("DPoP: token_type is DPoP", "warn", "the server issued token_type="+tt+", so it ignored the proof and the token is not bound to the key", "RFC 9449 §5")
	}
	if at := str(body["access_token"]); looksLikeJWT(at) {
		if p, err := parseJWT(at); err == nil && p.Claims != nil {
			cnf, _ := p.Claims["cnf"].(map[string]any)
			cs.ok(str(cnf["jkt"]) == jkt, "DPoP: access token cnf.jkt is the proof key", "cnf.jkt="+str(cnf["jkt"]), "RFC 9449 §6.1")
		}
	}
}

// mtlsTokenChecks reports whether a JWT access token is bound to the client
// certificate that was presented (RFC 8705 §3.1).
func mtlsTokenChecks(c *Ctx, cs *Checks, body M) {
	certs := parsePEMCerts([]byte(c.Str("mtls_cert")))
	if len(certs) == 0 {
		return
	}
	sum := sha256.Sum256(certs[0].Raw)
	want := b64url(sum[:])
	at := str(body["access_token"])
	if !looksLikeJWT(at) {
		cs.add("mTLS: access token bound to the client certificate", "info", "the access token is opaque; binding can only be seen through introspection", "RFC 8705 §3.2")
		return
	}
	p, err := parseJWT(at)
	if err != nil || p.Claims == nil {
		return
	}
	cnf, _ := p.Claims["cnf"].(map[string]any)
	got := str(cnf["x5t#S256"])
	if got == "" {
		cs.add("mTLS: access token bound to the client certificate", "warn", "the token has no cnf.x5t#S256, so it is an ordinary bearer token", "RFC 8705 §3.1")
		return
	}
	cs.ok(got == want, "mTLS: access token bound to the client certificate", "cnf.x5t#S256="+got, "RFC 8705 §3.1")
}

// ---- pushed and signed authorization requests ----

// requestObject wraps the authorization parameters in a signed JWT (JAR).
func requestObject(c *Ctx, meta M, params url.Values) (string, error) {
	signer, alg, header, err := clientSigner(c)
	if err != nil {
		return "", fmt.Errorf("jar: %w", err)
	}
	header["typ"] = "oauth-authz-req+jwt"
	now := time.Now().Unix()
	claims := M{"iss": c.Str("client_id"), "jti": randToken(16), "iat": now, "nbf": now, "exp": now + 300}
	if iss := str(meta["issuer"]); iss != "" {
		claims["aud"] = iss
	}
	for k := range params {
		claims[k] = params.Get(k)
	}
	if v, err := strconv.Atoi(params.Get("max_age")); err == nil {
		claims["max_age"] = v
	}
	return signJWS(signer, alg, header, claims)
}

// pushPAR sends the parameters to the PAR endpoint and returns the request_uri.
func pushPAR(c *Ctx, meta M, params url.Values, cs *Checks) (string, M, error) {
	ep, err := endpoint(c, meta, "pushed_authorization_request_endpoint")
	if err != nil {
		return "", nil, err
	}
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	hdr := map[string]string{}
	if err := clientAuth(c, meta, ep, form, hdr); err != nil {
		return "", nil, err
	}
	res, err := c.postForm(ep, form, hdr)
	if err != nil {
		return "", nil, err
	}
	info := M{"pushed_authorization_request_endpoint": ep, "status": res.Status, "response": res.payload()}
	body := res.obj()
	if !cs.ok(res.Status == 201 && body != nil, "PAR: response", fmt.Sprintf("HTTP %d %s", res.Status, str(body["error"])), "RFC 9126 §2.2") {
		return "", info, fmt.Errorf("the pushed authorization request was rejected (HTTP %d)", res.Status)
	}
	uri := str(body["request_uri"])
	cs.ok(uri != "", "PAR: request_uri returned", uri, "RFC 9126 §2.2")
	_, hasExp := body["expires_in"]
	cs.ok(hasExp, "PAR: expires_in returned", fmt.Sprint(body["expires_in"]), "RFC 9126 §2.2")
	if c.Bool("fapi") {
		fapiPAR(cs, body)
	}
	return uri, info, nil
}

// applyRequestModes turns plain authorization parameters into a signed
// request object and/or a pushed request, as asked.
func applyRequestModes(c *Ctx, meta M, a *authzRequest, q url.Values) (url.Values, error) {
	if c.Bool("jar") {
		ro, err := requestObject(c, meta, q)
		if err != nil {
			return nil, err
		}
		a.RequestObject = ro
		a.Checks.add("JAR: request object signed", "pass", "authorization parameters travel in a signed JWT", "RFC 9101 §4")
		// client_id stays outside; response_type and scope are repeated for OIDC Core §6.1.
		q = url.Values{"client_id": {q.Get("client_id")}, "request": {ro}, "response_type": {q.Get("response_type")}, "scope": {q.Get("scope")}}
		if q.Get("scope") == "" {
			q.Del("scope")
		}
	}
	if c.Bool("par") {
		uri, info, err := pushPAR(c, meta, q, &a.Checks)
		a.PAR = info
		if err != nil {
			return nil, err
		}
		q = url.Values{"client_id": {c.Str("client_id")}, "request_uri": {uri}}
	}
	return q, nil
}

// ---- mutual TLS ----

// applyMTLS installs the client certificate on the HTTP transport.
func applyMTLS(c *Ctx) error {
	cert, key := c.Str("mtls_cert"), c.Str("mtls_key")
	if cert == "" && key == "" {
		return nil
	}
	if cert == "" || key == "" {
		return errors.New("mtls_cert and mtls_key must be given together")
	}
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		return fmt.Errorf("mtls_cert/mtls_key: %w", err)
	}
	c.Rec.base.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{pair}
	return nil
}

// ---- operations ----

func init() {
	register(
		&Op{
			Name:    "oidc.logout",
			Browser: true,
			Summary: "Run RP-Initiated Logout: build the end_session request, send the browser there and wait on a loopback post-logout redirect to confirm the provider returns with the same state. With url_only it just builds the URL.",
			Params: append([]Param{pIssuer, pClientID,
				{Name: "end_session_endpoint", Type: "string", Desc: "End session endpoint, overriding discovery"},
				{Name: "id_token_hint", Type: "string", File: true, Desc: "ID token previously issued to this client (recommended)"},
				{Name: "logout_hint", Type: "string", Desc: "Hint about the user who is logging out"},
				{Name: "post_logout_redirect_uri", Type: "string", Desc: "Where the provider should send the browser afterwards; must be registered and, to be captured, point at this machine", Default: "http://localhost:8765/logged-out"},
				{Name: "url_only", Type: "bool", Desc: "Only build and return the logout URL"}}, browserParams...),
			Run: func(c *Ctx) (M, error) {
				meta, err := getMeta(c)
				if err != nil {
					return nil, err
				}
				ep, err := endpoint(c, meta, "end_session_endpoint")
				if err != nil {
					return nil, err
				}
				u, err := url.Parse(ep)
				if err != nil {
					return nil, err
				}
				state := randToken(16)
				q := u.Query()
				for _, n := range []string{"id_token_hint", "logout_hint", "client_id", "post_logout_redirect_uri"} {
					if v := c.Str(n); v != "" {
						q.Set(n, v)
					}
				}
				q.Set("state", state)
				u.RawQuery = q.Encode()
				var cs Checks
				out := M{"logout_url": u.String(), "state": state}
				cs.warn(c.Str("id_token_hint") != "", "id_token_hint supplied", "without it the provider may ask the user to confirm, or refuse to redirect back", "OIDC RP-Initiated Logout §2")
				if c.Bool("url_only") {
					out["checks"] = cs
					return out, nil
				}
				ru, err := url.Parse(c.Str("post_logout_redirect_uri"))
				if err != nil {
					return nil, err
				}
				port, _ := strconv.Atoi(ru.Port())
				if h := ru.Hostname(); (h != "localhost" && h != "127.0.0.1") || port == 0 {
					return nil, errors.New("post_logout_redirect_uri must be a loopback URL with a port to be captured; use url_only otherwise")
				}
				ch := make(chan url.Values, 1)
				mux := http.NewServeMux()
				mux.HandleFunc(ru.Path, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					fmt.Fprint(w, donePage)
					select {
					case ch <- r.URL.Query():
					default:
					}
				})
				stop, err := serveLoopback(port, mux)
				if err != nil {
					return nil, err
				}
				defer stop()
				vals, err := awaitBrowser(c, u.String(), ch)
				if err != nil {
					out["checks"] = cs
					return out, err
				}
				cs.add("provider redirected to post_logout_redirect_uri", "pass", "", "OIDC RP-Initiated Logout §3")
				cs.ok(vals.Get("state") == state, "state returned unchanged", "state="+vals.Get("state"), "OIDC RP-Initiated Logout §3")
				out["checks"] = cs
				return out, nil
			},
		},
		&Op{
			Name:     "oidc.register_manage",
			Mutating: true,
			Summary:  "Read, update or delete a dynamically registered client at its client configuration endpoint (RFC 7592) using the registration access token.",
			Params: []Param{
				{Name: "registration_client_uri", Type: "string", Required: true, Desc: "Client configuration endpoint returned at registration"},
				{Name: "registration_access_token", Type: "string", Required: true, Secret: true, Desc: "Registration access token returned at registration"},
				{Name: "action", Type: "string", Enum: []string{"read", "update", "delete"}, Desc: "What to do", Default: "read"},
				{Name: "metadata", Type: "json", Desc: "Complete client metadata for update (CLI: @file)"}},
			Run: func(c *Ctx) (M, error) {
				method, want := "GET", 200
				var body []byte
				hdr := map[string]string{"Authorization": "Bearer " + c.Str("registration_access_token"), "Accept": "application/json"}
				switch c.Str("action") {
				case "update":
					if !c.Has("metadata") {
						return nil, errors.New("update needs metadata")
					}
					method = "PUT"
					body, _ = json.Marshal(c.Args["metadata"])
					hdr["Content-Type"] = "application/json"
				case "delete":
					method, want = "DELETE", 204
				}
				res, err := c.do(method, c.Str("registration_client_uri"), hdr, body)
				if err != nil {
					return nil, err
				}
				var cs Checks
				cs.ok(res.Status == want, "client configuration response", fmt.Sprintf("HTTP %d, expected %d", res.Status, want), "RFC 7592 §2")
				if m := res.obj(); m != nil && res.Status == 200 {
					if t := str(m["registration_access_token"]); t != "" && t != c.Str("registration_access_token") {
						cs.add("registration access token rotated", "info", "the response carries a new registration_access_token; the old one may no longer work", "RFC 7592 §3")
					}
				}
				return M{"request": method + " " + c.Str("registration_client_uri"), "status": res.Status, "response": res.payload(), "checks": cs}, nil
			},
		},
	)
}
