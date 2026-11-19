package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GNAP (RFC 9635) client instance: signed grant requests, interaction with
// finish-hash verification, continuation, token rotation and revocation.

const gnapRef = "RFC 9635"

type gnapClient struct {
	key   crypto.Signer
	kid   string
	jwk   M
	ephem bool
}

func gnapKey(c *Ctx) (*gnapClient, error) {
	g := &gnapClient{}
	if s := c.Str("client_key"); s != "" {
		k, err := loadPrivateKey(s)
		if err != nil {
			return nil, fmt.Errorf("client_key: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("client_key cannot sign")
		}
		g.key = signer
	} else {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		g.key, g.ephem = priv, true
	}
	jwk, err := publicJWK(g.key.Public())
	if err != nil {
		return nil, err
	}
	g.kid = c.Str("key_id")
	if g.kid == "" {
		g.kid = jwkThumbprint(jwk)
	}
	jwk["kid"], jwk["alg"] = g.kid, httpsigAlg(g.key)
	g.jwk = jwk
	return g, nil
}

// send signs and sends one GNAP request (RFC 9635 §7.3.1, RFC 9421).
func (g *gnapClient) send(c *Ctx, method, uri, token string, body any) (*httpResult, error) {
	if err := c.allowDestination("a request signed with the GNAP client key", uri); err != nil {
		return nil, err
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	hdr := map[string]string{"Accept": "application/json"}
	comps := []string{"@method", "@target-uri"}
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
		hdr["Content-Type"], hdr["Content-Digest"] = "application/json", contentDigest(b, "sha-256")
		comps = append(comps, "content-digest", "content-type")
	}
	if token != "" {
		hdr["Authorization"] = "GNAP " + token
		comps = append(comps, "authorization")
	}
	lower := map[string]string{}
	for k, v := range hdr {
		lower[strings.ToLower(k)] = v
	}
	input, sig, _, err := signHTTP(g.key, g.kid, "gnap", &sigRequest{Method: method, URL: u, Headers: lower}, comps, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	hdr["Signature-Input"], hdr["Signature"] = input, sig
	return c.do(method, uri, hdr, b)
}

func gnapError(body M) string {
	switch e := body["error"].(type) {
	case string:
		return e
	case map[string]any:
		return strings.TrimSpace(str(e["code"]) + " " + str(e["description"]))
	}
	return ""
}

func gnapTokenChecks(cs *Checks, label string, t any) {
	tokens := []map[string]any{}
	switch v := t.(type) {
	case map[string]any:
		tokens = append(tokens, v)
	case []any:
		for _, x := range v {
			if m, ok := x.(map[string]any); ok {
				tokens = append(tokens, m)
			}
		}
	}
	for _, tok := range tokens {
		cs.ok(str(tok["value"]) != "", label+": value present", "", gnapRef+" §3.2.1")
		flags, _ := coerce(Param{Name: "f", Type: "list"}, tok["flags"], false)
		fl, _ := flags.([]string)
		if contains(fl, "bearer") {
			cs.add(label+": bound to the client key", "warn", "flag bearer: anyone holding the token can use it", gnapRef+" §3.2.1")
		} else {
			cs.add(label+": bound to the client key", "pass", "", gnapRef+" §3.2.1")
		}
		if m, _ := tok["manage"].(map[string]any); m != nil {
			cs.add(label+": management URI", "info", str(m["uri"]), gnapRef+" §6")
		}
	}
}

func sameOrigin(a, b string) bool {
	ua, e1 := url.Parse(a)
	ub, e2 := url.Parse(b)
	return e1 == nil && e2 == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host
}

func runGNAPGrant(c *Ctx) (M, error) {
	g, err := gnapKey(c)
	if err != nil {
		return nil, err
	}
	endpoint := c.Str("grant_endpoint")
	var cs Checks
	out := M{"grant_endpoint": endpoint, "client_key": g.jwk}
	defer func() { out["checks"] = cs }()
	if g.ephem {
		cs.add("client key", "info", "an ephemeral Ed25519 key was generated; tokens bound to it are unusable after this run (pass client_key to keep them)", gnapRef+" §7.1")
	}
	access, ok := c.Args["access"].([]any)
	if !ok || len(access) == 0 {
		return out, errors.New(`access must be a JSON array, e.g. [{"type":"photo-api","actions":["read"]}] or ["reference"]`)
	}
	req := M{"access_token": M{"access": access}, "client": M{"key": M{"proof": "httpsig", "jwk": g.jwk}, "display": M{"name": "idpdbg"}}}
	if f := c.List("sub_id_formats"); len(f) > 0 {
		req["subject"] = M{"sub_id_formats": f}
	}
	var nonce, finishURI string
	if c.Bool("interact") {
		nonce = randToken(16)
		finishURI = fmt.Sprintf("http://localhost:%d/gnap/finish", c.Int("finish_port"))
		req["interact"] = M{"start": []string{"redirect"}, "finish": M{"method": "redirect", "uri": finishURI, "nonce": nonce}}
	}
	out["request"] = req
	res, err := g.send(c, "POST", endpoint, "", req)
	if err != nil {
		return out, err
	}
	body := res.obj()
	out["response"] = res.payload()
	if e := gnapError(body); e != "" || res.Status != 200 {
		cs.add("grant response", "fail", fmt.Sprintf("HTTP %d %s", res.Status, e), gnapRef+" §3.6")
		return out, nil
	}
	cs.add("grant response", "pass", "HTTP 200", gnapRef+" §3")
	if instance := str(body["instance_id"]); instance != "" {
		cs.add("instance_id issued", "info", "later requests may use it instead of the key", gnapRef+" §3.5")
	}
	if t, ok := body["access_token"]; ok {
		gnapTokenChecks(&cs, "access token", t)
	}
	cont, _ := body["continue"].(map[string]any)
	if cont != nil {
		cs.ok(sameOrigin(str(cont["uri"]), endpoint), "continuation URI is at the AS", str(cont["uri"]), gnapRef+" §3.1")
		ct, _ := cont["access_token"].(map[string]any)
		cs.ok(str(ct["value"]) != "", "continuation access token present", "", gnapRef+" §3.1")
	}
	inter, _ := body["interact"].(map[string]any)
	if !c.Bool("interact") {
		return out, nil
	}
	if !cs.ok(inter != nil && str(inter["redirect"]) != "" && str(inter["finish"]) != "" && cont != nil, "AS offers redirect interaction with a finish nonce", "", gnapRef+" §3.3") {
		return out, nil
	}

	// Interaction: send the person to the AS, wait for the finish redirect.
	ch := make(chan url.Values, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/gnap/finish", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, donePage)
		select {
		case ch <- r.URL.Query():
		default:
		}
	})
	stop, err := serveLoopback(c.Int("finish_port"), mux)
	if err != nil {
		return out, err
	}
	defer stop()
	if !cs.ok(safeBrowserURL(str(inter["redirect"])), "interaction redirect is an http(s) URL", str(inter["redirect"]), gnapRef+" §3.3.1") {
		return out, nil
	}
	vals, err := awaitBrowser(c, str(inter["redirect"]), ch)
	if err != nil {
		return out, err
	}
	ref, got := vals.Get("interact_ref"), vals.Get("hash")
	// The client chooses the hash method in its request; idpdbg sends none,
	// so sha-256 applies (RFC 9635 §2.5.2), whatever the response says.
	h := sha256.Sum256([]byte(nonce + "\n" + str(inter["finish"]) + "\n" + ref + "\n" + endpoint))
	want := b64url(h[:])
	if !cs.ok(ref != "" && got == want, "interaction finish hash matches", "hash="+got, gnapRef+" §4.2.3") {
		cs.add("continuation", "info", "not attempted: a wrong hash means the redirect may have been injected", gnapRef+" §4.2.3")
		return out, nil
	}
	ct, _ := cont["access_token"].(map[string]any)
	res, err = g.send(c, "POST", str(cont["uri"]), str(ct["value"]), M{"interact_ref": ref})
	if err != nil {
		return out, err
	}
	out["continue_response"] = res.payload()
	cb := res.obj()
	if e := gnapError(cb); e != "" || res.Status != 200 {
		cs.add("continuation response", "fail", fmt.Sprintf("HTTP %d %s", res.Status, e), gnapRef+" §5")
		return out, nil
	}
	cs.add("continuation response", "pass", "", gnapRef+" §5")
	if t, ok := cb["access_token"]; ok {
		gnapTokenChecks(&cs, "access token", t)
	} else {
		cs.add("access token issued", "fail", "the continuation returned no access token", gnapRef+" §5.1")
	}
	return out, nil
}

func gnapSimple(c *Ctx, method, uri, token string, body any, want int, label string) (M, error) {
	if c.Str("client_key") == "" {
		return nil, errors.New("client_key is required: requests must be signed with the key the grant is bound to")
	}
	g, err := gnapKey(c)
	if err != nil {
		return nil, err
	}
	res, err := g.send(c, method, uri, token, body)
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{"status": res.Status, "response": res.payload()}
	cs.ok(res.Status == want, label, fmt.Sprintf("HTTP %d %s", res.Status, gnapError(res.obj())), gnapRef)
	if b := res.obj(); b != nil {
		if t, ok := b["access_token"]; ok {
			gnapTokenChecks(&cs, "access token", t)
		}
	}
	out["checks"] = cs
	return out, nil
}

func init() {
	key := []Param{
		{Name: "client_key", Type: "string", Path: true, Explicit: true, Desc: "Client private key (PEM or private JWK; Ed25519, P-256/384 or RSA). Default for grant: a new Ed25519 key"},
		{Name: "key_id", Type: "string", Desc: "keyid for signatures; default the JWK thumbprint"},
	}
	join := joinParams
	register(
		&Op{
			Name:    "gnap.grant",
			Browser: true,
			Summary: "Request a GNAP grant (RFC 9635): send a grant request bound to the client key with HTTP message signatures (RFC 9421, Content-Digest RFC 9530). With interact, send the person to the AS, verify the finish hash on a loopback redirect and continue the grant. Checks token key binding, continuation and errors.",
			Params: join([]Param{
				{Name: "grant_endpoint", Type: "string", Required: true, Desc: "AS grant endpoint"},
				{Name: "access", Type: "json", Required: true, Desc: `Access rights: [{"type":"photo-api","actions":["read"]}] or references ["read-photos"]`},
				{Name: "interact", Type: "bool", Desc: "Ask for redirect interaction and finish on a loopback URI"},
				{Name: "finish_port", Type: "int", Desc: "Loopback port for the finish redirect", Default: 8769},
				{Name: "sub_id_formats", Type: "list", Desc: "Also request subject information in these formats (opaque, iss_sub, email...)"}}, key, browserParams),
			Run: runGNAPGrant,
		},
		&Op{
			Name:     "gnap.continue",
			Mutating: true,
			Summary:  "Continue a GNAP grant at its continuation URI (polling, or after interaction with interact_ref).",
			Params: join([]Param{
				{Name: "continue_uri", Type: "string", Required: true, Desc: "continue.uri from the grant response"},
				{Name: "continue_token", Type: "string", Required: true, Secret: true, Explicit: true, Desc: "continue.access_token.value"},
				{Name: "interact_ref", Type: "string", Desc: "interact_ref from the finish redirect"}}, key),
			Run: func(c *Ctx) (M, error) {
				var body any
				if r := c.Str("interact_ref"); r != "" {
					body = M{"interact_ref": r}
				}
				return gnapSimple(c, "POST", c.Str("continue_uri"), c.Str("continue_token"), body, 200, "continuation response")
			},
		},
		&Op{
			Name:     "gnap.rotate",
			Mutating: true,
			Summary:  "Rotate a GNAP access token at its management URI and check a new value is issued.",
			Params: join([]Param{
				{Name: "manage_uri", Type: "string", Required: true, Desc: "access_token.manage.uri"},
				{Name: "token", Type: "string", Required: true, Secret: true, Explicit: true, Desc: "access_token.manage.access_token.value"}}, key),
			Run: func(c *Ctx) (M, error) {
				return gnapSimple(c, "POST", c.Str("manage_uri"), c.Str("token"), nil, 200, "token rotated")
			},
		},
		&Op{
			Name:     "gnap.revoke",
			Mutating: true,
			Summary:  "Revoke a GNAP access token at its management URI.",
			Params: join([]Param{
				{Name: "manage_uri", Type: "string", Required: true, Desc: "access_token.manage.uri"},
				{Name: "token", Type: "string", Required: true, Secret: true, Explicit: true, Desc: "access_token.manage.access_token.value"}}, key),
			Run: func(c *Ctx) (M, error) {
				return gnapSimple(c, "DELETE", c.Str("manage_uri"), c.Str("token"), nil, 204, "token revoked")
			},
		},
	)
}
