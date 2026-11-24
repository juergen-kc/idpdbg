package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// A software authenticator for running WebAuthn ceremonies against a
// relying party: it plays the browser (client data, RP ID rules) and the
// authenticator (keys, authenticator data, attestation), and can tamper
// with what it sends to see whether the server notices.

// ---- CBOR encoding (CTAP2 canonical: map keys sorted by encoding) ----

func cborEncode(v any) []byte {
	head := func(major byte, n uint64) []byte {
		switch {
		case n < 24:
			return []byte{major<<5 | byte(n)}
		case n < 1<<8:
			return []byte{major<<5 | 24, byte(n)}
		case n < 1<<16:
			return binary.BigEndian.AppendUint16([]byte{major<<5 | 25}, uint16(n))
		case n < 1<<32:
			return binary.BigEndian.AppendUint32([]byte{major<<5 | 26}, uint32(n))
		}
		return binary.BigEndian.AppendUint64([]byte{major<<5 | 27}, n)
	}
	switch t := v.(type) {
	case int:
		return cborEncode(int64(t))
	case int64:
		if t >= 0 {
			return head(0, uint64(t))
		}
		return head(1, uint64(-1-t))
	case nil:
		return []byte{0xF6}
	case bool:
		if t {
			return []byte{0xF5}
		}
		return []byte{0xF4}
	case []any:
		out := head(4, uint64(len(t)))
		for _, x := range t {
			out = append(out, cborEncode(x)...)
		}
		return out
	case cborTag:
		return append(head(6, t.Num), cborEncode(t.V)...)
	case string:
		return append(head(3, uint64(len(t))), t...)
	case []byte:
		return append(head(2, uint64(len(t))), t...)
	case map[any]any:
		type kv struct{ k, v []byte }
		var kvs []kv
		for k, x := range t {
			kvs = append(kvs, kv{cborEncode(k), cborEncode(x)})
		}
		sort.Slice(kvs, func(i, j int) bool {
			if len(kvs[i].k) != len(kvs[j].k) {
				return len(kvs[i].k) < len(kvs[j].k)
			}
			return bytes.Compare(kvs[i].k, kvs[j].k) < 0
		})
		out := head(5, uint64(len(t)))
		for _, e := range kvs {
			out = append(append(out, e.k...), e.v...)
		}
		return out
	}
	panic(fmt.Sprintf("cborEncode: unsupported %T", v))
}

// ---- the stored credential (what a real authenticator keeps) ----

type softCredential struct {
	ID         string `json:"id"` // base64url
	RPID       string `json:"rp_id"`
	UserHandle string `json:"user_handle,omitempty"` // base64url
	Alg        int    `json:"alg"`
	Key        string `json:"key"` // PKCS#8, base64
	SignCount  uint32 `json:"sign_count"`
	Backup     bool   `json:"backup_eligible,omitempty"`
	Origin     string `json:"origin,omitempty"`
	// A credential on a security key: no private key, only what is needed
	// to find it again and check its signatures.
	Hardware  bool   `json:"hardware,omitempty"`
	Protocol  string `json:"protocol,omitempty"`   // ctap2 or u2f, how it was made
	PublicKey string `json:"public_key,omitempty"` // COSE, base64
	AAGUID    string `json:"aaguid,omitempty"`
}

func (s *softCredential) encode() string {
	b, _ := json.Marshal(s)
	return "idpdbg-webauthn:" + base64.RawURLEncoding.EncodeToString(b)
}

func decodeSoftCredential(s string) (*softCredential, crypto.Signer, error) {
	s = strings.TrimSpace(s)
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, "idpdbg-webauthn:"))
	if err != nil {
		return nil, nil, errors.New("credential: not an idpdbg WebAuthn credential (from webauthn register)")
	}
	var sc softCredential
	if err := json.Unmarshal(b, &sc); err != nil {
		return nil, nil, fmt.Errorf("credential: %w", err)
	}
	if sc.Hardware {
		return &sc, nil, nil
	}
	der, err := base64.StdEncoding.DecodeString(sc.Key)
	if err != nil {
		return nil, nil, errors.New("credential: bad key")
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("credential key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("credential key cannot sign")
	}
	return &sc, signer, nil
}

func newCredentialKey(alg int) (crypto.Signer, map[any]any, error) {
	switch alg {
	case -7:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return k, coseOf(k.Public(), alg), nil
	case -8:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		return k, coseOf(k.Public(), alg), nil
	case -257:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		return k, coseOf(k.Public(), alg), nil
	}
	return nil, nil, fmt.Errorf("algorithm %d is not supported by the software authenticator (ES256 -7, EdDSA -8, RS256 -257)", alg)
}

func coseOf(pub crypto.PublicKey, alg int) map[any]any {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return map[any]any{1: 2, 3: alg, -1: 1, -2: k.X.FillBytes(make([]byte, 32)), -3: k.Y.FillBytes(make([]byte, 32))}
	case ed25519.PublicKey:
		return map[any]any{1: 1, 3: alg, -1: 6, -2: []byte(k)}
	case *rsa.PublicKey:
		e := big32(k.E)
		return map[any]any{1: 3, 3: alg, -1: k.N.Bytes(), -2: e}
	}
	return nil
}

func big32(e int) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(e))
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

func webauthnSign(k crypto.Signer, alg int, data []byte) ([]byte, error) {
	switch alg {
	case -8:
		return k.Sign(rand.Reader, data, crypto.Hash(0))
	default:
		sum := sha256.Sum256(data)
		return k.Sign(rand.Reader, sum[:], crypto.SHA256) // ECDSA: ASN.1 DER, as WebAuthn wants
	}
}

// ---- the client side: RP ID rules and client data ----

func originOf(u string) (string, error) {
	p, err := url.Parse(u)
	if err != nil || p.Scheme == "" || p.Host == "" {
		return "", fmt.Errorf("%q is not an origin", u)
	}
	return p.Scheme + "://" + p.Host, nil
}

// rpIDValid applies the browser's rule: the RP ID must be the origin's host
// or a registrable suffix of it, never a public suffix, and the origin must
// be https (or http://localhost).
func rpIDValid(origin, rpID string) error {
	p, err := url.Parse(origin)
	if err != nil {
		return err
	}
	host := p.Hostname()
	if p.Scheme != "https" && !(p.Scheme == "http" && (host == "localhost" || strings.HasSuffix(host, ".localhost"))) {
		return fmt.Errorf("origin %s is not a secure context (https, or http://localhost)", origin)
	}
	if rpID != host && !strings.HasSuffix(host, "."+rpID) {
		return fmt.Errorf("RP ID %q is neither %q nor a parent domain of it", rpID, host)
	}
	if rpID != "localhost" {
		if ps, _ := publicsuffix.PublicSuffix(rpID); ps == rpID {
			return fmt.Errorf("RP ID %q is a public suffix", rpID)
		}
	}
	return nil
}

// clientDataJSON is written by hand: type, challenge, origin come first and
// in this order, as browsers do and as some RPs' parsers expect.
func clientDataJSON(typ string, challenge []byte, origin string) []byte {
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	return []byte(`{"type":` + q(typ) + `,"challenge":` + q(b64url(challenge)) + `,"origin":` + q(origin) + `,"crossOrigin":false}`)
}

func authenticatorData(rpID string, flags byte, count uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := append(h[:], flags)
	b = binary.BigEndian.AppendUint32(b, count)
	return append(b, attested...)
}

// ---- options parsing (WebAuthn L3 JSON forms, possibly wrapped) ----

func webauthnOptions(raw M) M {
	if pk, ok := raw["publicKey"].(map[string]any); ok {
		return pk
	}
	return raw
}

func optBytes(v any) []byte {
	s, _ := v.(string)
	if s == "" {
		return nil
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b
		}
	}
	return nil
}

func challengeCheck(cs *Checks, ch []byte) bool {
	switch {
	case len(ch) == 0:
		cs.add("options: challenge present", "fail", "no challenge", "WebAuthn §5.4")
		return false
	case len(ch) < 16:
		cs.add("options: challenge length", "fail", fmt.Sprintf("%d bytes; at least 16 random bytes are required", len(ch)), "WebAuthn §13.4.3")
	default:
		cs.add("options: challenge length", "pass", fmt.Sprintf("%d bytes", len(ch)), "WebAuthn §13.4.3")
	}
	return true
}

func enumCheck(cs *Checks, name, val string, allowed ...string) {
	if val != "" && !contains(allowed, val) {
		cs.add("options: "+name, "warn", fmt.Sprintf("%q is not one of %s; browsers ignore unknown values", val, strings.Join(allowed, ", ")), "WebAuthn §5.4")
	}
}

func creationOptionChecks(cs *Checks, o M) {
	user, _ := o["user"].(map[string]any)
	uid := optBytes(user["id"])
	switch {
	case len(uid) == 0:
		cs.add("options: user.id", "fail", "missing", "WebAuthn §5.4.3")
	case len(uid) > 64:
		cs.add("options: user.id", "fail", fmt.Sprintf("%d bytes; at most 64", len(uid)), "WebAuthn §5.4.3")
	default:
		s := string(uid)
		name := str(user["name"])
		if strings.Contains(s, "@") || (len(name) >= 3 && strings.Contains(s, name)) {
			cs.add("options: user.id carries no personal data", "warn", fmt.Sprintf("user.id decodes to %q, which contains the account name or an email; it should be an opaque random handle", s), "WebAuthn §14.6.1")
		} else {
			cs.add("options: user.id", "pass", fmt.Sprintf("%d bytes", len(uid)), "WebAuthn §5.4.3")
		}
	}
	params, _ := o["pubKeyCredParams"].([]any)
	var algs []string
	has := map[int]bool{}
	for _, p := range params {
		if m, ok := p.(map[string]any); ok {
			a, _ := m["alg"].(float64)
			has[int(a)] = true
			algs = append(algs, fmt.Sprintf("%s(%d)", coseAlgs[int64(a)], int(a)))
		}
	}
	switch {
	case len(params) == 0:
		cs.add("options: pubKeyCredParams", "warn", "empty: the browser falls back to ES256 and RS256", "WebAuthn §5.4")
	case !has[-7]:
		cs.add("options: pubKeyCredParams includes ES256", "warn", "offered "+strings.Join(algs, ", ")+"; almost every authenticator supports ES256 (-7)", "WebAuthn §5.4")
	case !has[-257]:
		cs.add("options: pubKeyCredParams includes RS256", "info", "offered "+strings.Join(algs, ", ")+"; Windows Hello and some security keys use RS256 (-257)", "WebAuthn §5.4")
	default:
		cs.add("options: pubKeyCredParams", "pass", strings.Join(algs, ", "), "WebAuthn §5.4")
	}
	enumCheck(cs, "attestation", str(o["attestation"]), "none", "indirect", "direct", "enterprise")
	if sel, ok := o["authenticatorSelection"].(map[string]any); ok {
		enumCheck(cs, "residentKey", str(sel["residentKey"]), "discouraged", "preferred", "required")
		enumCheck(cs, "userVerification", str(sel["userVerification"]), "discouraged", "preferred", "required")
		enumCheck(cs, "authenticatorAttachment", str(sel["authenticatorAttachment"]), "platform", "cross-platform")
		if str(sel["residentKey"]) == "required" && sel["requireResidentKey"] != true {
			cs.add("options: requireResidentKey", "info", "residentKey=required without requireResidentKey=true; Level 1 browsers only read the latter", "WebAuthn §5.4.4")
		}
	}
	if ex, _ := o["excludeCredentials"].([]any); len(ex) > 0 {
		cs.add("options: excludeCredentials", "info", fmt.Sprintf("%d credential(s) the user already has", len(ex)), "WebAuthn §5.4")
	}
}

// ---- talking to the relying party ----

type rpAPI struct {
	kind                  string // fido | custom | offline
	optionsURL, resultURL string
	optionsBody           M
	pageURL               string // loaded first, as a browser would, to collect session cookies
	resultField           string
	resultExtra           M
	client                *http.Client
}

func newRPAPI(c *Ctx, ceremony string) (*rpAPI, error) {
	jar, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	cl := c.client()
	cl.Jar = jar // most RPs keep the challenge in a session cookie
	a := &rpAPI{client: cl}
	// json parameters arrive parsed; anything but an object is a mistake.
	object := func(name string) (M, error) {
		v, ok := c.Args[name]
		if !ok || v == nil {
			return M{}, nil
		}
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be a JSON object", name)
		}
		return m, nil
	}
	var err error
	if a.optionsBody, err = object("options_body"); err != nil {
		return nil, err
	}
	if a.resultExtra, err = object("result_extra"); err != nil {
		return nil, err
	}
	a.resultField = c.Str("result_field")
	switch {
	case c.Str("server") != "":
		a.kind = "fido"
		base := strings.TrimRight(c.Str("server"), "/")
		path := map[string]string{"registration": "attestation", "authentication": "assertion"}[ceremony]
		a.optionsURL, a.resultURL = base+"/"+path+"/options", base+"/"+path+"/result"
	case c.Str("options_url") != "" || c.Str("result_url") != "":
		if c.Str("options_url") == "" || c.Str("result_url") == "" {
			return nil, errors.New("options_url and result_url go together")
		}
		a.kind, a.optionsURL, a.resultURL = "custom", c.Str("options_url"), c.Str("result_url")
		a.pageURL = c.Str("page_url")
		if a.pageURL == "" {
			if o, err := originOf(a.optionsURL); err == nil {
				a.pageURL = o + "/"
			}
		}
	default:
		a.kind = "offline"
	}
	return a, nil
}

func (a *rpAPI) post(c *Ctx, u string, body any) (*httpResult, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(c, "POST", u, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "idpdbg/"+version)
	if o, err := originOf(u); err == nil {
		req.Header.Set("Origin", o)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	res := &httpResult{Status: resp.StatusCode, Header: resp.Header, Body: buf.Bytes()}
	var v any
	if json.Unmarshal(res.Body, &v) == nil {
		res.JSON = v
	}
	return res, nil
}

// accepted reads an RP's verdict: FIDO conformance {"status":"ok"},
// {"verified":true} (py_webauthn and SimpleWebAuthn demos), else HTTP 2xx.
func accepted(res *httpResult) (bool, string) {
	m := res.obj()
	switch {
	case res.Status < 200 || res.Status > 299:
		msg := fmt.Sprintf("HTTP %d", res.Status)
		if m != nil {
			if e := str(m["errorMessage"]) + str(m["error"]) + str(m["detail"]); e != "" {
				msg += ": " + e
			}
		}
		return false, msg
	case m != nil && m["status"] != nil:
		return str(m["status"]) == "ok", fmt.Sprintf("status=%v %s", m["status"], str(m["errorMessage"]))
	case m != nil && m["verified"] != nil:
		return m["verified"] == true, fmt.Sprintf("verified=%v", m["verified"])
	}
	return true, fmt.Sprintf("HTTP %d", res.Status)
}

func (a *rpAPI) fetchOptions(c *Ctx, cs *Checks, defaults M) (M, error) {
	// The FIDO conformance API gets its standard fields; a custom API gets
	// exactly the caller's body (servers often reject unknown fields).
	body := M{}
	if a.kind == "fido" {
		body = defaults
	}
	for k, v := range a.optionsBody {
		body[k] = v
	}
	if a.pageURL != "" && a.pageURL != "none" {
		// A browser has loaded the page before any ceremony; some RPs keep
		// state in that session and fail without it.
		req, err := http.NewRequestWithContext(c, "GET", a.pageURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "idpdbg/"+version)
		if resp, err := a.client.Do(req); err == nil {
			resp.Body.Close()
			u, _ := url.Parse(a.pageURL)
			cs.add("page loaded first", "info", fmt.Sprintf("HTTP %d from %s, %d cookie(s) kept for the ceremony", resp.StatusCode, a.pageURL, len(a.client.Jar.Cookies(u))), "")
		} else {
			cs.add("page loaded first", "warn", err.Error(), "")
		}
	}
	res, err := a.post(c, a.optionsURL, body)
	if err != nil {
		return nil, err
	}
	m := res.obj()
	if !cs.ok(res.Status == 200 && m != nil, "server: options returned", fmt.Sprintf("HTTP %d from %s", res.Status, a.optionsURL), "WebAuthn §5.1.3") {
		return nil, fmt.Errorf("the server returned no options (HTTP %d): %s", res.Status, excerpt(res.Body))
	}
	if a.kind == "fido" && str(m["status"]) != "ok" {
		return nil, fmt.Errorf("options: status=%v %s", m["status"], str(m["errorMessage"]))
	}
	return webauthnOptions(m), nil
}

func (a *rpAPI) submit(c *Ctx, credJSON M) (*httpResult, error) {
	body := credJSON
	if a.kind == "fido" {
		// The conformance API names the extension results after the method.
		body = M{}
		for k, v := range credJSON {
			body[k] = v
		}
		body["getClientExtensionResults"] = M{}
		delete(body, "clientExtensionResults")
	}
	if a.resultField != "" {
		body = M{a.resultField: credJSON}
	}
	for k, v := range a.resultExtra {
		body[k] = v
	}
	return a.post(c, a.resultURL, body)
}

// ---- tampering ----

var registerTampers = []string{"wrong_origin", "wrong_rp_id_hash", "wrong_challenge", "wrong_type", "no_user_present", "bad_attestation_signature",
	"broken_attestation_chain", "bad_attestation_certificate"}
var loginTampers = []string{"wrong_origin", "wrong_rp_id_hash", "wrong_challenge", "wrong_type", "no_user_present", "bad_signature", "counter_not_increased", "no_user_verified"}

var tamperWhat = map[string]string{
	"wrong_origin":                "client data from another origin (https://evil.example)",
	"wrong_rp_id_hash":            "authenticator data for another RP ID (evil.example)",
	"wrong_challenge":             "a challenge the server never issued",
	"wrong_type":                  "client data of the other ceremony's type",
	"no_user_present":             "authenticator data without the user-present flag",
	"bad_attestation_signature":   "a corrupted attestation signature",
	"broken_attestation_chain":    "an attestation certificate from an impostor CA with the trusted CA's name",
	"bad_attestation_certificate": "an attestation certificate that breaks the packed requirements (a CA certificate, wrong OU)",
	"bad_signature":               "a corrupted assertion signature",
	"counter_not_increased":       "a signature counter that did not increase",
	"no_user_verified":            "no user verification although the server required it",
}

var tamperRef = map[string]string{"wrong_origin": "WebAuthn §7.1 step 9 / §7.2 step 13", "wrong_rp_id_hash": "WebAuthn §7.1 step 13 / §7.2 step 15",
	"wrong_challenge": "WebAuthn §7.1 step 8 / §7.2 step 12", "wrong_type": "WebAuthn §7.1 step 7 / §7.2 step 11",
	"no_user_present": "WebAuthn §7.1 step 14 / §7.2 step 16", "bad_attestation_signature": "WebAuthn §7.1 step 19",
	"broken_attestation_chain": "WebAuthn §7.1 steps 20-21", "bad_attestation_certificate": "WebAuthn §8.2.1",
	"bad_signature": "WebAuthn §7.2 step 20", "counter_not_increased": "WebAuthn §7.2 step 21", "no_user_verified": "WebAuthn §7.2 step 17"}

func tamperVerdict(cs *Checks, tamper string, res *httpResult) {
	ok, detail := accepted(res)
	name := "server rejects " + tamperWhat[tamper]
	switch {
	case !ok:
		cs.add(name, "pass", "rejected: "+detail, tamperRef[tamper])
	case tamper == "counter_not_increased":
		cs.add(name, "warn", "accepted: the RP may only flag a possible cloned authenticator, but it should at least notice ("+detail+")", tamperRef[tamper])
	case tamper == "broken_attestation_chain":
		cs.add(name, "warn", "accepted: the RP does not check attestation against trusted roots. That is fine if it does not rely on attestation (most consumer sites); an RP that restricts authenticator models must reject it ("+detail+")", tamperRef[tamper])
	default:
		cs.add(name, "fail", "accepted: "+detail, tamperRef[tamper])
	}
}

// ---- registration ----

func runWebAuthnRegister(c *Ctx) (M, error) {
	tamper := c.Str("tamper")
	api, err := newRPAPI(c, "registration")
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{"api": api.kind}

	var o M
	if s := c.Str("options"); s != "" {
		var raw M
		if err := json.Unmarshal([]byte(s), &raw); err != nil {
			return nil, fmt.Errorf("options: %w", err)
		}
		o = webauthnOptions(raw)
	} else if api.kind == "offline" {
		return nil, errors.New("pass options (PublicKeyCredentialCreationOptions JSON), server (a FIDO conformance API), or options_url and result_url")
	} else {
		sel := M{"userVerification": "preferred", "residentKey": "preferred"}
		conveyance := "none" // ask for direct attestation when one will be sent
		if c.Str("attestation_format") != "none" || strings.Contains(tamper, "attestation") {
			conveyance = "direct"
		}
		if o, err = api.fetchOptions(c, &cs, M{"username": c.Str("username"), "displayName": c.Str("username"), "authenticatorSelection": sel, "attestation": conveyance}); err != nil {
			return nil, err
		}
	}
	out["options"] = o

	origin := c.Str("origin")
	if origin == "" {
		u := c.Str("server") + c.Str("options_url")
		if u == "" {
			return nil, errors.New("origin is required when no server URL is given")
		}
		if origin, err = originOf(u); err != nil {
			return nil, err
		}
	}
	rp, _ := o["rp"].(map[string]any)
	rpID := str(rp["id"])
	if rpID == "" {
		p, _ := url.Parse(origin)
		rpID = p.Hostname()
		cs.add("options: rp.id", "info", "absent: the browser uses the origin's host, "+rpID, "WebAuthn §5.4.2")
	}
	out["origin"], out["rp_id"] = origin, rpID
	if err := rpIDValid(origin, rpID); err != nil {
		cs.add("RP ID valid for the origin", "fail", err.Error()+"; a browser refuses this with SecurityError", "WebAuthn §5.1.3 step 7")
		out["checks"] = cs
		return out, nil
	}
	cs.add("RP ID valid for the origin", "pass", rpID+" for "+origin, "WebAuthn §5.1.3 step 7")
	challenge := optBytes(o["challenge"])
	if !challengeCheck(&cs, challenge) {
		out["checks"] = cs
		return out, nil
	}
	creationOptionChecks(&cs, o)

	var cred M
	var stored *softCredential
	if c.Str("authenticator") == "usb" {
		if cred, stored, err = hwRegister(c, &cs, api, out, o, origin, rpID, challenge, tamper); err != nil {
			return nil, err
		}
		if cred == nil {
			out["checks"] = cs
			return out, nil
		}
	} else {
		// Pick the algorithm: the caller's, else the RP's first one we support.
		alg := c.Int("alg")
		if alg == 0 {
			alg = -7
			if params, _ := o["pubKeyCredParams"].([]any); len(params) > 0 {
				alg = 0
				for _, p := range params {
					m, _ := p.(map[string]any)
					if a, _ := m["alg"].(float64); a == -7 || a == -8 || a == -257 {
						alg = int(a)
						break
					}
				}
				if alg == 0 {
					return nil, errors.New("the server offers no algorithm the software authenticator supports (ES256, EdDSA, RS256); a security key (authenticator=usb) may")
				}
			}
		}
		key, cose, err := newCredentialKey(alg)
		if err != nil {
			return nil, err
		}
		credID := make([]byte, 32)
		rand.Read(credID)

		typ, cdOrigin, rpHashID := "webauthn.create", origin, rpID
		switch tamper {
		case "wrong_origin":
			cdOrigin = "https://evil.example"
		case "wrong_challenge":
			challenge = make([]byte, 32)
			rand.Read(challenge)
		case "wrong_type":
			typ = "webauthn.get"
		case "wrong_rp_id_hash":
			rpHashID = "evil.example"
		}
		cd := clientDataJSON(typ, challenge, cdOrigin)
		flags := byte(0x01 | 0x40) // UP, AT
		if c.Bool("user_verified") {
			flags |= 0x04
		}
		if c.Bool("backup_eligible") {
			flags |= 0x08 | 0x10
		}
		if tamper == "no_user_present" {
			flags &^= 0x01
		}
		attFmt := c.Str("attestation_format")
		// The certificate tampers need a certificate: packed-x5c unless the
		// caller chose fido-u2f (which has no certificate requirements).
		switch {
		case tamper == "bad_attestation_certificate" && attFmt == "fido-u2f":
			return nil, errors.New("tamper bad_attestation_certificate needs attestation_format packed-x5c: fido-u2f sets no certificate requirements")
		case (tamper == "broken_attestation_chain" || tamper == "bad_attestation_certificate") && attFmt != "fido-u2f":
			attFmt = "packed-x5c"
		}
		aaguid := make([]byte, 16) // zeros: no model to name
		if attFmt == "packed-x5c" {
			aaguid = idpdbgAAGUID
		}
		attested := append(append([]byte{}, aaguid...), byte(len(credID)>>8), byte(len(credID)))
		attested = append(append(attested, credID...), cborEncode(cose)...)
		ad := authenticatorData(rpHashID, flags, 0, attested)
		cdHash := sha256.Sum256(cd)

		stmt := map[any]any{}
		if attFmt == "packed-x5c" || attFmt == "fido-u2f" {
			rpHash := sha256.Sum256([]byte(rpHashID))
			if stmt, err = certAttestation(c, attFmt, tamper, ad, cdHash[:], rpHash[:], credID, key, out); err != nil {
				return nil, err
			}
			if attFmt == "packed-x5c" {
				attFmt = "packed"
			}
		} else if attFmt == "packed" || tamper == "bad_attestation_signature" {
			attFmt = "packed"
			sig, err := webauthnSign(key, alg, append(append([]byte{}, ad...), cdHash[:]...))
			if err != nil {
				return nil, err
			}
			if tamper == "bad_attestation_signature" {
				sig[len(sig)/2] ^= 0xFF
			}
			stmt = map[any]any{"alg": alg, "sig": sig}
		}
		attObj := cborEncode(map[any]any{"fmt": attFmt, "attStmt": stmt, "authData": ad})
		spki, _ := x509.MarshalPKIXPublicKey(key.Public())
		cred = M{"id": b64url(credID), "rawId": b64url(credID), "type": "public-key", "authenticatorAttachment": "cross-platform",
			"response": M{"clientDataJSON": b64url(cd), "attestationObject": b64url(attObj), "transports": []string{"usb"},
				"authenticatorData": b64url(ad), "publicKey": b64url(spki), "publicKeyAlgorithm": alg},
			"clientExtensionResults": extensionResults(&cs, o, true)}
		out["credential_response"] = cred
		out["client_data"] = json.RawMessage(cd)

		stored = &softCredential{ID: b64url(credID), RPID: rpID, Alg: alg, Origin: origin, Backup: c.Bool("backup_eligible")}
		if user, ok := o["user"].(map[string]any); ok {
			stored.UserHandle = b64url(optBytes(user["id"]))
		}
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		stored.Key = base64.StdEncoding.EncodeToString(der)
	}

	if api.kind != "offline" {
		res, err := api.submit(c, cred)
		if err != nil {
			return nil, err
		}
		out["server_response"] = serverResponse(out, res)
		if tamper != "" {
			tamperVerdict(&cs, tamper, res)
		} else {
			ok, detail := accepted(res)
			cs.ok(ok, "server accepts the registration", detail, "WebAuthn §7.1")
			if !ok {
				stored = nil
			}
		}
	}
	if tamper == "" && stored != nil {
		blob := stored.encode()
		out["credential"] = blob
		c.Rec.secrets = append(c.Rec.secrets, blob)
		if p := c.Str("out"); p != "" {
			if !c.CLI {
				return nil, errors.New("out is only available from the CLI; over MCP the credential is returned in the result")
			}
			if err := os.WriteFile(p, []byte(blob+"\n"), 0o600); err != nil {
				return nil, err
			}
			out["written_to"] = p
		}
	}
	out["checks"] = cs
	return out, nil
}

// ---- authentication ----

func runWebAuthnLogin(c *Ctx) (M, error) {
	tamper := c.Str("tamper")
	// Without a credential: a passkey sign-in, where the security key finds
	// the account itself (a discoverable credential).
	discoverable := c.Bool("passkey")
	switch {
	case discoverable && c.Str("credential") != "":
		return nil, errors.New("pass either credential or passkey, not both")
	case !discoverable && c.Str("credential") == "":
		return nil, errors.New("pass credential (from webauthn.register), or passkey=true for a passkey sign-in with a security key")
	}
	sc, key := &softCredential{Hardware: true}, crypto.Signer(nil)
	var err error
	if !discoverable {
		if sc, key, err = decodeSoftCredential(c.Str("credential")); err != nil {
			return nil, err
		}
	}
	api, err := newRPAPI(c, "authentication")
	if err != nil {
		return nil, err
	}
	// A credential from a profile or the environment (CLI only: over MCP it
	// must be passed in the call) may only sign for an allowed destination;
	// the URLs themselves are checked by the stored-secret guard.
	if c.guard != nil && c.guard.active && api.kind == "offline" {
		return nil, errors.New("refusing to sign offline with a stored credential: the assertion would have no allowed destination; pass the credential explicitly, or use server / result_url")
	}
	var cs Checks
	out := M{"api": api.kind, "credential_id": sc.ID}

	var o M
	if s := c.Str("options"); s != "" {
		var raw M
		if err := json.Unmarshal([]byte(s), &raw); err != nil {
			return nil, fmt.Errorf("options: %w", err)
		}
		o = webauthnOptions(raw)
	} else if api.kind == "offline" {
		return nil, errors.New("pass options (PublicKeyCredentialRequestOptions JSON), server, or options_url and result_url")
	} else if o, err = api.fetchOptions(c, &cs, M{"username": c.Str("username"), "userVerification": "preferred"}); err != nil {
		return nil, err
	}
	out["options"] = o

	origin := c.Str("origin")
	if origin == "" {
		origin = sc.Origin
	}
	if origin == "" && discoverable && api.kind != "offline" {
		origin, _ = originOf(c.Str("server") + c.Str("options_url"))
	}
	if origin == "" {
		return nil, errors.New("origin is required")
	}
	rpID := str(o["rpId"])
	if rpID == "" {
		p, _ := url.Parse(origin)
		rpID = p.Hostname()
	}
	if err := rpIDValid(origin, rpID); err != nil {
		cs.add("RP ID valid for the origin", "fail", err.Error()+"; a browser refuses this with SecurityError", "WebAuthn §5.1.4 step 7")
		out["checks"] = cs
		return out, nil
	}
	if !discoverable && !cs.ok(rpID == sc.RPID, "RP ID matches the credential's", fmt.Sprintf("options rpId %s, credential registered for %s", rpID, sc.RPID), "WebAuthn §6.3.3") {
		out["checks"] = cs
		return out, nil
	}
	challenge := optBytes(o["challenge"])
	if !challengeCheck(&cs, challenge) {
		out["checks"] = cs
		return out, nil
	}
	uvRequired := str(o["userVerification"]) == "required"
	enumCheck(&cs, "userVerification", str(o["userVerification"]), "discouraged", "preferred", "required")
	allow, _ := o["allowCredentials"].([]any)
	if len(allow) == 0 {
		cs.add("options: allowCredentials", "info", "empty: a discoverable-credential (passkey) sign-in; the authenticator picks the account", "WebAuthn §5.5")
	} else if discoverable {
		cs.add("options: allowCredentials", "info", fmt.Sprintf("%d credential(s) allowed; the security key looks for any of them", len(allow)), "WebAuthn §6.3.3 step 3")
	} else {
		found := false
		for _, a := range allow {
			m, _ := a.(map[string]any)
			found = found || bytes.Equal(optBytes(m["id"]), optBytes(sc.ID))
		}
		if !cs.ok(found, "options: allowCredentials lists this credential", fmt.Sprintf("%d credential(s) allowed", len(allow)), "WebAuthn §6.3.3 step 3") {
			out["checks"] = cs
			return out, nil
		}
	}

	var cred M
	var count uint32
	if sc.Hardware {
		if cred, count, err = hwLogin(c, &cs, api, out, o, sc, origin, rpID, challenge, tamper); err != nil {
			return nil, err
		}
		if cred == nil {
			out["checks"] = cs
			return out, nil
		}
	} else {
		count = sc.SignCount + 1
		typ, cdOrigin, rpHashID := "webauthn.get", origin, rpID
		flags := byte(0x01)
		if c.Bool("user_verified") {
			flags |= 0x04
		}
		if sc.Backup {
			flags |= 0x08 | 0x10
		}
		switch tamper {
		case "wrong_origin":
			cdOrigin = "https://evil.example"
		case "wrong_challenge":
			challenge = make([]byte, 32)
			rand.Read(challenge)
		case "wrong_type":
			typ = "webauthn.create"
		case "wrong_rp_id_hash":
			rpHashID = "evil.example"
		case "no_user_present":
			flags &^= 0x01
		case "counter_not_increased":
			count = sc.SignCount
		case "no_user_verified":
			flags &^= 0x04
			if !uvRequired {
				return nil, errors.New("tamper no_user_verified needs a server that requires user verification (userVerification=required)")
			}
		}
		cd := clientDataJSON(typ, challenge, cdOrigin)
		ad := authenticatorData(rpHashID, flags, count, nil)
		cdHash := sha256.Sum256(cd)
		sig, err := webauthnSign(key, sc.Alg, append(append([]byte{}, ad...), cdHash[:]...))
		if err != nil {
			return nil, err
		}
		if tamper == "bad_signature" {
			sig[len(sig)/2] ^= 0xFF
		}
		resp := M{"clientDataJSON": b64url(cd), "authenticatorData": b64url(ad), "signature": b64url(sig)}
		if sc.UserHandle != "" {
			resp["userHandle"] = sc.UserHandle
		}
		cred = M{"id": sc.ID, "rawId": sc.ID, "type": "public-key", "authenticatorAttachment": "cross-platform", "response": resp, "clientExtensionResults": extensionResults(&cs, o, false)}
		out["credential_response"] = cred
		out["client_data"] = json.RawMessage(cd)
	}
	out["sign_count"] = count

	if api.kind != "offline" {
		res, err := api.submit(c, cred)
		if err != nil {
			return nil, err
		}
		out["server_response"] = serverResponse(out, res)
		if tamper != "" {
			tamperVerdict(&cs, tamper, res)
		} else {
			ok, detail := accepted(res)
			cs.ok(ok, "server accepts the assertion", detail, "WebAuthn §7.2")
		}
	}
	if tamper == "" || tamper == "counter_not_increased" {
		sc.SignCount = count
		blob := sc.encode()
		out["credential"] = blob // with the new signature counter: use it next time
		c.Rec.secrets = append(c.Rec.secrets, blob)
	}
	out["checks"] = cs
	return out, nil
}

func init() {
	common := []Param{
		{Name: "server", Type: "string", Desc: "Base URL of a FIDO2 conformance-style server API (/attestation/options, /attestation/result, /assertion/options, /assertion/result)"},
		{Name: "options_url", Type: "string", Desc: "Instead of server: URL that returns the options (POSTed options_body)"},
		{Name: "options_body", Type: "json", Desc: "JSON body for options_url (merged into the default body with server)"},
		{Name: "result_url", Type: "string", Desc: "Instead of server: URL that verifies the credential response"},
		{Name: "page_url", Type: "string", Desc: "With options_url: page to load first for session cookies, as a browser would (default the site's root; none to skip)"},
		{Name: "result_field", Type: "string", Desc: "Nest the credential response under this key when posting to result_url"},
		{Name: "result_extra", Type: "json", Desc: "Extra fields for the result body (e.g. {\"username\":\"alice\"})"},
		{Name: "options", Type: "string", File: true, Desc: "Options JSON to answer instead of fetching them (offline when no result URL)"},
		{Name: "origin", Type: "string", Desc: "Origin the browser would report (default: the server's)"},
		{Name: "username", Type: "string", Desc: "Account name sent with server", Default: "idpdbg-test"},
		{Name: "user_verified", Type: "bool", Desc: "Software authenticator: set the UV flag (a simulated PIN or biometric)", Default: true},
		{Name: "device", Type: "string", Desc: "Security key: index or path from fido.devices (default: the only one connected)"},
		{Name: "ctap", Type: "string", Enum: []string{"auto", "ctap2", "u2f"}, Default: "auto", Desc: "Security key protocol: auto does what a browser does (CTAP2, or U2F when the key would need a PIN that is not available)"},
		{Name: "pin", Type: "string", Secret: true, Desc: "Security key PIN, for user verification as a browser would ask for it (prefer env IDPDBG_PIN or a profile; from a terminal idpdbg asks). Never retried: a wrong PIN costs one of the key's attempts"},
	}
	register(
		&Op{
			Name: "webauthn.register",
			Summary: "Register a passkey with a relying party: fetches (or takes) the creation options and checks them (challenge, user handle, algorithms, RP ID against the origin), makes the credential, submits it and reports whether the server accepts it. " +
				"The authenticator is a software one (ES256, EdDSA or RS256; none, packed self attestation, packed with an attestation certificate chain, or fido-u2f) or, with authenticator=usb, a real security key over CTAP2 or U2F, whose attestation is verified locally (the person must touch the key: tell them first). " +
				"Returns the credential for webauthn.login. tamper sends a deliberately broken response to test that the server rejects it.",
			Mutating: true,
			Params: joinParams(common, []Param{
				{Name: "authenticator", Type: "string", Enum: []string{"software", "usb"}, Default: "software", Desc: "software, or usb for a connected security key"},
				{Name: "resident_key", Type: "bool", Desc: "Security key: make a discoverable credential (stored on the key, using one of its slots)"},
				{Name: "metadata", Type: "bool", Desc: "Security key: check the key's attestation against the FIDO Metadata Service (model, certification, security status, chain to the model's root)"},
				{Name: "alg", Type: "int", Desc: "Software authenticator: COSE algorithm (-7 ES256, -8 EdDSA, -257 RS256); default the server's first supported"},
				{Name: "attestation_format", Type: "string", Enum: []string{"none", "packed", "packed-x5c", "fido-u2f"}, Default: "none", Desc: "Software authenticator: attestation statement format: none, packed self attestation, packed with an attestation certificate (x5c), or fido-u2f (ES256 only)"},
				{Name: "attestation_ca", Type: "string", Path: true, Explicit: true, Desc: "With packed-x5c or fido-u2f: certificate and private key (PEM) of the CA that issues the attestation certificate, one the relying party trusts; default a throwaway CA, whose root the result shows"},
				{Name: "backup_eligible", Type: "bool", Desc: "Mark the credential as a synced passkey (BE and BS flags)"},
				{Name: "tamper", Type: "string", Enum: registerTampers, Desc: "Send a broken response; the check passes if the server rejects it"},
				{Name: "out", Type: "string", Desc: "Also write the credential to this file (CLI only)"},
			}),
			Run: runWebAuthnRegister,
		},
		&Op{
			Name: "webauthn.login",
			Summary: "Sign in to a relying party with a credential from webauthn.register: fetches (or takes) the request options and checks them (challenge, RP ID, allowCredentials, user verification), signs an assertion with the next signature counter, submits it and reports whether the server accepts it. " +
				"A credential made on a security key is used on that key (touch needed: tell the person first) and its signature checked locally. Returns the credential with its updated counter. tamper tests that the server rejects a wrong origin, RP ID, challenge or type, missing user presence or verification, a bad signature or a counter that did not increase.",
			Params: joinParams(common, []Param{
				{Name: "credential", Type: "string", Secret: true, Explicit: true, File: true, Path: true, Desc: "The credential from webauthn.register (idpdbg-webauthn:...)"},
				{Name: "passkey", Type: "bool", Desc: "Instead of credential: a passkey sign-in with a security key, which finds the account itself (touch needed; tell the person first)"},
				{Name: "account", Type: "string", Desc: "Passkey sign-in with several accounts on the key: which one (user name, display name, user handle, or number); from a terminal idpdbg asks"},
				{Name: "tamper", Type: "string", Enum: loginTampers, Desc: "Send a broken assertion; the check passes if the server rejects it"},
			}),
			Run: runWebAuthnLogin,
		},
	)
}

// excerpt is the start of a response body for an error message.
func excerpt(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	if s == "" {
		return "(empty body)"
	}
	return s
}

// extensionResults answers the extensions a browser handles itself.
// credProps (WebAuthn §10.1.3) is always answered when asked: RPs store
// whether the credential is discoverable, and some fail later without it.
// The software authenticator makes discoverable credentials unless the RP
// discourages it. Others are named as not supported.
func extensionResults(cs *Checks, o M, create bool) M {
	ext, _ := o["extensions"].(map[string]any)
	res := M{}
	var unsupported []string
	for name, v := range ext {
		switch {
		case name == "credProps" && create && v == true:
			rk := true
			if sel, ok := o["authenticatorSelection"].(map[string]any); ok && str(sel["residentKey"]) == "discouraged" && sel["requireResidentKey"] != true {
				rk = false
			}
			res["credProps"] = M{"rk": rk}
		case name == "credProps":
		default:
			unsupported = append(unsupported, name)
		}
	}
	if len(unsupported) > 0 {
		sort.Strings(unsupported)
		cs.add("options: extensions", "info", "requested but not handled by the software authenticator: "+strings.Join(unsupported, ", "), "WebAuthn §9")
	}
	return res
}
