package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Verifiable credentials: OpenID for Verifiable Credential Issuance 1.0
// (pre-authorized code flow) and OpenID for Verifiable Presentations 1.0
// (signed requests, DCQL, SD-JWT VC presentations, direct_post).

const (
	vciRef       = "OID4VCI 1.0"
	vpRef        = "OID4VP 1.0"
	preAuthGrant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// sub runs another operation's logic with its own arguments in this run.
func (c *Ctx) sub(args M) *Ctx {
	return &Ctx{Context: c.Context, Op: c.Op, Args: args, Rec: c.Rec, CLI: c.CLI, Log: c.Log, guard: c.guard}
}

func wellKnownURL(base, name string) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(base, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q is not an absolute URL", base)
	}
	return u.Scheme + "://" + u.Host + "/.well-known/" + name + u.Path, nil
}

func getJSON(c *Ctx, u string) (M, error) {
	res, err := c.do("GET", u, map[string]string{"Accept": "application/json"}, nil)
	if err != nil {
		return nil, err
	}
	if loc := res.Header.Get("Location"); res.Status >= 300 && res.Status < 400 {
		return nil, fmt.Errorf("%s redirects (HTTP %d) to %s; metadata must be served at the well-known URL itself", u, res.Status, loc)
	}
	if res.Status != 200 || res.obj() == nil {
		return nil, fmt.Errorf("%s returned HTTP %d", u, res.Status)
	}
	return res.obj(), nil
}

func holderKey(c *Ctx) (crypto.Signer, bool, error) {
	if s := c.Str("holder_key"); s != "" {
		k, err := loadPrivateKey(s)
		if err != nil {
			return nil, false, fmt.Errorf("holder_key: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, false, errors.New("holder_key cannot sign")
		}
		return signer, false, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k, true, err
}

func privateJWK(k crypto.Signer) M {
	jwk, _ := publicJWK(k.Public())
	if ec, ok := k.(*ecdsa.PrivateKey); ok {
		jwk["d"] = b64url(ec.D.FillBytes(make([]byte, (ec.Curve.Params().BitSize+7)/8)))
	}
	return jwk
}

// ---- issuance ----

func parseOffer(c *Ctx, s string) (M, error) {
	s = strings.TrimSpace(s)
	if looksLikeJSON(s) {
		var m M
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			return nil, fmt.Errorf("offer: %w", err)
		}
		return m, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("offer: %w", err)
	}
	q := u.Query()
	if v := q.Get("credential_offer"); v != "" {
		return parseOffer(c, v)
	}
	if v := q.Get("credential_offer_uri"); v != "" {
		return getJSON(c, v)
	}
	if u.Scheme == "https" {
		return getJSON(c, s)
	}
	return nil, errors.New("offer is neither JSON nor a URL with credential_offer or credential_offer_uri")
}

func checkOffer(cs *Checks, offer, meta M) {
	ids, _ := coerce(Param{Name: "x", Type: "list"}, offer["credential_configuration_ids"], false)
	idl, _ := ids.([]string)
	cs.ok(len(idl) > 0, "offer names credential configurations", strings.Join(idl, ", "), vciRef+" §4.1.1")
	if meta != nil {
		confs, _ := meta["credential_configurations_supported"].(map[string]any)
		for _, id := range idl {
			cs.ok(confs[id] != nil, "offered configuration "+id+" is in the issuer metadata", "", vciRef+" §4.1.1")
		}
	}
	grants, _ := offer["grants"].(map[string]any)
	if pre, _ := grants[preAuthGrant].(map[string]any); pre != nil {
		cs.ok(str(pre["pre-authorized_code"]) != "", "pre-authorized code present", "", vciRef+" §4.1.1")
		if tc, _ := pre["tx_code"].(map[string]any); tc != nil {
			cs.add("transaction code required", "info", fmt.Sprintf("%v characters, input %v: %v", tc["length"], tc["input_mode"], tc["description"]), vciRef+" §4.1.1")
		} else {
			cs.add("transaction code required", "warn", "no tx_code: whoever obtains the offer can redeem it", vciRef+" §13.6")
		}
	} else if grants[preAuthGrant] == nil && grants["authorization_code"] != nil {
		cs.add("grant type", "info", "authorization code offer: issuance continues through the issuer's authorization server", vciRef+" §4.1.1")
	}
}

func runVCIMetadata(c *Ctx) (M, error) {
	iss := strings.TrimSuffix(c.Str("issuer"), "/")
	mu, err := wellKnownURL(iss, "openid-credential-issuer")
	if err != nil {
		return nil, err
	}
	meta, err := getJSON(c, mu)
	if err != nil {
		return nil, err
	}
	var cs Checks
	cs.ok(strings.TrimSuffix(str(meta["credential_issuer"]), "/") == iss, "credential_issuer matches", str(meta["credential_issuer"]), vciRef+" §12.2.4")
	cs.ok(str(meta["credential_endpoint"]) != "", "credential_endpoint present", str(meta["credential_endpoint"]), vciRef+" §12.2.4")
	cs.warn(str(meta["nonce_endpoint"]) != "", "nonce_endpoint present", "needed for proof-of-possession nonces", vciRef+" §7")
	confs, _ := meta["credential_configurations_supported"].(map[string]any)
	cs.ok(len(confs) > 0, "credential configurations offered", fmt.Sprintf("%d", len(confs)), vciRef+" §12.2.4")
	var list []M
	for _, id := range sortedKeys(confs) {
		cf, _ := confs[id].(map[string]any)
		e := M{"id": id, "format": cf["format"], "vct": cf["vct"], "binding": cf["cryptographic_binding_methods_supported"], "proof_types": cf["proof_types_supported"]}
		list = append(list, e)
		if cf["cryptographic_binding_methods_supported"] == nil {
			cs.add("configuration "+id+": holder binding", "info", "not holder-bound: anyone holding the credential can present it", vciRef+" §12.2.4")
		}
	}
	out := M{"metadata_url": mu, "metadata": meta, "configurations": list}
	asList := []string{iss}
	if as, ok := meta["authorization_servers"].([]any); ok && len(as) > 0 {
		asList = []string{str(as[0])}
	}
	if am, _, err := fetchMeta(c.sub(M{"timeout": c.Int("timeout")}), asList[0]); err == nil {
		out["authorization_server"] = M{"issuer": am["issuer"], "token_endpoint": am["token_endpoint"], "pre_authorized_grant_anonymous_access_supported": am["pre-authorized_grant_anonymous_access_supported"]}
		cs.add("authorization server metadata", "pass", asList[0], vciRef+" §12.3")
	} else {
		cs.add("authorization server metadata", "warn", err.Error(), vciRef+" §12.3")
	}
	if c.Str("offer") != "" {
		offer, err := parseOffer(c, c.Str("offer"))
		if err != nil {
			return out, err
		}
		out["offer"] = offer
		checkOffer(&cs, offer, meta)
	}
	out["checks"] = cs
	return out, nil
}

func runVCIIssue(c *Ctx) (M, error) {
	var cs Checks
	out := M{}
	defer func() { out["checks"] = cs }()
	offer := M{}
	if s := c.Str("offer"); s != "" {
		var err error
		if offer, err = parseOffer(c, s); err != nil {
			return out, err
		}
		out["offer"] = offer
	}
	iss := strings.TrimSuffix(str(offer["credential_issuer"]), "/")
	if c.Str("issuer") != "" {
		iss = strings.TrimSuffix(c.Str("issuer"), "/")
	}
	if iss == "" {
		return out, errors.New("pass offer, or issuer with pre_authorized_code and configuration_id")
	}
	mu, _ := wellKnownURL(iss, "openid-credential-issuer")
	meta, err := getJSON(c, mu)
	if err != nil {
		return out, err
	}
	if len(offer) > 0 {
		checkOffer(&cs, offer, meta)
	}
	grants, _ := offer["grants"].(map[string]any)
	pre, _ := grants[preAuthGrant].(map[string]any)
	authGrant, _ := grants["authorization_code"].(map[string]any)
	code := c.Str("pre_authorized_code")
	if code == "" {
		code = str(pre["pre-authorized_code"])
	}
	confID := c.Str("configuration_id")
	if confID == "" {
		if ids, ok := offer["credential_configuration_ids"].([]any); ok && len(ids) > 0 {
			confID = str(ids[0])
		}
	}
	if confID == "" {
		return out, errors.New("pass configuration_id (or an offer that names one)")
	}
	confs, _ := meta["credential_configurations_supported"].(map[string]any)
	conf, _ := confs[confID].(map[string]any)
	if conf == nil {
		return out, fmt.Errorf("configuration %q is not in the issuer metadata", confID)
	}
	out["configuration_id"] = confID

	// The authorization server: the offer's choice, else the issuer's first.
	asBase := iss
	if as, ok := meta["authorization_servers"].([]any); ok && len(as) > 0 {
		asBase = str(as[0])
	}
	if a := str(authGrant["authorization_server"]); a != "" && code == "" {
		asBase = a
	}
	am, _, err := fetchMeta(c, asBase)
	if err != nil {
		return out, err
	}

	var tok M
	if code != "" {
		out["flow"] = "pre-authorized code"
		if tok, err = vciPreAuthorizedToken(c, &cs, out, am, code, pre); err != nil || tok == nil {
			return out, err
		}
	} else {
		out["flow"] = "authorization code"
		_, listsAS := meta["authorization_servers"].([]any)
		if tok, err = vciAuthorizationCodeToken(c, &cs, out, am, iss, confID, conf, authGrant, listsAS); err != nil || tok == nil {
			return out, err
		}
	}
	credIdent := ""
	if ad, ok := tok["authorization_details"].([]any); ok && len(ad) > 0 {
		if m, _ := ad[0].(map[string]any); m != nil {
			if ids, ok := m["credential_identifiers"].([]any); ok && len(ids) > 0 {
				credIdent = str(ids[0])
			}
		}
	}

	// Nonce and proof of possession.
	nonce := str(tok["c_nonce"])
	if ne := str(meta["nonce_endpoint"]); ne != "" {
		if err := c.allowDestination("the nonce request", ne); err != nil {
			return out, err
		}
		nr, err := c.do("POST", ne, map[string]string{"Accept": "application/json"}, nil)
		if err == nil && nr.obj() != nil {
			nonce = str(nr.obj()["c_nonce"])
		}
		cs.ok(nonce != "", "nonce from the nonce endpoint", "", vciRef+" §7")
	} else if nonce != "" {
		cs.add("nonce source", "warn", "c_nonce in the token response is from drafts; 1.0 uses a nonce endpoint", vciRef+" §7")
	}
	hk, ephemeral, err := holderKey(c)
	if err != nil {
		return out, err
	}
	alg, _ := signerAlg(hk, "")
	jwk, _ := publicJWK(hk.Public())
	proofClaims := M{"aud": str(meta["credential_issuer"]), "iat": time.Now().Unix()}
	if nonce != "" {
		proofClaims["nonce"] = nonce
	}
	if cid := c.Str("client_id"); cid != "" {
		proofClaims["iss"] = cid
	}
	proof, err := signJWS(hk, alg, M{"typ": "openid4vci-proof+jwt", "jwk": jwk}, proofClaims)
	if err != nil {
		return out, err
	}

	// Credential request.
	credEP := str(meta["credential_endpoint"])
	if err := c.allowDestination("the access token", credEP); err != nil {
		return out, err
	}
	body := M{"proofs": M{"jwt": []string{proof}}}
	if credIdent != "" {
		body["credential_identifier"] = credIdent
	} else {
		body["credential_configuration_id"] = confID
	}
	b, _ := json.Marshal(body)
	scheme := "Bearer"
	if strings.EqualFold(str(tok["token_type"]), "DPoP") {
		cs.add("token type", "warn", "the issuer issued a DPoP token; this flow sends it as a bearer token", "RFC 9449")
	}
	cr, err := c.do("POST", credEP, map[string]string{"Authorization": scheme + " " + str(tok["access_token"]), "Content-Type": "application/json", "Accept": "application/json"}, b)
	if err != nil {
		return out, err
	}
	crb := cr.obj()
	if cr.Status == 202 || str(crb["transaction_id"]) != "" {
		cs.add("credential response", "info", "deferred: transaction_id "+str(crb["transaction_id"]), vciRef+" §8.3")
		out["credential_response"] = cr.payload()
		return out, nil
	}
	if !cs.ok(cr.Status == 200 && crb != nil, "credential response", fmt.Sprintf("HTTP %d %s %s", cr.Status, str(crb["error"]), str(crb["error_description"])), vciRef+" §8.3") {
		out["credential_response"] = cr.payload()
		return out, nil
	}
	var creds []string
	if arr, ok := crb["credentials"].([]any); ok {
		for _, x := range arr {
			if m, _ := x.(map[string]any); m != nil {
				creds = append(creds, str(m["credential"]))
			}
		}
	} else if s := str(crb["credential"]); s != "" {
		creds = append(creds, s)
		cs.add("response format", "warn", "credential (singular) is from drafts; 1.0 returns credentials[]", vciRef+" §8.3")
	}
	if !cs.ok(len(creds) > 0, "credential issued", fmt.Sprintf("%d", len(creds)), vciRef+" §8.3") {
		return out, nil
	}
	out["credentials"] = creds
	holderThumb := jwkThumbprint(jwk)
	for i, cred := range creds {
		if !strings.Contains(cred, "~") {
			cs.add(fmt.Sprintf("credential %d", i+1), "info", "format "+str(conf["format"])+" is shown but not analysed", vciRef)
			continue
		}
		a, err := runSDJWT(c.sub(M{"token": cred, "issuer": str(meta["credential_issuer"]), "leeway": 60, "max_kb_age": 300, "timeout": c.Int("timeout")}))
		if err != nil {
			cs.add(fmt.Sprintf("credential %d decodes", i+1), "fail", err.Error(), "RFC 9901")
			continue
		}
		for _, ck := range a["checks"].(Checks) {
			if ck.Name == "key binding JWT present" {
				continue // an issued credential has no KB-JWT yet; that is expected
			}
			ck.Name = fmt.Sprintf("credential %d: %s", i+1, ck.Name)
			cs = append(cs, ck)
		}
		ij, _ := a["issuer_jwt"].(M)
		cl, _ := ij["claims"].(M)
		cnf, _ := cl["cnf"].(map[string]any)
		cj, _ := cnf["jwk"].(map[string]any)
		cs.ok(cj != nil && jwkThumbprint(cj) == holderThumb, fmt.Sprintf("credential %d: bound to the holder key (cnf.jwk)", i+1), "", vciRef+" §8.2.1")
		if v := str(conf["vct"]); v != "" {
			cs.ok(str(cl["vct"]) == v, fmt.Sprintf("credential %d: vct is the configuration's", i+1), "vct="+str(cl["vct"]), "SD-JWT VC §3.2.2.1.1")
		}
		out[fmt.Sprintf("credential_%d", i+1)] = M{"claims": a["claims"], "disclosures": a["disclosures"]}
	}
	if ephemeral {
		out["holder_key"] = privateJWK(hk)
		cs.add("holder key", "info", "a new P-256 key was generated; holder_key in this result is needed to present the credential (vp present)", vciRef)
	}
	return out, nil
}

// vciPreAuthorizedToken redeems a pre-authorized code (OID4VCI §6.1).
func vciPreAuthorizedToken(c *Ctx, cs *Checks, out, am M, code string, pre map[string]any) (M, error) {
	tokenEP := str(am["token_endpoint"])
	if err := c.allowDestination("the pre-authorized code", tokenEP); err != nil {
		return nil, err
	}
	form := url.Values{"grant_type": {preAuthGrant}, "pre-authorized_code": {code}}
	if pre != nil && pre["tx_code"] != nil && c.Str("tx_code") == "" {
		return nil, errors.New("the offer requires tx_code (the code sent to the holder out of band)")
	}
	if tc := c.Str("tx_code"); tc != "" {
		form.Set("tx_code", tc)
	}
	res, err := c.postForm(tokenEP, form, nil)
	if err != nil {
		return nil, err
	}
	tok := res.obj()
	if !cs.ok(res.Status == 200 && str(tok["access_token"]) != "", "token response", fmt.Sprintf("HTTP %d %s", res.Status, str(tok["error"])), vciRef+" §6.2") {
		out["token_response"] = res.payload()
		return nil, nil
	}
	return tok, nil
}

// vciAuthorizationCodeToken runs the authorization code flow (OID4VCI §5):
// the wallet asks the authorization server for the credential, with
// authorization_details of type openid_credential (RFC 9396) or the
// configuration's scope, passes the offer's issuer_state, signs the person
// in through the browser with PKCE (and PAR when the server wants it), and
// redeems the code.
func vciAuthorizationCodeToken(c *Ctx, cs *Checks, out, am M, iss, confID string, conf, authGrant map[string]any, listsAS bool) (M, error) {
	if c.Str("client_id") == "" {
		return nil, errors.New("the authorization code flow needs client_id: the wallet's client at the issuer's authorization server")
	}
	rarTypes, _ := am["authorization_details_types_supported"].([]any)
	rar := false
	for _, t := range rarTypes {
		rar = rar || str(t) == "openid_credential"
	}
	how := c.Str("request_by")
	switch {
	case how == "both" || how == "authorization_details" || how == "auto" && rar:
		if how != "both" {
			how = "authorization_details"
		}
		if !rar {
			cs.add("authorization server supports authorization_details", "warn", "its metadata does not list openid_credential in authorization_details_types_supported", vciRef+" §5.1.1")
		}
	default:
		how = "scope"
		if str(conf["scope"]) == "" {
			return nil, fmt.Errorf("configuration %q has no scope, and the authorization server does not list openid_credential authorization details: pass request_by authorization_details to try anyway", confID)
		}
	}
	out["requested_by"] = how

	args := M{}
	for k, v := range c.Args {
		args[k] = v
	}
	args["response_type"], args["pkce"], args["scope"] = "code", true, ""
	args["par"] = c.Bool("par") || am["require_pushed_authorization_requests"] == true
	extra := M{}
	if how == "both" && str(conf["scope"]) == "" {
		return nil, fmt.Errorf("configuration %q has no scope to send along with authorization_details", confID)
	}
	if how != "scope" {
		ad := M{"type": "openid_credential", "credential_configuration_id": confID}
		if listsAS {
			// Required whenever the issuer names its authorization servers,
			// even when it is its own (OID4VCI §5.1.1).
			ad["locations"] = []string{iss}
		}
		extra["authorization_details"] = []M{ad}
	}
	if how != "authorization_details" {
		args["scope"] = str(conf["scope"])
	}
	if st := str(authGrant["issuer_state"]); st != "" {
		extra["issuer_state"] = st
		cs.add("issuer_state passed on", "pass", "from the offer, so the issuer can tie the request to it", vciRef+" §5.1.3")
	}
	args["extra"] = extra
	sub := c.sub(args)
	redirectURI, port, path, err := loginRedirect(sub)
	if err != nil {
		return nil, err
	}
	a, err := buildAuthURL(sub, am, redirectURI)
	if err != nil {
		if a != nil {
			*cs = append(*cs, a.Checks...)
		}
		return nil, err
	}
	*cs = append(*cs, a.Checks...)
	out["authorization_url"] = a.URL
	a.describe(out)
	c.Log("Listening for the redirect on %s (register this exact redirect URI for client %s)", redirectURI, c.Str("client_id"))
	vals, err := captureRedirectScheme(sub, a.URL, port, path, redirectScheme(redirectURI), a.State)
	if err != nil {
		return nil, err
	}
	if e := vals.Get("error"); e != "" {
		cs.add("authorization response", "fail", e+": "+vals.Get("error_description"), "RFC 6749 §4.1.2.1")
		return nil, nil
	}
	if !cs.ok(vals.Get("state") == a.State, "state matches the request", "", "RFC 6749 §10.12") {
		return nil, nil
	}
	if is := vals.Get("iss"); is != "" {
		cs.ok(is == str(am["issuer"]), "iss response parameter matches the authorization server", "iss="+is, "RFC 9207 §2.4")
	} else if am["authorization_response_iss_parameter_supported"] == true {
		cs.add("iss response parameter present", "fail", "the metadata promises an iss parameter but the response has none", "RFC 9207 §2.4")
	}
	code := vals.Get("code")
	if !cs.ok(code != "", "authorization code returned", "", "RFC 6749 §4.1.2") {
		return nil, nil
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {a.Verifier}}
	res, err := tokenCall(sub, am, form, cs, "")
	if err != nil {
		return nil, err
	}
	tok, _ := res["response"].(map[string]any)
	if res["status"] != 200 || str(tok["access_token"]) == "" {
		out["token_response"] = res["response"]
		if how == "authorization_details" && str(conf["scope"]) != "" {
			cs.add("credential scope alongside authorization_details", "info", "some authorization servers (Keycloak) also need the configuration's scope, although OID4VCI does not require it: try request_by both", vciRef+" §5.1")
		}
		return nil, nil
	}
	if how != "scope" {
		ad, _ := tok["authorization_details"].([]any)
		var ids []any
		for _, x := range ad {
			if m, _ := x.(map[string]any); m != nil && str(m["credential_configuration_id"]) == confID {
				ids, _ = m["credential_identifiers"].([]any)
			}
		}
		cs.ok(len(ids) > 0, "token response names the credential (authorization_details with credential_identifiers)",
			fmt.Sprintf("%d credential identifier(s)", len(ids)), vciRef+" §6.2")
	} else {
		cs.ok(hasScope(str(tok["scope"]), str(conf["scope"])) || str(tok["scope"]) == "", "credential scope granted", "scope="+str(tok["scope"]), vciRef+" §5.1.2")
	}
	return tok, nil
}

// ---- presentation ----

type vpRequest struct {
	Claims   M
	ClientID string
	Prefix   string
	Raw      string
}

func runVPRequestCore(c *Ctx, cs *Checks) (*vpRequest, error) {
	in := strings.TrimSpace(c.Str("request"))
	r := &vpRequest{}
	queryClientID := ""
	var jwtStr string
	if looksLikeJWT(in) {
		jwtStr = in
	} else {
		u, err := url.Parse(in)
		if err != nil {
			return nil, fmt.Errorf("request: %w", err)
		}
		q := u.Query()
		queryClientID = q.Get("client_id")
		if ru := q.Get("request_uri"); ru != "" {
			method := "GET"
			var body []byte
			hdr := map[string]string{"Accept": "application/oauth-authz-req+jwt"}
			if q.Get("request_uri_method") == "post" {
				method, body = "POST", []byte("wallet_metadata="+url.QueryEscape(`{"vp_formats_supported":{"dc+sd-jwt":{}}}`))
				hdr["Content-Type"] = "application/x-www-form-urlencoded"
			}
			res, err := c.do(method, ru, hdr, body)
			if err != nil {
				return nil, err
			}
			if !cs.ok(res.Status == 200, "request object fetched", fmt.Sprintf("HTTP %d from %s", res.Status, ru), "RFC 9101 §5.2") {
				return nil, errors.New("could not fetch the request object")
			}
			cs.warn(strings.HasPrefix(res.Header.Get("Content-Type"), "application/oauth-authz-req+jwt"), "request object media type", res.Header.Get("Content-Type"), "RFC 9101 §5.2")
			jwtStr = strings.TrimSpace(string(res.Body))
		} else if q.Get("request") != "" {
			jwtStr = q.Get("request")
		} else {
			r.Claims = M{}
			for k := range q {
				var v any = q.Get(k)
				if k == "dcql_query" || k == "client_metadata" {
					var js any
					if json.Unmarshal([]byte(q.Get(k)), &js) == nil {
						v = js
					}
				}
				r.Claims[k] = v
			}
		}
	}
	if jwtStr != "" {
		p, err := parseJWT(jwtStr)
		if err != nil {
			return nil, fmt.Errorf("request object: %w", err)
		}
		r.Claims, r.Raw = p.Claims, jwtStr
		cs.warn(str(p.Header["typ"]) == "oauth-authz-req+jwt", "request object typ", "typ="+str(p.Header["typ"]), "RFC 9101 §10.8")
		r.ClientID = str(p.Claims["client_id"])
		if queryClientID != "" {
			cs.ok(queryClientID == r.ClientID, "client_id in the URL equals the request object's", queryClientID+" vs "+r.ClientID, vpRef+" §5.10")
		}
		verifyVPRequestSignature(c, cs, p, r)
	} else {
		r.ClientID = str(r.Claims["client_id"])
		prefix, rest, _ := strings.Cut(r.ClientID, ":")
		r.Prefix = prefix
		if prefix != "redirect_uri" {
			cs.add("request is signed", "fail", "an unsigned request may only use the redirect_uri client identifier prefix", vpRef+" §5.9.3")
		} else {
			target := str(r.Claims["response_uri"])
			if target == "" {
				target = str(r.Claims["redirect_uri"])
			}
			cs.ok(target == rest, "response or redirect URI is the client_id", target, vpRef+" §5.9.3")
		}
	}
	cl := r.Claims
	cs.ok(str(cl["response_type"]) == "vp_token", "response_type is vp_token", str(cl["response_type"]), vpRef+" §5.1")
	cs.ok(str(cl["nonce"]) != "", "nonce present", "", vpRef+" §5.2")
	mode := str(cl["response_mode"])
	if mode == "direct_post" || mode == "direct_post.jwt" {
		cs.ok(str(cl["response_uri"]) != "", "response_uri present for "+mode, str(cl["response_uri"]), vpRef+" §8.2")
		cs.ok(cl["redirect_uri"] == nil, "no redirect_uri with "+mode, "", vpRef+" §8.2")
	}
	if cl["presentation_definition"] != nil {
		cs.add("query language", "warn", "presentation_definition is from drafts; OID4VP 1.0 uses dcql_query", vpRef+" §6")
	}
	cs.ok(cl["dcql_query"] != nil || cl["scope"] != nil, "dcql_query (or scope) present", "", vpRef+" §5.1")
	return r, nil
}

func verifyVPRequestSignature(c *Ctx, cs *Checks, p *jwtParts, r *vpRequest) {
	prefix, rest, ok := strings.Cut(r.ClientID, ":")
	if !ok || strings.Contains(prefix, ".") || strings.Contains(prefix, "/") {
		prefix, rest = "", r.ClientID // pre-registered client
	}
	r.Prefix = prefix
	alg := str(p.Header["alg"])
	switch prefix {
	case "x509_san_dns", "x509_hash":
		x5c, _ := p.Header["x5c"].([]any)
		if !cs.ok(len(x5c) > 0, "request object carries x5c", "", vpRef+" §5.9.3") {
			return
		}
		var chain []*x509.Certificate
		for _, raw := range x5c {
			der, _ := base64.StdEncoding.DecodeString(str(raw))
			if ce, err := x509.ParseCertificate(der); err == nil {
				chain = append(chain, ce)
			}
		}
		if len(chain) == 0 {
			cs.add("x5c certificate parses", "fail", "", vpRef+" §5.9.3")
			return
		}
		leaf := chain[0]
		verr := verifySig(alg, leaf.PublicKey, p.SigningInput, p.Sig)
		cs.ok(verr == nil, "request object signature (x5c leaf)", detailOr(verr, leaf.Subject.String()), vpRef+" §5.9.3")
		if prefix == "x509_san_dns" {
			cs.ok(contains(leaf.DNSNames, rest), "certificate dNSName matches the client_id", "SANs: "+strings.Join(leaf.DNSNames, ", "), vpRef+" §5.9.3")
			if ru := str(r.Claims["response_uri"]); ru != "" {
				u, _ := url.Parse(ru)
				cs.ok(u != nil && u.Hostname() == rest, "response_uri host is the client_id DNS name", ru, vpRef+" §5.9.3")
			}
		} else {
			h := sha256.Sum256(leaf.Raw)
			cs.ok(b64url(h[:]) == rest, "certificate hash matches the client_id", "", vpRef+" §5.9.3")
		}
		if roots := c.Str("trust_anchors"); roots != "" {
			o, err := parsePKI(roots)
			if err == nil {
				pool, inter := x509.NewCertPool(), x509.NewCertPool()
				for _, rc := range o.Certs {
					pool.AddCert(rc)
				}
				for _, ic := range chain[1:] {
					inter.AddCert(ic)
				}
				_, verr := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
				cs.ok(verr == nil, "verifier certificate chains to a trust anchor", detailOr(verr, ""), vpRef+" §5.9.3")
			}
		} else {
			cs.add("verifier certificate trusted", "fail", "no trust_anchors given: anyone can self-sign a certificate for this name, so who the verifier is has not been established", vpRef+" §5.9.3")
		}
	case "redirect_uri":
		cs.ok(alg == "none" || alg == "", "redirect_uri requests are not signed", "alg="+alg, vpRef+" §5.9.3")
		target := str(r.Claims["response_uri"])
		if target == "" {
			target = str(r.Claims["redirect_uri"])
		}
		cs.ok(target == rest, "response or redirect URI is the client_id", target, vpRef+" §5.9.3")
	case "":
		cs.add("verifier identity established", "fail", "no client identifier prefix: trust rests on pre-registration, which idpdbg cannot check (vp present needs force)", vpRef+" §5.9.2")
	default:
		cs.add("verifier identity established", "fail", "client identifier prefix "+prefix+" is not evaluated by idpdbg (vp present needs force)", vpRef+" §5.9.3")
	}
}

func dcqlSummary(q any) []M {
	m, _ := q.(map[string]any)
	creds, _ := m["credentials"].([]any)
	var out []M
	for _, c := range creds {
		cq, _ := c.(map[string]any)
		meta, _ := cq["meta"].(map[string]any)
		var paths []string
		cl, _ := cq["claims"].([]any)
		for _, x := range cl {
			if xm, _ := x.(map[string]any); xm != nil {
				paths = append(paths, pathString(xm["path"]))
			}
		}
		out = append(out, M{"id": cq["id"], "format": cq["format"], "vct_values": meta["vct_values"], "claims": paths})
	}
	return out
}

// pathString renders a DCQL claims path the way disclosure paths are written.
func pathString(p any) string {
	arr, _ := p.([]any)
	s := ""
	for _, e := range arr {
		switch v := e.(type) {
		case string:
			if s != "" {
				s += "."
			}
			s += v
		case float64:
			s += fmt.Sprintf("[%d]", int(v))
		case nil:
			s += "[*]"
		}
	}
	return s
}

func runVPRequest(c *Ctx) (M, error) {
	var cs Checks
	r, err := runVPRequestCore(c, &cs)
	out := M{"checks": cs}
	if err != nil {
		return out, err
	}
	out["client_id"], out["client_id_prefix"], out["request"] = r.ClientID, r.Prefix, r.Claims
	out["dcql"] = dcqlSummary(r.Claims["dcql_query"])
	out["checks"] = cs
	return out, nil
}

// selectDisclosures picks the disclosures a DCQL credential query needs.
func selectDisclosures(ds []*disclosure, paths []string) (keep []*disclosure, missing []string) {
	hit := map[*disclosure]bool{}
	for _, p := range paths {
		wild := strings.HasSuffix(p, "[*]")
		base := strings.TrimSuffix(p, "[*]")
		found := false
		for _, d := range ds {
			dp := d.Path
			match := dp == p || strings.HasPrefix(dp, p+".") || strings.HasPrefix(dp, p+"[") || // the claim and what it contains
				strings.HasPrefix(p, dp+".") || strings.HasPrefix(p, dp+"[") || // what contains it
				(wild && (strings.HasPrefix(dp, base+"[") || dp == base))
			if match {
				hit[d], found = true, true
			}
		}
		if !found {
			missing = append(missing, p)
		}
	}
	for _, d := range ds {
		if hit[d] {
			keep = append(keep, d)
		}
	}
	return keep, missing
}

func runVPPresent(c *Ctx) (M, error) {
	var cs Checks
	out := M{}
	defer func() { out["checks"] = cs }()
	r, err := runVPRequestCore(c, &cs)
	if err != nil {
		return out, err
	}
	if hasFailure(M{"checks": cs}) && !c.Bool("force") {
		cs.add("presentation sent", "info", "not sent: the request failed checks (pass force to send anyway)", vpRef)
		return out, nil
	}
	cred := strings.TrimSpace(c.Str("credential"))
	if !strings.HasSuffix(cred, "~") {
		cred = cred[:strings.LastIndex(cred, "~")+1] // drop any old KB-JWT
	}
	parts := strings.Split(cred, "~")
	ip, err := parseJWT(parts[0])
	if err != nil || ip.Claims == nil {
		return out, errors.New("credential must be an issuer-signed SD-JWT VC (jwt~disclosure~...~)")
	}
	alg := "sha-256"
	if a := str(ip.Claims["_sd_alg"]); a != "" {
		alg = a
	}
	var ds []*disclosure
	sp := &sdProcessor{byDigest: map[string]*disclosure{}, seen: map[string]bool{}, cs: &Checks{}}
	for _, raw := range parts[1 : len(parts)-1] {
		if d, err := parseDisclosure(alg, raw); err == nil {
			sp.byDigest[d.Digest] = d
			ds = append(ds, d)
		}
	}
	full := sp.process(map[string]any(ip.Claims), "").(M)

	// Which credential query this credential answers.
	dq, _ := r.Claims["dcql_query"].(map[string]any)
	qs, _ := dq["credentials"].([]any)
	var query map[string]any
	for _, x := range qs {
		q, _ := x.(map[string]any)
		f := str(q["format"])
		if f != "dc+sd-jwt" && f != "vc+sd-jwt" {
			continue
		}
		meta, _ := q["meta"].(map[string]any)
		vcts, _ := coerce(Param{Name: "v", Type: "list"}, meta["vct_values"], false)
		vl, _ := vcts.([]string)
		if len(vl) == 0 || contains(vl, str(ip.Claims["vct"])) {
			query = q
			break
		}
	}
	if !cs.ok(query != nil, "a DCQL credential query matches this credential", "vct="+str(ip.Claims["vct"]), vpRef+" §6") {
		return out, nil
	}
	var paths []string
	if cl, ok := query["claims"].([]any); ok {
		for _, x := range cl {
			if xm, _ := x.(map[string]any); xm != nil {
				paths = append(paths, pathString(xm["path"]))
			}
		}
	}
	var keep []*disclosure
	var missing []string
	if len(paths) == 0 {
		keep = ds
		cs.add("data minimisation", "info", "the query names no claims, so every disclosure is sent", vpRef+" §6.1")
	} else {
		keep, missing = selectDisclosures(ds, paths)
		// A requested claim the issuer made always-visible needs no disclosure.
		var still []string
		for _, m := range missing {
			if _, ok := full[strings.Split(m, ".")[0]]; !ok || strings.Contains(m, "[") {
				still = append(still, m)
			}
		}
		missing = still
	}
	if !cs.ok(len(missing) == 0, "every requested claim is available", strings.Join(missing, ", "), vpRef+" §6.4") {
		return out, nil
	}
	var sent, withheld []string
	presentation := parts[0] + "~"
	for _, d := range keep {
		presentation += d.Raw + "~"
		sent = append(sent, d.Path)
	}
	for _, d := range ds {
		if !contains(sent, d.Path) {
			withheld = append(withheld, d.Path)
		}
	}
	sort.Strings(sent)
	sort.Strings(withheld)
	out["disclosed"], out["withheld"] = sent, withheld

	// Key binding.
	hk, _, err := holderKey(c)
	if err != nil {
		return out, err
	}
	if c.Str("holder_key") == "" {
		return out, errors.New("holder_key is required: the key the credential is bound to")
	}
	hj, _ := publicJWK(hk.Public())
	cnf, _ := ip.Claims["cnf"].(map[string]any)
	cj, _ := cnf["jwk"].(map[string]any)
	if !cs.ok(cj != nil && jwkThumbprint(cj) == jwkThumbprint(hj), "holder_key is the credential's cnf key", "", "RFC 9901 §4.3") {
		return out, nil
	}
	salg, _ := signerAlg(hk, "")
	kb, err := signJWS(hk, salg, M{"typ": "kb+jwt"}, M{"iat": time.Now().Unix(), "aud": r.ClientID, "nonce": str(r.Claims["nonce"]), "sd_hash": sdDigest(alg, presentation)})
	if err != nil {
		return out, err
	}
	presentation += kb
	qid := str(query["id"])
	vpToken, _ := json.Marshal(M{qid: []string{presentation}})
	out["vp_token"] = json.RawMessage(vpToken)

	// Response.
	mode, ru := str(r.Claims["response_mode"]), str(r.Claims["response_uri"])
	form := url.Values{}
	switch mode {
	case "direct_post":
		form.Set("vp_token", string(vpToken))
		if s := str(r.Claims["state"]); s != "" {
			form.Set("state", s)
		}
	case "direct_post.jwt":
		cm, _ := r.Claims["client_metadata"].(map[string]any)
		keys := jwksKeys(cm["jwks"])
		if !cs.ok(len(keys) > 0, "verifier encryption key in client_metadata.jwks", "", vpRef+" §8.3") {
			return out, nil
		}
		ek := keys[0]
		for _, k := range keys {
			if str(k["use"]) == "enc" {
				ek = k
			}
		}
		enc := "A128GCM"
		if l, ok := cm["encrypted_response_enc_values_supported"].([]any); ok && len(l) > 0 {
			enc = str(l[0])
		}
		kj, _ := json.Marshal(ek)
		payload, _ := json.Marshal(M{"vp_token": json.RawMessage(vpToken), "state": r.Claims["state"]})
		jw, err := runJWEEncrypt(c.sub(M{"alg": "ECDH-ES", "enc": enc, "key": string(kj), "payload": string(payload), "kid": str(ek["kid"]), "iat_now": false}))
		if err != nil {
			return out, fmt.Errorf("encrypting the response: %w", err)
		}
		form.Set("response", str(jw["token"]))
		cs.add("response encrypted", "pass", "ECDH-ES/"+enc+" to verifier key "+str(ek["kid"]), vpRef+" §8.3")
	default:
		cs.add("response delivery", "info", "response_mode "+mode+" returns through the browser; the vp_token is in this result for you to deliver", vpRef+" §8")
		return out, nil
	}
	if err := c.allowDestination("the presentation", ru); err != nil {
		return out, err
	}
	res, err := c.postForm(ru, form, nil)
	if err != nil {
		return out, err
	}
	out["verifier_status"], out["verifier_response"] = res.Status, res.payload()
	cs.ok(res.Status == 200, "verifier accepted the presentation", fmt.Sprintf("HTTP %d %s", res.Status, strings.TrimSpace(string(res.Body))), vpRef+" §8.2")
	if rb := res.obj(); rb != nil && str(rb["redirect_uri"]) != "" {
		out["redirect_uri"] = rb["redirect_uri"]
	}
	return out, nil
}

func init() {
	register(
		&Op{
			Name:    "vci.metadata",
			Summary: "Read a credential issuer's OID4VCI metadata and its authorization server's, list the credential configurations (format, vct, holder binding, proof types), and optionally check a credential offer against them.",
			Params: []Param{
				{Name: "issuer", Type: "string", Required: true, Desc: "Credential issuer URL"},
				{Name: "offer", Type: "string", Desc: "Credential offer: openid-credential-offer:// URL, JSON, or a credential_offer_uri"}},
			Run: runVCIMetadata,
		},
		&Op{
			Name:     "vci.issue",
			Mutating: true,
			Browser:  true,
			Summary: "Obtain a credential with OID4VCI, as a wallet. With a pre-authorized code: redeem the offer (with its transaction code). Otherwise the authorization code flow: ask the issuer's authorization server for the credential (authorization_details of type openid_credential, or the configuration's scope), with the offer's issuer_state, PKCE and PAR when wanted, sign in through the browser and redeem the code. " +
				"Then get a nonce, prove possession of a holder key, request the credential, and check the SD-JWT VC returned (issuer signature, disclosures, holder binding, vct). Generates a holder key if none is given and returns it for presenting later. The authorization code flow blocks until the person signs in.",
			Params: joinParams([]Param{
				{Name: "offer", Type: "string", Desc: "Credential offer: openid-credential-offer:// URL, JSON, or a credential_offer_uri"},
				{Name: "issuer", Type: "string", Desc: "Credential issuer, if not from the offer"},
				{Name: "pre_authorized_code", Type: "string", Desc: "Pre-authorized code, if not from the offer"},
				{Name: "configuration_id", Type: "string", Desc: "Credential configuration to request; default the offer's first"},
				{Name: "tx_code", Type: "string", Secret: true, Desc: "Transaction code the issuer sent out of band"},
				{Name: "holder_key", Type: "string", Path: true, Explicit: true, Desc: "Holder private key (PEM or JWK); default a new P-256 key"},
				{Name: "client_id", Type: "string", Desc: "The wallet's client_id at the authorization server: needed for the authorization code flow, and the proof's iss (omit for anonymous pre-authorized access)"},
				{Name: "request_by", Type: "string", Enum: []string{"auto", "authorization_details", "scope", "both"}, Default: "auto", Desc: "Authorization code flow: ask for the credential with authorization_details (RFC 9396), the configuration's scope, or both (some servers, such as Keycloak, need the scope too); auto uses authorization_details when the server lists openid_credential"},
				{Name: "par", Type: "bool", Desc: "Authorization code flow: push the authorization request first (RFC 9126); always done when the server requires it"}},
				redirectParams, browserParams),
			Run: runVCIIssue,
		},
		&Op{
			Name:    "vp.request",
			Summary: "Check an OID4VP authorization request as a wallet would: fetch the request object, verify its signature for the client identifier prefix (x509_san_dns, x509_hash, redirect_uri, pre-registered), and check response type, nonce, response mode and URI, and the DCQL query, which is summarised.",
			Params: []Param{
				{Name: "request", Type: "string", Required: true, File: true, Desc: "openid4vp:// (or https) request URL, or a request object JWT"},
				{Name: "trust_anchors", Type: "string", Path: true, Desc: "PEM roots for verifier certificates"}},
			Run: runVPRequest,
		},
		&Op{
			Name:     "vp.present",
			Mutating: true,
			Summary:  "Answer an OID4VP request with an SD-JWT VC, as a wallet: check the request, pick the credential query it matches, disclose only the requested claims, bind with a KB-JWT (aud = client_id, the request's nonce) and send the vp_token by direct_post, or encrypted with direct_post.jwt. Sends personal data to the verifier.",
			Params: []Param{
				{Name: "request", Type: "string", Required: true, File: true, Desc: "openid4vp:// (or https) request URL, or a request object JWT"},
				{Name: "credential", Type: "string", Required: true, File: true, Desc: "The issued SD-JWT VC (issuer-jwt~disclosures~), e.g. from vci issue"},
				{Name: "holder_key", Type: "string", Path: true, Explicit: true, Desc: "The holder private key the credential is bound to (PEM or JWK)"},
				{Name: "trust_anchors", Type: "string", Path: true, Desc: "PEM roots for verifier certificates"},
				{Name: "force", Type: "bool", Desc: "Send even if the request failed checks"}},
			Run: runVPPresent,
		},
	)
}
