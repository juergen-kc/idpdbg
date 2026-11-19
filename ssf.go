package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// OpenID Shared Signals Framework 1.0 with CAEP and RISC: transmitter
// discovery, stream management, push (RFC 8935) and poll (RFC 8936)
// delivery, and Security Event Token checks (RFC 8417, RFC 9493).

const (
	ssfPush   = "urn:ietf:rfc:8935"
	ssfPoll   = "urn:ietf:rfc:8936"
	ssfRef    = "OpenID SSF 1.0"
	caepBase  = "https://schemas.openid.net/secevent/caep/event-type/"
	riscBase  = "https://schemas.openid.net/secevent/risc/event-type/"
	ssfEvBase = "https://schemas.openid.net/secevent/ssf/event-type/"
)

// knownEvents maps event types to the members they require.
var knownEvents = map[string][]string{
	caepBase + "session-revoked": nil, caepBase + "token-claims-change": {"claims"}, caepBase + "credential-change": {"credential_type", "change_type"},
	caepBase + "assurance-level-change": {"namespace", "current_level"}, caepBase + "device-compliance-change": {"previous_status", "current_status"},
	caepBase + "session-established": nil, caepBase + "session-presented": nil, caepBase + "risk-level-change": {"current_level"},
	riscBase + "account-credential-change-required": nil, riscBase + "account-purged": nil, riscBase + "account-disabled": nil, riscBase + "account-enabled": nil,
	riscBase + "identifier-changed": nil, riscBase + "identifier-recycled": nil, riscBase + "credential-compromise": {"credential_type"},
	riscBase + "opt-in": nil, riscBase + "opt-out-initiated": nil, riscBase + "opt-out-cancelled": nil, riscBase + "opt-out-effective": nil,
	riscBase + "recovery-activated": nil, riscBase + "recovery-information-changed": nil, riscBase + "sessions-revoked": nil,
	ssfEvBase + "verification": nil, ssfEvBase + "stream-updated": {"status"},
}

// subjectFormats are the RFC 9493 formats and the members each requires.
var subjectFormats = map[string][]string{
	"account": {"uri"}, "email": {"email"}, "iss_sub": {"iss", "sub"}, "opaque": {"id"}, "phone_number": {"phone_number"},
	"did": {"url"}, "uri": {"uri"}, "aliases": {"identifiers"},
}

func checkSubject(cs *Checks, label string, sub any) {
	m, ok := sub.(map[string]any)
	if !ok {
		cs.add(label+": is an object", "fail", "", "RFC 9493 §3")
		return
	}
	format := str(m["format"])
	if format == "" {
		// SSF complex subjects: user, device, session, tenant, ... each a subject.
		if len(m) == 0 {
			cs.add(label+": format", "fail", "no format and no members", "RFC 9493 §3")
		}
		for k, v := range m {
			checkSubject(cs, label+"."+k, v)
		}
		return
	}
	req, known := subjectFormats[format]
	if !known {
		cs.add(label+": format", "info", "format "+format+" is not one of RFC 9493's", "RFC 9493 §3")
		return
	}
	var missing []string
	for _, r := range req {
		if _, ok := m[r]; !ok {
			missing = append(missing, r)
		}
	}
	cs.ok(len(missing) == 0, label+": "+format+" has its required members", strings.Join(missing, ", "), "RFC 9493 §3.2")
	if format == "email" && !strings.Contains(str(m["email"]), "@") {
		cs.add(label+": email value is an address", "fail", str(m["email"]), "RFC 9493 §3.2.2")
	}
}

// ssfKeys finds the transmitter's signing keys.
func ssfKeys(c *Ctx, iss string) ([]M, any, string, error) {
	if s := c.Str("pem"); s != "" {
		k, err := loadPublicKeyPEM(s)
		return nil, k, "PEM key", err
	}
	if s := c.Str("jwks"); s != "" {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return nil, nil, "", fmt.Errorf("jwks: %w", err)
		}
		return jwksKeys(v), nil, "supplied JWKS", nil
	}
	if iss == "" {
		return nil, nil, "", nil
	}
	cfg, _, err := ssfConfig(c, iss)
	if err != nil {
		return nil, nil, "", err
	}
	k, err := fetchJWKS(c, str(cfg["jwks_uri"]))
	return k, nil, str(cfg["jwks_uri"]), err
}

func ssfConfig(c *Ctx, issuer string) (M, string, error) {
	u, err := url.Parse(strings.TrimSuffix(issuer, "/"))
	if err != nil || u.Host == "" {
		return nil, "", errors.New("issuer must be an absolute URL")
	}
	mu := u.Scheme + "://" + u.Host + "/.well-known/ssf-configuration" + u.Path
	res, err := c.do("GET", mu, map[string]string{"Accept": "application/json"}, nil)
	if err != nil {
		return nil, mu, err
	}
	if res.Status != 200 || res.obj() == nil {
		return nil, mu, fmt.Errorf("%s returned HTTP %d", mu, res.Status)
	}
	return res.obj(), mu, nil
}

// checkSET verifies one Security Event Token.
func checkSET(cs *Checks, token string, keys []M, direct any, issuer, aud string) M {
	p, err := parseJWT(token)
	if err != nil {
		cs.add("SET is a JWS", "fail", err.Error(), "RFC 8417 §2")
		return nil
	}
	out := describeJWT(p)
	cs.ok(str(p.Header["typ"]) == "secevent+jwt", "typ is secevent+jwt", "typ="+str(p.Header["typ"]), ssfRef+" §6 / RFC 8417 §2.3")
	alg := str(p.Header["alg"])
	switch {
	case alg == "none" || alg == "":
		cs.add("SET is signed", "fail", "alg="+alg, "RFC 8417 §5")
	case direct != nil:
		verr := verifySig(alg, direct, p.SigningInput, p.Sig)
		cs.ok(verr == nil, "SET signature", detailOr(verr, ""), "RFC 8417 §5")
	case len(keys) > 0:
		used, verr := verifyWithJWKS(p, keys)
		cs.ok(verr == nil, "SET signature", detailOr(verr, "verified with key "+used), "RFC 8417 §5")
	default:
		cs.add("SET signature", "warn", "not verified: no transmitter keys (pass issuer, jwks or pem)", "RFC 8417 §5")
	}
	cl := p.Claims
	if cl == nil {
		cs.add("SET claims", "fail", "payload is not a JSON object", "RFC 8417 §2.2")
		return out
	}
	if issuer != "" {
		cs.ok(str(cl["iss"]) == issuer, "iss is the transmitter", "iss="+str(cl["iss"]), "RFC 8417 §2.2")
	}
	if aud != "" {
		cs.ok(contains(audList(cl), aud), "aud includes this receiver", "aud="+strings.Join(audList(cl), " "), "RFC 8417 §2.2")
	}
	_, hasIat := cl["iat"].(float64)
	cs.ok(hasIat, "iat present", "", "RFC 8417 §2.2")
	cs.ok(str(cl["jti"]) != "", "jti present", "", "RFC 8417 §2.2")
	if _, ok := cl["sub"]; ok {
		cs.add("subject in sub_id", "info", "the SET uses sub; SSF identifies subjects with sub_id", ssfRef+" §4.1")
	}
	if sid, ok := cl["sub_id"]; ok {
		checkSubject(cs, "sub_id", sid)
	}
	events, _ := cl["events"].(map[string]any)
	if !cs.ok(len(events) > 0, "events present", fmt.Sprintf("%d event(s)", len(events)), "RFC 8417 §2.2") {
		return out
	}
	var types []string
	for typ, body := range events {
		types = append(types, typ)
		short := typ[strings.LastIndex(typ, "/")+1:]
		req, known := knownEvents[typ]
		if !known {
			cs.add("event "+short+": known type", "info", typ+" is not a CAEP, RISC or SSF event type", ssfRef)
			continue
		}
		bm, _ := body.(map[string]any)
		var missing []string
		for _, r := range req {
			if _, ok := bm[r]; !ok {
				missing = append(missing, r)
			}
		}
		cs.ok(len(missing) == 0, "event "+short+": required members", strings.Join(missing, ", "), "CAEP 1.0 / RISC 1.0")
		if ts, ok := bm["event_timestamp"]; ok {
			_, isNum := ts.(float64)
			cs.ok(isNum, "event "+short+": event_timestamp is a NumericDate", fmt.Sprint(ts), "CAEP 1.0 §2")
		}
		if s, ok := bm["subject"]; ok {
			checkSubject(cs, "event "+short+": subject", s)
		}
		if _, hasTop := cl["sub_id"]; !hasTop && bm["subject"] == nil && !strings.HasPrefix(typ, ssfEvBase) {
			cs.add("event "+short+": subject", "fail", "neither sub_id nor a subject member identifies whom the event is about", ssfRef+" §4.1")
		}
	}
	sort.Strings(types)
	out["event_types"] = types
	return out
}

// ---- operations ----

func ssfAuth(c *Ctx) map[string]string {
	h := map[string]string{"Accept": "application/json"}
	if t := c.Str("ssf_token"); t != "" {
		h["Authorization"] = "Bearer " + t
	}
	return h
}

func ssfCall(c *Ctx, method, u string, body any) (*httpResult, error) {
	if u == "" {
		return nil, errors.New("the transmitter advertises no endpoint for this")
	}
	// Endpoints come from the transmitter's metadata or stream config: the
	// token only goes where a stored credential is allowed to go.
	if c.Str("ssf_token") != "" {
		if err := c.allowDestination("the SSF management token", u); err != nil {
			return nil, err
		}
	}
	h := ssfAuth(c)
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
		h["Content-Type"] = "application/json"
	}
	return c.do(method, u, h, b)
}

func runSSFDiscover(c *Ctx) (M, error) {
	cfg, mu, err := ssfConfig(c, c.Str("issuer"))
	if err != nil {
		return nil, err
	}
	var cs Checks
	cs.ok(str(cfg["issuer"]) == strings.TrimSuffix(c.Str("issuer"), "/") || str(cfg["issuer"]) == c.Str("issuer"), "issuer matches", "issuer="+str(cfg["issuer"]), ssfRef+" §7.1")
	for _, k := range []string{"jwks_uri", "delivery_methods_supported", "configuration_endpoint"} {
		_, ok := cfg[k]
		cs.ok(ok, "metadata: "+k, "", ssfRef+" §7.1")
	}
	dm, _ := coerce(Param{Name: "d", Type: "list"}, cfg["delivery_methods_supported"], false)
	methods, _ := dm.([]string)
	for _, m := range methods {
		if m != ssfPush && m != ssfPoll {
			cs.add("delivery method "+m, "info", "not RFC 8935 push or RFC 8936 poll", ssfRef+" §7.1")
		}
	}
	for _, k := range []string{"status_endpoint", "add_subject_endpoint", "remove_subject_endpoint", "verification_endpoint"} {
		if u := str(cfg[k]); u != "" && !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://localhost") && !strings.HasPrefix(u, "http://127.0.0.1") {
			cs.add("https: "+k, "fail", u, ssfRef+" §7.1")
		}
	}
	out := M{"metadata_url": mu, "metadata": cfg}
	if ju := str(cfg["jwks_uri"]); ju != "" {
		keys, err := fetchJWKS(c, ju)
		if cs.ok(err == nil, "jwks_uri is reachable", detailOr(err, fmt.Sprintf("%d key(s)", len(keys))), ssfRef+" §7.1") {
			var ds []M
			for _, k := range keys {
				ds = append(ds, describeJWK(k))
			}
			out["jwks"] = ds
		}
	}
	out["checks"] = cs
	return out, nil
}

func runSSFStream(c *Ctx) (M, error) {
	cfg, _, err := ssfConfig(c, c.Str("issuer"))
	if err != nil {
		return nil, err
	}
	ep := func(k string) (string, error) {
		if v := str(cfg[k]); v != "" {
			return v, nil
		}
		return "", fmt.Errorf("the transmitter advertises no %s", k)
	}
	sid := c.Str("stream_id")
	withID := func(u string) string {
		if sid == "" {
			return u
		}
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		return u + sep + "stream_id=" + url.QueryEscape(sid)
	}
	var cs Checks
	out := M{"action": c.Str("action")}
	defer func() { out["checks"] = cs }()
	var res *httpResult
	want := 200
	switch c.Str("action") {
	case "create", "update", "replace":
		u, err := ep("configuration_endpoint")
		if err != nil {
			return out, err
		}
		body := M{}
		if c.Has("events") {
			body["events_requested"] = c.List("events")
		}
		if d := c.Str("description"); d != "" {
			body["description"] = d
		}
		switch c.Str("delivery") {
		case "push":
			if c.Str("endpoint_url") == "" {
				return out, errors.New("push delivery needs endpoint_url (where the transmitter should POST events)")
			}
			d := M{"method": ssfPush, "endpoint_url": c.Str("endpoint_url")}
			if a := c.Str("push_authorization"); a != "" {
				d["authorization_header"] = a
			}
			body["delivery"] = d
		case "poll":
			body["delivery"] = M{"method": ssfPoll}
		}
		method := map[string]string{"create": "POST", "update": "PATCH", "replace": "PUT"}[c.Str("action")]
		if method != "POST" {
			if sid == "" {
				return out, errors.New("update and replace need stream_id")
			}
			body["stream_id"] = sid
		} else {
			want = 201
		}
		if res, err = ssfCall(c, method, u, body); err != nil {
			return out, err
		}
		if s := res.obj(); s != nil && res.Status < 300 {
			cs.ok(str(s["stream_id"]) != "", "stream_id returned", str(s["stream_id"]), ssfRef+" §8.1.1")
			cs.ok(str(s["iss"]) == str(cfg["issuer"]), "stream iss is the transmitter", "iss="+str(s["iss"]), ssfRef+" §8.1.1")
			cs.ok(s["aud"] != nil, "stream aud present", fmt.Sprint(s["aud"]), ssfRef+" §8.1.1")
			sup, _ := coerce(Param{Name: "x", Type: "list"}, s["events_supported"], false)
			del, _ := coerce(Param{Name: "x", Type: "list"}, s["events_delivered"], false)
			supL, _ := sup.([]string)
			delL, _ := del.([]string)
			for _, e := range delL {
				if len(supL) > 0 && !contains(supL, e) {
					cs.add("events_delivered within events_supported", "fail", e, ssfRef+" §8.1.1")
				}
			}
			for _, e := range c.List("events") {
				if !contains(delL, e) {
					cs.add("requested event delivered", "warn", e+" was requested but will not be delivered", ssfRef+" §8.1.1")
				}
			}
			if d, _ := s["delivery"].(map[string]any); d != nil && str(d["method"]) == ssfPoll {
				cs.ok(str(d["endpoint_url"]) != "", "poll endpoint_url provided by the transmitter", str(d["endpoint_url"]), ssfRef+" §8.1.1")
			}
		}
	case "get":
		u, err := ep("configuration_endpoint")
		if err != nil {
			return out, err
		}
		if res, err = ssfCall(c, "GET", withID(u), nil); err != nil {
			return out, err
		}
	case "delete":
		u, err := ep("configuration_endpoint")
		if err != nil || sid == "" {
			return out, errors.New("delete needs stream_id and a configuration_endpoint")
		}
		want = 204
		if res, err = ssfCall(c, "DELETE", withID(u), nil); err != nil {
			return out, err
		}
	case "status":
		u, err := ep("status_endpoint")
		if err != nil {
			return out, err
		}
		if res, err = ssfCall(c, "GET", withID(u), nil); err != nil {
			return out, err
		}
		if s := res.obj(); s != nil {
			st := str(s["status"])
			cs.ok(st == "enabled" || st == "paused" || st == "disabled", "status value", st, ssfRef+" §8.1.2")
		}
	case "set_status":
		u, err := ep("status_endpoint")
		if err != nil || sid == "" {
			return out, errors.New("set_status needs stream_id and a status_endpoint")
		}
		body := M{"stream_id": sid, "status": c.Str("status")}
		if r := c.Str("reason"); r != "" {
			body["reason"] = r
		}
		if res, err = ssfCall(c, "POST", u, body); err != nil {
			return out, err
		}
	case "add_subject", "remove_subject":
		u, err := ep(c.Str("action") + "_endpoint")
		if err != nil || sid == "" || !c.Has("subject") {
			return out, errors.New(c.Str("action") + " needs stream_id, subject and the endpoint")
		}
		checkSubject(&cs, "subject", c.Args["subject"])
		body := M{"stream_id": sid, "subject": c.Args["subject"]}
		if c.Str("action") == "add_subject" {
			body["verified"] = true
		} else {
			want = 204
		}
		if res, err = ssfCall(c, "POST", u, body); err != nil {
			return out, err
		}
	case "verify":
		u, err := ep("verification_endpoint")
		if err != nil || sid == "" {
			return out, errors.New("verify needs stream_id and a verification_endpoint")
		}
		state := c.Str("state")
		if state == "" {
			state = randToken(12)
		}
		out["state"] = state
		want = 204
		if res, err = ssfCall(c, "POST", u, M{"stream_id": sid, "state": state}); err != nil {
			return out, err
		}
	default:
		return out, fmt.Errorf("unknown action %q", c.Str("action"))
	}
	out["status"], out["response"] = res.Status, res.payload()
	ok := res.Status == want || (want == 204 && res.Status == 200) || (want == 201 && res.Status == 200)
	detail := fmt.Sprintf("HTTP %d", res.Status)
	if res.Status >= 400 {
		detail += " " + strings.TrimSpace(string(res.Body))
	}
	cs.ok(ok, "transmitter accepted the request", detail, ssfRef+" §8")
	return out, nil
}

func runSSFPoll(c *Ctx) (M, error) {
	u := c.Str("endpoint")
	if u == "" {
		cfg, _, err := ssfConfig(c, c.Str("issuer"))
		if err != nil {
			return nil, err
		}
		if c.Str("stream_id") == "" {
			return nil, errors.New("pass endpoint, or issuer with stream_id")
		}
		res, err := ssfCall(c, "GET", str(cfg["configuration_endpoint"])+"?stream_id="+url.QueryEscape(c.Str("stream_id")), nil)
		if err != nil {
			return nil, err
		}
		d, _ := res.obj()["delivery"].(map[string]any)
		if u = str(d["endpoint_url"]); u == "" || str(d["method"]) != ssfPoll {
			return nil, errors.New("the stream is not a poll stream, or has no endpoint_url")
		}
	}
	keys, direct, _, err := ssfKeys(c, c.Str("issuer"))
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{"endpoint": u}
	defer func() { out["checks"] = cs }()
	req := M{"maxEvents": c.Int("max_events"), "returnImmediately": true}
	if a := c.List("ack"); len(a) > 0 {
		req["ack"] = a
	}
	res, err := ssfCall(c, "POST", u, req)
	if err != nil {
		return out, err
	}
	body := res.obj()
	if !cs.ok(res.Status == 200 && body != nil, "poll response", fmt.Sprintf("HTTP %d", res.Status), "RFC 8936 §2.4") {
		out["response"] = res.payload()
		return out, nil
	}
	sets, _ := body["sets"].(map[string]any)
	out["more_available"] = body["moreAvailable"]
	var got []M
	var jtis []string
	for jti, tok := range sets {
		var sc Checks
		d := checkSET(&sc, str(tok), keys, direct, c.Str("issuer"), c.Str("audience"))
		if d != nil {
			if cl, _ := d["claims"].(M); cl != nil {
				sc.ok(str(cl["jti"]) == jti, "jti matches its key in sets", "", "RFC 8936 §2.4")
			}
		}
		for _, ck := range sc {
			ck.Name = "SET " + jti + ": " + ck.Name
			cs = append(cs, ck)
		}
		got = append(got, M{"jti": jti, "set": d})
		jtis = append(jtis, jti)
	}
	sort.Strings(jtis)
	out["sets"], out["jtis"] = got, jtis
	cs.add("events received", "info", fmt.Sprintf("%d SET(s); acknowledge them with ack on the next poll", len(sets)), "RFC 8936 §2.4")
	return out, nil
}

func runSSFReceive(c *Ctx) (M, error) {
	keys, direct, _, err := ssfKeys(c, c.Str("issuer"))
	if err != nil {
		return nil, err
	}
	port, path := c.Int("port"), c.Str("path")
	type arrival struct {
		token, auth, ctype string
	}
	ch := make(chan arrival, 32)
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if want := c.Str("expected_authorization"); want != "" && r.Header.Get("Authorization") != want {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			fmt.Fprint(w, `{"err":"authentication_failed","description":"unexpected Authorization"}`)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		select {
		case ch <- arrival{strings.TrimSpace(string(b)), r.Header.Get("Authorization"), r.Header.Get("Content-Type")}:
		default:
		}
	})
	stop, err := serveLoopback(port, mux)
	if err != nil {
		return nil, err
	}
	defer stop()
	endpoint := fmt.Sprintf("http://localhost:%d%s", port, path)
	c.Log("Push receiver listening on %s (the transmitter must be able to reach it)", endpoint)
	var cs Checks
	out := M{"endpoint": endpoint}
	defer func() { out["checks"] = cs }()
	if c.Bool("trigger_verification") {
		cfg, _, err := ssfConfig(c, c.Str("issuer"))
		if err != nil {
			return out, err
		}
		state := randToken(12)
		res, err := ssfCall(c, "POST", str(cfg["verification_endpoint"]), M{"stream_id": c.Str("stream_id"), "state": state})
		if err != nil {
			return out, err
		}
		cs.ok(res.Status == 204 || res.Status == 200, "verification requested", fmt.Sprintf("HTTP %d", res.Status), ssfRef+" §8.1.4")
		out["verification_state"] = state
	}
	var got []M
	deadline := time.After(time.Duration(c.Int("wait")) * time.Second)
loop:
	for len(got) < c.Int("max_events") {
		select {
		case a := <-ch:
			var sc Checks
			sc.ok(strings.HasPrefix(a.ctype, "application/secevent+jwt"), "Content-Type is application/secevent+jwt", a.ctype, "RFC 8935 §2")
			d := checkSET(&sc, a.token, keys, direct, c.Str("issuer"), c.Str("audience"))
			if st := str(out["verification_state"]); st != "" && d != nil {
				if cl, _ := d["claims"].(M); cl != nil {
					if ev, _ := cl["events"].(map[string]any)[ssfEvBase+"verification"].(map[string]any); ev != nil {
						sc.ok(str(ev["state"]) == st, "verification event echoes our state", "", ssfRef+" §8.1.4.1")
					}
				}
			}
			n := len(got) + 1
			for _, ck := range sc {
				ck.Name = fmt.Sprintf("SET %d: %s", n, ck.Name)
				cs = append(cs, ck)
			}
			got = append(got, M{"set": d, "authorization_sent": a.auth != ""})
		case <-deadline:
			break loop
		case <-c.Done():
			break loop
		}
	}
	out["received"] = got
	cs.ok(len(got) > 0, "events received", fmt.Sprintf("%d SET(s) in %ds", len(got), c.Int("wait")), "RFC 8935 §2")
	return out, nil
}

func init() {
	auth := []Param{
		{Name: "issuer", Type: "string", Required: true, Desc: "Transmitter issuer URL"},
		{Name: "ssf_token", Type: "string", Secret: true, Desc: "Bearer token for the transmitter's management API (prefer env IDPDBG_SSF_TOKEN or a profile)"},
	}
	keys := []Param{
		{Name: "jwks", Type: "string", Path: true, Desc: "Transmitter JWKS instead of discovery"},
		{Name: "pem", Type: "string", Path: true, Desc: "Transmitter public key (PEM) instead of discovery"},
		{Name: "audience", Type: "string", Desc: "Audience the SETs must carry (this receiver)"},
	}
	join := joinParams
	register(
		&Op{
			Name:    "ssf.discover",
			Summary: "Read a Shared Signals transmitter's configuration (/.well-known/ssf-configuration) and JWKS, and check the required metadata, delivery methods and endpoints.",
			Params:  []Param{{Name: "issuer", Type: "string", Required: true, Desc: "Transmitter issuer URL"}},
			Run:     runSSFDiscover,
		},
		&Op{
			Name:     "ssf.stream",
			Mutating: true,
			Summary:  "Manage a Shared Signals stream at a transmitter: create, get, update, replace or delete its configuration (push or poll delivery, requested CAEP/RISC events), read or set its status, add or remove subjects, or request a verification event. Checks each response against SSF 1.0.",
			Params: join(auth, []Param{
				{Name: "action", Type: "string", Required: true, Enum: []string{"create", "get", "update", "replace", "delete", "status", "set_status", "add_subject", "remove_subject", "verify"}, Desc: "What to do"},
				{Name: "stream_id", Type: "string", Desc: "Stream to act on"},
				{Name: "delivery", Type: "string", Enum: []string{"push", "poll"}, Desc: "Delivery method for create/update"},
				{Name: "endpoint_url", Type: "string", Desc: "Push receiver URL the transmitter should POST to"},
				{Name: "push_authorization", Type: "string", Desc: "Authorization header value the transmitter should send to the push receiver"},
				{Name: "events", Type: "list", Desc: "Event type URIs to request, e.g. " + caepBase + "session-revoked"},
				{Name: "description", Type: "string", Desc: "Stream description"},
				{Name: "status", Type: "string", Enum: []string{"enabled", "paused", "disabled"}, Desc: "New status for set_status"},
				{Name: "reason", Type: "string", Desc: "Reason for set_status"},
				{Name: "subject", Type: "json", Desc: `Subject for add/remove_subject (RFC 9493), e.g. {"format":"email","email":"alice@example.com"}`},
				{Name: "state", Type: "string", Desc: "State for verify; default random"}}),
			Run: runSSFStream,
		},
		&Op{
			Name:     "ssf.poll",
			Mutating: true,
			Summary:  "Poll a Shared Signals stream for events (RFC 8936), acknowledging earlier ones, and check every SET received: signature, typ, iss, aud, jti, subject identifiers and CAEP/RISC event members.",
			Params: join(auth, keys, []Param{
				{Name: "stream_id", Type: "string", Desc: "Stream whose poll endpoint to use"},
				{Name: "endpoint", Type: "string", Desc: "Poll endpoint, instead of looking it up from the stream"},
				{Name: "max_events", Type: "int", Desc: "maxEvents", Default: 10},
				{Name: "ack", Type: "list", Desc: "jti values to acknowledge"}}),
			Run: runSSFPoll,
		},
		&Op{
			Name:     "ssf.receive",
			Mutating: true,
			Summary:  "Run a local push receiver (RFC 8935) for a while, optionally first asking the transmitter for a verification event, and check every SET that arrives. The transmitter must be able to reach this machine.",
			Params: join([]Param{
				{Name: "issuer", Type: "string", Desc: "Transmitter issuer URL (for keys and verification)"},
				{Name: "ssf_token", Type: "string", Secret: true, Desc: "Bearer token for the verification request"},
				{Name: "stream_id", Type: "string", Desc: "Stream to verify"},
				{Name: "trigger_verification", Type: "bool", Desc: "Ask the transmitter to send a verification event first"},
				{Name: "port", Type: "int", Desc: "Loopback port", Default: 8768},
				{Name: "path", Type: "string", Desc: "Path", Default: "/ssf/events"},
				{Name: "expected_authorization", Type: "string", Desc: "Authorization header value to require from the transmitter"},
				{Name: "max_events", Type: "int", Desc: "Stop after this many events", Default: 1},
				{Name: "wait", Type: "int", Desc: "Seconds to listen", Default: 60}}, keys),
			Run: runSSFReceive,
		},
		&Op{
			Name:    "ssf.set",
			Summary: "Check a Security Event Token offline (RFC 8417): typ secevent+jwt, signature with the transmitter's keys, iss, aud, iat, jti, RFC 9493 subject identifiers, and the members each CAEP, RISC or SSF event type requires.",
			Params: join([]Param{
				{Name: "token", Type: "string", Required: true, File: true, Desc: "The SET (CLI: @file or - for stdin)"},
				{Name: "issuer", Type: "string", Desc: "Transmitter issuer; its keys are discovered"}}, keys),
			Run: func(c *Ctx) (M, error) {
				keys, direct, _, err := ssfKeys(c, c.Str("issuer"))
				if err != nil {
					return nil, err
				}
				var cs Checks
				out := checkSET(&cs, c.Str("token"), keys, direct, c.Str("issuer"), c.Str("audience"))
				if out == nil {
					out = M{}
				}
				out["checks"] = cs
				return out, nil
			},
		},
	)
}
