package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

const scimJSON = "application/scim+json"

var scimParams = []Param{
	{Name: "base_url", Type: "string", Required: true, Desc: "SCIM base URL, e.g. https://example.com/scim/v2"},
	{Name: "scim_token", Type: "string", Secret: true, Desc: "Bearer token (prefer env IDPDBG_SCIM_TOKEN or a profile)"},
	{Name: "headers", Type: "json", Desc: `Extra request headers as a JSON object, e.g. {"Authorization":"Basic ..."}`},
}

type scimStep struct {
	Step     string `json:"step"`
	Request  string `json:"request"`
	Status   int    `json:"status"`
	OK       bool   `json:"ok"`
	Detail   string `json:"detail,omitempty"`
	Response any    `json:"response,omitempty"`
}

func scimCall(c *Ctx, method, path string, body any) (*httpResult, string, error) {
	u := strings.TrimSuffix(c.Str("base_url"), "/")
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		// Absolute URLs (e.g. a meta.location) must stay on the base URL's
		// origin, so the bearer token cannot be sent somewhere else.
		bu, _ := url.Parse(u)
		pu, err := url.Parse(path)
		if err != nil || bu == nil || pu.Scheme != bu.Scheme || pu.Host != bu.Host {
			return nil, "", fmt.Errorf("path %q is not on the same origin as base_url", path)
		}
		u = path
	} else {
		u += "/" + strings.TrimPrefix(path, "/")
	}
	hdr := map[string]string{"Accept": scimJSON + ", application/json"}
	if t := c.Str("scim_token"); t != "" {
		hdr["Authorization"] = "Bearer " + t
	}
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
		hdr["Content-Type"] = scimJSON
	}
	if extra, ok := c.Args["headers"].(map[string]any); ok {
		for k, v := range extra {
			hdr[k] = fmt.Sprint(v)
		}
	}
	res, err := c.do(method, u, hdr, b)
	return res, method + " " + u, err
}

func scimError(res *httpResult) string {
	if m := res.obj(); m != nil {
		if d := str(m["detail"]); d != "" {
			return d
		}
	}
	if len(res.Body) > 300 {
		return string(res.Body[:300])
	}
	return string(res.Body)
}

// scenario runs steps in order, stopping at the first failure.
type scenario struct {
	c      *Ctx
	steps  []scimStep
	failed bool
	// protocol details, judged over all steps
	wrongType   []string // responses with a body but not application/scim+json
	etagOff     []string // ETag header differs from meta.version
	location    []string // creates whose Location is missing or differs from meta.location
	errProblems []string // error responses that are not proper SCIM error messages
	errors      int      // error responses seen
	bodies      int      // responses with a body
	etags       int      // responses with both an ETag header and meta.version
	creates     int      // 201 responses to a POST
	refusals    Checks   // requests the server must refuse
	userID      string   // the scenario's own user: never deleted by mustRefuse
}

// isSCIMJSON reports whether a Content-Type is application/scim+json (media
// types are case-insensitive).
func isSCIMJSON(ct string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), scimJSON)
}

// mustRefuse sends a create the server must refuse, records the outcome,
// and deletes whatever it wrongly created.
func (s *scenario) mustRefuse(name, path string, body M, want int, scimType, ref string) {
	if s.failed {
		return
	}
	res, req, err := scimCall(s.c, "POST", path, body)
	if err != nil {
		s.refusals.add(name, "info", "could not send: "+err.Error(), ref)
		return
	}
	s.observe(name, "POST", strings.TrimPrefix(req, "POST "), res)
	got := res.obj()
	switch {
	case res.Status >= 300 && res.Status < 400:
		s.refusals.add(name, "info", fmt.Sprintf("not judged: the server redirected (HTTP %d to %s)", res.Status, res.Header.Get("Location")), ref)
	case res.Status == want && scimType != "" && str(got["scimType"]) != scimType:
		s.refusals.add(name, "warn", fmt.Sprintf("refused with HTTP %d, but scimType is %q, not %q", res.Status, str(got["scimType"]), scimType), ref)
	case res.Status == want:
		s.refusals.add(name, "pass", strings.TrimSpace(fmt.Sprintf("refused with HTTP %d %s", res.Status, str(got["scimType"]))), ref)
	case res.Status >= 400:
		s.refusals.add(name, "warn", fmt.Sprintf("refused, but with HTTP %d instead of %d: %s", res.Status, want, scimError(res)), ref)
	default:
		detail := fmt.Sprintf("the server accepted it (HTTP %d)", res.Status)
		// Delete only what the server says it just created (201), and never
		// the scenario's own user: a server may answer a duplicate with the
		// existing resource (200), and that must survive.
		switch id := str(got["id"]); {
		case res.Status != 201 || id == "":
			detail += "; nothing was deleted (no 201 with an id)"
		case id == s.userID:
			detail += "; it returned the scenario's own user, which is kept"
		default:
			if del, _, err := scimCall(s.c, "DELETE", path+"/"+url.PathEscape(id), nil); err != nil || del.Status >= 300 {
				detail += fmt.Sprintf("; deleting %s again failed, so remove it by hand", id)
			} else {
				detail += fmt.Sprintf("; %s was deleted again", id)
			}
		}
		s.refusals.add(name, "fail", detail, ref)
	}
}

// observe records the protocol details of one response.
func (s *scenario) observe(name, method, reqURL string, res *httpResult) {
	if len(res.Body) > 0 {
		s.bodies++
		if !isSCIMJSON(res.Header.Get("Content-Type")) {
			s.wrongType = append(s.wrongType, fmt.Sprintf("%s (%q)", name, res.Header.Get("Content-Type")))
		}
	}
	body := res.obj()
	meta, _ := body["meta"].(map[string]any)
	if et := res.Header.Get("ETag"); et != "" && meta != nil && str(meta["version"]) != "" {
		s.etags++
		norm := func(v string) string { return strings.Trim(strings.TrimPrefix(v, "W/"), `"`) }
		if norm(et) != norm(str(meta["version"])) {
			s.etagOff = append(s.etagOff, fmt.Sprintf("%s (ETag %s, meta.version %s)", name, et, str(meta["version"])))
		}
	}
	if method == "POST" && res.Status == 201 {
		s.creates++
		// Location may be relative (RFC 9110 §10.2.2): resolve it against
		// the request URL before comparing.
		loc := res.Header.Get("Location")
		resolve := func(v string) string {
			if base, err := url.Parse(reqURL); err == nil && v != "" {
				if l, err := base.Parse(v); err == nil {
					return l.String()
				}
			}
			return v
		}
		switch {
		case loc == "":
			s.location = append(s.location, name+" (no Location header)")
		case meta != nil && str(meta["location"]) != "" && resolve(loc) != resolve(str(meta["location"])):
			s.location = append(s.location, fmt.Sprintf("%s (Location %q, meta.location %q)", name, loc, str(meta["location"])))
		}
	}
	if res.Status >= 400 {
		s.errors++
		if p := scimErrorProblem(res); p != "" {
			s.errProblems = append(s.errProblems, fmt.Sprintf("HTTP %d to %s: %s", res.Status, name, p))
		}
	}
}

// scimErrorProblem says what is wrong with an error response's body, or "".
func scimErrorProblem(res *httpResult) string {
	body := res.obj()
	if body == nil {
		return "the body is not a JSON object"
	}
	schemas, _ := body["schemas"].([]any)
	isErr := false
	for _, sc := range schemas {
		isErr = isErr || str(sc) == "urn:ietf:params:scim:api:messages:2.0:Error"
	}
	if !isErr {
		return "schemas lacks urn:ietf:params:scim:api:messages:2.0:Error"
	}
	switch st := body["status"].(type) {
	case string:
		if st != fmt.Sprint(res.Status) {
			return fmt.Sprintf("status %q differs from the HTTP status %d", st, res.Status)
		}
	case float64:
		return fmt.Sprintf("status is the number %v; it must be a JSON string (\"%d\")", st, res.Status)
	default:
		return "status is missing"
	}
	return ""
}

// protocolChecks judges what observe saw over the whole scenario.
// A check with nothing to judge is info, not a pass.
func (s *scenario) protocolChecks(cs *Checks) {
	judge := func(seen int, name, ref string, problems []string, level string) {
		switch {
		case seen == 0:
			cs.add(name, "info", "nothing to judge in this run", ref)
		case len(problems) == 0:
			cs.add(name, "pass", fmt.Sprintf("%d response(s) checked", seen), ref)
		default:
			cs.add(name, level, strings.Join(problems, "; "), ref)
		}
	}
	judge(s.bodies, "responses use application/scim+json", "RFC 7644 §3.1", s.wrongType, "warn")
	judge(s.creates, "created resources have a Location header matching meta.location", "RFC 7644 §3.3", s.location, "fail")
	judge(s.etags, "ETag headers match meta.version", "RFC 7644 §3.14", s.etagOff, "fail")
	judge(s.errors, "error responses are SCIM error messages", "RFC 7644 §3.12", s.errProblems, "warn")
}

func (s *scenario) do(name, method, path string, body any, want []int, verify func(M) string) M {
	if s.failed {
		return nil
	}
	res, req, err := scimCall(s.c, method, path, body)
	st := scimStep{Step: name, Request: req}
	if err != nil {
		st.Detail = err.Error()
		s.steps, s.failed = append(s.steps, st), true
		return nil
	}
	st.Status = res.Status
	s.observe(name, method, strings.TrimPrefix(req, method+" "), res)
	for _, w := range want {
		st.OK = st.OK || w == res.Status
	}
	if !st.OK {
		st.Detail = fmt.Sprintf("expected HTTP %v, got %d: %s", want, res.Status, scimError(res))
		st.Response = res.payload()
	} else if verify != nil && (res.obj() != nil || res.Status != 204) {
		if problem := verify(res.obj()); problem != "" {
			st.OK, st.Detail, st.Response = false, problem, res.payload()
		}
	}
	s.steps = append(s.steps, st)
	s.failed = !st.OK
	return res.obj()
}

func patchOp(ops ...M) M {
	return M{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": ops}
}

func runScenario(c *Ctx) (M, error) {
	s := &scenario{c: c}
	tag := strings.ToLower(randToken(5))
	userName := c.Str("user_name")
	if userName == "" {
		userName = "idpdbg-" + tag + "@" + c.Str("email_domain")
	}
	var userID, groupID string

	user := s.do("create user", "POST", "/Users", M{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": userName, "active": true,
		"name":   M{"givenName": "Idp", "familyName": "Debug " + tag},
		"emails": []M{{"value": userName, "type": "work", "primary": true}},
	}, []int{201}, func(m M) string {
		if userID = str(m["id"]); userID == "" {
			return "the response has no id"
		}
		s.userID = userID
		if str(m["userName"]) != userName {
			return "userName in the response is " + str(m["userName"])
		}
		if meta, _ := m["meta"].(map[string]any); meta == nil || str(meta["location"]) == "" {
			return "meta.location is missing (RFC 7643 §3.1)"
		}
		return ""
	})
	_ = user
	userPath := "/Users/" + url.PathEscape(userID)
	s.do("read user", "GET", userPath, nil, []int{200}, func(m M) string {
		if str(m["id"]) != userID {
			return "id mismatch"
		}
		return ""
	})
	s.do("filter by userName", "GET", "/Users?filter="+url.QueryEscape(`userName eq "`+userName+`"`), nil, []int{200}, func(m M) string {
		if n, _ := m["totalResults"].(float64); n != 1 {
			return fmt.Sprintf("expected totalResults 1, got %v", m["totalResults"])
		}
		return ""
	})

	if c.Str("scenario") == "group_lifecycle" {
		s.do("create group", "POST", "/Groups", M{
			"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
			"displayName": "idpdbg-group-" + tag,
		}, []int{201}, func(m M) string {
			if groupID = str(m["id"]); groupID == "" {
				return "the response has no id"
			}
			return ""
		})
		groupPath := "/Groups/" + url.PathEscape(groupID)
		hasMember := func(want bool) func(M) string {
			return func(m M) string {
				found := false
				members, _ := m["members"].([]any)
				for _, mem := range members {
					if mm, ok := mem.(map[string]any); ok && str(mm["value"]) == userID {
						found = true
					}
				}
				if found != want {
					return fmt.Sprintf("user is member = %v, expected %v", found, want)
				}
				return ""
			}
		}
		s.do("add member (PATCH)", "PATCH", groupPath, patchOp(M{"op": "add", "path": "members", "value": []M{{"value": userID}}}), []int{200, 204}, nil)
		s.do("verify membership", "GET", groupPath, nil, []int{200}, hasMember(true))
		s.do("remove member (PATCH)", "PATCH", groupPath, patchOp(M{"op": "remove", "path": `members[value eq "` + userID + `"]`}), []int{200, 204}, nil)
		s.do("verify removal", "GET", groupPath, nil, []int{200}, hasMember(false))
		if !c.Bool("keep") {
			s.do("delete group", "DELETE", groupPath, nil, []int{204}, nil)
		}
	} else {
		s.mustRefuse("duplicate userName refused", "/Users", M{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": userName,
		}, 409, "uniqueness", "RFC 7644 §3.3")
		s.mustRefuse("user without userName refused", "/Users", M{
			"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "displayName": "idpdbg " + tag + " without userName",
		}, 400, "", "RFC 7643 §4.1")
		s.do("update name (PATCH replace)", "PATCH", userPath, patchOp(M{"op": "replace", "path": "name.givenName", "value": "Patched"}), []int{200, 204}, nil)
		s.do("verify patch", "GET", userPath, nil, []int{200}, func(m M) string {
			if name, _ := m["name"].(map[string]any); name == nil || str(name["givenName"]) != "Patched" {
				return "name.givenName was not updated"
			}
			return ""
		})
		s.do("replace user (PUT)", "PUT", userPath, M{
			"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
			"id":       userID,
			"userName": userName, "active": true,
			"name":   M{"givenName": "Replaced", "familyName": "Debug " + tag},
			"emails": []M{{"value": userName, "type": "work", "primary": true}},
		}, []int{200}, func(m M) string {
			if name, _ := m["name"].(map[string]any); name == nil || str(name["givenName"]) != "Replaced" {
				return "name.givenName was not replaced"
			}
			return ""
		})
		s.do("deactivate (PATCH active=false)", "PATCH", userPath, patchOp(M{"op": "replace", "path": "active", "value": false}), []int{200, 204}, nil)
		s.do("verify deactivation", "GET", userPath, nil, []int{200}, func(m M) string {
			if active, ok := m["active"].(bool); !ok || active {
				return fmt.Sprintf("active is %v, expected false", m["active"])
			}
			return ""
		})
	}

	out := M{"scenario": c.Str("scenario"), "user_name": userName, "user_id": userID}
	if groupID != "" {
		out["group_id"] = groupID
	}
	if c.Bool("keep") {
		out["kept"] = true
	} else if userID != "" {
		// Clean up even after a failed step, so a broken run leaves nothing behind.
		if groupID != "" && s.failed {
			scimCall(c, "DELETE", "/Groups/"+url.PathEscape(groupID), nil)
		}
		failedBefore := s.failed
		s.failed = false
		s.do("delete user", "DELETE", userPath, nil, []int{204}, nil)
		s.do("verify deletion", "GET", userPath, nil, []int{404}, nil)
		s.failed = s.failed || failedBefore
	}
	var cs Checks
	for _, st := range s.steps {
		cs.ok(st.OK, st.Step, strings.TrimSpace(fmt.Sprintf("HTTP %d %s", st.Status, st.Detail)), "RFC 7644")
	}
	cs = append(cs, s.refusals...)
	s.protocolChecks(&cs)
	out["steps"], out["checks"] = s.steps, cs
	return out, nil
}

func init() {
	register(
		&Op{
			Name:    "scim.discover",
			Summary: "Read a SCIM 2.0 service provider's ServiceProviderConfig, ResourceTypes and Schemas, and summarise what it supports (patch, bulk, filter, sort, etag, authentication schemes).",
			Params:  scimParams,
			Run: func(c *Ctx) (M, error) {
				var cs Checks
				out := M{}
				for _, ep := range []string{"ServiceProviderConfig", "ResourceTypes", "Schemas"} {
					res, _, err := scimCall(c, "GET", "/"+ep, nil)
					if err != nil {
						return nil, err
					}
					if !cs.ok(res.Status == 200 && res.obj() != nil, "GET /"+ep, fmt.Sprintf("HTTP %d", res.Status), "RFC 7644 §4") {
						continue
					}
					cs.warn(isSCIMJSON(res.Header.Get("Content-Type")), "/"+ep+" Content-Type is application/scim+json",
						"Content-Type="+res.Header.Get("Content-Type"), "RFC 7644 §3.1")
					body := res.obj()
					switch ep {
					case "ServiceProviderConfig":
						feat := M{}
						for _, f := range []string{"patch", "bulk", "filter", "changePassword", "sort", "etag"} {
							if m, ok := body[f].(map[string]any); ok {
								feat[f] = m["supported"]
							} else {
								cs.add("ServiceProviderConfig: "+f+" present", "fail", "required attribute missing", "RFC 7643 §5")
							}
						}
						out["features"] = feat
						out["authentication_schemes"] = body["authenticationSchemes"]
						out["service_provider_config"] = body
					case "ResourceTypes":
						types := []M{}
						for _, r := range listResources(body) {
							types = append(types, M{"name": r["name"], "endpoint": r["endpoint"], "schema": r["schema"], "schemaExtensions": r["schemaExtensions"]})
						}
						out["resource_types"] = types
					case "Schemas":
						schemas := []M{}
						for _, r := range listResources(body) {
							attrs, _ := r["attributes"].([]any)
							names := []string{}
							for _, a := range attrs {
								if am, ok := a.(map[string]any); ok {
									names = append(names, str(am["name"]))
								}
							}
							schemas = append(schemas, M{"id": r["id"], "name": r["name"], "attributes": names})
						}
						out["schemas"] = schemas
					}
				}
				out["checks"] = cs
				return out, nil
			},
		},
		&Op{
			Name:     "scim.request",
			Mutating: true,
			Summary:  "Send one SCIM request by hand (any method and path) and show the response. GET is read-only; POST, PUT, PATCH and DELETE change data at the service provider.",
			Params: append(append([]Param{}, scimParams...),
				Param{Name: "method", Type: "string", Enum: []string{"GET", "POST", "PUT", "PATCH", "DELETE"}, Desc: "HTTP method", Default: "GET"},
				Param{Name: "path", Type: "string", Required: true, Desc: `Path under the base URL, with any query, e.g. /Users?filter=userName eq "a@b.c"`},
				Param{Name: "body", Type: "json", Desc: "JSON request body (CLI: @file)"}),
			Run: func(c *Ctx) (M, error) {
				path := c.Str("path")
				if p, q, ok := strings.Cut(path, "?"); ok {
					vals, err := url.ParseQuery(strings.ReplaceAll(q, "+", "%2B"))
					if err != nil {
						return nil, err
					}
					path = p + "?" + vals.Encode()
				}
				res, req, err := scimCall(c, c.Str("method"), path, c.Args["body"])
				if err != nil {
					return nil, err
				}
				var cs Checks
				cs.ok(res.Status < 400, "response status", fmt.Sprintf("HTTP %d", res.Status), "RFC 7644 §3.12")
				if len(res.Body) > 0 {
					cs.warn(isSCIMJSON(res.Header.Get("Content-Type")), "Content-Type is application/scim+json", "Content-Type="+res.Header.Get("Content-Type"), "RFC 7644 §3.1")
				}
				return M{"request": req, "status": res.Status, "headers": flatHeaders(res.Header, false), "response": res.payload(), "checks": cs}, nil
			},
		},
		&Op{
			Name:     "scim.bulk",
			Mutating: true,
			Summary:  "Send a SCIM Bulk request (RFC 7644 §3.7) and check every operation's result: status, location for creates, and bulkId echo (bulkId references let one operation use a resource another creates). Checks the advertised bulk limits first. This changes data.",
			Params: append(append([]Param{}, scimParams...),
				Param{Name: "operations", Type: "json", Required: true, Desc: `JSON array of bulk operations, e.g. [{"method":"POST","path":"/Users","bulkId":"u1","data":{...}},{"method":"POST","path":"/Groups","bulkId":"g1","data":{"displayName":"G","members":[{"value":"bulkId:u1"}]}}] (CLI: @file)`},
				Param{Name: "fail_on_errors", Type: "int", Desc: "Stop after this many failed operations"}),
			Run: runBulk,
		},
		&Op{
			Name:     "scim.scenario",
			Mutating: true,
			Summary:  "Run a provisioning scenario against a SCIM service provider and check every step. user_lifecycle: create, read, filter, a duplicate userName and a user without userName (both must be refused), PATCH, PUT, deactivate, delete, confirm 404. group_lifecycle: create a user and a group, add and remove the membership, delete both. Creates real (clearly named, temporary) objects and removes them afterwards unless keep is set.",
			Params: append(append([]Param{}, scimParams...),
				Param{Name: "scenario", Type: "string", Enum: []string{"user_lifecycle", "group_lifecycle"}, Desc: "Which scenario to run", Default: "user_lifecycle"},
				Param{Name: "user_name", Type: "string", Desc: "userName for the test user; default is a random idpdbg-xxxx address"},
				Param{Name: "email_domain", Type: "string", Desc: "Domain for the generated userName", Default: "example.com"},
				Param{Name: "keep", Type: "bool", Desc: "Leave the created objects in place instead of deleting them"}),
			Run: func(c *Ctx) (M, error) {
				if c.Str("base_url") == "" {
					return nil, errors.New("missing base_url")
				}
				return runScenario(c)
			},
		},
	)
}

func runBulk(c *Ctx) (M, error) {
	ops, ok := c.Args["operations"].([]any)
	if !ok || len(ops) == 0 {
		return nil, errors.New("operations must be a non-empty JSON array")
	}
	body := M{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkRequest"}, "Operations": ops}
	if c.Has("fail_on_errors") {
		body["failOnErrors"] = c.Int("fail_on_errors")
	}
	var cs Checks
	out := M{}
	// The service provider says whether it supports bulk and how much.
	if cfg, _, err := scimCall(c, "GET", "/ServiceProviderConfig", nil); err == nil && cfg.obj() != nil {
		bulk, _ := cfg.obj()["bulk"].(map[string]any)
		if bulk["supported"] != true {
			cs.add("bulk supported", "warn", "ServiceProviderConfig says bulk is not supported", "RFC 7643 §5")
		} else {
			cs.add("bulk supported", "pass", fmt.Sprintf("maxOperations=%v maxPayloadSize=%v", bulk["maxOperations"], bulk["maxPayloadSize"]), "RFC 7643 §5")
			if max, ok := bulk["maxOperations"].(float64); ok && len(ops) > int(max) {
				cs.add("within maxOperations", "warn", fmt.Sprintf("%d operations exceed the advertised maximum of %d", len(ops), int(max)), "RFC 7644 §3.7.4")
			}
		}
	}
	res, req, err := scimCall(c, "POST", "/Bulk", body)
	if err != nil {
		return nil, err
	}
	out["request"], out["status"], out["response"] = req, res.Status, res.payload()
	resp := res.obj()
	if !cs.ok(res.Status == 200 && resp != nil, "bulk response", fmt.Sprintf("HTTP %d %s", res.Status, scimError(res)), "RFC 7644 §3.7") {
		out["checks"] = cs
		return out, nil
	}
	results, _ := resp["Operations"].([]any)
	byBulkID := map[string]M{}
	for _, r := range results {
		if m, ok := r.(map[string]any); ok && str(m["bulkId"]) != "" {
			byBulkID[str(m["bulkId"])] = m
		}
	}
	summary := []M{}
	failed := 0
	for i, o := range ops {
		op, _ := o.(map[string]any)
		method, path, bulkID := strings.ToUpper(str(op["method"])), str(op["path"]), str(op["bulkId"])
		var r M
		if bulkID != "" {
			r = byBulkID[bulkID]
		} else if i < len(results) {
			r, _ = results[i].(map[string]any)
		}
		label := fmt.Sprintf("operation %d: %s %s", i+1, method, path)
		if r == nil {
			cs.add(label, "warn", "no result returned (the server may have stopped after failOnErrors)", "RFC 7644 §3.7.3")
			summary = append(summary, M{"operation": label, "result": "missing"})
			continue
		}
		status := fmt.Sprint(r["status"])
		code, _ := strconv.Atoi(status)
		if code == 0 {
			if sm, ok := r["status"].(map[string]any); ok { // some servers nest it
				code, _ = strconv.Atoi(fmt.Sprint(sm["code"]))
			}
		}
		detail := "HTTP " + status
		if resp, _ := r["response"].(map[string]any); resp != nil && str(resp["detail"]) != "" {
			detail += ": " + str(resp["detail"])
		}
		if code < 200 || code >= 300 {
			failed++
		}
		cs.ok(code >= 200 && code < 300, label, detail, "RFC 7644 §3.7.3")
		if _, isStr := r["status"].(string); !isStr {
			cs.add(label+": status is a string", "warn", fmt.Sprintf("status is %T; the schema defines it as a string", r["status"]), "RFC 7644 §3.7.3")
		}
		if method == "POST" && code == 201 {
			cs.ok(str(r["location"]) != "", label+": location returned", str(r["location"]), "RFC 7644 §3.7.3")
		}
		if bulkID != "" {
			cs.ok(str(r["bulkId"]) == bulkID, label+": bulkId echoed", "", "RFC 7644 §3.7.3")
		}
		summary = append(summary, M{"operation": label, "status": status, "location": r["location"], "bulkId": r["bulkId"]})
	}
	out["operations"], out["failed"] = summary, failed
	out["checks"] = cs
	return out, nil
}

func listResources(body M) []M {
	arr, _ := body["Resources"].([]any)
	var out []M
	for _, r := range arr {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
