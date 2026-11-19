package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
)

var ldapParams = []Param{
	{Name: "url", Type: "string", Required: true, Desc: "Directory URL, e.g. ldaps://ldap.example.com:636 or ldap://host:389"},
	{Name: "starttls", Type: "bool", Desc: "Upgrade an ldap:// connection with StartTLS before binding"},
	{Name: "bind_dn", Type: "string", Desc: "DN to bind as; omit for an anonymous bind"},
	{Name: "ldap_password", Type: "string", Secret: true, Desc: "Bind password (prefer env IDPDBG_LDAP_PASSWORD or a profile)"},
}

var ldapOIDs = map[string]string{
	"1.2.840.113556.1.4.319":    "Paged results control",
	"1.2.840.113556.1.4.473":    "Server-side sort control",
	"1.2.840.113556.1.4.417":    "Show deleted objects control (AD)",
	"1.2.840.113556.1.4.1339":   "Domain scope control (AD)",
	"1.2.840.113556.1.4.841":    "DirSync control (AD)",
	"2.16.840.1.113730.3.4.2":   "ManageDsaIT control",
	"2.16.840.1.113730.3.4.18":  "Proxied authorization control",
	"1.3.6.1.4.1.42.2.27.8.5.1": "Password policy control",
	"1.3.6.1.1.12":              "Assertion control",
	"1.3.6.1.1.13.1":            "Pre-read control",
	"1.3.6.1.1.13.2":            "Post-read control",
	"1.3.6.1.4.1.4203.1.9.1.1":  "Content sync (syncrepl) control",
	"1.3.6.1.4.1.1466.20037":    "StartTLS",
	"1.3.6.1.4.1.4203.1.11.1":   "Password modify",
	"1.3.6.1.4.1.4203.1.11.3":   "Who am I?",
	"1.3.6.1.1.8":               "Cancel",
	"1.3.6.1.4.1.1466.20036":    "Notice of disconnection",
	"1.3.6.1.1.14":              "Modify-increment",
	"1.3.6.1.4.1.4203.1.5.1":    "All operational attributes (+)",
	"1.3.6.1.4.1.4203.1.5.3":    "Absolute true/false filters",
	"1.2.840.113556.1.4.800":    "Active Directory",
	"1.2.840.113556.1.4.1670":   "Active Directory v51",
	"1.2.840.113556.1.4.1791":   "AD LDAP integrity (signing)",
	"1.2.840.113556.1.4.1935":   "Active Directory v60",
}

type ldapSession struct {
	conn *ldap.Conn
	log  []M
	info M
}

func (s *ldapSession) step(name string, start time.Time, err error) {
	e := M{"operation": name, "duration_ms": time.Since(start).Milliseconds(), "result": "success"}
	if err != nil {
		e["result"] = err.Error()
	}
	s.log = append(s.log, e)
}

func tlsVersionName(v uint16) string { return tls.VersionName(v) }

// ldapConnect dials, optionally upgrades to TLS, and binds.
func ldapConnect(c *Ctx, cs *Checks) (*ldapSession, error) {
	s := &ldapSession{info: M{}}
	// Only the two schemes this tool reasons about; go-ldap would also dial
	// ldapi:// and cldap://.
	if scheme, _, _ := strings.Cut(strings.ToLower(c.Str("url")), "://"); scheme != "ldap" && scheme != "ldaps" {
		return s, errors.New("url must start with ldap:// or ldaps://")
	}
	cfg := c.tlsConfig()
	// go-ldap sets the name to verify for ldaps:// itself, but StartTLS uses
	// the configuration as given.
	if u, err := url.Parse(c.Str("url")); err == nil && cfg.ServerName == "" {
		cfg.ServerName = u.Hostname()
	}
	timeout := time.Duration(c.Int("timeout")) * time.Second
	t := time.Now()
	conn, err := ldap.DialURL(c.Str("url"), ldap.DialWithTLSConfig(cfg), ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	s.step("connect "+c.Str("url"), t, err)
	if err != nil {
		return s, fmt.Errorf("connect: %w", err)
	}
	conn.SetTimeout(timeout)
	s.conn = conn
	if c.Bool("starttls") {
		t = time.Now()
		err = conn.StartTLS(cfg)
		s.step("StartTLS", t, err)
		if err != nil {
			conn.Close()
			return s, fmt.Errorf("StartTLS: %w", err)
		}
	}
	if st, ok := conn.TLSConnectionState(); ok {
		tlsInfo := M{"version": tlsVersionName(st.Version), "cipher_suite": tls.CipherSuiteName(st.CipherSuite)}
		if len(st.PeerCertificates) > 0 {
			tlsInfo["server_certificate"] = certInfo(st.PeerCertificates[0])
			tlsInfo["dns_names"] = st.PeerCertificates[0].DNSNames
		}
		s.info["tls"] = tlsInfo
		cs.add("transport is encrypted", "pass", fmt.Sprint(tlsInfo["version"]), "RFC 4513 §3")
		if c.Bool("insecure") {
			cs.add("server certificate verified", "warn", "verification was skipped (insecure)", "RFC 4513 §3.1.3")
		}
	} else {
		status := "info"
		if c.Str("bind_dn") != "" {
			status = "warn"
		}
		cs.add("transport is encrypted", status, "plain LDAP: a simple bind sends the password in clear text", "RFC 4513 §5.1.3")
	}
	t = time.Now()
	if dn := c.Str("bind_dn"); dn != "" {
		if c.Str("ldap_password") == "" {
			conn.Close()
			return s, errors.New("bind_dn is set but there is no ldap_password (pass it, or set IDPDBG_LDAP_PASSWORD)")
		}
		err = conn.Bind(dn, c.Str("ldap_password"))
		s.step("simple bind as "+dn, t, err)
		if !cs.ok(err == nil, "bind", detailOr(err, "bound as "+dn), "RFC 4511 §4.2") {
			conn.Close()
			s.conn = nil
			return s, nil
		}
	} else {
		err = conn.UnauthenticatedBind("")
		s.step("anonymous bind", t, err)
		if err != nil {
			cs.add("anonymous bind", "info", err.Error(), "RFC 4513 §5.1.1")
		}
	}
	return s, nil
}

func (s *ldapSession) close(out M) {
	if s.conn != nil {
		s.conn.Close()
	}
	for k, v := range s.info {
		out[k] = v
	}
	out["operations"] = s.log
}

func entryMap(e *ldap.Entry) M {
	attrs, decoded := M{}, M{}
	for _, a := range e.Attributes {
		kind := adBinaryKind(a.Name)
		vals := make([]any, 0, len(a.ByteValues))
		for _, b := range a.ByteValues {
			if kind == "" && utf8.Valid(b) && !strings.ContainsFunc(string(b), func(r rune) bool { return r < 0x20 && r != '\n' && r != '\t' && r != '\r' }) {
				vals = append(vals, string(b))
			} else {
				vals = append(vals, adBinaryValue(kind, b, base64.StdEncoding.EncodeToString(b)))
			}
		}
		attrs[a.Name] = vals
		if d := adDecoded(a.Name, a.Values); d != nil {
			decoded[a.Name] = d
		}
	}
	out := M{"dn": e.DN, "attributes": attrs}
	if len(decoded) > 0 {
		out["decoded"] = decoded
	}
	return out
}

func ldapErrDetail(err error) string {
	var le *ldap.Error
	if errors.As(err, &le) {
		return fmt.Sprintf("result code %d (%s): %s", le.ResultCode, ldap.LDAPResultCodeMap[le.ResultCode], cleanDiagnostic(fmt.Sprint(le.Err)))
	}
	return err.Error()
}

// cleanDiagnostic puts a server's diagnostic message on one line. Active
// Directory spreads its messages over several lines and ends them with NUL.
func cleanDiagnostic(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\x00", " ")), " ")
}

func init() {
	register(
		&Op{
			Name:    "ldap.rootdse",
			Summary: "Read a directory's root DSE: naming contexts, supported LDAP versions, SASL mechanisms, controls and extensions (with well-known OIDs named), vendor information and TLS details.",
			Params:  ldapParams,
			Run: func(c *Ctx) (M, error) {
				var cs Checks
				out := M{}
				s, err := ldapConnect(c, &cs)
				defer func() { s.close(out); out["checks"] = cs }()
				if err != nil || s.conn == nil {
					return out, err
				}
				t := time.Now()
				res, err := s.conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, c.Int("timeout"), false, "(objectClass=*)", []string{"*", "+"}, nil))
				s.step("search root DSE", t, err)
				if !cs.ok(err == nil && len(res.Entries) == 1, "root DSE readable", detailOr(err, ""), "RFC 4512 §5.1") {
					return out, nil
				}
				e := res.Entries[0]
				dse := M{}
				for _, a := range e.Attributes {
					switch a.Name {
					case "supportedControl", "supportedExtension", "supportedFeatures", "supportedCapabilities":
						named := []string{}
						for _, v := range a.Values {
							if n := ldapOIDs[v]; n != "" {
								v += " (" + n + ")"
							}
							named = append(named, v)
						}
						dse[a.Name] = named
					default:
						dse[a.Name] = a.Values
					}
				}
				out["root_dse"] = dse
				cs.ok(contains(e.GetAttributeValues("supportedLDAPVersion"), "3"), "LDAPv3 supported", "supportedLDAPVersion="+strings.Join(e.GetAttributeValues("supportedLDAPVersion"), " "), "RFC 4512 §5.1.5")
				cs.warn(len(e.GetAttributeValues("namingContexts")) > 0, "namingContexts published", strings.Join(e.GetAttributeValues("namingContexts"), " | "), "RFC 4512 §5.1.2")
				return out, nil
			},
		},
		&Op{
			Name:    "ldap.bind",
			Summary: "Test a bind against a directory: connect (LDAPS or StartTLS), bind, and ask the server who it thinks you are. Reports timings and TLS details.",
			Params:  ldapParams,
			Run: func(c *Ctx) (M, error) {
				var cs Checks
				out := M{}
				s, err := ldapConnect(c, &cs)
				defer func() { s.close(out); out["checks"] = cs }()
				if err != nil || s.conn == nil {
					return out, err
				}
				t := time.Now()
				who, err := s.conn.WhoAmI(nil)
				s.step("Who am I? extended operation", t, err)
				if err == nil {
					out["authorization_id"] = who.AuthzID
					cs.add("Who am I?", "pass", "authzId="+who.AuthzID, "RFC 4532")
				} else {
					cs.add("Who am I?", "info", "not supported or refused: "+ldapErrDetail(err), "RFC 4532")
				}
				return out, nil
			},
		},
		&Op{
			Name:    "ldap.search",
			Summary: "Search a directory and return the matching entries (binary values come back base64-encoded; Active Directory SIDs, GUIDs, account flags and timestamps are also decoded).",
			Params: append(append([]Param{}, ldapParams...),
				Param{Name: "base_dn", Type: "string", Required: true, Desc: "Search base DN"},
				Param{Name: "filter", Type: "string", Desc: "LDAP filter", Default: "(objectClass=*)"},
				Param{Name: "scope", Type: "string", Enum: []string{"base", "one", "sub"}, Desc: "Search scope", Default: "sub"},
				Param{Name: "attributes", Type: "list", Desc: "Attributes to return (default all user attributes; add + for operational ones)"},
				Param{Name: "limit", Type: "int", Desc: "Maximum number of entries to return", Default: 100},
				Param{Name: "page_size", Type: "int", Desc: "Fetch results in pages of this size with the paged results control (RFC 2696), for directories that cap result sizes"}),
			Run: func(c *Ctx) (M, error) {
				if _, err := ldap.CompileFilter(c.Str("filter")); err != nil {
					return nil, fmt.Errorf("filter: %w", err)
				}
				var cs Checks
				out := M{}
				s, err := ldapConnect(c, &cs)
				defer func() { s.close(out); out["checks"] = cs }()
				if err != nil || s.conn == nil {
					return out, err
				}
				scope := map[string]int{"base": ldap.ScopeBaseObject, "one": ldap.ScopeSingleLevel, "sub": ldap.ScopeWholeSubtree}[c.Str("scope")]
				limit := c.Int("limit")
				req := ldap.NewSearchRequest(c.Str("base_dn"), scope, ldap.NeverDerefAliases, limit, c.Int("timeout"), false, c.Str("filter"), c.List("attributes"), nil)
				t := time.Now()
				var res *ldap.SearchResult
				if ps := c.Int("page_size"); ps > 0 {
					req.SizeLimit = 0 // the limit is applied below; paging needs an unlimited request
					res, err = s.conn.SearchWithPaging(req, uint32(ps))
					s.step(fmt.Sprintf("paged search (%d per page) %s %s", ps, c.Str("base_dn"), c.Str("filter")), t, err)
					if res != nil && limit > 0 && len(res.Entries) > limit {
						res.Entries, err = res.Entries[:limit], ldap.NewError(ldap.LDAPResultSizeLimitExceeded, errors.New("limit reached"))
					}
				} else {
					res, err = s.conn.Search(req)
					s.step("search "+c.Str("base_dn")+" "+c.Str("filter"), t, err)
				}
				truncated := err != nil && ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded)
				if err != nil && !truncated {
					cs.add("search", "fail", ldapErrDetail(err), "RFC 4511 §4.5")
					return out, nil
				}
				entries := []M{}
				if res != nil {
					for _, e := range res.Entries {
						entries = append(entries, entryMap(e))
					}
				}
				out["entries"], out["count"], out["truncated"] = entries, len(entries), truncated
				detail := fmt.Sprintf("%d entries", len(entries))
				if truncated {
					detail += " (size limit reached; raise limit or narrow the filter)"
				}
				cs.add("search", "pass", detail, "RFC 4511 §4.5")
				return out, nil
			},
		},
		&Op{
			Name:     "ldap.modify",
			Mutating: true,
			Summary:  "Modify one directory entry: add, replace or delete attribute values. This changes data in the directory.",
			Params: append(append([]Param{}, ldapParams...),
				Param{Name: "dn", Type: "string", Required: true, Desc: "DN of the entry to modify"},
				Param{Name: "changes", Type: "json", Required: true, Desc: `JSON array of changes, e.g. [{"op":"replace","attr":"description","values":["new"]}]; op is add, replace or delete`}),
			Run: func(c *Ctx) (M, error) {
				changes, ok := c.Args["changes"].([]any)
				if !ok || len(changes) == 0 {
					return nil, errors.New("changes must be a non-empty JSON array")
				}
				req := ldap.NewModifyRequest(c.Str("dn"), nil)
				for i, ch := range changes {
					m, _ := ch.(map[string]any)
					attr := str(m["attr"])
					if attr == "" {
						return nil, fmt.Errorf("changes[%d]: attr is required", i)
					}
					v, _ := coerce(Param{Name: "values", Type: "list"}, m["values"], false)
					vals, _ := v.([]string)
					switch str(m["op"]) {
					case "add":
						req.Add(attr, vals)
					case "replace":
						req.Replace(attr, vals)
					case "delete":
						req.Delete(attr, vals)
					default:
						return nil, fmt.Errorf("changes[%d]: op must be add, replace or delete", i)
					}
				}
				var cs Checks
				out := M{"dn": c.Str("dn")}
				s, err := ldapConnect(c, &cs)
				defer func() { s.close(out); out["checks"] = cs }()
				if err != nil || s.conn == nil {
					return out, err
				}
				t := time.Now()
				err = s.conn.Modify(req)
				s.step("modify "+c.Str("dn"), t, err)
				detail := fmt.Sprintf("%d change(s) applied", len(changes))
				if err != nil {
					detail = ldapErrDetail(err)
				}
				cs.ok(err == nil, "modify", detail, "RFC 4511 §4.6")
				return out, nil
			},
		},
	)
}

// ldapWrite connects, binds and runs one change, recording it as a check.
func ldapWrite(c *Ctx, out M, name, ref string, do func(*ldap.Conn) (string, error)) (M, error) {
	return ldapWriteStep(c, out, func(conn *ldap.Conn) (string, string, string, error) {
		detail, err := do(conn)
		return name, ref, detail, err
	})
}

// ldapWriteStep is ldapWrite for operations that pick their check name and
// reference once connected.
func ldapWriteStep(c *Ctx, out M, do func(*ldap.Conn) (name, ref, detail string, err error)) (M, error) {
	var cs Checks
	s, err := ldapConnect(c, &cs)
	defer func() { s.close(out); out["checks"] = cs }()
	if err != nil || s.conn == nil {
		return out, err
	}
	if c.Str("bind_dn") == "" {
		cs.add("bound as a user", "warn", "anonymous bind: directories rarely allow changes without one", "RFC 4513 §5.1.1")
	}
	t := time.Now()
	name, ref, detail, err := do(s.conn)
	s.step(name, t, err)
	if err != nil {
		detail = ldapErrDetail(err)
		if h := adPasswordHint(err); h != "" {
			detail += ": " + h
		}
	}
	cs.ok(err == nil, name, detail, ref)
	return out, nil
}

func init() {
	register(
		&Op{
			Name:     "ldap.add",
			Mutating: true,
			Summary:  "Add an entry to the directory. This creates data.",
			Params: append(append([]Param{}, ldapParams...),
				Param{Name: "dn", Type: "string", Required: true, Desc: "DN of the new entry"},
				Param{Name: "attributes", Type: "json", Required: true, Desc: `Attributes as a JSON object of name to value or list of values, e.g. {"objectClass":["inetOrgPerson"],"cn":"Jane","sn":"Doe"}`}),
			Run: func(c *Ctx) (M, error) {
				attrs, ok := c.Args["attributes"].(map[string]any)
				if !ok || len(attrs) == 0 {
					return nil, errors.New("attributes must be a non-empty JSON object")
				}
				req := ldap.NewAddRequest(c.Str("dn"), nil)
				for _, name := range sortedKeys(attrs) {
					v, _ := coerce(Param{Name: name, Type: "list"}, attrs[name], false)
					vals, _ := v.([]string)
					req.Attribute(name, vals)
				}
				return ldapWrite(c, M{"dn": c.Str("dn")}, "add", "RFC 4511 §4.7", func(conn *ldap.Conn) (string, error) {
					return fmt.Sprintf("added with %d attribute(s)", len(attrs)), conn.Add(req)
				})
			},
		},
		&Op{
			Name:     "ldap.delete",
			Mutating: true,
			Summary:  "Delete a leaf entry from the directory. This removes data and cannot be undone.",
			Params: append(append([]Param{}, ldapParams...),
				Param{Name: "dn", Type: "string", Required: true, Desc: "DN of the entry to delete (it must have no children)"}),
			Run: func(c *Ctx) (M, error) {
				return ldapWrite(c, M{"dn": c.Str("dn")}, "delete", "RFC 4511 §4.8", func(conn *ldap.Conn) (string, error) {
					return "deleted", conn.Del(ldap.NewDelRequest(c.Str("dn"), nil))
				})
			},
		},
		&Op{
			Name:     "ldap.rename",
			Mutating: true,
			Summary:  "Rename an entry or move it under a new parent (ModifyDN). This changes data.",
			Params: append(append([]Param{}, ldapParams...),
				Param{Name: "dn", Type: "string", Required: true, Desc: "DN of the entry to rename"},
				Param{Name: "new_rdn", Type: "string", Required: true, Desc: "New RDN, e.g. uid=jane.doe"},
				Param{Name: "delete_old_rdn", Type: "bool", Desc: "Remove the old RDN value from the entry", Default: true},
				Param{Name: "new_superior", Type: "string", Desc: "DN of the new parent, to move the entry"}),
			Run: func(c *Ctx) (M, error) {
				newDN := c.Str("new_rdn") + ","
				if sup := c.Str("new_superior"); sup != "" {
					newDN += sup
				} else if _, parent, ok := strings.Cut(c.Str("dn"), ","); ok {
					newDN += parent
				}
				req := ldap.NewModifyDNRequest(c.Str("dn"), c.Str("new_rdn"), c.Bool("delete_old_rdn"), c.Str("new_superior"))
				return ldapWrite(c, M{"dn": c.Str("dn"), "new_dn": strings.TrimSuffix(newDN, ",")}, "rename", "RFC 4511 §4.9", func(conn *ldap.Conn) (string, error) {
					return "renamed to " + strings.TrimSuffix(newDN, ","), conn.ModifyDN(req)
				})
			},
		},
		&Op{
			Name:    "ldap.compare",
			Summary: "Ask the directory whether an entry has an attribute value (Compare), without reading the attribute. Useful where search access is restricted.",
			Params: append(append([]Param{}, ldapParams...),
				Param{Name: "dn", Type: "string", Required: true, Desc: "DN of the entry"},
				Param{Name: "attribute", Type: "string", Required: true, Desc: "Attribute to compare"},
				Param{Name: "value", Type: "string", Required: true, Desc: "Value to compare against"}),
			Run: func(c *Ctx) (M, error) {
				var cs Checks
				out := M{"dn": c.Str("dn"), "attribute": c.Str("attribute")}
				s, err := ldapConnect(c, &cs)
				defer func() { s.close(out); out["checks"] = cs }()
				if err != nil || s.conn == nil {
					return out, err
				}
				t := time.Now()
				match, err := s.conn.Compare(c.Str("dn"), c.Str("attribute"), c.Str("value"))
				s.step("compare "+c.Str("attribute"), t, err)
				if !cs.ok(err == nil, "compare", detailOr(err, fmt.Sprintf("the value %s", map[bool]string{true: "matches", false: "does not match"}[match])), "RFC 4511 §4.10") {
					cs[len(cs)-1].Detail = ldapErrDetail(err)
					return out, nil
				}
				out["match"] = match
				return out, nil
			},
		},
		&Op{
			Name:     "ldap.passwd",
			Mutating: true,
			Summary:  "Change or reset a password. Uses the Password Modify extended operation (RFC 3062) where the server offers it, and Active Directory's unicodePwd attribute (over an encrypted connection only) where it does not. With old_password the user's own password is changed; without it an administrator resets it. RFC 3062 servers generate a password when new_password is omitted; Active Directory cannot. Without user_dn the bound user's password is changed.",
			Params: append(append([]Param{}, ldapParams...),
				Param{Name: "user_dn", Type: "string", Desc: "Whose password to change; default is the bound user"},
				Param{Name: "old_password", Type: "string", Secret: true, Desc: "Current password, if the server requires it (prefer env IDPDBG_OLD_PASSWORD)"},
				Param{Name: "new_password", Type: "string", Secret: true, Desc: "New password; omit to have the server generate one (prefer env IDPDBG_NEW_PASSWORD)"},
				Param{Name: "method", Type: "string", Default: "auto", Enum: []string{"auto", "extended", "unicodepwd"}, Desc: "extended (RFC 3062), unicodepwd (Active Directory), or auto: chosen from the root DSE"}),
			Run: func(c *Ctx) (M, error) {
				out := M{}
				if u := c.Str("user_dn"); u != "" {
					out["user_dn"] = u
				}
				res, err := ldapWriteStep(c, out, func(conn *ldap.Conn) (string, string, string, error) {
					method := c.Str("method")
					dse, _ := readRootDSE(conn)
					if method == "auto" {
						method = "extended"
						if !contains(dse.extensions, oidPasswordModify) && contains(dse.capabilities, oidADCapability) {
							method = "unicodepwd"
						}
					}
					out["method"] = method
					if method == "unicodepwd" {
						const name, ref = "password change (unicodePwd)", "MS-ADTS §3.1.1.3.1.5"
						if _, encrypted := conn.TLSConnectionState(); !encrypted {
							return name, ref, "", errors.New("not sent: Active Directory accepts unicodePwd only over an encrypted connection; use ldaps:// or starttls")
						}
						if c.Str("new_password") == "" {
							return name, ref, "", errors.New("not sent: Active Directory cannot generate a password; pass new_password")
						}
						dn := c.Str("user_dn")
						if dn == "" {
							if c.Str("bind_dn") == "" {
								return name, ref, "", errors.New("pass user_dn, or bind as the user")
							}
							var err error
							if dn, err = adUserDN(conn, dse.defaultNC, c.Str("bind_dn")); err != nil {
								return name, ref, "", err
							}
						}
						out["user_dn"] = dn
						detail, err := adSetPassword(conn, dn, c.Str("old_password"), c.Str("new_password"))
						return name, ref, detail, err
					}
					r, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(c.Str("user_dn"), c.Str("old_password"), c.Str("new_password")))
					if err != nil {
						return "password modify", "RFC 3062", "", err
					}
					if r.GeneratedPassword != "" {
						out["generated_password"] = r.GeneratedPassword
						return "password modify", "RFC 3062", "changed; the server generated the new password", nil
					}
					return "password modify", "RFC 3062", "changed", nil
				})
				if c.Str("new_password") == "" && out["method"] == "extended" {
					if _, ok := out["generated_password"]; !ok && err == nil {
						if cs, _ := res["checks"].(Checks); cs != nil && !hasFailure(res) {
							cs.add("generated password returned", "fail", "no new_password was sent, so the server should have generated and returned one", "RFC 3062 §3.2")
							res["checks"] = cs
						}
					}
				}
				return res, err
			},
		},
	)
}
