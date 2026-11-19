package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// mockDirectory is a small in-process LDAPv3 server: enough of RFC 4511,
// RFC 2696 paging and RFC 3062 password modify to exercise the client side.
type mockDirectory struct {
	mu      sync.Mutex
	entries map[string]*mockEntry // normalised DN -> entry
	addr    string

	// Active Directory mode: no RFC 3062, passwords through unicodePwd over
	// an encrypted connection only, binds by userPrincipalName.
	ad          bool
	tlsCfg      *tls.Config // for StartTLS and the LDAPS listener
	ldapsAddr   string
	pwdModifies int // unicodePwd modify requests received
}

type mockEntry struct {
	dn    string
	attrs map[string][]string // lowercased name -> values
	names map[string]string   // lowercased name -> name as written
}

func normDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(parts[i]))
	}
	return strings.Join(parts, ",")
}

func parentDN(dn string) string {
	_, p, _ := strings.Cut(normDN(dn), ",")
	return p
}

func (d *mockDirectory) put(dn string, attrs map[string][]string) {
	e := &mockEntry{dn: dn, attrs: map[string][]string{}, names: map[string]string{}}
	for k, v := range attrs {
		e.attrs[strings.ToLower(k)], e.names[strings.ToLower(k)] = append([]string{}, v...), k
	}
	d.entries[normDN(dn)] = e
}

func newMockDirectory(t *testing.T) *mockDirectory {
	return newMockDir(t, false, nil)
}

func newMockDir(t *testing.T, ad bool, tlsCfg *tls.Config) *mockDirectory {
	d := &mockDirectory{entries: map[string]*mockEntry{}, ad: ad, tlsCfg: tlsCfg}
	d.put("dc=example,dc=com", map[string][]string{"objectClass": {"domain"}, "dc": {"example"}})
	d.put("ou=people,dc=example,dc=com", map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"people"}})
	d.put("cn=admin,dc=example,dc=com", map[string][]string{"objectClass": {"person"}, "cn": {"admin"}, "userPassword": {"adminpw"}})
	d.put("uid=alice,ou=people,dc=example,dc=com", map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {"alice"}, "cn": {"Alice"}, "mail": {"alice@example.com"}, "userPassword": {"alicepw"}})
	for i := 0; i < 25; i++ {
		uid := "user" + strconv.Itoa(i)
		d.put("uid="+uid+",ou=people,dc=example,dc=com", map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {uid}, "cn": {uid}})
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	d.addr = "ldap://" + l.Addr().String()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go d.serve(conn)
		}
	}()
	if tlsCfg != nil {
		ls, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ls.Close() })
		d.ldapsAddr = "ldaps://" + ls.Addr().String()
		go func() {
			for {
				conn, err := ls.Accept()
				if err != nil {
					return
				}
				go d.serve(conn)
			}
		}()
	}
	return d
}

func ldapResult(tag ber.Tag, code int, msg string) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, msg, ""))
	return op
}

func envelope(id int64, op *ber.Packet, controls ...ldap.Control) []byte {
	msg := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	msg.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	msg.AppendChild(op)
	if len(controls) > 0 {
		cs := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "")
		for _, c := range controls {
			cs.AppendChild(c.Encode())
		}
		msg.AppendChild(cs)
	}
	return msg.Bytes()
}

func pdata(p *ber.Packet) string {
	if p.Data != nil && p.Data.Len() > 0 {
		return p.Data.String()
	}
	if s, ok := p.Value.(string); ok {
		return s
	}
	return ""
}

func pint(p *ber.Packet) int64 {
	v, _ := p.Value.(int64)
	return v
}

func (d *mockDirectory) match(e *mockEntry, f *ber.Packet) bool {
	switch f.Tag {
	case 0: // and
		for _, c := range f.Children {
			if !d.match(e, c) {
				return false
			}
		}
		return true
	case 1: // or
		for _, c := range f.Children {
			if d.match(e, c) {
				return true
			}
		}
		return false
	case 2: // not
		return !d.match(e, f.Children[0])
	case 3: // equality
		for _, v := range e.attrs[strings.ToLower(pdata(f.Children[0]))] {
			if strings.EqualFold(v, pdata(f.Children[1])) {
				return true
			}
		}
		return false
	case 4: // substrings: initial / any / final
		attr := strings.ToLower(pdata(f.Children[0]))
		for _, v := range e.attrs[attr] {
			v, ok := strings.ToLower(v), true
			for _, sub := range f.Children[1].Children {
				s := strings.ToLower(pdata(sub))
				switch sub.Tag {
				case 0:
					ok = ok && strings.HasPrefix(v, s)
				case 1:
					ok = ok && strings.Contains(v, s)
				case 2:
					ok = ok && strings.HasSuffix(v, s)
				}
			}
			if ok {
				return true
			}
		}
		return false
	case 7: // present
		_, ok := e.attrs[strings.ToLower(pdata(f))]
		return ok
	}
	return false
}

func (d *mockDirectory) serve(conn net.Conn) {
	defer func() { conn.Close() }()
	_, encrypted := conn.(*tls.Conn)
	bound := ""
	write := func(b []byte) { conn.Write(b) }
	for {
		p, err := ber.ReadPacket(conn)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, op := pint(p.Children[0]), p.Children[1]
		var controls []*ber.Packet
		if len(p.Children) > 2 {
			controls = p.Children[2].Children
		}
		d.mu.Lock()
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			dn, pw := pdata(op.Children[1]), pdata(op.Children[2])
			if dn == "" && pw == "" {
				bound = ""
				write(envelope(id, ldapResult(ldap.ApplicationBindResponse, 0, "")))
			} else if e := d.lookupBind(dn); e != nil && len(e.attrs["userpassword"]) > 0 && e.attrs["userpassword"][0] == pw {
				bound = normDN(e.dn)
				write(envelope(id, ldapResult(ldap.ApplicationBindResponse, 0, "")))
			} else {
				write(envelope(id, ldapResult(ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "invalid credentials")))
			}
		case ldap.ApplicationUnbindRequest:
			d.mu.Unlock()
			return
		case ldap.ApplicationSearchRequest:
			base, scope, limit := normDN(pdata(op.Children[0])), pint(op.Children[1]), int(pint(op.Children[3]))
			filter, wanted := op.Children[6], map[string]bool{}
			for _, a := range op.Children[7].Children {
				wanted[strings.ToLower(pdata(a))] = true
			}
			if base == "" && scope == 0 {
				e := &mockEntry{dn: "", attrs: map[string][]string{"supportedldapversion": {"3"}, "namingcontexts": {"dc=example,dc=com"},
					"supportedcontrol":   {ldap.ControlTypePaging},
					"supportedextension": {ldap.ControlTypeWhoAmI, "1.3.6.1.4.1.4203.1.11.1"}},
					names: map[string]string{"supportedldapversion": "supportedLDAPVersion", "namingcontexts": "namingContexts", "supportedcontrol": "supportedControl", "supportedextension": "supportedExtension"}}
				if d.ad {
					e.attrs["supportedextension"] = []string{ldap.ControlTypeWhoAmI, "1.3.6.1.4.1.1466.20037"}
					e.attrs["supportedcapabilities"], e.names["supportedcapabilities"] = []string{"1.2.840.113556.1.4.800"}, "supportedCapabilities"
					e.attrs["defaultnamingcontext"], e.names["defaultnamingcontext"] = []string{"dc=example,dc=com"}, "defaultNamingContext"
				}
				write(envelope(id, entryPacket(e, nil)))
				write(envelope(id, ldapResult(ldap.ApplicationSearchResultDone, 0, "")))
				break
			}
			if d.entries[base] == nil {
				write(envelope(id, ldapResult(ldap.ApplicationSearchResultDone, ldap.LDAPResultNoSuchObject, "no such object")))
				break
			}
			var dns []string
			for k, e := range d.entries {
				in := k == base
				if scope == 1 {
					in = parentDN(k) == base
				} else if scope == 2 {
					in = in || strings.HasSuffix(k, ","+base)
				}
				if in && d.match(e, filter) {
					dns = append(dns, k)
				}
			}
			sort.Strings(dns)
			// Paged results (RFC 2696): the cookie is the offset of the next page.
			var paging *ldap.ControlPaging
			for _, c := range controls {
				if ctl, err := ldap.DecodeControl(c); err == nil {
					if pg, ok := ctl.(*ldap.ControlPaging); ok {
						paging = pg
					}
				}
			}
			start, end, code := 0, len(dns), 0
			var doneControls []ldap.Control
			if paging != nil {
				start, _ = strconv.Atoi(string(paging.Cookie))
				if end = start + int(paging.PagingSize); end >= len(dns) {
					end = len(dns)
				}
				next := &ldap.ControlPaging{}
				if end < len(dns) {
					next.SetCookie([]byte(strconv.Itoa(end)))
				}
				doneControls = append(doneControls, next)
			} else if limit > 0 && len(dns) > limit {
				end, code = limit, ldap.LDAPResultSizeLimitExceeded
			}
			// Without paging this server refuses more than 20 entries, like
			// directories with an administrative size limit.
			if paging == nil && end-start > 20 {
				end, code = start+20, ldap.LDAPResultSizeLimitExceeded
			}
			for _, k := range dns[start:end] {
				write(envelope(id, entryPacket(d.entries[k], wanted)))
			}
			write(envelope(id, ldapResult(ldap.ApplicationSearchResultDone, code, ""), doneControls...))
		case ldap.ApplicationAddRequest:
			dn := pdata(op.Children[0])
			code := d.writeAllowed(bound, dn)
			if code == 0 && d.entries[normDN(dn)] != nil {
				code = ldap.LDAPResultEntryAlreadyExists
			} else if code == 0 && d.entries[parentDN(dn)] == nil {
				code = ldap.LDAPResultNoSuchObject
			}
			if code == 0 {
				attrs := map[string][]string{}
				for _, a := range op.Children[1].Children {
					for _, v := range a.Children[1].Children {
						attrs[pdata(a.Children[0])] = append(attrs[pdata(a.Children[0])], pdata(v))
					}
				}
				d.put(dn, attrs)
			}
			write(envelope(id, ldapResult(ldap.ApplicationAddResponse, code, "")))
		case ldap.ApplicationDelRequest:
			dn := pdata(op)
			code := d.writeAllowed(bound, dn)
			if code == 0 && d.entries[normDN(dn)] == nil {
				code = ldap.LDAPResultNoSuchObject
			}
			for k := range d.entries {
				if code == 0 && parentDN(k) == normDN(dn) {
					code = ldap.LDAPResultNotAllowedOnNonLeaf
				}
			}
			if code == 0 {
				delete(d.entries, normDN(dn))
			}
			write(envelope(id, ldapResult(ldap.ApplicationDelResponse, code, "")))
		case ldap.ApplicationModifyRequest:
			dn := pdata(op.Children[0])
			if d.ad && d.adPassword(write, id, op, dn, bound, encrypted) {
				break
			}
			code := d.writeAllowed(bound, dn)
			e := d.entries[normDN(dn)]
			if code == 0 && e == nil {
				code = ldap.LDAPResultNoSuchObject
			}
			for _, ch := range op.Children[1].Children {
				if code != 0 {
					break
				}
				mod, attr := pint(ch.Children[0]), ch.Children[1]
				name := strings.ToLower(pdata(attr.Children[0]))
				var vals []string
				for _, v := range attr.Children[1].Children {
					vals = append(vals, pdata(v))
				}
				switch mod {
				case 0:
					e.attrs[name], e.names[name] = append(e.attrs[name], vals...), pdata(attr.Children[0])
				case 1:
					delete(e.attrs, name)
				case 2:
					e.attrs[name], e.names[name] = vals, pdata(attr.Children[0])
				}
			}
			write(envelope(id, ldapResult(ldap.ApplicationModifyResponse, code, "")))
		case ldap.ApplicationModifyDNRequest:
			dn, rdn, delOld := pdata(op.Children[0]), pdata(op.Children[1]), op.Children[2].Value == true
			parent := parentDN(dn)
			if len(op.Children) > 3 {
				parent = normDN(pdata(op.Children[3]))
			}
			code := d.writeAllowed(bound, dn)
			e := d.entries[normDN(dn)]
			newDN := rdn + "," + parent
			if code == 0 && e == nil {
				code = ldap.LDAPResultNoSuchObject
			} else if code == 0 && d.entries[normDN(newDN)] != nil {
				code = ldap.LDAPResultEntryAlreadyExists
			} else if code == 0 && d.entries[parent] == nil {
				code = ldap.LDAPResultNoSuchObject
			}
			if code == 0 {
				oldName, oldVal, _ := strings.Cut(strings.Split(dn, ",")[0], "=")
				newName, newVal, _ := strings.Cut(rdn, "=")
				if delOld {
					var keep []string
					for _, v := range e.attrs[strings.ToLower(oldName)] {
						if !strings.EqualFold(v, oldVal) {
							keep = append(keep, v)
						}
					}
					e.attrs[strings.ToLower(oldName)] = keep
				}
				e.attrs[strings.ToLower(newName)] = append(e.attrs[strings.ToLower(newName)], newVal)
				e.dn = newDN
				delete(d.entries, normDN(dn))
				d.entries[normDN(newDN)] = e
			}
			write(envelope(id, ldapResult(ldap.ApplicationModifyDNResponse, code, "")))
		case ldap.ApplicationCompareRequest:
			e := d.entries[normDN(pdata(op.Children[0]))]
			code := ldap.LDAPResultNoSuchObject
			if e != nil {
				code = ldap.LDAPResultCompareFalse
				for _, v := range e.attrs[strings.ToLower(pdata(op.Children[1].Children[0]))] {
					if strings.EqualFold(v, pdata(op.Children[1].Children[1])) {
						code = ldap.LDAPResultCompareTrue
					}
				}
			}
			write(envelope(id, ldapResult(ldap.ApplicationCompareResponse, code, "")))
		case ldap.ApplicationExtendedRequest:
			oid := pdata(op.Children[0])
			resp := ldapResult(ldap.ApplicationExtendedResponse, 0, "")
			if d.ad && oid == "1.3.6.1.4.1.4203.1.11.1" {
				oid = "unknown to AD"
			}
			switch oid {
			case "1.3.6.1.4.1.1466.20037": // StartTLS (RFC 4511 §4.14)
				if d.tlsCfg == nil || encrypted {
					resp = ldapResult(ldap.ApplicationExtendedResponse, ldap.LDAPResultOperationsError, "no StartTLS here")
					break
				}
				write(envelope(id, resp))
				conn, encrypted = tls.Server(conn, d.tlsCfg), true
				resp = nil
			case "unknown to AD":
				resp = ldapResult(ldap.ApplicationExtendedResponse, ldap.LDAPResultProtocolError, "0000203D: LdapErr: DSID-0C091282, comment: Unknown extended request OID, data 0, v4f7c\x00")
			case ldap.ControlTypeWhoAmI:
				authz := ""
				if bound != "" {
					authz = "dn:" + bound
				}
				resp.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, authz, ""))
			case "1.3.6.1.4.1.4203.1.11.1":
				var user, old, newPw string
				if len(op.Children) > 1 {
					if v, err := ber.DecodePacketErr(op.Children[1].Data.Bytes()); err == nil {
						for _, f := range v.Children {
							switch f.Tag {
							case 0:
								user = pdata(f)
							case 1:
								old = pdata(f)
							case 2:
								newPw = pdata(f)
							}
						}
					}
				}
				if user == "" {
					user = bound
				}
				e := d.entries[normDN(user)]
				code := d.writeAllowed(bound, user)
				if code == 0 && e == nil {
					code = ldap.LDAPResultNoSuchObject
				} else if code == 0 && old != "" && (len(e.attrs["userpassword"]) == 0 || e.attrs["userpassword"][0] != old) {
					code = ldap.LDAPResultUnwillingToPerform
				}
				if code != 0 {
					resp = ldapResult(ldap.ApplicationExtendedResponse, code, "password change refused")
					break
				}
				if newPw == "" {
					newPw = "gen-" + strconv.Itoa(len(d.entries))
					value := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
					value.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, newPw, ""))
					wrapped := ber.Encode(ber.ClassContext, ber.TypePrimitive, 11, nil, "")
					wrapped.Data.Write(value.Bytes())
					resp.AppendChild(wrapped)
				}
				e.attrs["userpassword"] = []string{newPw}
			default:
				resp = ldapResult(ldap.ApplicationExtendedResponse, ldap.LDAPResultProtocolError, "unsupported extended operation")
			}
			if resp != nil {
				write(envelope(id, resp))
			}
		}
		d.mu.Unlock()
	}
}

// writeAllowed: only the admin may change other entries; users may change
// themselves; anonymous sessions may change nothing.
func (d *mockDirectory) writeAllowed(bound, dn string) int {
	if bound == "" || (bound != "cn=admin,dc=example,dc=com" && bound != normDN(dn)) {
		return ldap.LDAPResultInsufficientAccessRights
	}
	return 0
}

func entryPacket(e *mockEntry, wanted map[string]bool) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, ""))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	all := len(wanted) == 0 || wanted["*"]
	for _, k := range sortedKeys(e.attrs) {
		if (!all && !wanted[k]) || k == "userpassword" || len(e.attrs[k]) == 0 {
			continue
		}
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.names[k], ""))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		for _, v := range e.attrs[k] {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
		}
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	op.AppendChild(attrs)
	return op
}

func TestLDAP(t *testing.T) {
	d := newMockDirectory(t)
	admin := M{"url": d.addr, "bind_dn": "cn=admin,dc=example,dc=com", "ldap_password": "adminpw"}
	with := func(base M, extra M) M {
		out := M{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	const jane = "uid=jane,ou=people,dc=example,dc=com"

	t.Run("rootdse, bind and who am I", func(t *testing.T) {
		res := run(t, "ldap.rootdse", M{"url": d.addr}, nil)
		noFailures(t, res)
		if fmt := strings.Join(res["root_dse"].(M)["supportedControl"].([]string), " "); !strings.Contains(fmt, "Paged results") {
			t.Errorf("paging control not named: %s", fmt)
		}
		b := run(t, "ldap.bind", admin, nil)
		noFailures(t, b)
		if b["authorization_id"] != "dn:cn=admin,dc=example,dc=com" {
			t.Errorf("who am I: %v", b["authorization_id"])
		}
		wantStatus(t, b, "transport is encrypted", "warn")
		wantStatus(t, run(t, "ldap.bind", with(admin, M{"ldap_password": "wrong"}), nil), "bind", "fail")
	})

	t.Run("paged search gets past the server's size limit", func(t *testing.T) {
		q := with(admin, M{"base_dn": "ou=people,dc=example,dc=com", "filter": "(uid=user*)", "attributes": []string{"uid"}, "limit": 1000})
		plain := run(t, "ldap.search", q, nil)
		if plain["truncated"] != true || plain["count"] != 20 {
			t.Errorf("unpaged search: count=%v truncated=%v", plain["count"], plain["truncated"])
		}
		paged := run(t, "ldap.search", with(q, M{"page_size": 7}), nil)
		noFailures(t, paged)
		if paged["count"] != 25 || paged["truncated"] != false {
			t.Errorf("paged search: count=%v truncated=%v", paged["count"], paged["truncated"])
		}
		capped := run(t, "ldap.search", with(q, M{"page_size": 7, "limit": 10}), nil)
		if capped["count"] != 10 || capped["truncated"] != true {
			t.Errorf("paged search with limit: count=%v truncated=%v", capped["count"], capped["truncated"])
		}
	})

	t.Run("add, compare, rename, delete", func(t *testing.T) {
		add := run(t, "ldap.add", with(admin, M{"dn": jane, "attributes": map[string]any{"objectClass": []any{"inetOrgPerson"}, "uid": "jane", "cn": "Jane", "mail": "jane@example.com"}}), nil)
		noFailures(t, add)
		wantStatus(t, run(t, "ldap.add", with(admin, M{"dn": jane, "attributes": map[string]any{"uid": "jane"}}), nil), "add", "fail")

		cmp := run(t, "ldap.compare", with(admin, M{"dn": jane, "attribute": "mail", "value": "jane@example.com"}), nil)
		if cmp["match"] != true {
			t.Errorf("compare should match: %+v", cmp)
		}
		if run(t, "ldap.compare", with(admin, M{"dn": jane, "attribute": "mail", "value": "x@example.com"}), nil)["match"] != false {
			t.Error("compare should not match")
		}

		moved := "uid=jane.doe,dc=example,dc=com"
		ren := run(t, "ldap.rename", with(admin, M{"dn": jane, "new_rdn": "uid=jane.doe", "new_superior": "dc=example,dc=com"}), nil)
		noFailures(t, ren)
		if ren["new_dn"] != moved {
			t.Errorf("new_dn=%v", ren["new_dn"])
		}
		found := run(t, "ldap.search", with(admin, M{"base_dn": moved, "scope": "base", "attributes": []string{"uid"}}), nil)
		if uids := found["entries"].([]M)[0]["attributes"].(M)["uid"].([]any); len(uids) != 1 || uids[0] != "jane.doe" {
			t.Errorf("old RDN value should be gone: %v", uids)
		}

		wantStatus(t, run(t, "ldap.delete", with(admin, M{"dn": "ou=people,dc=example,dc=com"}), nil), "delete", "fail")
		noFailures(t, run(t, "ldap.delete", with(admin, M{"dn": moved}), nil))
		wantStatus(t, run(t, "ldap.compare", with(admin, M{"dn": moved, "attribute": "uid", "value": "jane.doe"}), nil), "compare", "fail")
	})

	t.Run("writes need a user with rights", func(t *testing.T) {
		anon := run(t, "ldap.add", M{"url": d.addr, "dn": jane, "attributes": map[string]any{"uid": "jane"}}, nil)
		wantStatus(t, anon, "add", "fail")
		wantStatus(t, anon, "bound as a user", "warn")
		alice := M{"url": d.addr, "bind_dn": "uid=alice,ou=people,dc=example,dc=com", "ldap_password": "alicepw"}
		wantStatus(t, run(t, "ldap.delete", with(alice, M{"dn": "uid=user1,ou=people,dc=example,dc=com"}), nil), "delete", "fail")
	})

	t.Run("password modify", func(t *testing.T) {
		alice := M{"url": d.addr, "bind_dn": "uid=alice,ou=people,dc=example,dc=com", "ldap_password": "alicepw"}
		noFailures(t, run(t, "ldap.passwd", with(alice, M{"old_password": "alicepw", "new_password": "alicepw2"}), nil))
		wantStatus(t, run(t, "ldap.bind", alice, nil), "bind", "fail")
		alice["ldap_password"] = "alicepw2"
		noFailures(t, run(t, "ldap.bind", alice, nil))
		wantStatus(t, run(t, "ldap.passwd", with(alice, M{"old_password": "not-it", "new_password": "x"}), nil), "password modify", "fail")

		gen := run(t, "ldap.passwd", with(admin, M{"user_dn": "uid=alice,ou=people,dc=example,dc=com"}), nil)
		noFailures(t, gen)
		pw := str(gen["generated_password"])
		if pw == "" {
			t.Fatal("no generated password returned")
		}
		alice["ldap_password"] = pw
		noFailures(t, run(t, "ldap.bind", alice, nil))
	})

	t.Run("only ldap and ldaps URLs", func(t *testing.T) {
		if _, err := runOp(t.Context(), findOp("ldap.bind"), M{"url": strings.Replace(d.addr, "ldap://", "cldap://", 1)}, false, nil); err == nil {
			t.Error("cldap:// was dialled")
		}
	})
	_ = errors.New
}

// lookupBind finds the entry a bind name refers to: a DN, or in AD mode a
// userPrincipalName.
func (d *mockDirectory) lookupBind(name string) *mockEntry {
	if e := d.entries[normDN(name)]; e != nil {
		return e
	}
	if d.ad {
		for _, e := range d.entries {
			if v := e.attrs["userprincipalname"]; len(v) > 0 && strings.EqualFold(v[0], name) {
				return e
			}
		}
	}
	return nil
}

// adPassword handles a modify of unicodePwd the way Active Directory does,
// with its diagnostic messages. It reports whether the request was one.
func (d *mockDirectory) adPassword(write func([]byte), id int64, op *ber.Packet, dn, bound string, encrypted bool) bool {
	type change struct {
		mod int64
		pw  string
	}
	var changes []change
	for _, ch := range op.Children[1].Children {
		attr := ch.Children[1]
		if !strings.EqualFold(pdata(attr.Children[0]), "unicodePwd") {
			return false
		}
		for _, v := range attr.Children[1].Children {
			b := []byte(pdata(v))
			u := make([]uint16, len(b)/2)
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(b[2*i:])
			}
			pw := string(utf16.Decode(u))
			if len(pw) < 2 || pw[0] != '"' || pw[len(pw)-1] != '"' {
				pw = "\x00malformed"
			}
			changes = append(changes, change{pint(ch.Children[0]), strings.Trim(pw, `"`)})
		}
	}
	d.pwdModifies++
	reply := func(code int, msg string) {
		write(envelope(id, ldapResult(ldap.ApplicationModifyResponse, code, msg)))
	}
	e := d.entries[normDN(dn)]
	switch {
	case !encrypted:
		reply(ldap.LDAPResultUnwillingToPerform, "0000001F: SvcErr: DSID-031A126C, problem 5003 (WILL_NOT_PERFORM), data 0\n\x00")
	case e == nil:
		reply(ldap.LDAPResultNoSuchObject, "0000208D: NameErr: DSID-03100241, problem 2001 (NO_OBJECT)\x00")
	case len(changes) == 2 && changes[0].mod == 1 && changes[1].mod == 0 && bound == normDN(dn):
		if len(e.attrs["userpassword"]) == 0 || e.attrs["userpassword"][0] != changes[0].pw {
			reply(ldap.LDAPResultConstraintViolation, "00000056: AtrErr: DSID-03191039, #1:\n\t0: 00000056: DSID-03191039, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)\n\x00")
		} else if len(changes[1].pw) < 7 {
			reply(ldap.LDAPResultConstraintViolation, "0000052D: AtrErr: DSID-03191039, #1:\n\t0: 0000052D: DSID-03191039, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)\n\x00")
		} else {
			e.attrs["userpassword"] = []string{changes[1].pw}
			reply(0, "")
		}
	case len(changes) == 1 && changes[0].mod == 2 && bound == "cn=admin,dc=example,dc=com":
		e.attrs["userpassword"] = []string{changes[0].pw}
		reply(0, "")
	default:
		reply(ldap.LDAPResultInsufficientAccessRights, "00000005: SecErr: DSID-031A11E3, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0\n\x00")
	}
	return true
}

// testServerTLS issues a server certificate for 127.0.0.1 from a new CA and
// returns the server configuration and the CA certificate in PEM.
func testServerTLS(t *testing.T) (*tls.Config, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Directory CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "dc.example.com"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	return cfg, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
}

func TestLDAPActiveDirectoryPasswords(t *testing.T) {
	srvTLS, caPEM := testServerTLS(t)
	d := newMockDir(t, true, srvTLS)
	d.mu.Lock()
	alice := d.entries["uid=alice,ou=people,dc=example,dc=com"]
	alice.attrs["userprincipalname"], alice.names["userprincipalname"] = []string{"alice@example.com"}, "userPrincipalName"
	alice.attrs["objectclass"] = append(alice.attrs["objectclass"], "user")
	d.mu.Unlock()
	aliceDN := "uid=alice,ou=people,dc=example,dc=com"
	with := func(base M, extra M) M {
		out := M{}
		for _, m := range []M{base, extra} {
			for k, v := range m {
				out[k] = v
			}
		}
		return out
	}

	t.Run("ca_cert makes LDAPS and StartTLS verify", func(t *testing.T) {
		if _, err := runOp(context.Background(), findOp("ldap.rootdse"), M{"url": d.ldapsAddr}, false, nil); err == nil {
			t.Error("LDAPS verified without the CA")
		}
		wantStatus(t, run(t, "ldap.rootdse", M{"url": d.ldapsAddr, "ca_cert": caPEM}, nil), "transport is encrypted", "pass")
		// StartTLS must verify the URL's host too (it once had no server name).
		wantStatus(t, run(t, "ldap.rootdse", M{"url": d.addr, "starttls": true, "ca_cert": caPEM}, nil), "transport is encrypted", "pass")
		if _, err := runOp(context.Background(), findOp("ldap.rootdse"), M{"url": d.addr, "starttls": true}, false, nil); err == nil {
			t.Error("StartTLS verified without the CA")
		}
		if _, err := runOp(context.Background(), findOp("ldap.rootdse"), M{"url": d.ldapsAddr, "ca_cert": "not a certificate"}, false, nil); err == nil {
			t.Error("a ca_cert without a certificate was accepted")
		}
	})

	upn := M{"url": d.ldapsAddr, "ca_cert": caPEM, "bind_dn": "alice@example.com", "ldap_password": "alicepw"}
	t.Run("plain LDAP: refused before sending", func(t *testing.T) {
		res := run(t, "ldap.passwd", with(upn, M{"url": d.addr, "old_password": "alicepw", "new_password": "Alice-pw-2"}), nil)
		wantStatus(t, res, "password change (unicodePwd)", "fail")
		if d.pwdModifies != 0 {
			t.Error("the password went over an unencrypted connection")
		}
	})

	t.Run("refusals carry AD's reason", func(t *testing.T) {
		for _, tc := range []struct {
			args M
			want string
		}{
			{M{"old_password": "wrong", "new_password": "Alice-pw-2"}, "current password"},
			{M{"old_password": "alicepw", "new_password": "short"}, "password policy"},
			{M{"old_password": "alicepw"}, "cannot generate"},
			{M{"old_password": "alicepw", "new_password": "Alice-pw-2", "method": "extended"}, "use method unicodepwd"},
			{M{"user_dn": "uid=user1,ou=people,dc=example,dc=com", "new_password": "User1-pw-2"}, "Reset Password right"},
		} {
			res := run(t, "ldap.passwd", with(upn, tc.args), nil)
			var detail string
			for _, c := range res["checks"].(Checks) {
				if c.Status == "fail" {
					detail = c.Detail
				}
			}
			if !strings.Contains(detail, tc.want) || strings.ContainsAny(detail, "\x00\n") {
				t.Errorf("%v: %q, want %q on one line", tc.args, detail, tc.want)
			}
		}
	})

	t.Run("change own password, then an administrative reset", func(t *testing.T) {
		res := run(t, "ldap.passwd", with(upn, M{"url": d.addr, "starttls": true, "old_password": "alicepw", "new_password": "Alice-pw-2"}), nil)
		noFailures(t, res)
		if res["method"] != "unicodepwd" || res["user_dn"] != aliceDN {
			t.Errorf("method %v, user %v", res["method"], res["user_dn"])
		}
		noFailures(t, run(t, "ldap.bind", with(upn, M{"ldap_password": "Alice-pw-2"}), nil))

		admin := M{"url": d.ldapsAddr, "ca_cert": caPEM, "bind_dn": "cn=admin,dc=example,dc=com", "ldap_password": "adminpw"}
		noFailures(t, run(t, "ldap.passwd", with(admin, M{"user_dn": aliceDN, "new_password": "Alice-pw-3"}), nil))
		noFailures(t, run(t, "ldap.bind", with(upn, M{"ldap_password": "Alice-pw-3"}), nil))
	})
}
