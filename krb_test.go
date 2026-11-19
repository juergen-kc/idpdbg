package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
)

// mockKDC is a small in-process KDC speaking RFC 4120 over TCP: AS and TGS
// exchanges, PA-ENC-TIMESTAMP pre-authentication, AES and RC4 service keys.
type mockKDC struct {
	realm     string
	addr      string
	kt        *keytab.Keytab // krbtgt and every service
	users     map[string]string
	noPreauth map[string]bool
	services  map[string]int32 // SPN -> ticket etype
	asReqs    int              // AS-REQs received
	mu        sync.Mutex
	pk        *mockPKINIT // answers PKINIT when set (krb_pkinit_test.go)
}

func newMockKDC(t *testing.T, realm string) *mockKDC {
	k := &mockKDC{realm: realm, kt: keytab.New(), users: map[string]string{}, noPreauth: map[string]bool{}, services: map[string]int32{}}
	k.kt.AddEntry("krbtgt/"+realm, realm, "krbtgt-secret", time.Now(), 1, 18)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	k.addr = l.Addr().String()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go k.serve(conn)
		}
	}()
	return k
}

// addService registers an SPN and returns a keytab holding only its key.
func (k *mockKDC) addService(spn, password string, etype int32) *keytab.Keytab {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.kt.AddEntry(spn, k.realm, password, time.Now(), 1, etype)
	k.services[spn] = etype
	svc := keytab.New()
	svc.AddEntry(spn, k.realm, password, time.Now(), 1, etype)
	return svc
}

func (k *mockKDC) serve(conn net.Conn) {
	defer conn.Close()
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	b := make([]byte, binary.BigEndian.Uint32(hdr))
	if _, err := io.ReadFull(conn, b); err != nil {
		return
	}
	var reply []byte
	k.mu.Lock()
	switch b[0] {
	case 0x6a:
		k.asReqs++
		reply = k.as(b)
	case 0x6c:
		reply = k.tgs(b)
	}
	k.mu.Unlock()
	binary.BigEndian.PutUint32(hdr, uint32(len(reply)))
	conn.Write(append(hdr, reply...))
}

func (k *mockKDC) krbErr(sname types.PrincipalName, code int32, edata []byte) []byte {
	e := messages.NewKRBError(sname, k.realm, code, errorcode.Lookup(code))
	e.EData = edata
	b, _ := e.Marshal()
	return b
}

func (k *mockKDC) ticketFlags(preauth bool) asn1.BitString {
	f := types.NewKrbFlags()
	types.SetFlags(&f, []int{flags.Forwardable, flags.Renewable})
	if preauth {
		types.SetFlag(&f, flags.PreAuthent)
	}
	return f
}

func (k *mockKDC) as(b []byte) []byte {
	var req messages.ASReq
	if err := req.Unmarshal(b); err != nil {
		return nil
	}
	tgs := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+k.realm)
	if k.pk != nil {
		if rep := k.pkinitAS(req, b); rep != nil {
			return rep
		}
	}
	user := req.ReqBody.CName.PrincipalNameString()
	pw, ok := k.users[user]
	if !ok {
		return k.krbErr(tgs, errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, nil)
	}
	clientKey, _, _ := crypto.GetKeyFromPassword(pw, req.ReqBody.CName, k.realm, 18, types.PADataSequence{})
	info, _ := asn1.Marshal(types.ETypeInfo2{{EType: 18, Salt: k.realm + user}})
	etypeInfo := types.PAData{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info}
	preauth := false
	if !k.noPreauth[user] {
		var ts *types.PAData
		for i := range req.PAData {
			if req.PAData[i].PADataType == patype.PA_ENC_TIMESTAMP {
				ts = &req.PAData[i]
			}
		}
		if ts == nil {
			edata, _ := asn1.Marshal(types.PADataSequence{etypeInfo, {PADataType: patype.PA_ENC_TIMESTAMP}})
			return k.krbErr(tgs, errorcode.KDC_ERR_PREAUTH_REQUIRED, edata)
		}
		var ed types.EncryptedData
		if ed.Unmarshal(ts.PADataValue) != nil {
			return k.krbErr(tgs, errorcode.KDC_ERR_PREAUTH_FAILED, nil)
		}
		plain, err := crypto.DecryptEncPart(ed, clientKey, keyusage.AS_REQ_PA_ENC_TIMESTAMP)
		var pts types.PAEncTSEnc
		if err != nil || pts.Unmarshal(plain) != nil || time.Since(pts.PATimestamp).Abs() > 5*time.Minute {
			return k.krbErr(tgs, errorcode.KDC_ERR_PREAUTH_FAILED, nil)
		}
		preauth = true
	}
	now := time.Now().UTC().Truncate(time.Second)
	f := k.ticketFlags(preauth)
	tkt, sess, err := messages.NewTicket(req.ReqBody.CName, k.realm, tgs, k.realm, f, k.kt, 18, 1, now, now, now.Add(10*time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		return nil
	}
	enc := messages.EncKDCRepPart{Key: sess, LastReqs: []messages.LastReq{{LRType: 0, LRValue: now}}, Nonce: req.ReqBody.Nonce, Flags: f,
		AuthTime: now, StartTime: now, EndTime: now.Add(10 * time.Hour), RenewTill: now.Add(7 * 24 * time.Hour), SRealm: k.realm, SName: tgs}
	eb, _ := enc.Marshal()
	ed, _ := crypto.GetEncryptedData(eb, clientKey, keyusage.AS_REP_ENCPART, 1)
	rep := messages.ASRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 11, PAData: []types.PAData{etypeInfo}, CRealm: k.realm, CName: req.ReqBody.CName, Ticket: tkt, EncPart: ed}}
	rb, _ := rep.Marshal()
	return rb
}

func (k *mockKDC) tgs(b []byte) []byte {
	var req messages.TGSReq
	if err := req.Unmarshal(b); err != nil {
		return nil
	}
	sname := req.ReqBody.SName
	var ap messages.APReq
	for _, pa := range req.PAData {
		if pa.PADataType == patype.PA_TGS_REQ {
			ap.Unmarshal(pa.PADataValue)
		}
	}
	if err := ap.Ticket.DecryptEncPart(k.kt, nil); err != nil {
		return k.krbErr(sname, errorcode.KRB_AP_ERR_BAD_INTEGRITY, nil)
	}
	sess := ap.Ticket.DecryptedEncPart.Key
	if ap.DecryptAuthenticator(sess) != nil {
		return k.krbErr(sname, errorcode.KRB_AP_ERR_BAD_INTEGRITY, nil)
	}
	et, ok := k.services[sname.PrincipalNameString()]
	if !ok {
		return k.krbErr(sname, errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, nil)
	}
	now := time.Now().UTC().Truncate(time.Second)
	cname := ap.Ticket.DecryptedEncPart.CName
	f := k.ticketFlags(true)
	tkt, svcSess, err := messages.NewTicket(cname, k.realm, sname, k.realm, f, k.kt, et, 1, now, now, now.Add(10*time.Hour), now.Add(7*24*time.Hour))
	if err != nil {
		return nil
	}
	enc := messages.EncKDCRepPart{Key: svcSess, LastReqs: []messages.LastReq{{LRType: 0, LRValue: now}}, Nonce: req.ReqBody.Nonce, Flags: f,
		AuthTime: now, StartTime: now, EndTime: now.Add(10 * time.Hour), RenewTill: now.Add(7 * 24 * time.Hour), SRealm: k.realm, SName: sname}
	eb, _ := asn1.Marshal(enc)
	eb = asn1tools.AddASNAppTag(eb, 26) // EncTGSRepPart
	ed, _ := crypto.GetEncryptedData(eb, sess, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
	rep := messages.TGSRep{KDCRepFields: messages.KDCRepFields{PVNO: 5, MsgType: 13, CRealm: k.realm, CName: cname, Ticket: tkt, EncPart: ed}}
	rb, _ := rep.Marshal()
	return rb
}

func ktBase64(t *testing.T, kt *keytab.Keytab) string {
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func TestKerberos(t *testing.T) {
	kdc := newMockKDC(t, "IDPDBG.TEST")
	kdc.users["alice"] = "alice-pw"
	kdc.users["legacy"] = "legacy-pw"
	kdc.noPreauth["legacy"] = true
	webKT := kdc.addService("HTTP/web.idpdbg.test", "web-secret", 18)
	oldKT := kdc.addService("MSSQLSvc/db.idpdbg.test", "db-secret", 23)
	alice := M{"principal": "alice@IDPDBG.TEST", "password": "alice-pw", "kdc": kdc.addr}
	with := func(base, extra M) M {
		out := M{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}

	t.Run("kinit", func(t *testing.T) {
		res := run(t, "krb.kinit", alice, nil)
		noFailures(t, res)
		for _, n := range []string{"pre-authentication enforced", "AS exchange", "TGT session key: encryption type", "ticket flag pre-authent", "clock skew"} {
			wantStatus(t, res, n, "pass")
		}
		if res["tgt"].(M)["server"] != "krbtgt/IDPDBG.TEST@IDPDBG.TEST" {
			t.Errorf("tgt: %v", res["tgt"])
		}
		if salts := res["preauth_probe"].(M)["pa_data"].([]M)[0]["etype_info2"].([]M); salts[0]["salt"] != "IDPDBG.TESTalice" {
			t.Errorf("salt: %v", salts)
		}
		wantStatus(t, run(t, "krb.kinit", with(alice, M{"password": "wrong"}), nil), "AS exchange", "fail")
		wantStatus(t, run(t, "krb.kinit", M{"principal": "legacy@IDPDBG.TEST", "password": "legacy-pw", "kdc": kdc.addr}, nil), "pre-authentication enforced", "warn")
		wantStatus(t, run(t, "krb.kinit", M{"principal": "nobody@IDPDBG.TEST", "password": "x", "kdc": kdc.addr}, nil), "client principal known", "fail")
	})

	t.Run("service ticket, decrypt and SPNEGO token", func(t *testing.T) {
		res := run(t, "krb.service_ticket", with(alice, M{"spn": "HTTP/web.idpdbg.test", "service_keytab": ktBase64(t, webKT), "spnego_token": true}), nil)
		noFailures(t, res)
		wantStatus(t, res, "service ticket decrypts with the service keytab", "pass")
		if res["ticket_contents"].(M)["client"] != "alice@IDPDBG.TEST" {
			t.Errorf("ticket contents: %v", res["ticket_contents"])
		}
		wantStatus(t, res, "PAC present", "info")
		hdr := str(res["authorization_header"])
		dec := run(t, "krb.decode", M{"message": hdr, "keytab": ktBase64(t, webKT)}, nil)
		noFailures(t, dec)
		if dec["type"] != "SPNEGO NegTokenInit" || !strings.Contains(dec["mech_types"].([]string)[0], "Kerberos") {
			t.Errorf("decoded header: %v", dec)
		}
		wantStatus(t, dec, "authenticator client matches the ticket", "pass")
		wantStatus(t, dec, "authenticator is fresh", "pass")
		wantStatus(t, run(t, "krb.decode", M{"message": hdr, "keytab": ktBase64(t, oldKT)}, nil), "ticket decrypts with the keytab", "fail")
		wantStatus(t, run(t, "krb.service_ticket", with(alice, M{"spn": "HTTP/web.idpdbg.test", "service_keytab": ktBase64(t, oldKT)}), nil), "service ticket decrypts", "fail")
	})

	t.Run("RC4 service is Kerberoastable", func(t *testing.T) {
		res := run(t, "krb.service_ticket", with(alice, M{"spn": "MSSQLSvc/db.idpdbg.test", "etypes": "aes256-cts-hmac-sha1-96,rc4-hmac"}), nil)
		wantStatus(t, res, "service ticket: encryption type", "warn")
		wantStatus(t, res, "service account exposure", "warn")
		wantStatus(t, run(t, "krb.service_ticket", with(alice, M{"spn": "HTTP/missing.idpdbg.test"}), nil), "TGS exchange", "fail")
	})

	t.Run("keytab", func(t *testing.T) {
		res := run(t, "krb.keytab", M{"keytab": ktBase64(t, kdc.kt)}, nil)
		if n := len(res["entries"].([]M)); n != 3 {
			t.Errorf("entries: %d", n)
		}
		wantStatus(t, res, "keytab MSSQLSvc/db.idpdbg.test@IDPDBG.TEST: rc4-hmac", "warn")
	})

	t.Run("decode KRB-ERROR with salts", func(t *testing.T) {
		probe := run(t, "krb.kinit", alice, nil)["preauth_probe"].(M)
		if probe["error"] != errorcode.Lookup(errorcode.KDC_ERR_PREAUTH_REQUIRED) {
			t.Errorf("probe error: %v", probe["error"])
		}
	})

	t.Run("SPNEGO web single sign-on", func(t *testing.T) {
		svcKT := kdc.addService("HTTP/127.0.0.1", "http-secret", 18)
		inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "hello") })
		srv := httptest.NewServer(spnego.SPNEGOKRB5Authenticate(inner, svcKT))
		defer srv.Close()
		res := run(t, "spnego.http", with(alice, M{"url": srv.URL}), nil)
		noFailures(t, res)
		wantStatus(t, res, "server offers Negotiate", "pass")
		wantStatus(t, res, "request accepted with the Kerberos ticket", "pass")
		if res["body"] != "hello" {
			t.Errorf("body: %v", res["body"])
		}
	})

	t.Run("config values cannot inject krb5.conf lines", func(t *testing.T) {
		for _, raw := range []M{
			with(alice, M{"realm": "IDPDBG.TEST\n[realms]\n EVIL = {"}),
			with(alice, M{"etypes": "aes256-cts-hmac-sha1-96\n dns_lookup_kdc = true"}),
			with(alice, M{"kdc": "127.0.0.1:88\n kdc = evil.example"}),
		} {
			if _, err := runOp(t.Context(), findOp("krb.kinit"), raw, false, nil); err == nil {
				t.Errorf("accepted %v", raw)
			}
		}
	})

	t.Run("a krb5.conf with DNS lookups and other realms is pinned to the checked KDC", func(t *testing.T) {
		dir := filepath.ToSlash(t.TempDir()) // goes into JSON below
		t.Setenv("IDPDBG_CONFIG", dir+"/c.json")
		conf := "[libdefaults]\n default_realm = IDPDBG.TEST\n dns_lookup_kdc = true\n udp_preference_limit = 1\n[realms]\n IDPDBG.TEST = {\n  kdc = " + kdc.addr + "\n }\n OTHER.TEST = {\n  kdc = evil.example:88\n }\n"
		os.WriteFile(dir+"/krb5.conf", []byte(conf), 0o600)
		os.WriteFile(dir+"/c.json", []byte(`{"profiles":{"k":{"principal":"alice","password":"alice-pw","kdc":"`+kdc.addr+`","krb5_conf":"`+dir+`/krb5.conf"}}}`), 0o600)
		noFailures(t, run(t, "krb.kinit", M{"profile": "k"}, nil))
	})

	t.Run("a stored password only goes to the profile's KDC", func(t *testing.T) {
		dir := filepath.ToSlash(t.TempDir()) // goes into JSON below
		t.Setenv("IDPDBG_CONFIG", dir+"/c.json")
		os.WriteFile(dir+"/c.json", []byte(`{"profiles":{"k":{"principal":"alice@IDPDBG.TEST","password":"alice-pw","kdc":"`+kdc.addr+`"}}}`), 0o600)
		noFailures(t, run(t, "krb.kinit", M{"profile": "k"}, nil))
		if _, err := runOp(t.Context(), findOp("krb.kinit"), M{"profile": "k", "kdc": "evil.example:88"}, false, nil); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Errorf("stored password sent to a caller-chosen KDC: %v", err)
		}
		// No Negotiate header minted from stored credentials for an MCP caller...
		st := run(t, "krb.service_ticket", M{"profile": "k", "spn": "HTTP/web.idpdbg.test", "spnego_token": true}, nil)
		if st["authorization_header"] != nil {
			t.Error("MCP caller received a Negotiate header minted from a stored password")
		}
		// ...but explicitly passed credentials still get one.
		if run(t, "krb.service_ticket", with(alice, M{"spn": "HTTP/web.idpdbg.test", "spnego_token": true}), nil)["authorization_header"] == nil {
			t.Error("explicit credentials should still produce a header")
		}
		// spnego.http with a stored credential only sends a ticket for the URL's own host.
		os.WriteFile(dir+"/c.json", []byte(`{"profiles":{"k":{"principal":"alice@IDPDBG.TEST","password":"alice-pw","kdc":"`+kdc.addr+`","url":"http://127.0.0.1:1"}}}`), 0o600)
		if _, err := runOp(t.Context(), findOp("spnego.http"), M{"profile": "k", "url": "http://127.0.0.1:1/", "spn": "HTTP/web.idpdbg.test"}, false, nil); err == nil || !strings.Contains(err.Error(), "refusing a ticket") {
			t.Errorf("ticket for another SPN sent to the URL: %v", err)
		}
	})
}

func TestPACVector(t *testing.T) {
	// A real Active Directory PAC and the service keytab from gokrb5's test data.
	pacHex := testdata.MarshaledPAC_AD_WIN2K_PAC
	ktBytes, _ := hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	kt := base64.StdEncoding.EncodeToString(ktBytes)
	args := M{"pac": pacHex, "keytab": kt, "service_principal": "sysHTTP", "realm": "TEST.GOKRB5", "kvno": 2}
	res := run(t, "krb.pac", args, nil)
	noFailures(t, res)
	li := res["pac"].(M)["logon_info"].(M)
	if li["effective_name"] == "" || !strings.HasPrefix(str(li["domain_sid"]), "S-1-5-21-") || len(li["group_sids"].([]string)) == 0 {
		t.Errorf("logon info: %v", li)
	}
	if res["pac"].(M)["upn_dns_info"].(M)["dns_domain"] == "" {
		t.Errorf("UPN/DNS info: %v", res["pac"])
	}
	// One flipped byte in the logon info breaks the server signature.
	b, _ := hex.DecodeString(pacHex)
	b[len(b)/3] ^= 0x01
	tampered, err := runOp(t.Context(), findOp("krb.pac"), M{"pac": hex.EncodeToString(b), "keytab": kt, "service_principal": "sysHTTP", "realm": "TEST.GOKRB5", "kvno": 2}, false, nil)
	if err == nil {
		wantStatus(t, tampered, "PAC server signature", "fail")
	}
}
