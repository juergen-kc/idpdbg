package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/pac"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/jcmturner/rpc/v2/mstypes"
)

// Regressions found against a Windows Server 2022 domain controller.

// A decrypted S4U2Self ticket must go back to the KDC as its four ASN.1
// fields only: gokrb5 marshals DecryptedEncPart too, and Windows silently
// drops the malformed S4U2Proxy request.
func TestS4U2ProxyEvidenceTicketIsClean(t *testing.T) {
	realm := "IDPDBG.TEST"
	svc := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "svc-web")
	s := &krbSetup{cfg: config.New(), realm: realm, cname: svc}
	sk := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{1}, 32)}
	tgt := messages.Ticket{TktVNO: 5, Realm: realm, SName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm),
		EncPart: types.EncryptedData{EType: 18, KVNO: 2, Cipher: []byte("tgt")}}
	evidence := messages.Ticket{TktVNO: 5, Realm: realm, SName: svc, EncPart: types.EncryptedData{EType: 18, KVNO: 2, Cipher: []byte("evidence")}}
	evidence.DecryptedEncPart = messages.EncTicketPart{CName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"), CRealm: realm,
		Key: sk, AuthTime: time.Now(), EndTime: time.Now().Add(time.Hour)}

	clean := evidence
	clean.DecryptedEncPart = messages.EncTicketPart{}
	want, _ := clean.Marshal()
	dirty, _ := evidence.Marshal()
	if bytes.Equal(want, dirty) {
		t.Fatal("gokrb5 no longer marshals DecryptedEncPart; this test needs a new way to detect it")
	}

	req, err := newS4U2ProxyReq(s, tgt, sk, evidence, types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/app.idpdbg.test"), true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, want) || bytes.Contains(b, dirty) {
		t.Error("S4U2Proxy request carries the decrypted part of the evidence ticket")
	}
	if !evidence.DecryptedEncPart.CName.Equal(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")) {
		t.Error("the caller's ticket was modified")
	}
}

func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

// Windows Server 2022 PACs carry buffers gokrb5 does not decode: the
// extended UPN_DNS_INFO, PAC_ATTRIBUTES_INFO and PAC_REQUESTOR.
func TestDescribePACWindowsBuffers(t *testing.T) {
	sid := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0}
	for _, r := range []uint32{604731677, 72106263, 1373082493, 1103} {
		sid = binary.LittleEndian.AppendUint32(sid, r)
	}
	upn, dns, sam := utf16le("alice@idpdbg.test"), utf16le("IDPDBG.TEST"), utf16le("alice")
	u := make([]byte, 20)
	off := 20
	put := func(at int, v []byte) {
		binary.LittleEndian.PutUint16(u[at:], uint16(len(v)))
		binary.LittleEndian.PutUint16(u[at+2:], uint16(off))
		off += len(v)
	}
	put(0, upn)
	put(4, dns)
	binary.LittleEndian.PutUint32(u[8:], 2) // S: extended
	put(12, sam)
	put(16, sid)
	u = append(append(append(append(u, upn...), dns...), sam...), sid...)
	attrs := []byte{2, 0, 0, 0, 1, 0, 0, 0} // 2 bits: PAC_WAS_REQUESTED

	var data []byte
	var bufs []pac.InfoBuffer
	for _, b := range []struct {
		typ uint32
		v   []byte
	}{{12, u}, {17, attrs}, {18, sid}, {19, make([]byte, 16)}} {
		bufs = append(bufs, pac.InfoBuffer{ULType: b.typ, CBBufferSize: uint32(len(b.v)), Offset: uint64(len(data))})
		data = append(data, b.v...)
		for len(data)%8 != 0 {
			data = append(data, 0)
		}
	}
	p := &pac.PACType{Buffers: bufs, Data: data, UPNDNSInfo: &pac.UPNDNSInfo{UPN: "alice@idpdbg.test", DNSDomain: "IDPDBG.TEST", Flags: 2}}
	out := describePAC(p)
	ui := out["upn_dns_info"].(M)
	if ui["sam_name"] != "alice" || ui["sid"] != "S-1-5-21-604731677-72106263-1373082493-1103" {
		t.Errorf("extended UPN_DNS_INFO: %v", ui)
	}
	if a := out["attributes"].(M); a["pac_was_requested"] != true || a["pac_was_given_implicitly"] != false {
		t.Errorf("attributes: %v", a)
	}
	if out["requestor_sid"] != "S-1-5-21-604731677-72106263-1373082493-1103" {
		t.Errorf("requestor: %v", out["requestor_sid"])
	}
	if bt := out["buffer_types"].([]string); len(bt) != 4 || bt[3] != "full checksum" {
		t.Errorf("buffer types: %v", bt)
	}
	// Truncated or malformed SIDs are ignored, not misread.
	for _, bad := range [][]byte{nil, sid[:10], append(append([]byte{}, sid...), 0)} {
		if _, ok := sidString(bad); ok {
			t.Errorf("sidString accepted %x", bad)
		}
	}
}

func TestLDAPActiveDirectoryValues(t *testing.T) {
	// Values read from a Windows Server 2022 DC (Get-ADUser agrees).
	g, _ := base64.StdEncoding.DecodeString("S1dslLhD8EerRAw9slxBew==")
	if s, _ := guidString(g); s != "946c574b-43b8-47f0-ab44-0c3db25c417b" {
		t.Errorf("guid: %s", s)
	}
	if s, _ := fileTime("134395105272036685"); s != "2026-11-18T21:22:07Z" {
		t.Errorf("pwdLastSet: %s", s)
	}
	if s, _ := fileTime("9223372036854775807"); s != "never" {
		t.Errorf("accountExpires: %s", s)
	}
	uac := adDecoded("userAccountControl", []string{"16843264"}).([]string)
	if len(uac) != 3 || uac[2] != "TRUSTED_TO_AUTH_FOR_DELEGATION" {
		t.Errorf("uac: %v", uac)
	}
	if et := adDecoded("msDS-SupportedEncryptionTypes", []string{"24"}).([]string); len(et) != 2 {
		t.Errorf("enctypes: %v", et)
	}
	if v := flagNames(0x200|0x8000000, uacFlags); v[1] != "0x8000000" {
		t.Errorf("unknown bits: %v", v)
	}

	// A GUID whose bytes are printable ASCII must still come back as a GUID.
	ascii := []byte("ABCDEFGHIJKLMNOP")
	e := ldap.NewEntry("CN=x", nil)
	e.Attributes = []*ldap.EntryAttribute{{Name: "objectGUID", Values: []string{string(ascii)}, ByteValues: [][]byte{ascii}}, {Name: "cn", Values: []string{"x"}, ByteValues: [][]byte{[]byte("x")}}}
	m := entryMap(e)
	v, ok := m["attributes"].(M)["objectGUID"].([]any)[0].(M)
	if !ok || v["guid"] != "44434241-4645-4847-494a-4b4c4d4e4f50" {
		t.Errorf("objectGUID: %v", m["attributes"])
	}
	if m["attributes"].(M)["cn"].([]any)[0] != "x" {
		t.Errorf("cn: %v", m["attributes"])
	}
}

// What the S4U2Self step learns decides how an S4U2Proxy refusal is
// explained; these are the cases seen on Windows Server 2022.
func TestS4UProxyHint(t *testing.T) {
	for _, tc := range []struct {
		notDelegable      string
		forwardable, rbcd bool
		want, notWant     string
	}{
		{"the account is in Protected Users", false, true, "cannot be delegated: the account is in Protected Users", "TrustedToAuthForDelegation"},
		{"", false, true, "not forwardable", "rbcd=true"},
		{"", true, false, "rbcd=true", "not forwardable"},
		{"", true, true, "msDS-AllowedToActOnBehalfOfOtherIdentity", "rbcd=true"},
	} {
		got := s4uProxyHint(13, "", tc.notDelegable, tc.forwardable, tc.rbcd)
		if !strings.Contains(got, tc.want) || strings.Contains(got, tc.notWant) {
			t.Errorf("%+v: %q", tc, got)
		}
	}
	if got := s4uProxyHint(13, "UNSUPPORTED_S4U2PROXY_REQUEST", "", true, true); !strings.Contains(got, "MIT krb5") {
		t.Errorf("MIT's refusal: %q", got)
	}
	if got := s4uProxyHint(7, "", "", true, true); got != s4uHint(7, "S4U2Proxy") {
		t.Errorf("other codes: %q", got)
	}
}

func TestPACNotDelegable(t *testing.T) {
	domain := mstypes.RPCSID{Revision: 1, SubAuthorityCount: 4, IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5}, SubAuthority: []uint32{21, 1, 2, 3}}
	kvi := func(uac uint32, rids ...uint32) *pac.PACType {
		k := &pac.KerbValidationInfo{UserAccountControl: uac, LogonDomainID: domain}
		for _, r := range rids {
			k.GroupIDs = append(k.GroupIDs, mstypes.GroupMembership{RelativeID: r})
		}
		return &pac.PACType{KerbValidationInfo: k}
	}
	if got := pacNotDelegable(kvi(0x210, 513)); got != "" {
		t.Errorf("ordinary user: %q", got)
	}
	if got := pacNotDelegable(kvi(0x210|samrNotDelegated, 513)); !strings.Contains(got, "sensitive") {
		t.Errorf("sensitive user: %q", got)
	}
	if got := pacNotDelegable(kvi(0x210, 513, 525)); !strings.Contains(got, "Protected Users") {
		t.Errorf("Protected Users: %q", got)
	}
	// The directory's NOT_DELEGATED bit (0x100000) means something else in
	// the PAC's SAMR flags (PARTIAL_SECRETS_ACCOUNT).
	if got := pacNotDelegable(kvi(0x210 | 0x100000)); got != "" {
		t.Errorf("wrong flag space: %q", got)
	}
	if f := flagNames(0x210|samrNotDelegated, samrUserFlags); strings.Join(f, ",") != "NORMAL_ACCOUNT,DONT_EXPIRE_PASSWORD,NOT_DELEGATED" {
		t.Errorf("SAMR flag names: %v", f)
	}
}
