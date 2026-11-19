package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/pac"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Kerberos v5 (RFC 4120) and SPNEGO (RFC 4178 / RFC 4559): a client that
// reports what the KDC and services do.

var etypeNames = map[int32]string{
	1: "des-cbc-crc", 3: "des-cbc-md5", 16: "des3-cbc-sha1-kd", 17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96",
	19: "aes128-cts-hmac-sha256-128", 20: "aes256-cts-hmac-sha384-192", 23: "rc4-hmac", 24: "rc4-hmac-exp",
}

func etypeName(e int32) string {
	if n := etypeNames[e]; n != "" {
		return n
	}
	return fmt.Sprintf("etype %d", e)
}

func etypeCheck(cs *Checks, what string, e int32) {
	switch e {
	case 17, 18, 19, 20:
		cs.add(what+": encryption type", "pass", etypeName(e), "RFC 8429")
	case 23, 24:
		cs.add(what+": encryption type", "warn", etypeName(e)+" is deprecated: RC4 tickets and replies crack offline far faster (Kerberoasting, AS-REP roasting)", "RFC 8429 §4")
	default:
		cs.add(what+": encryption type", "fail", etypeName(e)+" is broken", "RFC 6649 / RFC 8429")
	}
}

var ticketFlagNames = map[int]string{1: "forwardable", 2: "forwarded", 3: "proxiable", 4: "proxy", 5: "may-postdate", 6: "postdated", 7: "invalid",
	8: "renewable", 9: "initial", 10: "pre-authent", 11: "hw-authent", 12: "transited-policy-checked", 13: "ok-as-delegate", 15: "enc-pa-rep", 16: "anonymous"}

func flagList(f asn1.BitString) []string {
	var out []string
	for i := 0; i < 32; i++ {
		if types.IsFlagSet(&f, i) {
			if n := ticketFlagNames[i]; n != "" {
				out = append(out, n)
			} else {
				out = append(out, "flag "+strconv.Itoa(i))
			}
		}
	}
	return out
}

func krbTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339) + " (" + relTime(t) + ")"
}

func describeTicket(t messages.Ticket) M {
	return M{"realm": t.Realm, "server": t.SName.PrincipalNameString(), "enc_type": etypeName(t.EncPart.EType), "kvno": t.EncPart.KVNO, "cipher_bytes": len(t.EncPart.Cipher)}
}

func describeEncTicketPart(e messages.EncTicketPart) M {
	out := M{"client": e.CName.PrincipalNameString() + "@" + e.CRealm, "flags": flagList(e.Flags), "session_key_type": etypeName(e.Key.KeyType),
		"auth_time": krbTime(e.AuthTime), "start_time": krbTime(e.StartTime), "end_time": krbTime(e.EndTime)}
	if !e.RenewTill.IsZero() {
		out["renew_till"] = krbTime(e.RenewTill)
	}
	if len(e.Transited.Contents) > 0 {
		out["transited"] = string(e.Transited.Contents)
	}
	var ad []int32
	for _, a := range e.AuthorizationData {
		ad = append(ad, a.ADType)
	}
	if len(ad) > 0 {
		out["authorization_data_types"] = ad
	}
	return out
}

// samrUserFlags are the USER_* account flags in the PAC's logon info
// (MS-SAMR §2.2.1.12), not the directory's userAccountControl bits.
var samrUserFlags = []struct {
	bit  int64
	name string
}{
	{0x1, "ACCOUNT_DISABLED"}, {0x2, "HOME_DIRECTORY_REQUIRED"}, {0x4, "PASSWORD_NOT_REQUIRED"}, {0x8, "TEMP_DUPLICATE_ACCOUNT"},
	{0x10, "NORMAL_ACCOUNT"}, {0x20, "MNS_LOGON_ACCOUNT"}, {0x40, "INTERDOMAIN_TRUST_ACCOUNT"}, {0x80, "WORKSTATION_TRUST_ACCOUNT"},
	{0x100, "SERVER_TRUST_ACCOUNT"}, {0x200, "DONT_EXPIRE_PASSWORD"}, {0x400, "ACCOUNT_AUTO_LOCKED"}, {0x800, "ENCRYPTED_TEXT_PASSWORD_ALLOWED"},
	{0x1000, "SMARTCARD_REQUIRED"}, {0x2000, "TRUSTED_FOR_DELEGATION"}, {samrNotDelegated, "NOT_DELEGATED"}, {0x8000, "USE_DES_KEY_ONLY"},
	{0x10000, "DONT_REQUIRE_PREAUTH"}, {0x20000, "PASSWORD_EXPIRED"}, {0x40000, "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION"},
	{0x80000, "NO_AUTH_DATA_REQUIRED"}, {0x100000, "PARTIAL_SECRETS_ACCOUNT"}, {0x200000, "USE_AES_KEYS"},
}

const samrNotDelegated = 0x4000

// pacBufferNames are the PAC_INFO_BUFFER types of MS-PAC §2.4.
var pacBufferNames = map[uint32]string{1: "logon info", 2: "credentials", 6: "server checksum", 7: "KDC checksum",
	10: "client info", 11: "S4U delegation info", 12: "UPN and DNS info", 13: "client claims", 14: "device info",
	15: "device claims", 16: "ticket checksum", 17: "attributes", 18: "requestor", 19: "full checksum"}

func describePAC(p *pac.PACType) M {
	out := M{"buffers": len(p.Buffers)}
	var kinds []string
	for _, b := range p.Buffers {
		if n, ok := pacBufferNames[b.ULType]; ok {
			kinds = append(kinds, n)
		} else {
			kinds = append(kinds, fmt.Sprintf("type %d", b.ULType))
		}
	}
	out["buffer_types"] = kinds
	if k := p.KerbValidationInfo; k != nil {
		out["logon_info"] = M{"effective_name": k.EffectiveName.Value, "full_name": k.FullName.Value, "logon_server": k.LogonServer.Value,
			"logon_domain": k.LogonDomainName.Value, "domain_sid": k.LogonDomainID.String(), "user_rid": k.UserID, "primary_group_rid": k.PrimaryGroupID,
			"group_sids": k.GetGroupMembershipSIDs(), "logon_count": k.LogonCount, "bad_password_count": k.BadPasswordCount,
			"user_account_control": fmt.Sprintf("0x%08x", k.UserAccountControl), "user_account_flags": flagNames(int64(k.UserAccountControl), samrUserFlags)}
	}
	if u := p.UPNDNSInfo; u != nil {
		info := M{"upn": u.UPN, "dns_domain": u.DNSDomain}
		if u.Flags&1 != 0 {
			info["upn_constructed"] = true // the account has no userPrincipalName
		}
		// The extended form (flag S) adds the account name and SID.
		if b := pacBuffer(p, 12); u.Flags&2 != 0 && len(b) >= 20 {
			if name, ok := pacUTF16(b, binary.LittleEndian.Uint16(b[14:]), binary.LittleEndian.Uint16(b[12:])); ok {
				info["sam_name"] = name
			}
			off, n := int(binary.LittleEndian.Uint16(b[18:])), int(binary.LittleEndian.Uint16(b[16:]))
			if off+n <= len(b) {
				if sid, ok := sidString(b[off : off+n]); ok {
					info["sid"] = sid
				}
			}
		}
		out["upn_dns_info"] = info
	}
	if ci := p.ClientInfo; ci != nil {
		out["client_info"] = M{"name": ci.Name}
	}
	if d := p.S4UDelegationInfo; d != nil {
		var via []string
		for _, s := range d.S4UTransitedServices {
			via = append(via, s.Value)
		}
		out["s4u_delegation"] = M{"proxy_target": d.S4U2proxyTarget.Value, "transited_services": via}
	}
	if b := pacBuffer(p, 17); len(b) >= 8 {
		f := binary.LittleEndian.Uint32(b[4:])
		out["attributes"] = M{"pac_was_requested": f&1 != 0, "pac_was_given_implicitly": f&2 != 0}
	}
	if sid, ok := sidString(pacBuffer(p, 18)); ok {
		out["requestor_sid"] = sid
	}
	out["has_client_claims"] = p.ClientClaimsInfo != nil
	return out
}

// pacBuffer returns the first PAC buffer of a type, or nil.
func pacBuffer(p *pac.PACType, typ uint32) []byte {
	for _, b := range p.Buffers {
		if b.ULType == typ && b.Offset+uint64(b.CBBufferSize) <= uint64(len(p.Data)) {
			return p.Data[b.Offset : b.Offset+uint64(b.CBBufferSize)]
		}
	}
	return nil
}

// pacUTF16 reads a UTF-16LE string at an offset within a PAC buffer.
func pacUTF16(b []byte, off, n uint16) (string, bool) {
	if int(off)+int(n) > len(b) || n%2 != 0 {
		return "", false
	}
	u := make([]uint16, n/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[int(off)+2*i:])
	}
	return string(utf16.Decode(u)), true
}

// sidString formats a binary SID (MS-DTYP §2.4.2.2).
func sidString(b []byte) (string, bool) {
	if len(b) < 8 || b[0] != 1 || len(b) != 8+4*int(b[1]) {
		return "", false
	}
	var auth uint64
	for _, x := range b[2:8] {
		auth = auth<<8 | uint64(x)
	}
	s := fmt.Sprintf("S-1-%d", auth)
	for i := 0; i < int(b[1]); i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s, true
}

// ---- configuration and transport ----

var (
	krbRealmRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	krbEtypeRe = regexp.MustCompile(`^[a-z0-9-]+$`)
	krbKDCRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+(:[0-9]{1,5})?$|^\[[0-9A-Fa-f:]+\](:[0-9]{1,5})?$`)
)

type krbSetup struct {
	cfg   *config.Config
	realm string
	user  string
	cname types.PrincipalName
	kdcs  []string
	kt    *keytab.Keytab
	found M // how the KDCs were discovered, when not given
}

func loadKeytab(s string) (*keytab.Keytab, error) {
	kt := keytab.New()
	if err := kt.Unmarshal([]byte(s)); err == nil {
		return kt, nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil, errors.New("not a keytab (binary from a file, or base64)")
	}
	kt = keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("not a keytab: %w", err)
	}
	return kt, nil
}

func krbPrepare(c *Ctx) (*krbSetup, error) {
	s := &krbSetup{}
	princ := c.Str("principal")
	if u, r, ok := strings.Cut(princ, "@"); ok {
		s.user, s.realm = u, r
	} else {
		s.user = princ
	}
	if r := c.Str("realm"); r != "" {
		s.realm = r
	}
	// These values are written into a krb5.conf: hold them to strict shapes.
	if s.realm != "" && !krbRealmRe.MatchString(s.realm) {
		return nil, fmt.Errorf("realm %q contains characters a realm may not", s.realm)
	}
	for _, e := range c.List("etypes") {
		if !krbEtypeRe.MatchString(e) {
			return nil, fmt.Errorf("etype %q is not an encryption type name", e)
		}
	}
	for _, k := range c.List("kdc") {
		if !krbKDCRe.MatchString(k) {
			return nil, fmt.Errorf("kdc %q is not host[:port]", k)
		}
	}
	etypes := strings.Join(c.List("etypes"), " ")
	var err error
	if conf := c.Str("krb5_conf"); conf != "" {
		if s.cfg, err = config.NewFromString(conf); err != nil {
			return nil, fmt.Errorf("krb5_conf: %w", err)
		}
		if s.realm == "" {
			s.realm = s.cfg.LibDefaults.DefaultRealm
		}
		// The realm's kdc lines first; DNS only when there are none and
		// dns_lookup_kdc allows it (as MIT and gokrb5 do).
		dns := s.cfg.LibDefaults.DNSLookupKDC
		s.cfg.LibDefaults.DNSLookupKDC = false
		_, kdcs, cerr := s.cfg.GetKDCs(s.realm, true)
		s.cfg.LibDefaults.DNSLookupKDC = dns
		switch {
		case cerr == nil:
			for i := 1; i <= len(kdcs); i++ {
				s.kdcs = append(s.kdcs, kdcs[i])
			}
		case dns:
			if s.kdcs, s.found, err = discoverKDCs(c, s.realm, time.Duration(c.Int("timeout"))*time.Second); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("no KDC for %s in krb5_conf: %w", s.realm, cerr)
		}
	} else {
		if s.realm == "" {
			return nil, errors.New("pass realm, or principal as user@REALM")
		}
		s.kdcs = c.List("kdc")
		var b strings.Builder
		fmt.Fprintf(&b, "[libdefaults]\n default_realm = %s\n udp_preference_limit = 1\n forwardable = true\n dns_lookup_kdc = %v\n", s.realm, len(s.kdcs) == 0)
		fmt.Fprintf(&b, " default_tkt_enctypes = %s\n default_tgs_enctypes = %s\n permitted_enctypes = %s\n", etypes, etypes, etypes)
		fmt.Fprintf(&b, "[realms]\n %s = {\n", s.realm)
		for _, k := range s.kdcs {
			if !strings.Contains(k, ":") {
				k += ":88"
			}
			fmt.Fprintf(&b, "  kdc = %s\n", k)
		}
		b.WriteString(" }\n")
		if s.cfg, err = config.NewFromString(b.String()); err != nil {
			return nil, err
		}
		if len(s.kdcs) == 0 {
			if s.kdcs, s.found, err = discoverKDCs(c, s.realm, time.Duration(c.Int("timeout"))*time.Second); err != nil {
				return nil, err
			}
		}
	}
	for i, k := range s.kdcs {
		if !strings.Contains(k, ":") {
			s.kdcs[i] = k + ":88"
		}
		if err := c.allowDestination("Kerberos credentials", "kerberos://"+s.kdcs[i]); err != nil {
			return nil, err
		}
	}
	// Pin the client to the KDCs just checked: no later DNS lookups, and with
	// a stored credential no other realms a referral could lead to.
	s.cfg.LibDefaults.DNSLookupKDC, s.cfg.LibDefaults.DNSLookupRealm = false, false
	realms := []config.Realm{}
	pinned := false
	for _, r := range s.cfg.Realms {
		if r.Realm == s.realm {
			r.KDC, r.MasterKDC, pinned = append([]string{}, s.kdcs...), nil, true
			realms = append(realms, r)
		} else if c.guard == nil {
			realms = append(realms, r)
		}
	}
	if !pinned {
		realms = append(realms, config.Realm{Realm: s.realm, KDC: append([]string{}, s.kdcs...)})
	}
	s.cfg.Realms = realms
	s.cname = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, s.user)
	if k := c.Str("keytab"); k != "" {
		if s.kt, err = loadKeytab(k); err != nil {
			return nil, fmt.Errorf("keytab: %w", err)
		}
	}
	return s, nil
}

func (s *krbSetup) client(c *Ctx) (*client.Client, error) {
	if s.user == "" {
		return nil, errors.New("pass principal")
	}
	if s.kt != nil {
		return client.NewWithKeytab(s.user, s.realm, s.kt, s.cfg, client.DisablePAFXFAST(true)), nil
	}
	if c.Str("password") == "" {
		return nil, errors.New("pass password (or IDPDBG_PASSWORD) or keytab")
	}
	return client.NewWithPassword(s.user, s.realm, c.Str("password"), s.cfg, client.DisablePAFXFAST(true)), nil
}

// krbSend exchanges one message with a KDC over TCP (RFC 4120 §7.2.2).
func krbSend(c *Ctx, kdc string, msg []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", kdc, time.Duration(c.Int("timeout"))*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(c.Int("timeout")) * time.Second))
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(msg)))
	if _, err := conn.Write(append(hdr, msg...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr)
	if n > 1<<20 {
		return nil, errors.New("KDC reply larger than 1 MiB")
	}
	b := make([]byte, n)
	_, err = io.ReadFull(conn, b)
	return b, err
}

func describeKRBError(e messages.KRBError) M {
	out := M{"error_code": e.ErrorCode, "error": errorcode.Lookup(e.ErrorCode), "server": e.SName.PrincipalNameString(), "realm": e.Realm}
	if e.EText != "" {
		out["e_text"] = e.EText
	}
	if !e.STime.IsZero() {
		out["kdc_time"] = e.STime.UTC().Format(time.RFC3339)
	}
	var pas types.PADataSequence
	if len(e.EData) > 0 && pas.Unmarshal(e.EData) == nil {
		out["pa_data"] = describePAData(pas)
	}
	return out
}

// probePreauth sends an AS-REQ without pre-authentication. A KDC that answers
// with a ticket lets anyone fetch material to crack offline (AS-REP roasting).
func probePreauth(c *Ctx, s *krbSetup, cs *Checks) M {
	req, err := messages.NewASReqForTGT(s.realm, s.cfg, s.cname)
	if err != nil {
		return nil
	}
	b, _ := req.Marshal()
	reply, err := krbSend(c, s.kdcs[0], b)
	if err != nil || len(reply) == 0 {
		cs.add("pre-authentication enforced", "warn", "probe failed: "+detailOr(err, "empty reply"), "RFC 4120 §5.2.7")
		return nil
	}
	switch reply[0] {
	case 0x7e:
		var ke messages.KRBError
		if err := ke.Unmarshal(reply); err != nil {
			return nil
		}
		info := describeKRBError(ke)
		switch ke.ErrorCode {
		case errorcode.KDC_ERR_PREAUTH_REQUIRED:
			cs.add("pre-authentication enforced", "pass", "the KDC demanded pre-authentication", "RFC 4120 §5.2.7")
		case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
			cs.add("client principal known", "fail", s.user+"@"+s.realm+" is unknown to the KDC", "RFC 4120 §7.5.9")
		default:
			cs.add("pre-authentication probe", "info", errorcode.Lookup(ke.ErrorCode), "RFC 4120 §7.5.9")
		}
		if !ke.STime.IsZero() {
			skew := time.Since(ke.STime)
			if skew < 0 {
				skew = -skew
			}
			status := "pass"
			if skew > 5*time.Minute {
				status = "fail"
			} else if skew > time.Minute {
				status = "warn"
			}
			cs.add("clock skew with the KDC", status, skew.Round(time.Second).String(), "RFC 4120 §1.6")
		}
		return info
	case 0x6b:
		cs.add("pre-authentication enforced", "warn", "the KDC issued a TGT without pre-authentication: the reply can be cracked offline (AS-REP roasting); require pre-authentication for this principal", "RFC 4120 §5.2.7")
	}
	return nil
}

func runKinit(c *Ctx) (M, error) {
	s, err := krbPrepare(c)
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{"realm": s.realm, "kdcs": s.kdcs, "client": s.user + "@" + s.realm}
	if s.found != nil {
		out["kdc_discovery"] = s.found
	}
	defer func() { out["checks"] = cs }()
	if c.Bool("check_preauth") {
		if info := probePreauth(c, s, &cs); info != nil {
			out["preauth_probe"] = info
		}
	}
	cl, err := s.client(c)
	if err != nil {
		return out, err
	}
	req, err := messages.NewASReqForTGT(s.realm, s.cfg, s.cname)
	if err != nil {
		return out, err
	}
	rep, err := cl.ASExchange(s.realm, req, 0)
	if !cs.ok(err == nil, "AS exchange (TGT issued)", detailOr(err, "krbtgt/"+s.realm), "RFC 4120 §3.1") {
		return out, nil
	}
	if rep.DecryptedEncPart.Key.KeyType == 0 {
		if _, err := rep.DecryptEncPart(cl.Credentials); err != nil {
			cs.add("AS-REP decrypted", "fail", err.Error(), "RFC 4120 §3.1.5")
			return out, nil
		}
	}
	d := rep.DecryptedEncPart
	out["ticket"] = describeTicket(rep.Ticket)
	tgt := M{"flags": flagList(d.Flags), "session_key_type": etypeName(d.Key.KeyType), "auth_time": krbTime(d.AuthTime),
		"start_time": krbTime(d.StartTime), "end_time": krbTime(d.EndTime), "server": d.SName.PrincipalNameString() + "@" + d.SRealm}
	if !d.RenewTill.IsZero() {
		tgt["renew_till"] = krbTime(d.RenewTill)
	}
	out["tgt"] = tgt
	etypeCheck(&cs, "TGT session key", d.Key.KeyType)
	etypeCheck(&cs, "TGT", rep.Ticket.EncPart.EType)
	cs.warn(types.IsFlagSet(&d.Flags, 10), "ticket flag pre-authent", "", "RFC 4120 §2.6")
	life := d.EndTime.Sub(d.StartTime)
	if d.StartTime.IsZero() {
		life = d.EndTime.Sub(d.AuthTime)
	}
	cs.add("TGT lifetime", "info", life.Round(time.Minute).String(), "RFC 4120 §2.1")
	return out, nil
}

func runServiceTicket(c *Ctx) (M, error) {
	s, err := krbPrepare(c)
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{"realm": s.realm, "spn": c.Str("spn")}
	defer func() { out["checks"] = cs }()
	cl, err := s.client(c)
	if err != nil {
		return out, err
	}
	lerr := cl.Login()
	if !cs.ok(lerr == nil, "AS exchange (TGT issued)", detailOr(lerr, ""), "RFC 4120 §3.1") {
		return out, nil
	}
	tkt, key, err := cl.GetServiceTicket(c.Str("spn"))
	if !cs.ok(err == nil, "TGS exchange (service ticket issued)", detailOr(err, c.Str("spn")), "RFC 4120 §3.3") {
		return out, nil
	}
	out["ticket"] = describeTicket(tkt)
	out["session_key_type"] = etypeName(key.KeyType)
	etypeCheck(&cs, "service ticket", tkt.EncPart.EType)
	if tkt.EncPart.EType == 23 {
		cs.add("service account exposure", "warn", "anyone with a TGT can request this RC4 ticket and crack the service account's password offline (Kerberoasting); enable AES for the account", "RFC 8429 §4")
	}
	if k := c.Str("service_keytab"); k != "" {
		kt, err := loadKeytab(k)
		if err != nil {
			return out, fmt.Errorf("service_keytab: %w", err)
		}
		// Decrypt a copy: gokrb5 marshals DecryptedEncPart along with the
		// ticket, which would corrupt the AP-REQ in the Negotiate header.
		tkt := tkt
		if !cs.ok(tkt.DecryptEncPart(kt, nil) == nil, "service ticket decrypts with the service keytab", "", "RFC 4120 §3.2.3") {
			cs[len(cs)-1].Detail = "wrong keytab, or the service key changed (kvno mismatch)"
		} else {
			out["ticket_contents"] = describeEncTicketPart(tkt.DecryptedEncPart)
			isPAC, p, perr := ticketPACFromKeytab(tkt, kt)
			switch {
			case !isPAC:
				cs.add("PAC present", "info", "no PAC: not an Active Directory KDC, or PACs are disabled", "MS-PAC")
			case perr != nil:
				cs.add("PAC signatures", "fail", perr.Error(), "MS-PAC §2.8")
			default:
				out["pac"] = describePAC(&p)
				cs.add("PAC signatures", "pass", "server signature verified with the service key", "MS-PAC §2.8")
			}
		}
	}
	if c.Bool("spnego_token") {
		// The header is a live credential for the service: never hand one
		// minted from stored credentials to an MCP caller.
		if !c.CLI && c.guard != nil {
			cs.add("Negotiate header", "info", "not returned: over MCP a header is only minted from credentials passed in the call", "")
			return out, nil
		}
		init, err := spnego.NewNegTokenInitKRB5(cl, tkt, key)
		if err == nil {
			tok := spnego.SPNEGOToken{Init: true, NegTokenInit: init}
			if b, err := tok.Marshal(); err == nil {
				out["authorization_header"] = "Negotiate " + base64.StdEncoding.EncodeToString(b)
			}
		}
	}
	return out, nil
}

func runKeytab(c *Ctx) (M, error) {
	kt, err := loadKeytab(c.Str("keytab"))
	if err != nil {
		return nil, err
	}
	var cs Checks
	var entries []M
	kvnos := map[string]map[uint32]bool{}
	for _, e := range kt.Entries {
		p := e.Principal.String()
		entries = append(entries, M{"principal": p, "kvno": e.KVNO, "etype": etypeName(e.Key.KeyType), "timestamp": e.Timestamp.UTC().Format(time.RFC3339)})
		if kvnos[p] == nil {
			kvnos[p] = map[uint32]bool{}
		}
		kvnos[p][e.KVNO] = true
		switch e.Key.KeyType {
		case 23, 24:
			cs.add("keytab "+p+": "+etypeName(e.Key.KeyType), "warn", "RC4 key present", "RFC 8429")
		case 1, 3, 16:
			cs.add("keytab "+p+": "+etypeName(e.Key.KeyType), "fail", "DES/3DES key present", "RFC 6649")
		}
	}
	for p, ks := range kvnos {
		if len(ks) > 1 {
			cs.add("keytab "+p+": key versions", "info", fmt.Sprintf("%d kvnos (normal right after a password change)", len(ks)), "")
		}
	}
	cs.ok(len(entries) > 0, "keytab has entries", fmt.Sprintf("%d", len(entries)), "")
	return M{"entries": entries, "checks": cs}, nil
}

// ---- decoding ----

func krbBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, p := range []string{"Negotiate ", "Kerberos ", "negotiate "} {
		s = strings.TrimPrefix(s, p)
	}
	compact := strings.Join(strings.Fields(s), "")
	if b, err := hex.DecodeString(compact); err == nil && len(b) > 0 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(compact); err == nil {
		return b, nil
	}
	return b64urlDecode(compact)
}

func describeAPReq(ap messages.APReq, kt *keytab.Keytab, cs *Checks) M {
	out := M{"ticket": describeTicket(ap.Ticket), "authenticator_enc_type": etypeName(ap.EncryptedAuthenticator.EType)}
	if types.IsFlagSet(&ap.APOptions, 2) {
		out["mutual_required"] = true
	}
	if kt == nil {
		return out
	}
	if err := ap.Ticket.DecryptEncPart(kt, nil); err != nil {
		cs.add("ticket decrypts with the keytab", "fail", err.Error(), "RFC 4120 §3.2.3")
		return out
	}
	cs.add("ticket decrypts with the keytab", "pass", "", "RFC 4120 §3.2.3")
	out["ticket_contents"] = describeEncTicketPart(ap.Ticket.DecryptedEncPart)
	if err := ap.DecryptAuthenticator(ap.Ticket.DecryptedEncPart.Key); err == nil {
		a := ap.Authenticator
		out["authenticator"] = M{"client": a.CName.PrincipalNameString() + "@" + a.CRealm, "ctime": krbTime(a.CTime), "has_subkey": a.SubKey.KeyType != 0, "seq_number": a.SeqNumber}
		cs.ok(a.CName.Equal(ap.Ticket.DecryptedEncPart.CName), "authenticator client matches the ticket", "", "RFC 4120 §3.2.3")
		skew := time.Since(a.CTime)
		cs.ok(skew < 5*time.Minute && skew > -5*time.Minute, "authenticator is fresh", relTime(a.CTime), "RFC 4120 §3.2.3")
	}
	if isPAC, p, err := ticketPACFromKeytab(ap.Ticket, kt); isPAC {
		if err != nil {
			cs.add("PAC signatures", "fail", err.Error(), "MS-PAC §2.8")
		} else {
			out["pac"] = describePAC(&p)
			cs.add("PAC signatures", "pass", "", "MS-PAC §2.8")
		}
	}
	return out
}

func runKrbDecode(c *Ctx) (M, error) {
	b, err := krbBytes(c.Str("message"))
	if err != nil || len(b) == 0 {
		return nil, errors.New("message is not hex, base64 or base64url")
	}
	var kt *keytab.Keytab
	if k := c.Str("keytab"); k != "" {
		if kt, err = loadKeytab(k); err != nil {
			return nil, fmt.Errorf("keytab: %w", err)
		}
	}
	var cs Checks
	out := M{"bytes": len(b)}
	defer func() { out["checks"] = cs }()
	switch b[0] {
	case 0x60, 0xa0, 0xa1: // GSS-API / SPNEGO
		var tok spnego.SPNEGOToken
		if err := tok.Unmarshal(b); err == nil {
			if tok.Init {
				var mechs []string
				for _, m := range tok.NegTokenInit.MechTypes {
					mechs = append(mechs, oidName(m.String()))
				}
				out["type"], out["mech_types"] = "SPNEGO NegTokenInit", mechs
				var k5 spnego.KRB5Token
				if err := k5.Unmarshal(tok.NegTokenInit.MechTokenBytes); err == nil && k5.IsAPReq() {
					out["ap_req"] = describeAPReq(k5.APReq, kt, &cs)
				}
				cs.warn(len(mechs) > 0 && strings.Contains(mechs[0], "Kerberos"), "preferred mechanism is Kerberos", strings.Join(mechs, ", "), "RFC 4178 §4.2.1")
				if contains(mechs, oidName("1.3.6.1.4.1.311.2.2.10")) {
					cs.add("NTLM offered", "warn", "the client also offers NTLM, which a downgrade could select", "MS-NLMP")
				}
			} else {
				states := map[int]string{0: "accept-completed", 1: "accept-incomplete", 2: "reject", 3: "request-mic"}
				out["type"], out["neg_state"] = "SPNEGO NegTokenResp", states[int(tok.NegTokenResp.NegState)]
				out["supported_mech"] = oidName(tok.NegTokenResp.SupportedMech.String())
				out["has_response_token"] = len(tok.NegTokenResp.ResponseToken) > 0
			}
			return out, nil
		}
		var k5 spnego.KRB5Token
		if err := k5.Unmarshal(b); err == nil {
			out["type"] = "GSS-API Kerberos token"
			if k5.IsAPReq() {
				out["ap_req"] = describeAPReq(k5.APReq, kt, &cs)
			} else if k5.IsAPRep() {
				out["ap_rep"] = M{"enc_type": etypeName(k5.APRep.EncPart.EType)}
			} else if k5.IsKRBError() {
				out["krb_error"] = describeKRBError(k5.KRBError)
			}
			return out, nil
		}
		return nil, errors.New("not a recognisable SPNEGO or GSS-API token")
	case 0x6a, 0x6c:
		var r messages.ASReq
		name := "AS-REQ"
		var body messages.KDCReqBody
		var pas types.PADataSequence
		if b[0] == 0x6a {
			if err := r.Unmarshal(b); err != nil {
				return nil, err
			}
			body, pas = r.ReqBody, r.PAData
		} else {
			var t messages.TGSReq
			if err := t.Unmarshal(b); err != nil {
				return nil, err
			}
			name, body, pas = "TGS-REQ", t.ReqBody, t.PAData
		}
		var ets []string
		for _, e := range body.EType {
			ets = append(ets, etypeName(e))
			if e == 23 || e < 17 {
				cs.add("requested encryption types", "warn", "the client offers "+etypeName(e), "RFC 8429")
			}
		}
		var pt []int32
		for _, p := range pas {
			pt = append(pt, p.PADataType)
		}
		out["type"] = name
		out["request"] = M{"client": body.CName.PrincipalNameString(), "realm": body.Realm, "server": body.SName.PrincipalNameString(), "etypes": ets,
			"till": krbTime(body.Till), "nonce": body.Nonce, "kdc_options": flagList(body.KDCOptions), "pa_data_types": pt}
		if name == "AS-REQ" && !pas.Contains(patype.PA_ENC_TIMESTAMP) {
			cs.add("pre-authentication data", "info", "no PA-ENC-TIMESTAMP: a first attempt, or a client relying on the KDC not requiring pre-authentication", "RFC 4120 §5.2.7")
		}
	case 0x6b, 0x6d:
		var f messages.KDCRepFields
		name := "AS-REP"
		if b[0] == 0x6b {
			var r messages.ASRep
			if err := r.Unmarshal(b); err != nil {
				return nil, err
			}
			f = r.KDCRepFields
		} else {
			var r messages.TGSRep
			if err := r.Unmarshal(b); err != nil {
				return nil, err
			}
			name, f = "TGS-REP", r.KDCRepFields
		}
		out["type"], out["client"], out["ticket"], out["enc_part_type"] = name, f.CName.PrincipalNameString()+"@"+f.CRealm, describeTicket(f.Ticket), etypeName(f.EncPart.EType)
		etypeCheck(&cs, "ticket", f.Ticket.EncPart.EType)
		if kt != nil {
			if err := f.Ticket.DecryptEncPart(kt, nil); err == nil {
				out["ticket_contents"] = describeEncTicketPart(f.Ticket.DecryptedEncPart)
			}
		}
	case 0x6e:
		var ap messages.APReq
		if err := ap.Unmarshal(b); err != nil {
			return nil, err
		}
		out["type"], out["ap_req"] = "AP-REQ", describeAPReq(ap, kt, &cs)
	case 0x7e:
		var e messages.KRBError
		if err := e.Unmarshal(b); err != nil {
			return nil, err
		}
		out["type"], out["krb_error"] = "KRB-ERROR", describeKRBError(e)
	default:
		return nil, fmt.Errorf("unrecognised Kerberos message (first byte 0x%02x)", b[0])
	}
	return out, nil
}

func oidName(oid string) string {
	n := map[string]string{"1.2.840.113554.1.2.2": "Kerberos 5", "1.2.840.48018.1.2.2": "Kerberos 5 (Microsoft legacy OID)",
		"1.3.6.1.4.1.311.2.2.10": "NTLM", "1.3.6.1.5.5.2": "SPNEGO", "1.3.6.1.4.1.311.2.2.30": "NegoEx"}[oid]
	if n == "" {
		return oid
	}
	return n + " (" + oid + ")"
}

func runPACDecode(c *Ctx) (M, error) {
	b, err := krbBytes(c.Str("pac"))
	if err != nil {
		return nil, errors.New("pac is not hex or base64")
	}
	var p pac.PACType
	if err := p.Unmarshal(b); err != nil {
		return nil, fmt.Errorf("not a PAC: %w", err)
	}
	var cs Checks
	out := M{}
	if k := c.Str("keytab"); k != "" {
		kt, err := loadKeytab(k)
		if err != nil {
			return nil, fmt.Errorf("keytab: %w", err)
		}
		pn, realm := types.ParseSPNString(c.Str("service_principal"))
		if r := c.Str("realm"); r != "" {
			realm = r
		}
		key, _, err := kt.GetEncryptionKey(pn, realm, c.Int("kvno"), int32(c.Int("etype")))
		if err != nil {
			return nil, fmt.Errorf("no key for %s@%s in the keytab: %w", c.Str("service_principal"), realm, err)
		}
		err = processPAC(&p, key)
		cs.ok(err == nil, "PAC server signature", detailOr(err, "verified with the service key"), "MS-PAC §2.8")
	} else {
		// Decode the buffers without a key; signatures stay unverified.
		_ = p.ProcessPACInfoBuffers(types.EncryptionKey{}, log.New(io.Discard, "", 0))
		cs.add("PAC server signature", "warn", "not verified: pass keytab, service_principal and realm", "MS-PAC §2.8")
	}
	out["pac"] = describePAC(&p)
	out["checks"] = cs
	return out, nil
}

// ---- SPNEGO over HTTP ----

func runSPNEGOHTTP(c *Ctx) (M, error) {
	u, err := url.Parse(c.Str("url"))
	if err != nil || u.Host == "" {
		return nil, errors.New("url must be an absolute http(s) URL")
	}
	spn := c.Str("spn")
	if spn == "" {
		spn = "HTTP/" + u.Hostname()
	}
	// With a stored credential the ticket may only be for the host it is sent
	// to, so the server cannot relay it to another service.
	if c.guard != nil && !strings.EqualFold(spn, "HTTP/"+u.Hostname()) {
		return nil, fmt.Errorf("refusing a ticket for %s while a stored credential is in use: only HTTP/%s can be sent to %s", spn, u.Hostname(), u.Host)
	}
	var cs Checks
	out := M{"url": u.String(), "spn": spn}
	defer func() { out["checks"] = cs }()

	// 1. Without credentials: does the server offer Negotiate?
	first, err := c.do("GET", u.String(), nil, nil)
	if err != nil {
		return out, err
	}
	var schemes []string
	for _, h := range first.Header.Values("WWW-Authenticate") {
		schemes = append(schemes, strings.SplitN(h, " ", 2)[0])
	}
	out["unauthenticated_status"], out["offered_schemes"] = first.Status, schemes
	cs.ok(first.Status == http.StatusUnauthorized && containsFold(schemes, "Negotiate"), "server offers Negotiate", fmt.Sprintf("HTTP %d, WWW-Authenticate: %s", first.Status, strings.Join(schemes, ", ")), "RFC 4559 §4")
	if containsFold(schemes, "NTLM") {
		cs.add("NTLM also offered", "warn", "clients that cannot get a Kerberos ticket fall back to NTLM", "MS-NLMP")
	}

	// 2. With a Kerberos ticket for the SPN.
	s, err := krbPrepare(c)
	if err != nil {
		return out, err
	}
	cl, err := s.client(c)
	if err != nil {
		return out, err
	}
	lerr := cl.Login()
	if !cs.ok(lerr == nil, "AS exchange (TGT issued)", detailOr(lerr, ""), "RFC 4120 §3.1") {
		return out, nil
	}
	req, _ := http.NewRequestWithContext(c, "GET", u.String(), nil)
	if err := spnego.SetSPNEGOHeader(cl, req, spn); !cs.ok(err == nil, "service ticket for "+spn, detailOr(err, ""), "RFC 4559 §4.2") {
		return out, nil
	}
	res, err := c.client().Do(req)
	if err != nil {
		return out, err
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	res.Body.Close()
	out["authenticated_status"] = res.StatusCode
	if len(body) > 0 && len(body) < 4096 {
		out["body"] = string(body)
	}
	cs.ok(res.StatusCode < 400, "request accepted with the Kerberos ticket", fmt.Sprintf("HTTP %d", res.StatusCode), "RFC 4559 §4.2")
	if h := res.Header.Get("WWW-Authenticate"); strings.HasPrefix(h, "Negotiate ") {
		b, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Negotiate "))
		var tok spnego.SPNEGOToken
		if tok.Unmarshal(b) == nil && tok.Resp {
			out["mutual_auth"] = M{"neg_state": int(tok.NegTokenResp.NegState), "has_ap_rep": len(tok.NegTokenResp.ResponseToken) > 0}
			cs.add("mutual authentication token returned", "pass", "", "RFC 4559 §5")
		}
	} else if res.StatusCode < 400 {
		cs.add("mutual authentication token returned", "info", "the server did not prove its identity back (no Negotiate token in the response)", "RFC 4559 §5")
	}
	return out, nil
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// krbParams are shared by the Kerberos operations.
var krbParams = []Param{
	{Name: "principal", Type: "string", Desc: "Client principal, user or user@REALM"},
	{Name: "realm", Type: "string", Desc: "Realm, if not in principal"},
	{Name: "kdc", Type: "list", Desc: "KDC host[:port] list; default from krb5_conf or DNS SRV records"},
	{Name: "krb5_conf", Type: "string", Path: true, Desc: "krb5.conf to use instead of kdc/etypes (a path from the CLI or a profile)"},
	{Name: "password", Type: "string", Secret: true, Desc: "Password (prefer env IDPDBG_PASSWORD or a profile)"},
	{Name: "keytab", Type: "string", Path: true, Desc: "Client keytab instead of a password (a path, or base64)"},
	{Name: "etypes", Type: "list", Desc: "Encryption types to request", Default: "aes256-cts-hmac-sha1-96,aes128-cts-hmac-sha1-96,aes256-cts-hmac-sha384-192,aes128-cts-hmac-sha256-128"},
}

func init() {
	join := joinParams
	register(
		&Op{
			Name:    "krb.kinit",
			Summary: "Get a Kerberos TGT (AS exchange) with a password or keytab and report it: flags, lifetimes, encryption types and the KDC's salt. Also probes whether the KDC enforces pre-authentication (AS-REP roasting) and measures clock skew.",
			Params:  join(krbParams, []Param{{Name: "check_preauth", Type: "bool", Desc: "Send an AS-REQ without pre-authentication first to see whether the KDC demands it", Default: true}}),
			Run:     runKinit,
		},
		&Op{
			Name:    "krb.service_ticket",
			Summary: "Get a service ticket (TGS exchange) for an SPN and report its encryption type (RC4 means Kerberoastable), key version and flags. With the service keytab it also decrypts the ticket and decodes and verifies the PAC (groups, SIDs, UPN). Can emit a ready Negotiate header.",
			Params: join(krbParams, []Param{
				{Name: "spn", Type: "string", Required: true, Desc: "Service principal name, e.g. HTTP/web.example.com"},
				{Name: "service_keytab", Type: "string", Path: true, Desc: "The service's keytab, to decrypt the ticket and verify the PAC"},
				{Name: "spnego_token", Type: "bool", Desc: "Also return an Authorization: Negotiate header value"}}),
			Run: runServiceTicket,
		},
		&Op{
			Name:    "krb.keytab",
			Summary: "List a keytab's entries (principal, key version, encryption type, timestamp) and flag weak keys.",
			Params:  []Param{{Name: "keytab", Type: "string", Required: true, Path: true, Desc: "Keytab (a path from the CLI or a profile, or base64)"}},
			Run:     runKeytab,
		},
		&Op{
			Name:    "krb.decode",
			Summary: "Decode a Kerberos or SPNEGO message (hex, base64, or an Authorization: Negotiate header): AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP, KRB-ERROR (with ETYPE-INFO2 salts), NegTokenInit/Resp (mechanisms, NTLM offered). With the service keytab it decrypts tickets and authenticators and verifies the PAC.",
			Params: []Param{
				{Name: "message", Type: "string", Required: true, File: true, Desc: "The message (CLI: @file or - for stdin)"},
				{Name: "keytab", Type: "string", Path: true, Desc: "Service keytab to decrypt tickets (a path, or base64)"}},
			Run: runKrbDecode,
		},
		&Op{
			Name:    "krb.pac",
			Summary: "Decode a Microsoft PAC (MS-PAC): logon info (user, groups and SIDs, logon server, account control), UPN/DNS info, client info, delegation info; verify its server signature with the service key.",
			Params: []Param{
				{Name: "pac", Type: "string", Required: true, File: true, Desc: "The PAC, hex or base64"},
				{Name: "keytab", Type: "string", Path: true, Desc: "Service keytab to verify the signature"},
				{Name: "service_principal", Type: "string", Desc: "Service principal in the keytab, e.g. HTTP/web.example.com"},
				{Name: "realm", Type: "string", Desc: "Realm of the service principal"},
				{Name: "kvno", Type: "int", Desc: "Key version; 0 for the latest", Default: 0},
				{Name: "etype", Type: "int", Desc: "Encryption type of the key (18 = aes256-cts-hmac-sha1-96, 23 = rc4-hmac)", Default: 18}},
			Run: runPACDecode,
		},
		&Op{
			Name:    "spnego.http",
			Summary: "Test Kerberos single sign-on to a web resource (SPNEGO, RFC 4559): check the server offers Negotiate (and whether it also offers NTLM), get a ticket for HTTP/host, send it, and report the result and any mutual-authentication token.",
			Params:  join([]Param{{Name: "url", Type: "string", Required: true, Desc: "Protected URL"}, {Name: "spn", Type: "string", Desc: "Service principal; default HTTP/<host>"}}, krbParams),
			Run:     runSPNEGOHTTP,
		},
	)
}
