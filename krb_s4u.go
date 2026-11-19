package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/jcmturner/gokrb5/v8/iana/adtype"
	"github.com/jcmturner/gokrb5/v8/pac"
	"io"
	"log"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Kerberos constrained delegation (MS-SFU): S4U2Self gets a ticket to the
// service itself on behalf of a user (protocol transition), S4U2Proxy turns
// that ticket into one for another service (constrained delegation, or
// resource-based constrained delegation).

const (
	paPACOptions        int32 = 167 // MS-KILE
	kdcOptCNameInAddTkt       = 14  // RFC 4120 §5.4.1: cname-in-addl-tkt (MS-SFU "constrained-delegation")
	cksumHMACMD5        int32 = -138
)

// paForUser is PA-FOR-USER (MS-SFU §2.2.1).
type paForUser struct {
	UserName    types.PrincipalName `asn1:"explicit,tag:0"`
	UserRealm   string              `asn1:"generalstring,explicit,tag:1"`
	Cksum       types.Checksum      `asn1:"explicit,tag:2"`
	AuthPackage string              `asn1:"generalstring,explicit,tag:3"`
}

type paPACOptionsValue struct {
	Flags asn1.BitString `asn1:"explicit,tag:0"`
}

// hmacMD5Checksum is the RFC 4757 keyed checksum MS-SFU prescribes for
// PA-FOR-USER, whatever the session key's type (key usage 17).
func hmacMD5Checksum(key []byte, usage uint32, data []byte) []byte {
	ks := hmac.New(md5.New, key)
	ks.Write([]byte("signaturekey\x00"))
	ksign := ks.Sum(nil)
	h := md5.New()
	binary.Write(h, binary.LittleEndian, usage)
	h.Write(data)
	m := hmac.New(md5.New, ksign)
	m.Write(h.Sum(nil))
	return m.Sum(nil)
}

func newPAForUser(user types.PrincipalName, realm string, sessionKey types.EncryptionKey) (types.PAData, error) {
	var data []byte
	data = binary.LittleEndian.AppendUint32(data, uint32(user.NameType))
	for _, s := range user.NameString {
		data = append(data, s...)
	}
	data = append(append(data, realm...), "Kerberos"...)
	v := paForUser{UserName: user, UserRealm: realm, AuthPackage: "Kerberos",
		Cksum: types.Checksum{CksumType: cksumHMACMD5, Checksum: hmacMD5Checksum(sessionKey.KeyValue, 17, data)}}
	b, err := asn1.Marshal(v)
	if err != nil {
		return types.PAData{}, err
	}
	return types.PAData{PADataType: patype.PA_FOR_USER, PADataValue: b}, nil
}

// signTGSReq (re)builds PA-TGS-REQ after the body is final: the
// authenticator's checksum covers the request body.
func signTGSReq(req *messages.TGSReq, tgt messages.Ticket, sessionKey types.EncryptionKey, extra ...types.PAData) error {
	body, err := req.ReqBody.Marshal()
	if err != nil {
		return err
	}
	et, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return err
	}
	ck, err := et.GetChecksumHash(sessionKey.KeyValue, body, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	if err != nil {
		return err
	}
	auth, err := types.NewAuthenticator(tgt.Realm, req.ReqBody.CName)
	if err != nil {
		return err
	}
	auth.Cksum = types.Checksum{CksumType: et.GetHashID(), Checksum: ck}
	ap, err := messages.NewAPReq(tgt, sessionKey, auth)
	if err != nil {
		return err
	}
	apb, err := ap.Marshal()
	if err != nil {
		return err
	}
	req.PAData = append(types.PADataSequence{{PADataType: patype.PA_TGS_REQ, PADataValue: apb}}, extra...)
	return nil
}

// tgsRoundTrip sends a TGS-REQ to the pinned KDCs and decrypts the reply
// with the TGT session key; a KRB-ERROR comes back described.
func tgsRoundTrip(c *Ctx, s *krbSetup, req messages.TGSReq, sessionKey types.EncryptionKey) (*messages.TGSRep, M, error) {
	b, err := req.Marshal()
	if err != nil {
		return nil, nil, err
	}
	reply, err := krbSendAny(c, s, b)
	if err != nil {
		return nil, nil, err
	}
	if len(reply) > 0 && reply[0] == 0x7e { // [APPLICATION 30] KRB-ERROR
		var ke messages.KRBError
		if err := ke.Unmarshal(reply); err != nil {
			return nil, nil, err
		}
		return nil, describeKRBError(ke), nil
	}
	var rep messages.TGSRep
	if err := rep.Unmarshal(reply); err != nil {
		return nil, nil, fmt.Errorf("TGS-REP: %w", err)
	}
	if err := rep.DecryptEncPart(sessionKey); err != nil {
		return nil, nil, err
	}
	if rep.DecryptedEncPart.Nonce != req.ReqBody.Nonce {
		return nil, nil, errors.New("TGS-REP nonce does not match the request")
	}
	return &rep, nil, nil
}

func principalString(p types.PrincipalName, realm string) string {
	return strings.Join(p.NameString, "/") + "@" + realm
}

// s4uProxyHint explains an S4U2Proxy refusal with what the S4U2Self step
// revealed. The order is the order of the causes: a user who cannot be
// delegated fails everything; Active Directory and Samba take only
// forwardable evidence, for resource-based delegation too (seen on Windows
// Server 2022 and Samba 4.22); then the service's rights, and the request
// flag RBCD needs.
func s4uProxyHint(code int32, eText, notDelegable string, forwardable, rbcd bool) string {
	if code != 13 { // KDC_ERR_BADOPTION
		return s4uHint(code, "S4U2Proxy")
	}
	switch {
	case strings.Contains(eText, "UNSUPPORTED_S4U2PROXY_REQUEST"):
		return "the KDC does not support S4U2Proxy for this service (" + eText + "): MIT krb5's default db2 database cannot hold delegation rights; constrained delegation needs its LDAP back end (krbAllowedToDelegateTo), or a resource-based setup"
	case notDelegable != "":
		return "the user cannot be delegated: " + notDelegable
	case !forwardable:
		return "the evidence ticket is not forwardable, and Active Directory and Samba accept only a forwardable one, for resource-based delegation too. Set TrustedToAuthForDelegation on the service (Samba needs it for every S4U2Self evidence ticket; Active Directory only when the service also has msDS-AllowedToDelegateTo, so there clearing msDS-AllowedToDelegateTo works too for resource-based delegation)"
	case !rbcd:
		return s4uHint(code, "S4U2Proxy") + ". For resource-based delegation a Windows KDC also needs the request flag: run with rbcd=true"
	}
	return s4uHint(code, "S4U2Proxy")
}

// s4uHint explains the KDC errors delegation setups usually hit.
func s4uHint(code int32, step string) string {
	switch code {
	case 13: // KDC_ERR_BADOPTION
		if step == "S4U2Proxy" {
			return "the service is not allowed to delegate to this SPN: add it to msDS-AllowedToDelegateTo (classic constrained delegation), or add the service to the target's msDS-AllowedToActOnBehalfOfOtherIdentity (resource-based)"
		}
		return "the KDC refused the option: is the service account allowed to use protocol transition?"
	case 7: // KDC_ERR_S_PRINCIPAL_UNKNOWN
		return "the KDC does not know that service principal"
	case 6: // KDC_ERR_C_PRINCIPAL_UNKNOWN
		return "the KDC does not know the user to impersonate"
	case 16: // KDC_ERR_PADATA_TYPE_NOSUPP
		return "the KDC does not support S4U (PA-FOR-USER)"
	case 12: // KDC_ERR_POLICY
		return "refused by policy: the account may not be trusted for delegation, or the user is marked sensitive and cannot be delegated"
	}
	return ""
}

// newS4U2ProxyReq builds a signed S4U2Proxy TGS-REQ: the service's TGT, and
// the S4U2Self ticket as evidence in additional-tickets.
func newS4U2ProxyReq(s *krbSetup, tgt messages.Ticket, sk types.EncryptionKey, evidence messages.Ticket, target types.PrincipalName, rbcd bool) (messages.TGSReq, error) {
	proxy, err := messages.NewTGSReq(s.cname, s.realm, s.cfg, tgt, sk, target, false)
	if err != nil {
		return proxy, err
	}
	types.SetFlag(&proxy.ReqBody.KDCOptions, flags.Forwardable)
	types.SetFlag(&proxy.ReqBody.KDCOptions, kdcOptCNameInAddTkt)
	// gokrb5 marshals a ticket's DecryptedEncPart after its four fields once
	// the ticket has been decrypted; the KDC then cannot parse the request
	// (Windows drops it without an answer, Heimdal reports a decode error).
	evidence.DecryptedEncPart = messages.EncTicketPart{}
	proxy.ReqBody.AdditionalTickets = []messages.Ticket{evidence}
	var extra []types.PAData
	if rbcd {
		// PA-PAC-OPTIONS with resource-based-constrained-delegation (bit 3),
		// which Windows KDCs require for RBCD and ignore otherwise.
		v, err := asn1.Marshal(paPACOptionsValue{Flags: asn1.BitString{Bytes: []byte{0x10, 0, 0, 0}, BitLength: 32}})
		if err != nil {
			return proxy, err
		}
		extra = append(extra, types.PAData{PADataType: paPACOptions, PADataValue: v})
	}
	return proxy, signTGSReq(&proxy, tgt, sk, extra...)
}

func runS4U(c *Ctx) (M, error) {
	s, err := krbPrepare(c)
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{"realm": s.realm, "service": principalString(s.cname, s.realm)}
	defer func() { out["checks"] = cs }()

	// The impersonated user: name[@REALM].
	imp := c.Str("impersonate")
	userRealm := s.realm
	if i := strings.LastIndex(imp, "@"); i > 0 {
		imp, userRealm = imp[:i], imp[i+1:]
	}
	user := types.NewPrincipalName(nametype.KRB_NT_ENTERPRISE, imp)
	if !strings.Contains(imp, "@") {
		user = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, imp)
	}
	out["impersonate"] = imp + "@" + userRealm

	// The service's own TGT.
	cl, err := s.client(c)
	if err != nil {
		return out, err
	}
	asReq, err := messages.NewASReqForTGT(s.realm, s.cfg, s.cname)
	if err != nil {
		return out, err
	}
	asRep, err := cl.ASExchange(s.realm, asReq, 0)
	if !cs.ok(err == nil, "AS exchange (service TGT issued)", detailOr(err, principalString(s.cname, s.realm)), "RFC 4120 §3.1") {
		return out, nil
	}
	tgt, sk := asRep.Ticket, asRep.DecryptedEncPart.Key

	// S4U2Self: a ticket to ourselves, for the user.
	self, err := messages.NewTGSReq(s.cname, s.realm, s.cfg, tgt, sk, s.cname, false)
	if err != nil {
		return out, err
	}
	types.SetFlag(&self.ReqBody.KDCOptions, flags.Forwardable)
	pafu, err := newPAForUser(user, userRealm, sk)
	if err != nil {
		return out, err
	}
	if err := signTGSReq(&self, tgt, sk, pafu); err != nil {
		return out, err
	}
	rep, kerr, err := tgsRoundTrip(c, s, self, sk)
	if err != nil {
		return out, err
	}
	if kerr != nil {
		out["s4u2self_error"] = kerr
		code, _ := kerr["error_code"].(int32)
		cs.add("S4U2Self (protocol transition)", "fail", fmt.Sprintf("%v %s", kerr["error"], s4uHint(code, "S4U2Self")), "MS-SFU §3.2.5.1")
		return out, nil
	}
	selfInfo := describeTicket(rep.Ticket)
	selfInfo["client"] = principalString(rep.CName, rep.CRealm)
	selfInfo["flags"] = flagList(rep.DecryptedEncPart.Flags)
	out["s4u2self_ticket"] = selfInfo
	cs.ok(rep.CName.Equal(user), "S4U2Self ticket names the impersonated user", principalString(rep.CName, rep.CRealm), "MS-SFU §3.2.5.1.2")
	forwardable := types.IsFlagSet(&rep.DecryptedEncPart.Flags, flags.Forwardable)
	if forwardable {
		cs.add("S4U2Self ticket forwardable", "pass", "usable as evidence for S4U2Proxy, classic or resource-based", "MS-SFU §3.2.5.1.2")
	} else {
		cs.add("S4U2Self ticket forwardable", "info", "not forwardable. Active Directory withholds the flag when the account has msDS-AllowedToDelegateTo but is not trusted for protocol transition (TrustedToAuthForDelegation); Samba withholds it whenever the account is not trusted for protocol transition; Active Directory also withholds it when the user is sensitive or in Protected Users. Both then refuse the ticket as S4U2Proxy evidence, for resource-based delegation too (other KDCs may accept it there)", "MS-SFU §3.2.5.1.2")
	}
	// The service can read its own ticket: flags, and the PAC, which says
	// whether the user may be delegated at all.
	var notDelegable string
	if et, err := crypto.GetEtype(rep.Ticket.EncPart.EType); err == nil {
		if key, _, err := cl.Key(et, rep.Ticket.EncPart.KVNO, nil); err == nil && rep.Ticket.Decrypt(key) == nil {
			out["s4u2self_ticket_contents"] = describeEncTicketPart(rep.Ticket.DecryptedEncPart)
			if p, ok, perr := ticketPAC(rep.Ticket.DecryptedEncPart, key); ok && perr == nil && p.KerbValidationInfo == nil {
				cs.add("user can be delegated", "info", "the PAC carries no logon info (not an Active Directory KDC), so it does not say whether the user may be delegated", "MS-SFU §3.2.5.2")
			} else if ok && perr == nil {
				if notDelegable = pacNotDelegable(p); notDelegable != "" {
					cs.add("user can be delegated", "warn", notDelegable+": no service may act for them through delegation, so the KDC must refuse S4U2Proxy", "MS-SFU §3.2.5.2")
				} else {
					cs.add("user can be delegated", "pass", "not marked sensitive, not in Protected Users", "MS-SFU §3.2.5.2")
				}
			}
		}
	}

	target := c.Str("target_spn")
	if target == "" {
		return out, nil
	}

	// S4U2Proxy: that ticket as evidence, for a ticket to the target.
	tsn, _ := types.ParseSPNString(target)
	proxy, err := newS4U2ProxyReq(s, tgt, sk, rep.Ticket, tsn, c.Bool("rbcd"))
	if err != nil {
		return out, err
	}
	prep, kerr, err := tgsRoundTrip(c, s, proxy, sk)
	if err != nil {
		return out, err
	}
	if kerr != nil {
		out["s4u2proxy_error"] = kerr
		code, _ := kerr["error_code"].(int32)
		hint := s4uProxyHint(code, str(kerr["e_text"]), notDelegable, forwardable, c.Bool("rbcd"))
		cs.add("S4U2Proxy (constrained delegation)", "fail", fmt.Sprintf("%v %s", kerr["error"], hint), "MS-SFU §3.2.5.2")
		return out, nil
	}
	proxyInfo := describeTicket(prep.Ticket)
	proxyInfo["client"] = principalString(prep.CName, prep.CRealm)
	proxyInfo["flags"] = flagList(prep.DecryptedEncPart.Flags)
	out["s4u2proxy_ticket"] = proxyInfo
	cs.add("S4U2Proxy (constrained delegation)", "pass", "ticket issued for "+target, "MS-SFU §3.2.5.2")
	if notDelegable != "" {
		cs.add("KDC refuses to delegate this user", "fail", "the KDC issued a delegated ticket although "+notDelegable+"; MS-SFU requires the KDC to refuse it", "MS-SFU §3.2.5.2")
	}
	cs.ok(prep.CName.Equal(user), "S4U2Proxy ticket names the impersonated user", principalString(prep.CName, prep.CRealm), "MS-SFU §3.2.5.2.2")
	etypeCheck(&cs, "delegated ticket", prep.Ticket.EncPart.EType)
	if k := c.Str("target_keytab"); k != "" {
		kt, err := loadKeytab(k)
		if err != nil {
			return out, fmt.Errorf("target_keytab: %w", err)
		}
		if cs.ok(prep.Ticket.DecryptEncPart(kt, nil) == nil, "delegated ticket decrypts with the target's keytab", "", "RFC 4120 §3.2.3") {
			out["s4u2proxy_ticket_contents"] = describeEncTicketPart(prep.Ticket.DecryptedEncPart)
			isPAC, p, perr := prep.Ticket.GetPACType(kt, nil, log.New(io.Discard, "", 0))
			switch {
			case !isPAC:
				cs.add("delegated ticket PAC", "info", "no PAC: not an Active Directory KDC, or PACs are disabled", "MS-PAC")
			case perr != nil:
				cs.add("delegated ticket PAC signatures", "fail", perr.Error(), "MS-PAC §2.8")
			default:
				out["s4u2proxy_pac"] = describePAC(&p)
				cs.add("delegated ticket PAC signatures", "pass", "server signature verified with the target's key", "MS-PAC §2.8")
				// MS-PAC §2.9: the KDC records who delegated in S4U_DELEGATION_INFO.
				if d := p.S4UDelegationInfo; d == nil {
					cs.add("PAC records the delegating service", "warn", "no S4U_DELEGATION_INFO buffer: the target cannot see which service delegated", "MS-PAC §2.9")
				} else {
					var via []string
					for _, t := range d.S4UTransitedServices {
						via = append(via, t.Value)
					}
					cs.add("PAC records the delegating service", "pass", "transited services: "+strings.Join(via, ", "), "MS-PAC §2.9")
				}
			}
		}
	}
	return out, nil
}

func init() {
	register(&Op{
		Name: "krb.s4u",
		Summary: "Test Kerberos constrained delegation (MS-SFU) as a service account: S4U2Self gets a ticket to the service on behalf of a user (protocol transition) and reports whether it is forwardable; with target_spn, S4U2Proxy turns it into a ticket for that service (classic or resource-based constrained delegation). " +
			"KDC refusals come back with what usually causes them. Returns ticket descriptions only, never usable tickets or keys.",
		Params: joinParams(krbParams, []Param{
			{Name: "impersonate", Type: "string", Required: true, Desc: "The user to act for: name, name@REALM, or a UPN"},
			{Name: "target_spn", Type: "string", Desc: "Service to delegate to (S4U2Proxy), e.g. cifs/files.example.com"},
			{Name: "rbcd", Type: "bool", Default: true, Desc: "Send PA-PAC-OPTIONS asking for resource-based constrained delegation (needed by Windows KDCs for RBCD)"},
			{Name: "target_keytab", Type: "string", Path: true, Desc: "The target service's keytab, to decrypt the delegated ticket"},
		}),
		Run: runS4U,
	})
}

// ticketPAC extracts the PAC from a decrypted ticket and verifies its server
// signature with the ticket's key.
// processPAC decodes a PAC's buffers and verifies its server signature.
// gokrb5 insists on a Windows logon-info buffer before it checks the
// signature; MIT krb5 (1.20 and later) issues PACs without one, so then
// the signature is checked here.
func processPAC(p *pac.PACType, key types.EncryptionKey) error {
	err := p.ProcessPACInfoBuffers(key, log.New(io.Discard, "", 0))
	// Only the one case where gokrb5 parsed every buffer and then gave up
	// because the Windows logon info is missing; any other error stands.
	if err == nil || p.KerbValidationInfo != nil || err.Error() != "PAC Info Buffers does not contain a KerbValidationInfo" {
		return err
	}
	switch {
	case p.ServerChecksum == nil:
		return fmt.Errorf("the PAC has no server signature")
	case p.KDCChecksum == nil:
		return fmt.Errorf("the PAC has no KDC signature")
	case p.ClientInfo == nil:
		return fmt.Errorf("the PAC has no client info")
	}
	sigType, sig, zeroed, err := pacServerSignature(p)
	if err != nil {
		return err
	}
	et, err := crypto.GetChksumEtype(sigType)
	if err != nil {
		return err
	}
	if !et.VerifyChecksum(key.KeyValue, zeroed, sig, keyusage.KERB_NON_KERB_CKSUM_SALT) {
		return fmt.Errorf("PAC service checksum verification failed")
	}
	return nil
}

// pacSignatureLen is the signature length of each checksum type a PAC may
// use (MS-PAC §2.8 and RFC 8009); gokrb5 only knows the first three.
var pacSignatureLen = map[int32]int{
	15: 12, 16: 12, // hmac-sha1-96-aes128/256
	-138: 16, // hmac-md5 (RC4)
	12:   20, // hmac-sha1-des3-kd
	19:   16, // hmac-sha256-128-aes128
	20:   24, // hmac-sha384-192-aes256
}

// pacServerSignature reads the server signature from the PAC itself and
// returns the PAC with both signatures zeroed, as signed (MS-PAC §2.8.1).
func pacServerSignature(p *pac.PACType) (int32, []byte, []byte, error) {
	zeroed := append([]byte(nil), p.Data...)
	var sigType int32
	var sig []byte
	found := false
	for _, buf := range p.Buffers {
		if buf.ULType != 6 && buf.ULType != 7 { // server and KDC signature
			continue
		}
		off, size := int(buf.Offset), int(buf.CBBufferSize)
		if off < 0 || size < 4 || off+size > len(p.Data) {
			return 0, nil, nil, fmt.Errorf("PAC signature buffer out of bounds")
		}
		t := int32(binary.LittleEndian.Uint32(p.Data[off:]))
		n, ok := pacSignatureLen[t]
		if !ok || 4+n > size {
			return 0, nil, nil, fmt.Errorf("PAC signature type %d is not supported", t)
		}
		if buf.ULType == 6 && !found {
			sigType, sig, found = t, append([]byte(nil), p.Data[off+4:off+4+n]...), true
		}
		clear(zeroed[off+4 : off+4+n])
	}
	if !found {
		return 0, nil, nil, fmt.Errorf("the PAC has no server signature")
	}
	return sigType, sig, zeroed, nil
}

// ticketPACFromKeytab finds a decrypted ticket's PAC and verifies it with
// the service key from the keytab.
func ticketPACFromKeytab(tkt messages.Ticket, kt *keytab.Keytab) (bool, pac.PACType, error) {
	key, _, err := kt.GetEncryptionKey(tkt.SName, tkt.Realm, tkt.EncPart.KVNO, tkt.EncPart.EType)
	if err != nil {
		p, isPAC, _ := ticketPAC(tkt.DecryptedEncPart, types.EncryptionKey{})
		if p == nil {
			return isPAC, pac.PACType{}, err
		}
		return isPAC, *p, err
	}
	p, isPAC, err := ticketPAC(tkt.DecryptedEncPart, key)
	if p == nil {
		return isPAC, pac.PACType{}, err
	}
	return isPAC, *p, err
}

func ticketPAC(e messages.EncTicketPart, key types.EncryptionKey) (*pac.PACType, bool, error) {
	for _, ad := range e.AuthorizationData {
		if ad.ADType != adtype.ADIfRelevant {
			continue
		}
		var inner types.AuthorizationData
		if inner.Unmarshal(ad.ADData) != nil {
			continue
		}
		for _, a := range inner {
			if a.ADType != adtype.ADWin2KPAC {
				continue
			}
			var p pac.PACType
			if err := p.Unmarshal(a.ADData); err != nil {
				return nil, true, err
			}
			return &p, true, processPAC(&p, key)
		}
	}
	return nil, false, nil
}

// pacNotDelegable says why a user may not be delegated: the account is
// marked sensitive (NOT_DELEGATED), or it is in Protected Users (RID 525).
func pacNotDelegable(p *pac.PACType) string {
	k := p.KerbValidationInfo
	if k == nil {
		return ""
	}
	if k.UserAccountControl&samrNotDelegated != 0 {
		return "the account is marked sensitive and cannot be delegated (USER_NOT_DELEGATED)"
	}
	for _, sid := range k.GetGroupMembershipSIDs() {
		if sid == k.LogonDomainID.String()+"-525" {
			return "the account is in Protected Users"
		}
	}
	return ""
}
