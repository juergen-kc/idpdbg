package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CTAP 2.1 authenticatorCredentialManagement (§6.8): the passkeys a security
// key stores, listed by relying party, and deleted one at a time. Every
// request but the "get next" ones carries a MAC with a PIN/UV auth token
// that has the cm permission, so the PIN is always needed.

const (
	ctapCredMgmt        = 0x0A
	ctapCredMgmtPreview = 0x41 // FIDO_2_1_PRE keys (credentialMgmtPreview)

	cmGetCredsMetadata     = 0x01
	cmEnumerateRPsBegin    = 0x02
	cmEnumerateRPsNext     = 0x03
	cmEnumerateCredsBegin  = 0x04
	cmEnumerateCredsNext   = 0x05
	cmDeleteCredential     = 0x06
	permCredentialMgmt     = 0x04
	cmMaxEnumerated        = 1000 // a key that claims more is not believed
	credMgmtRef            = "CTAP 2.1 §6.8"
	credProtectRef         = "CTAP 2.1 §12.1"
	credMgmtNoPINRefusal   = "credential management needs the key's PIN; " + pinMissingHint
	credMgmtNotSetRefusal  = "the key has no PIN set, and credential management needs one (set it with the vendor's tool or a browser)"
	credMgmtNoSupportShort = "not supported"
)

var credProtectNames = map[int64]string{1: "userVerificationOptional", 2: "userVerificationOptionalWithCredentialIDList", 3: "userVerificationRequired"}

// credMgmt is a session of credential management commands with one token.
type credMgmt struct {
	d       *ctapDevice
	cmd     byte
	token   []byte
	proto   int
	preview bool
}

func (s *credMgmt) call(sub int, params map[any]any, auth bool) (map[any]any, error) {
	req := map[any]any{1: sub}
	if params != nil {
		req[2] = params
	}
	if auth {
		msg := []byte{byte(sub)}
		if params != nil {
			msg = append(msg, cborEncode(params)...)
		}
		req[3], req[4] = s.proto, pinAuth(s.proto, s.token, msg)
	}
	b, err := s.d.cbor(s.cmd, req, 10*time.Second)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return map[any]any{}, nil
	}
	m, _, err := cborMapFields(b)
	return m, err
}

func isNoCredentials(err error) bool {
	var ce *ctapError
	return errors.As(err, &ce) && ce.code == 0x2E
}

// openCredMgmt checks that the key does credential management and that a
// PIN is set, and trades the PIN for a token with the cm permission.
// A nil session with a nil error means a check already said why not.
func openCredMgmt(c *Ctx, cs *Checks, out M, d *ctapDevice) (*credMgmt, error) {
	info, err := getInfo(d)
	if err != nil {
		return nil, err
	}
	opts, _ := info[int64(4)].(map[any]any)
	s := &credMgmt{d: d}
	switch {
	case opts["credMgmt"] == true:
		s.cmd = ctapCredMgmt
		out["command"] = "authenticatorCredentialManagement (0x0A)"
	case opts["credentialMgmtPreview"] == true:
		s.cmd, s.preview = ctapCredMgmtPreview, true
		out["command"] = "credentialManagement preview (0x41)"
	}
	versions := strings.Join(strList(info[int64(1)]), ", ")
	if !cs.ok(s.cmd != 0, "credential management supported", map[bool]string{true: versions, false: credMgmtNoSupportShort + " (" + versions + "): this key cannot list or delete its passkeys"}[s.cmd != 0], credMgmtRef) {
		return nil, nil
	}
	if s.preview {
		cs.add("credential management version", "info", "the pre-2.1 preview (FIDO_2_1_PRE): same commands under 0x41, and a PIN token without permissions", credMgmtRef)
	}
	if opts["clientPin"] != true {
		cs.add("PIN set", "fail", credMgmtNotSetRefusal, credMgmtRef)
		return nil, nil
	}
	pin, err := pinFor(c, d, "credential management")
	if err != nil {
		return nil, err
	}
	if pin == "" {
		return nil, errors.New(credMgmtNoPINRefusal)
	}
	if s.token, s.proto, err = pinToken(d, info, pin, permCredentialMgmt, ""); err != nil {
		return nil, err
	}
	out["pin_uv_auth_protocol"] = s.proto
	return s, nil
}

type mgmtRP struct {
	id, name string
	hash     []byte
}

// relyingParties enumerates the relying parties with passkeys on the key.
func (s *credMgmt) relyingParties(cs *Checks) ([]mgmtRP, error) {
	first, err := s.call(cmEnumerateRPsBegin, nil, true)
	if isNoCredentials(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enumerateRPsBegin: %w", err)
	}
	total, _ := first[int64(5)].(int64)
	if total < 1 || total > cmMaxEnumerated {
		return nil, fmt.Errorf("enumerateRPsBegin: totalRPs %d", total)
	}
	var rps []mgmtRP
	var badHash []string
	for i := int64(0); i < total; i++ {
		m := first
		if i > 0 {
			if m, err = s.call(cmEnumerateRPsNext, nil, false); err != nil {
				return rps, fmt.Errorf("enumerateRPsGetNextRP %d of %d: %w", i+1, total, err)
			}
		}
		e, _ := m[int64(3)].(map[any]any)
		hash, _ := m[int64(4)].([]byte)
		rp := mgmtRP{id: str(e["id"]), name: str(e["name"]), hash: hash}
		if want := sha256.Sum256([]byte(rp.id)); rp.id == "" || !bytes.Equal(hash, want[:]) {
			badHash = append(badHash, safeText(rp.id))
		}
		rps = append(rps, rp)
	}
	cs.ok(len(badHash) == 0, "rpIDHash is SHA-256 of the RP ID", strings.Join(badHash, ", "), credMgmtRef+".3")
	return rps, nil
}

// credentials enumerates one relying party's passkeys, as the raw response
// maps.
func (s *credMgmt) credentials(rp mgmtRP) ([]map[any]any, error) {
	first, err := s.call(cmEnumerateCredsBegin, map[any]any{1: rp.hash}, true)
	if isNoCredentials(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enumerateCredentialsBegin for %s: %w", safeText(rp.id), err)
	}
	total, _ := first[int64(9)].(int64)
	if total < 1 || total > cmMaxEnumerated {
		return nil, fmt.Errorf("enumerateCredentialsBegin for %s: totalCredentials %d", safeText(rp.id), total)
	}
	list := []map[any]any{first}
	for i := int64(1); i < total; i++ {
		m, err := s.call(cmEnumerateCredsNext, nil, false)
		if err != nil {
			return list, fmt.Errorf("enumerateCredentialsGetNextCredential %d of %d for %s: %w", i+1, total, safeText(rp.id), err)
		}
		list = append(list, m)
	}
	return list, nil
}

func credentialID(m map[any]any) []byte {
	desc, _ := m[int64(7)].(map[any]any)
	id, _ := desc["id"].([]byte)
	return id
}

// describeStoredCredential is what the list shows of one passkey: never the
// large blob key, which is a secret.
func describeStoredCredential(m map[any]any) M {
	e := M{"credential_id": b64url(credentialID(m))}
	if u, ok := m[int64(6)].(map[any]any); ok {
		if id, ok := u["id"].([]byte); ok {
			e["user_id"] = b64url(id)
		}
		if n := str(u["name"]); n != "" {
			e["user_name"] = safeText(n)
		}
		if n := str(u["displayName"]); n != "" {
			e["user_display_name"] = safeText(n)
		}
	}
	if pk, alg, err := coseKey(m[int64(8)]); err == nil {
		k := M{"alg": alg}
		if j, err := publicJWK(pk); err == nil {
			k["kty"], k["crv"], k["thumbprint"] = j["kty"], j["crv"], jwkThumbprint(j)
		}
		e["public_key"] = k
	}
	if p, ok := m[int64(10)].(int64); ok {
		e["cred_protect"] = credProtectNames[p]
		if e["cred_protect"] == "" {
			e["cred_protect"] = p
		}
	}
	if _, ok := m[int64(11)]; ok {
		e["large_blob_key"] = true
	}
	if v, ok := m[int64(12)].(bool); ok {
		e["third_party_payment"] = v
	}
	return e
}

// listAll enumerates every relying party and its passkeys.
func (s *credMgmt) listAll(cs *Checks, filter string) ([]M, map[string][2]any, int, error) {
	rps, err := s.relyingParties(cs)
	if err != nil {
		return nil, nil, 0, err
	}
	index := map[string][2]any{} // credential ID → {rp, raw response}
	var out []M
	n := 0
	for _, rp := range rps {
		creds, err := s.credentials(rp)
		if err != nil {
			return out, index, n, err
		}
		n += len(creds)
		var list []M
		for _, m := range creds {
			index[string(credentialID(m))] = [2]any{rp, m}
			list = append(list, describeStoredCredential(m))
		}
		if filter != "" && rp.id != filter {
			continue
		}
		e := M{"rp_id": safeText(rp.id), "credentials": list}
		if rp.name != "" {
			e["rp_name"] = safeText(rp.name)
		}
		out = append(out, e)
	}
	return out, index, n, nil
}

func runFIDOCredentials(c *Ctx) (M, error) {
	var cs Checks
	out := M{}
	err := withFIDO(c, c.Str("device"), func(d *ctapDevice) error {
		out["device"] = M{"path": d.info.Path, "manufacturer": d.info.Manufacturer, "product": d.info.Product}
		s, err := openCredMgmt(c, &cs, out, d)
		if s == nil || err != nil {
			return err
		}
		meta, err := s.call(cmGetCredsMetadata, nil, true)
		if err != nil {
			return fmt.Errorf("getCredsMetadata: %w", err)
		}
		existing, _ := meta[int64(1)].(int64)
		remaining, _ := meta[int64(2)].(int64)
		out["stored"], out["remaining"] = existing, remaining
		cs.add("passkeys stored", "info", fmt.Sprintf("%d, room for about %d more", existing, remaining), credMgmtRef+".1")
		rps, _, n, err := s.listAll(&cs, c.Str("rp_id"))
		out["relying_parties"] = rps
		if err != nil {
			return err
		}
		cs.ok(int64(n) == existing, "enumerated passkeys match the stored count", fmt.Sprintf("%d listed, %d reported by getCredsMetadata", n, existing), credMgmtRef+".1")
		if f := c.Str("rp_id"); f != "" && len(rps) == 0 {
			cs.add("passkeys for "+safeText(f), "info", "none on this key", credMgmtRef)
		}
		for _, rp := range rps {
			for _, cr := range rp["credentials"].([]M) {
				if cr["cred_protect"] == "userVerificationOptional" || cr["cred_protect"] == nil {
					cs.add("credProtect for "+str(rp["rp_id"]), "info", "a passkey without credProtect level 2 or 3 can be found without user verification, which tells whoever holds the key that this account exists", credProtectRef)
					break
				}
			}
		}
		return nil
	})
	out["checks"] = cs
	return out, err
}

func decodeCredentialID(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, errors.New("credential_id: not base64url (take it from fido.credentials)")
}

func runFIDOCredentialDelete(c *Ctx) (M, error) {
	id, err := decodeCredentialID(c.Str("credential_id"))
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{}
	err = withFIDO(c, c.Str("device"), func(d *ctapDevice) error {
		out["device"] = M{"path": d.info.Path, "manufacturer": d.info.Manufacturer, "product": d.info.Product}
		s, err := openCredMgmt(c, &cs, out, d)
		if s == nil || err != nil {
			return err
		}
		_, index, _, err := s.listAll(&cs, "")
		if err != nil {
			return err
		}
		hit, found := index[string(id)]
		if !cs.ok(found, "the passkey is on this key", b64url(id), credMgmtRef) {
			return nil
		}
		rp := hit[0].(mgmtRP)
		target := describeStoredCredential(hit[1].(map[any]any))
		target["rp_id"] = safeText(rp.id)
		out["credential"] = target
		if want := c.Str("rp_id"); want != "" && want != rp.id {
			cs.add("the passkey belongs to rp_id", "fail", fmt.Sprintf("it belongs to %s, not %s: nothing deleted", safeText(rp.id), safeText(want)), credMgmtRef)
			return nil
		}
		if !c.Bool("confirm") {
			out["deleted"] = false
			cs.add("deleted", "info", "dry run: pass confirm to delete this passkey for good (the account it signs in to may have no other way in)", credMgmtRef+".5")
			return nil
		}
		desc := hit[1].(map[any]any)[int64(7)]
		if _, err := s.call(cmDeleteCredential, map[any]any{2: desc}, true); err != nil {
			return fmt.Errorf("deleteCredential: %w", err)
		}
		out["deleted"] = true
		// The key's own word is not proof: list again.
		_, after, _, err := s.listAll(&Checks{}, "")
		if err != nil {
			return fmt.Errorf("listing after the delete: %w", err)
		}
		_, still := after[string(id)]
		cs.ok(!still, "the passkey is gone", "deleteCredential answered success, and the key no longer lists it", credMgmtRef+".5")
		return nil
	})
	out["checks"] = cs
	return out, err
}

func init() {
	device := Param{Name: "device", Type: "string", Desc: "Which key: index or path from fido.devices (default: the only one on USB); nfc, or nfc:<part of the reader name>, for a key on an NFC reader"}
	pin := Param{Name: "pin", Type: "string", Secret: true, Desc: "Security key PIN (prefer env IDPDBG_PIN or a profile; from a terminal idpdbg asks). Never retried: a wrong PIN costs one of the key's attempts"}
	// Deleting cannot be undone and has no relying party to bind a stored
	// PIN to, so over MCP the PIN must come in the call.
	deletePIN := pin
	deletePIN.Explicit = true
	deletePIN.Desc = "Security key PIN (from a terminal idpdbg asks). Never retried: a wrong PIN costs one of the key's attempts"
	register(
		&Op{
			Name:    "fido.credentials",
			Summary: "List the passkeys (discoverable credentials) stored on a FIDO security key with CTAP 2.1 credential management: per relying party the credential ID, user handle and name, public key and credProtect level, plus how many are stored and how much room is left. Needs the key's PIN; needs no touch.",
			Params: joinParams([]Param{device, pin}, []Param{
				{Name: "rp_id", Type: "string", Desc: "Show only this relying party's passkeys"},
			}),
			Run: runFIDOCredentials,
		},
		&Op{
			Name:     "fido.credential_delete",
			Mutating: true,
			Summary:  "Delete one passkey from a FIDO security key (CTAP 2.1 credential management). Without confirm it is a dry run that shows which passkey and account would go; with confirm the key deletes it and idpdbg lists again to see that it is gone. Cannot be undone. Needs the key's PIN.",
			Params: joinParams([]Param{device, deletePIN}, []Param{
				{Name: "credential_id", Type: "string", Required: true, Desc: "The passkey's credential ID (base64url, from fido.credentials)"},
				{Name: "rp_id", Type: "string", Desc: "Refuse unless the passkey belongs to this relying party"},
				{Name: "confirm", Type: "bool", Explicit: true, Desc: "Really delete it. Without it nothing is deleted"},
			}),
			Run: runFIDOCredentialDelete,
		},
	)
}
