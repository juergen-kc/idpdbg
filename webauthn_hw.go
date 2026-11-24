package main

import (
	"bytes"
	"os"
	"unicode"

	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/term"
	"strings"
	"time"
)

// A real security key as the authenticator: idpdbg plays the browser
// (client data, RP ID rules, what to ask the key) and the key makes and
// uses the credential over CTAP2, or over U2F (CTAP1) where a browser
// would fall back to it.

func fidoTimeout(c *Ctx) time.Duration {
	t := time.Duration(c.Int("timeout")) * time.Second
	if t < 30*time.Second {
		t = 30 * time.Second
	}
	return t
}

// hwOriginGuard keeps a real key from signing for a site other than the
// one the response goes to. A browser binds the signature to the page's
// origin; here the caller names the origin, so over MCP (where the caller
// is a model that untrusted content may steer) the key only signs when the
// origin is the destination's, or for localhost when nothing is sent.
// Otherwise a touch could produce a valid sign-in for someone's real
// account, relayed to wherever the caller chose.
func hwOriginGuard(c *Ctx, cs *Checks, api *rpAPI, origin, rpID string) (withhold bool, err error) {
	dest := ""
	if api.kind != "offline" {
		dest, _ = originOf(api.resultURL)
	}
	local := rpID == "localhost" || strings.HasSuffix(rpID, ".localhost")
	if !c.CLI && local && dest != "" && !isLoopbackURL(dest) {
		return false, fmt.Errorf("refusing to send a security key's response for %s to %s over MCP: a localhost relying party's response stays on this machine", rpID, dest)
	}
	if !c.CLI && !local {
		// The site's own options (its challenge) and its own result URL,
		// and the signed response goes only there.
		switch {
		case dest == "":
			return false, fmt.Errorf("refusing to have the security key sign for %s offline over MCP: use server or options_url/result_url on %s, or the CLI", rpID, origin)
		case dest != origin:
			return false, fmt.Errorf("refusing to have the security key sign for origin %s while the response goes to %s: over MCP the origin must be the destination's (a browser never sends one site's signature to another)", origin, dest)
		case c.Str("options") != "":
			return false, errors.New("refusing pasted options with a security key over MCP: the challenge must come from the relying party itself (server or options_url)")
		}
		if o, _ := originOf(api.optionsURL); o != origin {
			return false, fmt.Errorf("refusing to have the security key sign for %s with options from %s: over MCP both must be the same site", origin, o)
		}
		withhold = true
	} else if dest != "" && dest != origin {
		cs.add("origin matches the destination", "warn", fmt.Sprintf("the key signs for %s but the response goes to %s: fine for a split front end and API you control, a phishing relay otherwise", origin, dest), "WebAuthn §13.4.9")
	}
	if c.Log != nil {
		to := dest
		if to == "" {
			to = "nowhere (offline)"
		}
		c.Log("The security key will sign for RP ID %s, origin %s; the response goes to %s.", rpID, origin, to)
	}
	return withhold, nil
}

// withholdSigned keeps a real key's signed response out of an MCP result
// and out of traces: it goes to the relying party and nowhere else.
func withholdSigned(c *Ctx, out, cred M, withhold bool) {
	resp, _ := cred["response"].(M)
	for _, k := range []string{"signature", "attestationObject", "authenticatorData"} {
		if v, ok := resp[k].(string); ok && withhold {
			c.Rec.secrets = append(c.Rec.secrets, v)
		}
	}
	if withhold {
		out["credential_response"] = M{"id": cred["id"], "type": cred["type"],
			"withheld": "over MCP the signed response from a security key goes only to the relying party, so it cannot be relayed"}
		// What the relying party answers (a session cookie or token for the
		// person's real account) must not reach the caller either.
		c.Rec.withholdResponses = true
	}
}

// serverResponse is the relying party's answer as shown in a result: in
// full, unless a real key's response was withheld over MCP.
func serverResponse(out M, res *httpResult) any {
	if cr, _ := out["credential_response"].(M); cr != nil && cr["withheld"] != nil {
		return M{"status": res.Status, "withheld": "the relying party's answer to a real security key may hold a session for the person's account, so over MCP only the verdict is shown"}
	}
	return res.JSON
}

// ---- U2F (CTAP1) over CTAPHID_MSG ----

const ctaphidMsg = 0x83

func u2fAPDU(ins, p1 byte, data []byte) []byte {
	b := []byte{0, ins, p1, 0, 0, byte(len(data) >> 8), byte(len(data))}
	return append(append(b, data...), 0, 0)
}

// u2fCall sends an APDU, repeating it while the key waits for a touch
// (SW 6985, CONDITIONS_NOT_SATISFIED).
func u2fCall(c *Ctx, d *ctapDevice, ins, p1 byte, data []byte, deadline time.Time) ([]byte, uint16, error) {
	prompted := false
	for {
		resp, err := d.transact(ctaphidMsg, u2fAPDU(ins, p1, data), 3*time.Second)
		if err != nil {
			return nil, 0, err
		}
		if len(resp) < 2 {
			return nil, 0, errors.New("U2F: short response")
		}
		sw := binary.BigEndian.Uint16(resp[len(resp)-2:])
		if sw != 0x6985 || p1 == 0x07 {
			return resp[:len(resp)-2], sw, nil
		}
		if time.Now().After(deadline) {
			return nil, sw, errTouchTimeout
		}
		if !prompted && c.Log != nil {
			prompted = true
			c.Log("Touch your security key (%s %s)...", safeText(d.info.Manufacturer), safeText(d.info.Product))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func u2fStatus(sw uint16) error {
	switch sw {
	case 0x9000:
		return nil
	case 0x6A80:
		return errors.New("U2F: the key does not recognise this credential (SW 6A80)")
	case 0x6D00:
		return errors.New("U2F: instruction not supported (SW 6D00)")
	}
	return fmt.Errorf("U2F: status word %04X", sw)
}

func derLength(b []byte) (int, error) {
	if len(b) < 2 || b[0] != 0x30 {
		return 0, errors.New("not a DER SEQUENCE")
	}
	switch l := b[1]; {
	case l < 0x80:
		return 2 + int(l), nil
	case l == 0x81 && len(b) > 2:
		return 3 + int(b[2]), nil
	case l == 0x82 && len(b) > 3:
		return 4 + int(binary.BigEndian.Uint16(b[2:4])), nil
	}
	return 0, errors.New("unsupported DER length")
}

// u2fRegister makes a credential with U2F_REGISTER and returns it as
// WebAuthn authenticator data with a fido-u2f attestation statement.
func u2fRegister(c *Ctx, d *ctapDevice, cdHash, rpIDHash []byte) (authData []byte, stmt map[any]any, err error) {
	resp, sw, err := u2fCall(c, d, 0x01, 0x00, append(append([]byte{}, cdHash...), rpIDHash...), time.Now().Add(fidoTimeout(c)))
	if err != nil {
		return nil, nil, err
	}
	if err := u2fStatus(sw); err != nil {
		return nil, nil, err
	}
	if len(resp) < 67 || resp[0] != 0x05 || resp[1] != 0x04 {
		return nil, nil, errors.New("U2F register: malformed response")
	}
	pub, khLen := resp[1:66], int(resp[66])
	if len(resp) < 67+khLen {
		return nil, nil, errors.New("U2F register: truncated key handle")
	}
	kh, rest := resp[67:67+khLen], resp[67+khLen:]
	cl, err := derLength(rest)
	if err != nil || cl > len(rest) {
		return nil, nil, fmt.Errorf("U2F register: attestation certificate: %v", err)
	}
	cose := cborEncode(map[any]any{1: 2, 3: -7, -1: 1, -2: pub[1:33], -3: pub[33:65]})
	attested := append(make([]byte, 16), byte(khLen>>8), byte(khLen))
	attested = append(append(attested, kh...), cose...)
	authData = append(append(append([]byte{}, rpIDHash...), 0x41), 0, 0, 0, 0) // UP, AT; counter 0
	authData = append(authData, attested...)
	return authData, map[any]any{"sig": append([]byte{}, rest[cl:]...), "x5c": []any{append([]byte{}, rest[:cl]...)}}, nil
}

// u2fExcluded reports whether the key already holds one of the key handles
// (U2F_AUTHENTICATE check-only answers 6985 for its own handles).
func u2fExcluded(c *Ctx, d *ctapDevice, rpIDHash []byte, ids [][]byte) bool {
	for _, id := range ids {
		if len(id) > 255 {
			continue
		}
		data := append(append(make([]byte, 32), rpIDHash...), byte(len(id)))
		if _, sw, err := u2fCall(c, d, 0x02, 0x07, append(data, id...), time.Now()); err == nil && sw == 0x6985 {
			return true
		}
	}
	return false
}

func u2fAuthenticate(c *Ctx, d *ctapDevice, cdHash, rpIDHash, credID []byte, presence bool) (authData, sig []byte, err error) {
	if len(credID) > 255 {
		return nil, nil, errors.New("U2F: credential ID longer than a key handle can be")
	}
	p1 := byte(0x03)
	if !presence {
		p1 = 0x08
	}
	data := append(append(append(append([]byte{}, cdHash...), rpIDHash...), byte(len(credID))), credID...)
	resp, sw, err := u2fCall(c, d, 0x02, p1, data, time.Now().Add(fidoTimeout(c)))
	if err != nil {
		return nil, nil, err
	}
	if err := u2fStatus(sw); err != nil {
		return nil, nil, err
	}
	if len(resp) < 6 {
		return nil, nil, errors.New("U2F authenticate: malformed response")
	}
	return append(append([]byte{}, rpIDHash...), resp[:5]...), resp[5:], nil
}

// ---- registration ----

func credList(v any) ([]any, [][]byte) {
	var list []any
	var ids [][]byte
	for _, e := range anyList(v) {
		m, _ := e.(map[string]any)
		if id := optBytes(m["id"]); id != nil {
			list = append(list, map[any]any{"type": "public-key", "id": id})
			ids = append(ids, id)
		}
	}
	return list, ids
}

func hwRegister(c *Ctx, cs *Checks, api *rpAPI, out, o M, origin, rpID string, challenge []byte, tamper string) (M, *softCredential, error) {
	withhold, err := hwOriginGuard(c, cs, api, origin, rpID)
	if err != nil {
		return nil, nil, err
	}
	switch tamper {
	case "", "wrong_origin", "wrong_challenge", "wrong_type", "wrong_rp_id_hash", "bad_attestation_signature":
	default:
		return nil, nil, fmt.Errorf("tamper %s is not possible with a security key: the key sets those fields itself", tamper)
	}
	typ, cdOrigin, keyRPID := "webauthn.create", origin, rpID
	switch tamper {
	case "wrong_origin":
		cdOrigin = "https://evil.example"
	case "wrong_challenge":
		challenge = randomBytes(32)
	case "wrong_type":
		typ = "webauthn.get"
	case "wrong_rp_id_hash":
		keyRPID = "evil.example"
	}
	cd := clientDataJSON(typ, challenge, cdOrigin)
	cdHash := sha256.Sum256(cd)
	rpHash := sha256.Sum256([]byte(keyRPID))

	sel, _ := o["authenticatorSelection"].(map[string]any)
	rk := c.Bool("resident_key")
	if (str(sel["residentKey"]) == "required" || sel["requireResidentKey"] == true) && !rk {
		return nil, nil, errors.New("the relying party requires a discoverable credential (passkey), which is stored on the key: pass resident_key=true to allow that")
	}
	policy := str(sel["userVerification"])
	var params []any
	es256 := false
	for _, p := range anyList(o["pubKeyCredParams"]) {
		m, _ := p.(map[string]any)
		if a, ok := m["alg"].(float64); ok && (str(m["type"]) == "" || str(m["type"]) == "public-key") {
			params = append(params, map[any]any{"alg": int64(a), "type": "public-key"})
			es256 = es256 || a == -7
		}
	}
	if len(params) == 0 {
		params, es256 = []any{map[any]any{"alg": int64(-7), "type": "public-key"}}, true
	}
	exclude, excludeIDs := credList(o["excludeCredentials"])
	rp, _ := o["rp"].(map[string]any)
	user, _ := o["user"].(map[string]any)
	uid := optBytes(user["id"])
	if len(uid) == 0 {
		return nil, nil, errors.New("options: user.id is missing")
	}

	var authBytes []byte
	var att map[any]any
	var attStmtRaw []byte
	protocol := "ctap2"
	uvWanted := false
	plat, err := usePlatform(c)
	if err != nil {
		return nil, nil, err
	}
	if plat {
		platformCheckParams(c, cs)
		protocol, uvWanted = "windows", policy == "required"
		var algs []int64
		for _, p := range params {
			algs = append(algs, p.(map[any]any)["alg"].(int64))
		}
		var a *platformAttestation
		a, err = platformAPI.MakeCredential(platformCreate{RPID: keyRPID, RPName: str(rp["name"]), UserID: uid, UserName: str(user["name"]),
			UserDisplayName: str(user["displayName"]), ClientDataJSON: cd, Algs: algs, Exclude: excludeIDs, ResidentKey: rk,
			UserVerification: uvPolicy(policy), Timeout: fidoTimeout(c)})
		if err == nil {
			out["key"] = M{"product": "chosen in the " + platformAPI.Name() + " dialog", "protocol": "windows", "transport": a.Transport}
			cs.add("protocol", "info", platformAPI.Name()+": Windows let the person choose the key and asked for its PIN and touch", "WebAuthn §5.1.3")
			authBytes, attStmtRaw = a.AuthData, a.AttStmtRaw
			stmt := map[any]any{}
			if v, _, derr := cborDecode(a.AttStmtRaw); derr == nil {
				stmt, _ = v.(map[any]any)
			}
			att = map[any]any{"fmt": a.Format, "attStmt": stmt, "authData": a.AuthData}
		}
	} else {
		err = withFIDO(c, c.Str("device"), func(d *ctapDevice) error {
			// A key that speaks only U2F has no getInfo: it offers U2F alone.
			info := map[any]any{int64(1): []any{"U2F_V2"}}
			if d.caps&0x04 != 0 {
				if info, err = getInfo(d); err != nil {
					return err
				}
			}
			opts, _ := info[int64(4)].(map[any]any)
			pinSet, _ := opts["clientPin"].(bool)
			uvNotRqd, _ := opts["makeCredUvNotRqd"].(bool)
			hasU2F := false
			for _, v := range strList(info[int64(1)]) {
				hasU2F = hasU2F || v == "U2F_V2"
			}
			mode := c.Str("ctap")
			u2fOK := !rk && hasU2F && es256 && policy != "required"
			must := pinSet && (!uvNotRqd || rk) // the key wants the PIN for this makeCredential
			why := "requested with ctap=u2f"
			var plan uvPlan
			switch {
			case mode == "u2f" && !u2fOK:
				return errors.New("U2F cannot do this registration (it needs ES256, no discoverable credential, no required user verification, and a key that speaks U2F)")
			case mode == "u2f":
				protocol = "u2f"
			case d.caps&0x04 == 0 && u2fOK:
				protocol = "u2f"
				why = "the key speaks only U2F"
			case d.caps&0x04 == 0:
				return errors.New("this key speaks only U2F, which cannot do this registration (it needs ES256, no discoverable credential and no required user verification)")
			case mode == "auto" && must && policy == "discouraged" && u2fOK:
				protocol = "u2f"
				why = "the key has a PIN set and needs it for CTAP2 registration, and the relying party discourages user verification, so, like a browser, idpdbg used U2F, which needs only a touch"
			default:
				var missing bool
				if plan, missing, err = planUV(c, d, info, policy, must, permMakeCredential, keyRPID); err != nil {
					return err
				}
				if missing {
					if mode != "auto" || !u2fOK {
						return errors.New("this registration needs the key's PIN: " + pinMissingHint)
					}
					protocol = "u2f"
					why = "a browser would ask for the key's PIN here; without one (" + pinMissingHint + ") idpdbg used U2F, which needs only a touch"
				}
			}
			out["key"] = M{"product": d.info.Manufacturer + " " + d.info.Product, "protocol": protocol}
			if protocol == "u2f" {
				cs.add("protocol", "info", "U2F register (CTAP1): "+why, "CTAP 2.1 §10")
				if len(excludeIDs) > 0 && u2fExcluded(c, d, rpHash[:], excludeIDs) {
					return &ctapError{code: 0x19}
				}
				ad, stmt, err := u2fRegister(c, d, cdHash[:], rpHash[:])
				if err != nil {
					return err
				}
				authBytes, attStmtRaw = ad, cborEncode(stmt)
				att = map[any]any{"fmt": "fido-u2f", "attStmt": stmt, "authData": ad}
				return nil
			}
			cs.add("protocol", "info", "CTAP2 authenticatorMakeCredential"+uvNote(plan), "CTAP 2.1 §6.1")
			uvWanted = plan.how != ""
			req := map[any]any{1: cdHash[:], 2: map[any]any{"id": keyRPID, "name": str(rp["name"])},
				3: map[any]any{"id": uid, "name": str(user["name"]), "displayName": str(user["displayName"])}, 4: params}
			if len(exclude) > 0 {
				req[5] = exclude
			}
			if rk {
				req[7] = map[any]any{"rk": true}
			}
			plan.params(req, cdHash[:], 8, 9, 7)
			resp, err := d.cbor(ctapMakeCredential, req, fidoTimeout(c))
			if err != nil {
				return err
			}
			vals, raws, err := cborMapFields(resp)
			if err != nil {
				return err
			}
			fmtName, _ := vals[int64(1)].(string)
			authBytes, _ = vals[int64(2)].([]byte)
			stmt, _ := vals[int64(3)].(map[any]any)
			attStmtRaw = raws[int64(3)]
			att = map[any]any{"fmt": fmtName, "attStmt": stmt, "authData": authBytes}
			return nil
		})
	}
	if err != nil {
		cs.add("security key made a credential", "fail", err.Error(), "CTAP 2.1 §6.1")
		return nil, nil, nil
	}

	// What the key produced, checked locally.
	ad, err := parseAuthData(authBytes)
	if !cs.ok(err == nil, "security key made a credential", detailOr(err, fmt.Sprintf("%v attestation", att["fmt"])), "CTAP 2.1 §6.1") {
		return nil, nil, nil
	}
	out["authenticator_data"] = ad.describe()
	cs.ok(bytes.Equal(ad.RPIDHash, rpHash[:]), "rpIdHash is SHA-256 of the RP ID", keyRPID, "WebAuthn §6.1")
	cs.ok(ad.Flags&0x01 != 0, "user present (UP)", "", "WebAuthn §6.1")
	uvCheck(cs, ad, uvWanted)
	if ad.CredKey == nil {
		cs.add("attested credential data present", "fail", "", "WebAuthn §6.5.1")
		return nil, nil, nil
	}
	out["key_attestation"] = verifyAttestation(cs, att, authBytes, cdHash[:], ad)
	if c.Bool("metadata") {
		stmt, _ := att["attStmt"].(map[any]any)
		out["metadata"] = mdsForAttestation(c, cs, ad, attestationCerts(stmt), true)
	}

	// What goes to the server: like a browser, honour attestation "none"
	// by replacing the statement and zeroing the AAGUID.
	conveyance := str(o["attestation"])
	attObj := append([]byte{0xA3}, cborEncode("fmt")...)
	sentAuth := authBytes
	if conveyance == "" || conveyance == "none" {
		if tamper == "bad_attestation_signature" {
			return nil, nil, errors.New("tamper bad_attestation_signature needs a relying party that asks for attestation (direct or enterprise); this one asks for none")
		}
		sentAuth = append([]byte{}, authBytes...)
		copy(sentAuth[37:53], make([]byte, 16))
		attObj = cborEncode(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": sentAuth})
		cs.add("attestation sent", "info", "the relying party asked for attestation \"none\", so like a browser idpdbg sends fmt none with a zero AAGUID; the key's own attestation is checked above", "WebAuthn §5.4.7")
	} else {
		raw := append([]byte{}, attStmtRaw...)
		if tamper == "bad_attestation_signature" {
			stmt, _ := att["attStmt"].(map[any]any)
			sig, _ := stmt["sig"].([]byte)
			if i := bytes.Index(raw, sig); len(sig) > 0 && i >= 0 {
				raw[i+len(sig)/2] ^= 0xFF
			}
		}
		attObj = append(append(attObj, cborEncode(att["fmt"].(string))...), cborEncode("attStmt")...)
		attObj = append(append(append(attObj, raw...), cborEncode("authData")...), cborEncode(authBytes)...)
		cs.add("attestation sent", "info", fmt.Sprintf("the key's %v statement, as the relying party asked for %q", att["fmt"], conveyance), "WebAuthn §5.4.7")
	}
	spki, _ := x509.MarshalPKIXPublicKey(ad.CredKey)
	algID := int64(0)
	if m, ok := ad.CredCOSE.(map[any]any); ok {
		algID, _ = coseInt(m, 3)
	}
	ext := extensionResults(cs, o, true)
	if _, asked := ext["credProps"]; asked {
		ext["credProps"] = M{"rk": rk}
	}
	cred := M{"id": b64url(ad.CredID), "rawId": b64url(ad.CredID), "type": "public-key", "authenticatorAttachment": "cross-platform",
		"response": M{"clientDataJSON": b64url(cd), "attestationObject": b64url(attObj), "transports": []string{"usb"},
			"authenticatorData": b64url(sentAuth), "publicKey": b64url(spki), "publicKeyAlgorithm": algID},
		"clientExtensionResults": ext}
	out["credential_response"] = cred
	out["client_data"] = json.RawMessage(cd)
	withholdSigned(c, out, cred, withhold)

	coseRaw := cborEncodeCOSE(ad.CredCOSE)
	stored := &softCredential{ID: b64url(ad.CredID), RPID: rpID, Alg: int(algID), Origin: origin, Hardware: true, Protocol: protocol,
		PublicKey: base64.StdEncoding.EncodeToString(coseRaw), AAGUID: uuidString(ad.AAGUID), SignCount: ad.SignCount, UserHandle: b64url(uid)}
	return cred, stored, nil
}

// cborEncodeCOSE re-encodes a decoded COSE key (int64 labels, byte strings).
func cborEncodeCOSE(v any) []byte {
	m, _ := v.(map[any]any)
	return cborEncode(m)
}

// ---- authentication ----

func hwLogin(c *Ctx, cs *Checks, api *rpAPI, out, o M, sc *softCredential, origin, rpID string, challenge []byte, tamper string) (M, uint32, error) {
	withhold, err := hwOriginGuard(c, cs, api, origin, rpID)
	if err != nil {
		return nil, 0, err
	}
	switch tamper {
	case "", "wrong_origin", "wrong_challenge", "wrong_type", "no_user_present", "bad_signature":
	default:
		return nil, 0, fmt.Errorf("tamper %s is not possible with a security key: the key sets those fields itself", tamper)
	}
	typ, cdOrigin := "webauthn.get", origin
	switch tamper {
	case "wrong_origin":
		cdOrigin = "https://evil.example"
	case "wrong_challenge":
		challenge = randomBytes(32)
	case "wrong_type":
		typ = "webauthn.create"
	}
	policy := str(o["userVerification"])
	cd := clientDataJSON(typ, challenge, cdOrigin)
	cdHash := sha256.Sum256(cd)
	rpHash := sha256.Sum256([]byte(rpID))
	discoverable := sc.ID == ""
	if discoverable && tamper == "no_user_present" {
		return nil, 0, errors.New("tamper no_user_present is not allowed with passkey: without a touch the key would reveal which accounts it holds for the site")
	}
	var credID []byte
	allow := []any{}
	if discoverable {
		allowList, _ := credList(o["allowCredentials"])
		allow = allowList
	} else {
		if credID, err = b64urlDecode(sc.ID); err != nil {
			return nil, 0, errors.New("credential: bad id")
		}
		allow = []any{map[any]any{"type": "public-key", "id": credID}}
	}
	presence := tamper != "no_user_present"
	var authBytes, sig, userHandle []byte
	uvWanted := false
	plat, err := usePlatform(c)
	if err != nil {
		return nil, 0, err
	}
	if plat {
		if !presence {
			return nil, 0, errors.New("tamper no_user_present talks to the key directly: the Windows WebAuthn API always asks for a touch (pass a device from fido.devices, which needs administrator rights)")
		}
		platformCheckParams(c, cs)
		uvWanted = policy == "required"
		var ids [][]byte
		for _, a := range allow {
			if m, ok := a.(map[any]any); ok {
				if id, ok := m["id"].([]byte); ok {
					ids = append(ids, id)
				}
			}
		}
		var r *platformAssertion
		r, err = platformAPI.GetAssertion(platformGet{RPID: rpID, ClientDataJSON: cd, Allow: ids, UserVerification: uvPolicy(policy), Timeout: fidoTimeout(c)})
		if err == nil {
			out["key"] = M{"product": "chosen in the " + platformAPI.Name() + " dialog", "protocol": "windows"}
			cs.add("protocol", "info", platformAPI.Name()+": Windows let the person choose the key (and, for a passkey, the account) and asked for its PIN and touch", "WebAuthn §5.1.4")
			authBytes, sig, userHandle = r.AuthData, r.Signature, r.UserHandle
			switch {
			case discoverable:
				credID = r.CredID
			case !bytes.Equal(r.CredID, credID):
				err = fmt.Errorf("Windows answered with credential %s, not the one asked for", b64url(r.CredID))
			}
		}
	} else {
		err = withFIDO(c, c.Str("device"), func(d *ctapDevice) error {
			out["key"] = M{"product": d.info.Manufacturer + " " + d.info.Product}
			if c.Str("ctap") == "u2f" && policy == "required" {
				return errors.New("U2F cannot verify the user, which the relying party requires")
			}
			if discoverable && (c.Str("ctap") == "u2f" || d.caps&0x04 == 0) {
				return errors.New("a passkey sign-in needs CTAP2: U2F cannot find credentials by itself")
			}
			if c.Str("ctap") != "u2f" && d.caps&0x04 != 0 {
				info, err := getInfo(d)
				if err != nil {
					return err
				}
				plan, missing, err := planUV(c, d, info, policy, false, permGetAssertion, rpID)
				if err != nil {
					return err
				}
				if missing {
					if policy == "required" {
						return errors.New("the relying party requires user verification, which needs the key's PIN: " + pinMissingHint)
					}
					cs.add("user verification", "info", "a browser would ask for the key's PIN here; without one ("+pinMissingHint+") the assertion carries no UV", "WebAuthn §5.4.6")
				}
				uvWanted = plan.how != ""
				req := map[any]any{1: rpID, 2: cdHash[:], 5: map[any]any{"up": presence}}
				if len(allow) > 0 {
					req[3] = allow
				}
				plan.params(req, cdHash[:], 6, 7, 5)
				resp, err := d.cbor(ctapGetAssertion, req, fidoTimeout(c))
				var ce *ctapError
				if err == nil {
					as, err := collectAssertions(d, resp)
					if err != nil {
						return err
					}
					a := as[0]
					if discoverable {
						if a, err = chooseAccount(c, cs, out, as, withhold); err != nil {
							return err
						}
						credID = a.credID
					}
					authBytes, sig, userHandle = a.authData, a.sig, a.user
					cs.add("protocol", "info", "CTAP2 authenticatorGetAssertion"+uvNote(plan), "CTAP 2.1 §6.2")
					return nil
				}
				if !(errors.As(err, &ce) && (ce.code == 0x2E || ce.code == 0x36) && sc.Protocol == "u2f" && c.Str("ctap") == "auto") {
					return err
				}
			}
			cs.add("protocol", "info", "U2F authenticate (CTAP1)", "CTAP 2.1 §10")
			authBytes, sig, err = u2fAuthenticate(c, d, cdHash[:], rpHash[:], credID, presence)
			return err
		})
	}
	if err != nil {
		cs.add("security key signed the assertion", "fail", err.Error(), "CTAP 2.1 §6.2")
		return nil, 0, nil
	}
	ad, err := parseAuthData(authBytes)
	if !cs.ok(err == nil, "security key signed the assertion", detailOr(err, ""), "CTAP 2.1 §6.2") {
		return nil, 0, nil
	}
	if discoverable {
		// What the stored credential returned for next time would hold.
		sc.ID, sc.RPID, sc.Origin, sc.Protocol = b64url(credID), rpID, origin, "ctap2"
		if len(userHandle) > 0 {
			sc.UserHandle = b64url(userHandle)
		}
		out["credential_id"] = sc.ID
		if len(allow) == 0 { // the RP then identifies the account by it
			cs.ok(len(userHandle) > 0, "passkey returned the user handle", "", "WebAuthn §7.2 step 6")
		}
	}
	out["authenticator_data"] = ad.describe()
	cs.ok(bytes.Equal(ad.RPIDHash, rpHash[:]), "rpIdHash is SHA-256 of the RP ID", rpID, "WebAuthn §6.1")
	if presence {
		cs.ok(ad.Flags&0x01 != 0, "user present (UP)", "", "WebAuthn §6.1")
	}
	uvCheck(cs, ad, uvWanted)
	if ad.SignCount == 0 && sc.SignCount == 0 {
		cs.add("signature counter", "info", "0: the key keeps no counter for this credential", "WebAuthn §6.1.1")
	} else {
		cs.ok(ad.SignCount > sc.SignCount, "signature counter increased", fmt.Sprintf("%d after %d", ad.SignCount, sc.SignCount), "WebAuthn §6.1.1")
	}
	if sc.PublicKey == "" {
		cs.add("assertion signature verifies with the registered key", "info", "not checked here: a passkey sign-in has no registered public key at hand (the relying party checks it)", "WebAuthn §7.2 step 20")
	} else if cose, err := base64.StdEncoding.DecodeString(sc.PublicKey); err == nil {
		if v, _, err := cborDecode(cose); err == nil {
			if pub, alg, err := coseKey(v); err == nil {
				err := webauthnVerify(alg, pub, append(append([]byte{}, authBytes...), cdHash[:]...), sig)
				cs.ok(err == nil, "assertion signature verifies with the registered key", detailOr(err, alg), "WebAuthn §7.2 step 20")
			}
		}
	}
	if tamper == "bad_signature" {
		sig = append([]byte{}, sig...)
		sig[len(sig)/2] ^= 0xFF
	}
	resp := M{"clientDataJSON": b64url(cd), "authenticatorData": b64url(authBytes), "signature": b64url(sig)}
	if len(userHandle) > 0 {
		resp["userHandle"] = b64url(userHandle)
	} else if sc.UserHandle != "" {
		resp["userHandle"] = sc.UserHandle
	}
	cred := M{"id": sc.ID, "rawId": sc.ID, "type": "public-key", "authenticatorAttachment": "cross-platform", "response": resp,
		"clientExtensionResults": extensionResults(cs, o, false)}
	out["credential_response"] = cred
	out["client_data"] = json.RawMessage(cd)
	withholdSigned(c, out, cred, withhold)
	return cred, ad.SignCount, nil
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func uvNote(p uvPlan) string {
	switch p.how {
	case "pin":
		return fmt.Sprintf(", user verified with the PIN (PIN/UV auth protocol %d)", p.proto)
	case "builtin":
		return ", user verified by the key itself"
	}
	return ""
}

func uvCheck(cs *Checks, ad *authData, wanted bool) {
	switch uv := ad.Flags&0x04 != 0; {
	case wanted:
		cs.ok(uv, "user verified (UV)", "", "WebAuthn §6.1")
	case uv:
		cs.add("user verified (UV)", "info", "set", "WebAuthn §6.1")
	default:
		cs.add("user verified (UV)", "info", "not performed", "WebAuthn §6.1")
	}
}

type assertion struct {
	credID, authData, sig, user []byte
	userName, displayName       string
}

func parseAssertion(b []byte) (assertion, int, error) {
	vals, _, err := cborMapFields(b)
	if err != nil {
		return assertion{}, 0, err
	}
	var a assertion
	if cm, ok := vals[int64(1)].(map[any]any); ok {
		a.credID, _ = cm["id"].([]byte)
	}
	a.authData, _ = vals[int64(2)].([]byte)
	a.sig, _ = vals[int64(3)].([]byte)
	if u, ok := vals[int64(4)].(map[any]any); ok {
		a.user, _ = u["id"].([]byte)
		a.userName, _ = u["name"].(string)
		a.displayName, _ = u["displayName"].(string)
	}
	n, _ := vals[int64(5)].(int64)
	return a, int(n), nil
}

// collectAssertions reads the first assertion and, when the key reports
// several matching credentials, the rest with authenticatorGetNextAssertion
// (signed under the same touch).
func collectAssertions(d *ctapDevice, first []byte) ([]assertion, error) {
	a, n, err := parseAssertion(first)
	if err != nil {
		return nil, err
	}
	out := []assertion{a}
	for i := 1; i < n && i < 64; i++ {
		b, err := d.cbor(ctapGetNextAssertion, nil, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("getNextAssertion: %w", err)
		}
		a, _, err := parseAssertion(b)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// chooseAccount picks one of several passkeys for the site: by the account
// parameter, or from a terminal by asking, as a browser shows its picker.
// Over MCP (private set) the caller learns only how many accounts there
// are: the names and handles are the person's, for the person to read.
func chooseAccount(c *Ctx, cs *Checks, out M, as []assertion, private bool) (assertion, error) {
	var list []M
	for i, a := range as {
		e := M{"number": i + 1}
		if !private {
			e["user_name"], e["display_name"], e["user_handle"], e["credential_id"] = a.userName, a.displayName, b64url(a.user), b64url(a.credID)
		}
		list = append(list, e)
	}
	out["accounts"] = list
	cs.add("passkeys for this site on the key", "info", fmt.Sprint(len(as)), "CTAP 2.1 §6.3")
	if len(as) == 1 {
		return as[0], nil
	}
	want := c.Str("account")
	if want == "" && c.CLI && term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "Several passkeys for this site are on the key:")
		for i, a := range as {
			fmt.Fprintf(os.Stderr, "  %d: %s %s\n", i+1, safeText(a.userName), safeText(a.displayName))
		}
		fmt.Fprint(os.Stderr, "Which one? ")
		fmt.Fscanln(os.Stdin, &want)
	}
	if want == "" {
		return assertion{}, fmt.Errorf("%d passkeys for this site are on the key; pass account (user name, display name, user handle or number; accounts lists them)", len(as))
	}
	for i, a := range as {
		if want == fmt.Sprint(i+1) || want == a.userName || want == a.displayName || want == b64url(a.user) {
			return a, nil
		}
	}
	return assertion{}, fmt.Errorf("no passkey on the key matches account %q", want)
}

// safeText drops control characters (escape sequences included) from text
// that came from a device or a relying party before it reaches a terminal.
func safeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
