package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Presenting an mdoc over OID4VP (Appendix B.2): only the data elements the
// DCQL query asks for, in a DeviceResponse whose device signature covers
// the OID4VP SessionTranscript, which binds it to this verifier, nonce and
// response URI.

// isMdocCredential tells an mdoc (CBOR IssuerSigned, base64url or hex) from
// an SD-JWT VC.
func isMdocCredential(s string) bool {
	if strings.Contains(s, "~") || strings.Count(s, ".") == 2 {
		return false
	}
	b, err := mdocBytes(s)
	if err != nil {
		return false
	}
	v, _, err := cborDecodeTagged(b)
	return err == nil && mapOf(v)["issuerAuth"] != nil
}

// oid4vpSessionTranscript builds the SessionTranscript of OID4VP 1.0
// Appendix B.2.6.1: [null, null, ["OpenID4VPHandover", SHA-256 of
// [client_id, nonce, jwkThumbprint or null, response_uri]]].
func oid4vpSessionTranscript(clientID, nonce string, encKeyThumb []byte, responseURI string) []byte {
	var thumb any
	if encKeyThumb != nil {
		thumb = encKeyThumb
	}
	info := sha256.Sum256(cborEncode([]any{clientID, nonce, thumb, responseURI}))
	return cborEncode([]any{nil, nil, []any{"OpenID4VPHandover", info[:]}})
}

func presentMdoc(c *Ctx, cs *Checks, out M, r *vpRequest, cred string) ([]byte, error) {
	b, _ := mdocBytes(cred)
	top, _, err := cborDecodeTagged(b)
	if err != nil {
		return nil, err
	}
	is := mapOf(top)
	auth, err := parseCOSESign1(is["issuerAuth"])
	if err != nil {
		return nil, fmt.Errorf("credential: issuerAuth: %w", err)
	}
	payload, _, _ := cborDecodeTagged(auth.Payload)
	mso := mapOf(payload)
	docType, _ := mso["docType"].(string)

	// The credential query for this docType.
	dq, _ := r.Claims["dcql_query"].(map[string]any)
	qs, _ := dq["credentials"].([]any)
	var query map[string]any
	for _, x := range qs {
		q, _ := x.(map[string]any)
		meta, _ := q["meta"].(map[string]any)
		if str(q["format"]) == "mso_mdoc" && str(meta["doctype_value"]) == docType {
			query = q
			break
		}
	}
	if !cs.ok(query != nil, "a DCQL credential query matches this credential", "mso_mdoc, doctype "+docType, vpRef+" §6, Appendix B.2.3") {
		return nil, nil
	}

	// Only the requested elements.
	want := map[string]bool{}
	if cl, ok := query["claims"].([]any); ok {
		for _, x := range cl {
			xm, _ := x.(map[string]any)
			path, _ := xm["path"].([]any)
			if len(path) == 2 {
				want[str(path[0])+"/"+str(path[1])] = true
				if xm["intent_to_retain"] == true {
					cs.add("verifier intends to retain "+str(path[1]), "info", "intent_to_retain is set for this element", vpRef+" §6.3")
				}
			}
		}
	}
	nsMap := mapOf(is["nameSpaces"])
	sel := map[any]any{}
	var sent, withheld []string
	found := map[string]bool{}
	for _, nsKey := range sortedAnyKeys(nsMap) {
		ns := fmt.Sprint(nsKey)
		items, _ := untag(nsMap[nsKey]).([]any)
		var keep []any
		for _, it := range items {
			name := fmt.Sprint(mapOf(it)["elementIdentifier"])
			if len(want) == 0 || want[ns+"/"+name] {
				keep = append(keep, it)
				sent = append(sent, ns+"/"+name)
				found[ns+"/"+name] = true
			} else {
				withheld = append(withheld, ns+"/"+name)
			}
		}
		if len(keep) > 0 {
			sel[nsKey] = keep
		}
	}
	if len(want) == 0 {
		cs.add("data minimisation", "info", "the query names no claims, so every element is sent", vpRef+" §6.1")
	}
	var missing []string
	for k := range want {
		if !found[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if !cs.ok(len(missing) == 0, "every requested claim is available", strings.Join(missing, ", "), vpRef+" §6.4") {
		return nil, nil
	}
	sort.Strings(sent)
	sort.Strings(withheld)
	out["disclosed"], out["withheld"] = sent, withheld

	// The holder key must be the MSO's device key.
	if c.Str("holder_key") == "" {
		return nil, errors.New("holder_key is required: the device key the mdoc is bound to")
	}
	hk, _, err := holderKey(c)
	if err != nil {
		return nil, err
	}
	ek, ok := hk.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("holder_key: an mdoc device key is an EC key")
	}
	dki := mapOf(mso["deviceKeyInfo"])
	dpub, _, err := coseKey(untag(dki["deviceKey"]))
	djwk, _ := publicJWK(dpub)
	hjwk, _ := publicJWK(hk.Public())
	if !cs.ok(err == nil && jwkThumbprint(djwk) == jwkThumbprint(hjwk), "holder_key is the MSO's device key", "", mdocRef+" §9.1.2.4") {
		return nil, nil
	}

	// The session, and the device signature over it.
	responseURI := str(r.Claims["response_uri"])
	if responseURI == "" {
		responseURI = str(r.Claims["redirect_uri"])
	}
	var thumb []byte
	if str(r.Claims["response_mode"]) == "direct_post.jwt" {
		if k := vpEncryptionKey(r); k != nil {
			thumb, _ = base64.RawURLEncoding.DecodeString(jwkThumbprint(k))
		}
	}
	transcript := oid4vpSessionTranscript(r.ClientID, str(r.Claims["nonce"]), thumb, responseURI)
	nsBytes := cborTag{Num: 24, V: cborEncode(map[any]any{})}
	dab := deviceAuthenticationBytes(transcript, docType, cborEncode(nsBytes))
	alg, h := int64(-7), crypto.SHA256
	if ek.Curve == elliptic.P384() {
		alg, h = -35, crypto.SHA384
	} else if ek.Curve != elliptic.P256() {
		return nil, errors.New("holder_key: P-256 or P-384")
	}
	protected := cborEncode(map[any]any{int64(1): alg})
	tbs := cborEncode([]any{"Signature1", protected, []byte{}, dab})
	var digest []byte
	if h == crypto.SHA384 {
		d := sha512.Sum384(tbs)
		digest = d[:]
	} else {
		d := sha256.Sum256(tbs)
		digest = d[:]
	}
	rr, ss, err := ecdsa.Sign(rand.Reader, ek, digest)
	if err != nil {
		return nil, err
	}
	n := (ek.Curve.Params().BitSize + 7) / 8
	sig := append(rr.FillBytes(make([]byte, n)), ss.FillBytes(make([]byte, n))...)
	doc := map[any]any{"docType": docType,
		"issuerSigned": map[any]any{"nameSpaces": sel, "issuerAuth": is["issuerAuth"]},
		"deviceSigned": map[any]any{"nameSpaces": nsBytes, "deviceAuth": map[any]any{"deviceSignature": []any{protected, map[any]any{}, nil, sig}}}}
	resp := cborEncode(map[any]any{"version": "1.0", "documents": []any{doc}, "status": int64(0)})
	cs.add("device signature over the OID4VP session", "pass", "SessionTranscript with OpenID4VPHandover for "+r.ClientID, vpRef+" Appendix B.2.6.1")

	// Check our own work as a verifier would.
	a, err := runMdocDecode(c.sub(M{"credential": b64url(resp), "session_transcript": b64url(transcript), "leeway": 60, "timeout": c.Int("timeout")}))
	if err == nil {
		bad := []string{}
		for _, ck := range a["checks"].(Checks) {
			if ck.Status == "fail" {
				bad = append(bad, ck.Name+": "+ck.Detail)
			}
		}
		cs.ok(len(bad) == 0, "the DeviceResponse verifies as the verifier will check it", strings.Join(bad, "; "), mdocRef)
	}
	qid := str(query["id"])
	vpToken, _ := json.Marshal(M{qid: []string{b64url(resp)}})
	return vpToken, nil
}
