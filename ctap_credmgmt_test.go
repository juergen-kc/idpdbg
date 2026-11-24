package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
)

// credMgmt answers authenticatorCredentialManagement as CTAP 2.1 §6.8 says:
// a MAC with a cm-permission token on every request but the "next" ones.
func (k *fakeKey) credMgmt(cmd byte, req map[any]any) []byte {
	sub, _ := req[int64(1)].(int64)
	params, _ := req[int64(2)].(map[any]any)
	ok := func(m map[any]any) []byte { return append([]byte{0}, cborEncode(m)...) }
	if sub != cmEnumerateRPsNext && sub != cmEnumerateCredsNext {
		proto, _ := req[int64(3)].(int64)
		auth, _ := req[int64(4)].([]byte)
		msg := []byte{byte(sub)}
		if params != nil {
			msg = append(msg, cborEncode(params)...)
		}
		if auth == nil {
			return []byte{0x36} // PUAT_REQUIRED
		}
		if k.token == nil || int(proto) != k.tokProto || !bytes.Equal(auth, pinAuth(int(proto), k.token, msg)) {
			return []byte{0x33}
		}
		if cmd == ctapCredMgmt && k.tokPerms&permCredentialMgmt == 0 {
			return []byte{0x40} // UNAUTHORIZED_PERMISSION
		}
	}
	next := func() []byte {
		if len(k.cmQueue) == 0 {
			return []byte{0x30}
		}
		r := k.cmQueue[0]
		k.cmQueue = k.cmQueue[1:]
		return r
	}
	switch sub {
	case cmGetCredsMetadata:
		n := len(k.rks)
		if k.cmLie {
			n++
		}
		return ok(map[any]any{1: n, 2: 25 - len(k.rks)})
	case cmEnumerateRPsBegin, cmEnumerateCredsBegin:
		var resps []map[any]any
		if sub == cmEnumerateRPsBegin {
			seen := map[string]bool{}
			for _, r := range k.rks {
				if !seen[r.rpID] {
					seen[r.rpID] = true
					h := sha256.Sum256([]byte(r.rpID))
					resps = append(resps, map[any]any{3: map[any]any{"id": r.rpID}, 4: h[:]})
				}
			}
		} else {
			want, _ := params[int64(1)].([]byte)
			for _, r := range k.rks {
				if h := sha256.Sum256([]byte(r.rpID)); bytes.Equal(h[:], want) {
					m := map[any]any{6: r.user, 7: map[any]any{"type": "public-key", "id": r.id}, 8: coseOf(k.creds[string(r.id)].Public(), -7)}
					if r.protect != 0 {
						m[10] = r.protect
					}
					resps = append(resps, m)
				}
			}
		}
		if len(resps) == 0 {
			return []byte{0x2E}
		}
		resps[0][map[int64]int{cmEnumerateRPsBegin: 5, cmEnumerateCredsBegin: 9}[sub]] = len(resps)
		k.cmQueue = nil
		for _, m := range resps[1:] {
			k.cmQueue = append(k.cmQueue, ok(m))
		}
		return ok(resps[0])
	case cmEnumerateRPsNext, cmEnumerateCredsNext:
		return next()
	case cmDeleteCredential:
		desc, _ := params[int64(2)].(map[any]any)
		id, _ := desc["id"].([]byte)
		for i, r := range k.rks {
			if bytes.Equal(r.id, id) {
				k.rks = append(k.rks[:i], k.rks[i+1:]...)
				delete(k.creds, string(id))
				return []byte{0}
			}
		}
		return []byte{0x2E}
	}
	return []byte{0x3F}
}

func (k *fakeKey) seedRK(rpID, name string, protect int64) []byte {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id := randomBytes(32)
	k.creds[string(id)] = key
	k.rks = append(k.rks, fakeRK{rpID: rpID, id: id, user: map[any]any{"id": []byte(name), "name": name, "displayName": strings.ToUpper(name)}, protect: protect})
	return id
}

func TestFIDOCredentialManagement(t *testing.T) {
	k := newFakeKey(t, true)
	k.v21, k.cmV21 = true, true
	useFakeKey(t, k)
	alice := k.seedRK("example.com", "alice", 2)
	k.seedRK("example.com", "bob", 3)
	k.seedRK("other.example", "carol", 0)

	res := run(t, "fido.credentials", M{"pin": "123456"}, nil)
	noFailures(t, res)
	wantStatus(t, res, "credential management supported", "pass")
	wantStatus(t, res, "rpIDHash is SHA-256 of the RP ID", "pass")
	wantStatus(t, res, "enumerated passkeys match the stored count", "pass")
	wantStatus(t, res, "credProtect for other.example", "info")
	if checkOf(res, "credProtect for example.com") != nil {
		t.Error("credProtect warning for an RP whose passkeys all have level 2 or 3")
	}
	if k.tokPerms != permCredentialMgmt {
		t.Errorf("token permissions %#x, want cm only", k.tokPerms)
	}
	rps := res["relying_parties"].([]M)
	if res["stored"] != int64(3) || len(rps) != 2 || rps[0]["rp_id"] != "example.com" {
		t.Fatalf("list: %v", res)
	}
	creds := rps[0]["credentials"].([]M)
	if len(creds) != 2 || creds[0]["user_name"] != "alice" || creds[1]["cred_protect"] != "userVerificationRequired" ||
		creds[0]["public_key"].(M)["alg"] != "ES256" || creds[0]["credential_id"] != b64url(alice) {
		t.Fatalf("credentials: %v", creds)
	}

	// Filtered to one relying party; the count check still covers them all.
	res = run(t, "fido.credentials", M{"pin": "123456", "rp_id": "other.example"}, nil)
	if rps := res["relying_parties"].([]M); len(rps) != 1 || rps[0]["rp_id"] != "other.example" {
		t.Fatalf("filter: %v", rps)
	}
	wantStatus(t, res, "enumerated passkeys match the stored count", "pass")

	// No PIN to be had (MCP, no terminal): refused before anything is sent.
	before := len(k.requests)
	if _, err := tryOp(t, "fido.credentials", M{}); err == nil || !strings.Contains(err.Error(), "needs the key's PIN") {
		t.Fatalf("no PIN: %v", err)
	}
	if bytes.Contains(k.requests[before:], []byte{ctapCredMgmt}) {
		t.Error("credential management request without a PIN")
	}

	// A dry run deletes nothing.
	res = run(t, "fido.credential_delete", M{"pin": "123456", "credential_id": b64url(alice)}, nil)
	if res["deleted"] != false || len(k.rks) != 3 || res["credential"].(M)["user_name"] != "alice" {
		t.Fatalf("dry run: %v, %d left", res, len(k.rks))
	}
	// The wrong relying party: refused.
	res = run(t, "fido.credential_delete", M{"pin": "123456", "credential_id": b64url(alice), "rp_id": "other.example", "confirm": true}, nil)
	wantStatus(t, res, "the passkey belongs to rp_id", "fail")
	if len(k.rks) != 3 {
		t.Fatal("deleted despite the rp_id mismatch")
	}
	// An ID that is not on the key.
	res = run(t, "fido.credential_delete", M{"pin": "123456", "credential_id": b64url(randomBytes(32)), "confirm": true}, nil)
	wantStatus(t, res, "the passkey is on this key", "fail")
	// Confirmed: deleted, and gone when listed again.
	res = run(t, "fido.credential_delete", M{"pin": "123456", "credential_id": b64url(alice), "rp_id": "example.com", "confirm": true}, nil)
	noFailures(t, res)
	wantStatus(t, res, "the passkey is gone", "pass")
	if res["deleted"] != true || len(k.rks) != 2 {
		t.Fatalf("delete: %v, %d left", res, len(k.rks))
	}

	// Over MCP a stored PIN lists, but never deletes.
	t.Setenv("IDPDBG_PIN", "123456")
	if _, err := runOp(context.Background(), findOp("fido.credentials"), M{}, false, nil); err != nil {
		t.Fatalf("list with IDPDBG_PIN: %v", err)
	}
	_, err := runOp(context.Background(), findOp("fido.credential_delete"), M{"credential_id": b64url(k.rks[0].id), "confirm": true}, false, nil)
	if err == nil || !strings.Contains(err.Error(), "needs the key's PIN") || len(k.rks) != 2 {
		t.Fatalf("delete with IDPDBG_PIN over MCP: %v, %d left", err, len(k.rks))
	}
	// From the CLI the stored PIN is fine.
	res, err = runOp(context.Background(), findOp("fido.credential_delete"), M{"credential_id": b64url(k.rks[0].id), "confirm": true}, true, nil)
	if err != nil || res["deleted"] != true || len(k.rks) != 1 {
		t.Fatalf("delete with IDPDBG_PIN from the CLI: %v, %d left", err, len(k.rks))
	}
	t.Setenv("IDPDBG_PIN", "")

	// A key whose count disagrees with what it lists.
	k.cmLie = true
	res = run(t, "fido.credentials", M{"pin": "123456"}, nil)
	wantStatus(t, res, "enumerated passkeys match the stored count", "fail")
}

func TestFIDOCredentialManagementPreview(t *testing.T) {
	k := newFakeKey(t, true)
	k.cmPreview = true // a CTAP 2.0 key with the 2.1 preview: getPinToken, command 0x41
	useFakeKey(t, k)
	k.seedRK("example.com", "dave", 0)
	res := run(t, "fido.credentials", M{"pin": "123456"}, nil)
	noFailures(t, res)
	wantStatus(t, res, "credential management version", "info")
	if res["stored"] != int64(1) || !bytes.Contains(k.requests, []byte{ctapCredMgmtPreview}) || bytes.Contains(k.requests, []byte{ctapCredMgmt}) {
		t.Fatalf("preview: %v, requests %x", res, k.requests)
	}
}

func TestFIDOCredentialManagementRefusals(t *testing.T) {
	// A CTAP 2.0 key without it.
	useFakeKey(t, newFakeKey(t, true))
	res := run(t, "fido.credentials", M{"pin": "123456"}, nil)
	wantStatus(t, res, "credential management supported", "fail")
	// No PIN set: the key could not authorise it.
	k := newFakeKey(t, false)
	k.v21, k.cmV21 = true, true
	useFakeKey(t, k)
	res = run(t, "fido.credentials", M{"pin": "123456"}, nil)
	wantStatus(t, res, "PIN set", "fail")
	if bytes.Contains(k.requests, []byte{ctapClientPIN}) {
		t.Error("PIN sent to a key without one")
	}
	// A wrong PIN costs one attempt and stops.
	k = newFakeKey(t, true)
	k.v21, k.cmV21 = true, true
	useFakeKey(t, k)
	if _, err := tryOp(t, "fido.credentials", M{"pin": "999999"}); err == nil || !strings.Contains(err.Error(), "wrong PIN: 7 attempts left") || k.retries != 7 {
		t.Fatalf("wrong PIN: %v, %d left", err, k.retries)
	}
}
