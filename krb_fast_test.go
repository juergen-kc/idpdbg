package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/types"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 6113 Appendix A: KRB-FX-CF2(string-to-key("key1", "key1"),
// string-to-key("key2", "key2"), "a", "b").
func TestCF2RFC6113Vectors(t *testing.T) {
	for _, v := range []struct {
		etype int32
		want  string
	}{
		{17, "97df97e4b798b29eb31ed7280287a92a"},
		{18, "4d6ca4e629785c1f01baf55e2e548566b9617ae3a96868c337cb93b5e72b1c7b"},
		{23, "24d7f6b6bae4e5c00d2082c5ebab3672"},
	} {
		et, err := crypto.GetEtype(v.etype)
		if err != nil {
			t.Fatal(err)
		}
		key := func(s string) types.EncryptionKey {
			b, err := et.StringToKey(s, s, et.GetDefaultStringToKeyParams())
			if err != nil {
				t.Fatal(err)
			}
			return types.EncryptionKey{KeyType: v.etype, KeyValue: b}
		}
		got, err := krbCF2(key("key1"), key("key2"), "a", "b")
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got.KeyValue) != v.want || got.KeyType != v.etype {
			t.Errorf("%s: got %x, want %s", etypeName(v.etype), got.KeyValue, v.want)
		}
	}
}

// RFC 8009 §A: sample PRF invocations with input "test".
func TestPRFRFC8009Vectors(t *testing.T) {
	for _, v := range []struct {
		etype     int32
		key, want string
	}{
		{19, "3705D96080C17728A0E800EAB6E0D23C",
			"9D188616F63852FE86915BB840B4A886FF3E6BB0F819B49B893393D393854295"},
		{20, "6D404D37FAF79F9DF0D33568D320669800EB4836472EA8A026D16B7182460C52",
			"9801F69A368C2BF675E59521E177D9A07F67EFE1CFDE8D3C8D6F6A0256E3B17DB3C1B62AD1B8553360D17367EB1514D2"},
	} {
		got, err := krbPRF(types.EncryptionKey{KeyType: v.etype, KeyValue: unhex(t, v.key)}, []byte("test"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, unhex(t, v.want)) {
			t.Errorf("%s: got %X", etypeName(v.etype), got)
		}
	}
}

// A request wrapped by one side decrypts and parses with the same armor
// key, and a response encrypted the way a KDC does unwraps.
func TestFASTWrapUnwrap(t *testing.T) {
	et, _ := crypto.GetEtype(18)
	k, _ := et.StringToKey("armor", "ARMOR", et.GetDefaultStringToKeyParams())
	f := &fastTunnel{armorKey: types.EncryptionKey{KeyType: 18, KeyValue: k},
		armor: krbFastArmor{ArmorType: fxFastArmorAPRequest, ArmorValue: []byte{0x6e, 0}}}
	body := []byte{0x30, 0x03, 0x02, 0x01, 0x07}
	pa, err := f.wrap(body, types.PADataSequence{{PADataType: paFXCookie, PADataValue: []byte("c")}}, body)
	if err != nil {
		t.Fatal(err)
	}
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(pa.PADataValue, &outer); err != nil || outer.Class != asn1.ClassContextSpecific || outer.Tag != 0 {
		t.Fatalf("PA-FX-FAST-REQUEST: %v %+v", err, outer)
	}
	var ar krbFastArmoredReq
	if _, err := asn1.Unmarshal(outer.Bytes, &ar); err != nil {
		t.Fatal(err)
	}
	if ar.Armor.ArmorType != fxFastArmorAPRequest || !verifyKeyedChecksum(f.armorKey, body, ar.ReqChecksum, usageFastReqChecksum) {
		t.Fatal("armor or request checksum wrong")
	}
	pt, err := crypto.DecryptEncPart(ar.EncFastReq, f.armorKey, usageFastEnc)
	if err != nil {
		t.Fatal(err)
	}
	var fr krbFastReq
	if _, err := asn1.Unmarshal(pt, &fr); err != nil {
		t.Fatal(err)
	}
	if len(fr.PAData) != 1 || fr.PAData[0].PADataType != paFXCookie || !bytes.Equal(fr.ReqBody.Bytes, body) {
		t.Fatalf("KrbFastReq: %+v", fr)
	}

	// Implicit armor (TGS) leaves the armor field out.
	g := &fastTunnel{armorKey: f.armorKey}
	pa, _ = g.wrap(body, nil, body)
	asn1.Unmarshal(pa.PADataValue, &outer)
	var seq, first asn1.RawValue
	asn1.Unmarshal(outer.Bytes, &seq)
	asn1.Unmarshal(seq.Bytes, &first)
	if first.Class != asn1.ClassContextSpecific || first.Tag != 1 {
		t.Fatalf("implicit armor should start with req-checksum [1], got [%d]", first.Tag)
	}

	// The KDC side.
	resp, _ := asn1.Marshal(krbFastResponse{PAData: types.PADataSequence{{PADataType: paFXError, PADataValue: []byte{1}}}, Nonce: 4242})
	enc, _ := crypto.GetEncryptedData(resp, f.armorKey, usageFastRep, 0)
	rep, _ := asn1.Marshal(krbFastArmoredRep{EncFastRep: enc})
	v, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, IsCompound: true, Tag: 0, Bytes: rep})
	got, err := f.unwrap(types.PADataSequence{{PADataType: patypeETypeInfo2, PADataValue: nil}, {PADataType: paFXFast, PADataValue: v}})
	if err != nil || got == nil || got.Nonce != 4242 || got.PAData[0].PADataType != paFXError {
		t.Fatalf("unwrap: %v %+v", err, got)
	}
	if got, err := g.unwrap(types.PADataSequence{{PADataType: paFXFast, PADataValue: v}}); err != nil || got.Nonce != 4242 {
		t.Fatal("same key, same result")
	}
	other := &fastTunnel{armorKey: types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}}
	if _, err := other.unwrap(types.PADataSequence{{PADataType: paFXFast, PADataValue: v}}); err == nil {
		t.Fatal("a response under another armor key must not decrypt")
	}
}

const patypeETypeInfo2 = 19

// gokrb5 reports 24 bytes for aes256-cts-hmac-sha384-192 keys; CF2 output
// must still be a full 32-byte key the enctype can encrypt with.
func TestCF2KeyLengthSHA384(t *testing.T) {
	et, _ := crypto.GetEtype(20)
	k, _ := et.StringToKey("x", "y", et.GetDefaultStringToKeyParams())
	key := types.EncryptionKey{KeyType: 20, KeyValue: k}
	got, err := krbCF2(key, key, "a", "b")
	if err != nil || len(got.KeyValue) != 32 {
		t.Fatalf("cf2: %v, %d bytes", err, len(got.KeyValue))
	}
	if _, err := crypto.GetEncryptedData([]byte("x"), got, usageFastEnc, 0); err != nil {
		t.Fatal(err)
	}
}
