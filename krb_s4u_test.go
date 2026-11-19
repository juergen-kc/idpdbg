package main

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// The PA-FOR-USER checksum is RFC 4757's keyed HMAC-MD5; gokrb5's RC4-HMAC
// etype implements the same function independently.
func TestHMACMD5ChecksumMatchesRFC4757(t *testing.T) {
	rc4, err := crypto.GetEtype(23)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{16, 32} { // RC4 and AES-sized session keys
		key := make([]byte, n)
		rand.Read(key)
		data := []byte("\x01\x00\x00\x00aliceIDPDBG.TESTKerberos")
		want, err := rc4.GetChecksumHash(key, data, 17)
		if err != nil {
			t.Fatal(err)
		}
		if got := hmacMD5Checksum(key, 17, data); !bytes.Equal(got, want) {
			t.Errorf("key %d bytes: %x, want %x", n, got, want)
		}
	}
}

func TestPAForUserEncoding(t *testing.T) {
	key := types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{7}, 32)}
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	pa, err := newPAForUser(user, "IDPDBG.TEST", key)
	if err != nil || pa.PADataType != patype.PA_FOR_USER {
		t.Fatal(pa.PADataType, err)
	}
	var back paForUser
	if _, err := asn1.Unmarshal(pa.PADataValue, &back); err != nil {
		t.Fatal(err)
	}
	if back.UserRealm != "IDPDBG.TEST" || back.AuthPackage != "Kerberos" || back.UserName.NameString[0] != "alice" || back.Cksum.CksumType != -138 {
		t.Errorf("round trip: %+v", back)
	}
	// The checksum covers name type (LE), names, realm and auth package.
	want := hmacMD5Checksum(key.KeyValue, 17, []byte("\x01\x00\x00\x00aliceIDPDBG.TESTKerberos"))
	if !bytes.Equal(back.Cksum.Checksum, want) {
		t.Error("checksum input differs from MS-SFU §2.2.1")
	}
}
