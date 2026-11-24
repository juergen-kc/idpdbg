package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha3"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ML-DSA private keys in PKCS #8 (RFC 9881 §6): the key is a seed, an
// expanded key, or both. Go reads only the seed form; OpenSSL writes both
// by default. idpdbg takes the seed out of "both" and checks that the
// expanded half belongs to it, so a key whose halves disagree is refused.

var mldsaOIDs = map[string]func() mldsa.Parameters{
	"2.16.840.1.101.3.4.3.17": mldsa.MLDSA44, "2.16.840.1.101.3.4.3.18": mldsa.MLDSA65, "2.16.840.1.101.3.4.3.19": mldsa.MLDSA87,
}

type pkcs8Info struct {
	Version    int
	Algorithm  struct{ OID asn1.ObjectIdentifier }
	PrivateKey []byte
}

// parseMLDSAPKCS8 reads an ML-DSA PKCS #8 key in any of the three forms.
// ok is false when der is not an ML-DSA key at all.
func parseMLDSAPKCS8(der []byte) (key *mldsa.PrivateKey, ok bool, err error) {
	var p pkcs8Info
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		return nil, false, nil
	}
	params := mldsaOIDs[p.Algorithm.OID.String()]
	if params == nil {
		return nil, false, nil
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(p.PrivateKey, &raw); err != nil {
		return nil, true, fmt.Errorf("ML-DSA private key: %w", err)
	}
	switch {
	case raw.Class == asn1.ClassContextSpecific && raw.Tag == 0: // seed [0] OCTET STRING
		k, err := mldsa.NewPrivateKey(params(), raw.Bytes)
		return k, true, err
	case raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagOctetString: // expandedKey
		return nil, true, errors.New("this ML-DSA private key holds only the expanded key, from which the seed Go needs cannot be recovered; export it with the seed (openssl pkey -provparam ml-dsa.output_formats=seed-only)")
	case raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence: // both
		var both struct{ Seed, Expanded []byte }
		if _, err := asn1.Unmarshal(p.PrivateKey, &both); err != nil {
			return nil, true, fmt.Errorf("ML-DSA private key (seed and expanded key): %w", err)
		}
		k, err := mldsa.NewPrivateKey(params(), both.Seed)
		if err != nil {
			return nil, true, err
		}
		// The expanded key starts with rho (the public key's first 32
		// bytes), then K (32 bytes), then tr = SHAKE256(public key, 64)
		// (FIPS 204, Algorithm 24).
		pub := k.PublicKey().Bytes()
		tr := sha3.SumSHAKE256(pub, 64)
		if len(both.Expanded) < 128 || !bytes.Equal(both.Expanded[:32], pub[:32]) || !bytes.Equal(both.Expanded[64:128], tr) {
			return nil, true, errors.New("this ML-DSA private key's seed and expanded key do not belong together")
		}
		return k, true, nil
	}
	return nil, true, errors.New("ML-DSA private key in an unknown form")
}
