package main

import (
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ML-DSA in JOSE (draft-ietf-cose-dilithium): AKP keys, ML-DSA-44/65/87
// signatures, thumbprints over alg, kty and pub.
func TestJOSEMLDSA(t *testing.T) {
	for _, name := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		k, err := mldsa.GenerateKey(mldsaAlgs[name]())
		if err != nil {
			t.Fatal(err)
		}
		pub, _ := publicJWK(k.Public())
		if pub["kty"] != "AKP" || pub["alg"] != name {
			t.Fatalf("%s: public JWK %v", name, pub)
		}
		pub["kid"] = "pq-" + name
		set, _ := json.Marshal(M{"keys": []M{pub}})

		// From a PEM key, with the public key in the header.
		tok := run(t, "jwt.sign", M{"claims": map[string]any{"sub": "alice"}, "key": keyPEM(k), "kid": "pq-" + name, "embed_jwk": true}, nil)
		if tok["header"].(M)["alg"] != name {
			t.Fatalf("%s: header %v", name, tok["header"])
		}
		v := run(t, "jwt.verify", M{"token": tok["token"], "jwks": string(set)}, nil)
		noFailures(t, v)
		wantStatus(t, v, "signature", "pass")

		// From a private AKP JWK.
		priv := privateJWK(k)
		pj, _ := json.Marshal(priv)
		tok2 := run(t, "jwt.sign", M{"claims": map[string]any{"sub": "bob"}, "key": string(pj)}, nil)
		noFailures(t, run(t, "jwt.verify", M{"token": tok2["token"], "jwks": string(set)}, nil))

		// Thumbprint: SHA-256 of {"alg","kty","pub"} in that order.
		want := sha256.Sum256([]byte(`{"alg":"` + name + `","kty":"AKP","pub":"` + str(pub["pub"]) + `"}`))
		if jwkThumbprint(pub) != b64url(want[:]) {
			t.Errorf("%s: thumbprint %s", name, jwkThumbprint(pub))
		}
	}

	// A token whose alg names another ML-DSA size than the key's fails.
	k44, _ := mldsa.GenerateKey(mldsa.MLDSA44())
	k65, _ := mldsa.GenerateKey(mldsa.MLDSA65())
	tok := run(t, "jwt.sign", M{"claims": map[string]any{"sub": "x"}, "key": keyPEM(k44)}, nil)
	pub65, _ := publicJWK(k65.Public())
	set, _ := json.Marshal(M{"keys": []M{pub65}})
	bad := run(t, "jwt.verify", M{"token": tok["token"], "jwks": string(set)}, nil)
	if c := checkOf(bad, "signature"); c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "ML-DSA-44 needs an ML-DSA-44 key") {
		t.Errorf("mismatched size: %+v", c)
	}
	// A tampered payload fails.
	parts := strings.Split(str(tok["token"]), ".")
	parts[1] = b64url([]byte(`{"sub":"mallory"}`))
	pub44, _ := publicJWK(k44.Public())
	set44, _ := json.Marshal(M{"keys": []M{pub44}})
	wantStatus(t, run(t, "jwt.verify", M{"token": strings.Join(parts, "."), "jwks": string(set44)}, nil), "signature", "fail")
	// A private JWK whose pub belongs to another key is refused.
	mixed := privateJWK(k44)
	mixed["pub"] = pub65["pub"]
	mj, _ := json.Marshal(mixed)
	if _, err := tryOp(t, "jwt.sign", M{"claims": map[string]any{"sub": "x"}, "key": string(mj)}); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("mismatched private JWK: %v", err)
	}

	// jwks.fetch names the post-quantum key.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(set44)
	}))
	defer srv.Close()
	f := run(t, "jwks.fetch", M{"jwks_uri": srv.URL, "allow_private_urls": true}, nil)
	keys, _ := f["keys"].([]M)
	if len(keys) != 1 || !strings.Contains(str(keys[0]["post_quantum"]), "ML-DSA-44") || keys[0]["thumbprint_sha256"] == nil {
		t.Errorf("jwks.fetch: %v", f)
	}
}

// OpenSSL's ML-DSA private key forms (testdata/pq): seed and expanded key
// (its default), seed only, expanded only; and a "both" key whose halves
// disagree.
func TestMLDSAKeyForms(t *testing.T) {
	read := func(n string) string {
		b, err := os.ReadFile("testdata/pq/" + n)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	pubPEM := read("key-pub.pem")
	for _, f := range []string{"key-both.pem", "key-seed.pem"} {
		k, err := loadSigner(read(f))
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		tok := run(t, "jwt.sign", M{"claims": map[string]any{"sub": f}, "key": read(f)}, nil)
		v := run(t, "jwt.verify", M{"token": tok["token"], "pem": pubPEM}, nil)
		noFailures(t, v)
		if k.Public().(*mldsa.PublicKey).Parameters().String() != "ML-DSA-44" {
			t.Errorf("%s: %v", f, k.Public())
		}
	}
	if _, err := loadSigner(read("key-expanded.pem")); err == nil || !strings.Contains(err.Error(), "only the expanded key") {
		t.Errorf("expanded only: %v", err)
	}

	// Make the expanded half disagree with the seed.
	blk, _ := pem.Decode([]byte(read("key-both.pem")))
	var p pkcs8Info
	if _, err := asn1.Unmarshal(blk.Bytes, &p); err != nil {
		t.Fatal(err)
	}
	var both struct{ Seed, Expanded []byte }
	if _, err := asn1.Unmarshal(p.PrivateKey, &both); err != nil {
		t.Fatal(err)
	}
	both.Expanded[70] ^= 0xFF // inside tr
	p.PrivateKey, _ = asn1.Marshal(both)
	der, _ := asn1.Marshal(p)
	bad := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := loadSigner(bad); err == nil || !strings.Contains(err.Error(), "do not belong together") {
		t.Errorf("mismatched halves: %v", err)
	}
}
