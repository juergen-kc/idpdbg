package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// loadSigner reads an RSA, EC or Ed25519 private key from PEM text.
func loadSigner(pemText string) (crypto.Signer, error) {
	b := []byte(pemText)
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil, errors.New("no usable private key found in the PEM")
		}
		if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
			if s, ok := k.(crypto.Signer); ok {
				return s, nil
			}
		}
		if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
			return k, nil
		}
	}
}

// signerAlg picks the JWS algorithm for a key; prefer may ask for PS256/384/512
// with an RSA key.
func signerAlg(s crypto.Signer, prefer string) (string, error) {
	switch pub := s.Public().(type) {
	case *rsa.PublicKey:
		if strings.HasPrefix(prefer, "PS") || strings.HasPrefix(prefer, "RS") {
			return prefer, nil
		}
		return "RS256", nil
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().BitSize {
		case 256:
			return "ES256", nil
		case 384:
			return "ES384", nil
		case 521:
			return "ES512", nil
		}
	case ed25519.PublicKey:
		return "EdDSA", nil
	}
	return "", errors.New("unsupported key type for JWT signing")
}

// publicJWK is the public JWK for a key.
func publicJWK(pub crypto.PublicKey) (M, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return M{"kty": "RSA", "n": b64url(k.N.Bytes()), "e": b64url(big.NewInt(int64(k.E)).Bytes())}, nil
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		crv := map[elliptic.Curve]string{elliptic.P256(): "P-256", elliptic.P384(): "P-384", elliptic.P521(): "P-521"}[k.Curve]
		if crv == "" {
			return nil, errors.New("unsupported EC curve")
		}
		return M{"kty": "EC", "crv": crv, "x": b64url(k.X.FillBytes(make([]byte, size))), "y": b64url(k.Y.FillBytes(make([]byte, size)))}, nil
	case ed25519.PublicKey:
		return M{"kty": "OKP", "crv": "Ed25519", "x": b64url(k)}, nil
	}
	return nil, errors.New("unsupported public key type")
}

func jwsInput(alg string, header, claims M) string {
	h := M{"alg": alg}
	for k, v := range header {
		h[k] = v
	}
	hb, _ := json.Marshal(h)
	cb, _ := json.Marshal(claims)
	return b64url(hb) + "." + b64url(cb)
}

// signJWS produces a compact JWS with an asymmetric key.
func signJWS(s crypto.Signer, alg string, header, claims M) (string, error) {
	input := jwsInput(alg, header, claims)
	var sig []byte
	var err error
	ch, newHash := algHash(alg)
	h := newHash()
	h.Write([]byte(input))
	digest := h.Sum(nil)
	switch {
	case alg == "EdDSA":
		sig, err = s.Sign(rand.Reader, []byte(input), crypto.Hash(0))
	case strings.HasPrefix(alg, "RS"):
		sig, err = s.Sign(rand.Reader, digest, ch)
	case strings.HasPrefix(alg, "PS"):
		sig, err = s.Sign(rand.Reader, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: ch})
	case strings.HasPrefix(alg, "ES"):
		pub, ok := s.Public().(*ecdsa.PublicKey)
		if !ok {
			return "", fmt.Errorf("%s needs an EC key", alg)
		}
		var der []byte
		if der, err = s.Sign(rand.Reader, digest, ch); err == nil {
			// JWS wants the fixed-width r||s form, not ASN.1 DER.
			var rs struct{ R, S *big.Int }
			if _, err = asn1.Unmarshal(der, &rs); err == nil {
				size := (pub.Curve.Params().BitSize + 7) / 8
				sig = append(rs.R.FillBytes(make([]byte, size)), rs.S.FillBytes(make([]byte, size))...)
			}
		}
	default:
		return "", fmt.Errorf("unsupported signing alg %q", alg)
	}
	if err != nil {
		return "", err
	}
	return input + "." + b64url(sig), nil
}

// signHS produces a compact JWS with a shared secret.
func signHS(secret []byte, alg string, header, claims M) string {
	input := jwsInput(alg, header, claims)
	_, newHash := algHash(alg)
	mac := hmac.New(newHash, secret)
	mac.Write([]byte(input))
	return input + "." + b64url(mac.Sum(nil))
}
