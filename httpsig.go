package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
)

// HTTP Message Signatures (RFC 9421) and Content-Digest (RFC 9530).

func contentDigest(body []byte, alg string) string {
	if alg == "sha-512" {
		s := sha512.Sum512(body)
		return "sha-512=:" + base64.StdEncoding.EncodeToString(s[:]) + ":"
	}
	s := sha256.Sum256(body)
	return "sha-256=:" + base64.StdEncoding.EncodeToString(s[:]) + ":"
}

// sigRequest is what a signature covers.
type sigRequest struct {
	Method  string
	URL     *url.URL
	Headers map[string]string // lowercase names
}

func (r *sigRequest) component(name string) (string, error) {
	switch name {
	case "@method":
		return strings.ToUpper(r.Method), nil
	case "@target-uri":
		return r.URL.String(), nil
	case "@authority":
		h := strings.ToLower(r.URL.Hostname())
		if p := r.URL.Port(); p != "" && !(r.URL.Scheme == "https" && p == "443") && !(r.URL.Scheme == "http" && p == "80") {
			h += ":" + p
		}
		return h, nil
	case "@scheme":
		return strings.ToLower(r.URL.Scheme), nil
	case "@path":
		p := r.URL.EscapedPath()
		if p == "" {
			p = "/"
		}
		return p, nil
	case "@query":
		return "?" + r.URL.RawQuery, nil
	case "@request-target":
		t := r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			t += "?" + r.URL.RawQuery
		}
		return t, nil
	}
	if strings.HasPrefix(name, "@") {
		return "", fmt.Errorf("unsupported derived component %s", name)
	}
	v, ok := r.Headers[name]
	if !ok {
		return "", fmt.Errorf("the message has no %s header to sign", name)
	}
	return strings.TrimSpace(v), nil
}

// signatureParams renders the inner list and parameters (RFC 9421 §2.3).
func signatureParams(components []string, params [][2]string) string {
	var q []string
	for _, c := range components {
		q = append(q, `"`+c+`"`)
	}
	s := "(" + strings.Join(q, " ") + ")"
	for _, p := range params {
		if p[0] == "created" || p[0] == "expires" {
			s += ";" + p[0] + "=" + p[1]
		} else {
			s += ";" + p[0] + `="` + p[1] + `"`
		}
	}
	return s
}

// signatureBase builds the signature base (RFC 9421 §2.5).
func signatureBase(r *sigRequest, components []string, sigParams string) (string, error) {
	var b strings.Builder
	for _, c := range components {
		v, err := r.component(c)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&b, "%q: %s\n", c, v)
	}
	b.WriteString(`"@signature-params": ` + sigParams)
	return b.String(), nil
}

// httpsigAlg names the RFC 9421 algorithm for a key.
func httpsigAlg(k crypto.Signer) string {
	switch p := k.Public().(type) {
	case ed25519.PublicKey:
		return "ed25519"
	case *ecdsa.PublicKey:
		if p.Curve.Params().BitSize == 384 {
			return "ecdsa-p384-sha384"
		}
		return "ecdsa-p256-sha256"
	}
	return "rsa-pss-sha512"
}

func httpsigSign(k crypto.Signer, alg string, base []byte) ([]byte, error) {
	switch alg {
	case "ed25519":
		return k.Sign(rand.Reader, base, crypto.Hash(0))
	case "ecdsa-p256-sha256", "ecdsa-p384-sha384":
		h, size := crypto.SHA256, 32
		if alg == "ecdsa-p384-sha384" {
			h, size = crypto.SHA384, 48
		}
		hh := h.New()
		hh.Write(base)
		der, err := k.Sign(rand.Reader, hh.Sum(nil), h)
		if err != nil {
			return nil, err
		}
		var rs struct{ R, S *big.Int } // RFC 9421 §3.3.4: r || s, not DER
		if _, err := asn1.Unmarshal(der, &rs); err != nil {
			return nil, err
		}
		return append(rs.R.FillBytes(make([]byte, size)), rs.S.FillBytes(make([]byte, size))...), nil
	case "rsa-pss-sha512":
		d := sha512.Sum512(base)
		return k.Sign(rand.Reader, d[:], &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512})
	case "rsa-v1_5-sha256":
		d := sha256.Sum256(base)
		return k.Sign(rand.Reader, d[:], crypto.SHA256)
	}
	return nil, fmt.Errorf("unsupported signature algorithm %q", alg)
}

func httpsigVerify(pub crypto.PublicKey, alg string, base, sig []byte) error {
	switch alg {
	case "ed25519":
		k, ok := pub.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(k, base, sig) {
			return errors.New("ed25519 signature does not verify")
		}
		return nil
	case "ecdsa-p256-sha256", "ecdsa-p384-sha384":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig)%2 != 0 {
			return errors.New("bad ECDSA key or signature")
		}
		h := crypto.SHA256
		if alg == "ecdsa-p384-sha384" {
			h = crypto.SHA384
		}
		hh := h.New()
		hh.Write(base)
		if !ecdsa.Verify(k, hh.Sum(nil), new(big.Int).SetBytes(sig[:len(sig)/2]), new(big.Int).SetBytes(sig[len(sig)/2:])) {
			return errors.New("ECDSA signature does not verify")
		}
		return nil
	case "rsa-pss-sha512":
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("not an RSA key")
		}
		d := sha512.Sum512(base)
		return rsa.VerifyPSS(k, crypto.SHA512, d[:], sig, &rsa.PSSOptions{SaltLength: 64, Hash: crypto.SHA512})
	}
	return fmt.Errorf("unsupported signature algorithm %q", alg)
}

// signHTTP adds Signature-Input and Signature headers for label sig1.
func signHTTP(k crypto.Signer, keyID, tag string, r *sigRequest, components []string, created int64) (input, signature, base string, err error) {
	alg := httpsigAlg(k)
	params := [][2]string{{"created", strconv.FormatInt(created, 10)}, {"keyid", keyID}}
	if tag != "" {
		params = append(params, [2]string{"tag", tag})
	}
	sp := signatureParams(components, params)
	if base, err = signatureBase(r, components, sp); err != nil {
		return
	}
	sig, err := httpsigSign(k, alg, []byte(base))
	if err != nil {
		return
	}
	return "sig1=" + sp, "sig1=:" + base64.StdEncoding.EncodeToString(sig) + ":", base, nil
}
