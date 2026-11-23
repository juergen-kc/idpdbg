package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Attestation with a certificate for the software authenticator: packed
// attestation with an x5c chain (WebAuthn §8.2) and fido-u2f (§8.6), signed
// by an attestation key whose certificate a CA issued. The CA is the
// caller's (attestation_ca), so the relying party can be set to trust it,
// or a throwaway one. Two tampers test whether the relying party verifies
// the certificate: one issued by an impostor CA with the CA's name, and
// one that breaks the packed certificate requirements.

// idpdbgAAGUID identifies idpdbg's software authenticator when it attests
// with a certificate (packed-x5c). It is not registered with the FIDO
// Metadata Service.
var idpdbgAAGUID, _ = hex.DecodeString("54c655a5e79242b7b2a930cec2bf370e")

var oidFIDOGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

type attestationCA struct {
	cert      *x509.Certificate
	key       crypto.Signer
	generated bool
}

// loadAttestationCA takes the CA from attestation_ca (its certificate and
// private key, PEM), or makes a throwaway one.
func loadAttestationCA(c *Ctx) (*attestationCA, error) {
	if s := c.Str("attestation_ca"); s != "" {
		certs, err := loadCerts(s)
		if err != nil || len(certs) == 0 {
			return nil, fmt.Errorf("attestation_ca: no certificate (%v)", err)
		}
		key, err := loadSigner(s)
		if err != nil {
			return nil, fmt.Errorf("attestation_ca: %w", err)
		}
		if !publicKeysEqual(certs[0].PublicKey, key.Public()) {
			return nil, errors.New("attestation_ca: the private key does not belong to the certificate")
		}
		return &attestationCA{cert: certs[0], key: key}, nil
	}
	ca, err := newTestCA("idpdbg software authenticator attestation root (throwaway)")
	if err != nil {
		return nil, err
	}
	ca.generated = true
	return ca, nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ea.Equal(b)
}

func newTestCA(cn string) (*attestationCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"idpdbg"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return &attestationCA{cert: cert, key: key}, err
}

// attestationCert issues an attestation certificate for a new P-256
// attestation key. packed adds what WebAuthn §8.2.1 requires of a packed
// attestation certificate (OU "Authenticator Attestation", not a CA, the
// AAGUID extension). The tampers break the chain or those requirements.
func (ca *attestationCA) attestationCert(packed bool, tamper string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	notAfter := time.Now().Add(24 * time.Hour)
	if ca.cert.NotAfter.Before(notAfter) {
		notAfter = ca.cert.NotAfter
	}
	tpl := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, BasicConstraintsValid: true,
		Subject: pkix.Name{Country: []string{"US"}, Organization: []string{"idpdbg"}, CommonName: "idpdbg software authenticator"}}
	if packed {
		tpl.Subject.OrganizationalUnit = []string{"Authenticator Attestation"}
		ext, _ := asn1.Marshal(idpdbgAAGUID)
		tpl.ExtraExtensions = []pkix.Extension{{Id: oidFIDOGenCeAAGUID, Value: ext}}
	}
	issuer, signer := ca.cert, ca.key
	switch tamper {
	case "broken_attestation_chain":
		// An impostor CA with the same name: the certificate names the
		// right issuer, but no trusted key signed it.
		imp, err := newTestCA(ca.cert.Subject.CommonName)
		if err != nil {
			return nil, nil, err
		}
		tpl.AuthorityKeyId = nil
		issuer, signer = &x509.Certificate{RawSubject: ca.cert.RawSubject, Subject: ca.cert.Subject, PublicKey: imp.cert.PublicKey,
			SubjectKeyId: imp.cert.SubjectKeyId}, imp.key
	case "bad_attestation_certificate":
		tpl.IsCA = true
		tpl.Subject.OrganizationalUnit = []string{"Not Authenticator Attestation"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuer, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, key, err
}

// certAttestation builds the attestation statement for packed-x5c or
// fido-u2f. authData is the authenticator data (whose AAGUID the caller set
// to idpdbgAAGUID for packed-x5c, to zeros for fido-u2f).
func certAttestation(c *Ctx, format string, tamper string, authData, cdHash, rpIDHash, credID []byte, credKey crypto.Signer, out M) (map[any]any, error) {
	ca, err := loadAttestationCA(c)
	if err != nil {
		return nil, err
	}
	cert, key, err := ca.attestationCert(format == "packed-x5c", tamper)
	if err != nil {
		return nil, err
	}
	var data []byte
	if format == "fido-u2f" {
		pub, ok := credKey.Public().(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("fido-u2f attestation needs an ES256 (P-256) credential: pass alg -7")
		}
		data = append([]byte{0x00}, rpIDHash...)
		data = append(append(data, cdHash...), credID...)
		data = append(append(data, 0x04), append(pub.X.FillBytes(make([]byte, 32)), pub.Y.FillBytes(make([]byte, 32))...)...)
	} else {
		data = append(append([]byte{}, authData...), cdHash...)
	}
	sig, err := webauthnSign(key, -7, data)
	if err != nil {
		return nil, err
	}
	if tamper == "bad_attestation_signature" {
		sig[len(sig)/2] ^= 0xFF
	}
	info := M{"format": format, "certificate": certDetail(cert), "ca": ca.cert.Subject.String()}
	if ca.generated {
		info["root"] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}))
		info["note"] = "a throwaway CA made for this run; pass attestation_ca (its certificate and key) to use one the relying party trusts"
	}
	if format == "packed-x5c" {
		info["aaguid"] = formatAAGUID(idpdbgAAGUID)
	}
	out["attestation"] = info
	stmt := map[any]any{"sig": sig, "x5c": []any{cert.Raw}}
	if format == "packed-x5c" {
		stmt["alg"] = -7
	}
	return stmt, nil
}

func formatAAGUID(b []byte) string {
	h := hex.EncodeToString(b)
	if len(h) != 32 {
		return h
	}
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
