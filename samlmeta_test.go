package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func TestSAMLMetadataChecks(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := func(notAfter time.Time) string {
		tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp-signing"},
			NotBefore: time.Now().Add(-500 * 24 * time.Hour), NotAfter: notAfter}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(der)
	}
	md := func(entity, certB64 string) string {
		return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + entity + `"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
			`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>` + certB64 +
			`</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
			`<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>`
	}
	good := run(t, "saml.metadata", M{"idp_metadata": md("https://idp.example/saml", cert(time.Now().Add(400*24*time.Hour)))}, nil)
	noFailures(t, good)
	wantStatus(t, good, "entityID is an absolute URI", "pass")
	wantStatus(t, good, "signing idp-signing: validity", "pass")
	wantStatus(t, run(t, "saml.metadata", M{"idp_metadata": md("urn:example:idp", cert(time.Now().Add(400*24*time.Hour)))}, nil), "entityID is an absolute URI", "pass")
	wantStatus(t, run(t, "saml.metadata", M{"idp_metadata": md("IdP Entity ID", cert(time.Now().Add(400*24*time.Hour)))}, nil), "entityID is an absolute URI", "warn")
	wantStatus(t, run(t, "saml.metadata", M{"idp_metadata": md("https://idp.example/saml", cert(time.Now().Add(-24*time.Hour)))}, nil), "signing idp-signing: validity", "fail")
	wantStatus(t, run(t, "saml.metadata", M{"idp_metadata": md("https://idp.example/saml", cert(time.Now().Add(10*24*time.Hour)))}, nil), "signing idp-signing: validity", "warn")
}
