package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// testMdoc builds an mDL IssuerSigned the way an issuer does, signed by a
// document signer that a test IACA issued.
type testMdoc struct {
	iaca, ds    *x509.Certificate
	dsKey       *ecdsa.PrivateKey
	deviceKey   *ecdsa.PrivateKey
	devicePub   *ecdsa.PublicKey // the holder's key, when given (OID4VCI binds it)
	validUntil  time.Time
	dsEKU       bool
	tamperValue bool // change a value after signing
}

func newTestMdocIssuer(t *testing.T) *testMdoc {
	t.Helper()
	m := &testMdoc{validUntil: time.Now().Add(24 * time.Hour), dsEKU: true}
	iacaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test IACA", Country: []string{"UT"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &iacaKey.PublicKey, iacaKey)
	m.iaca, _ = x509.ParseCertificate(der)
	m.dsKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m.deviceKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m.ds = m.issueDS(t, iacaKey, true)
	return m
}

func (m *testMdoc) issueDS(t *testing.T, signer *ecdsa.PrivateKey, eku bool) *x509.Certificate {
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test DS", Country: []string{"UT"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if eku {
		tpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{oidMdlDS}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, m.iaca, &m.dsKey.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func (m *testMdoc) issuerSigned(t *testing.T) []byte {
	t.Helper()
	const ns = "org.iso.18013.5.1"
	elems := []struct {
		name  string
		value any
	}{{"family_name", "Mustermann"}, {"given_name", "Erika"}, {"birth_date", cborTag{Num: 1004, V: "1984-01-26"}}, {"age_over_18", true}}
	var items []any
	digests := map[any]any{}
	for i, e := range elems {
		salt := make([]byte, 16)
		rand.Read(salt)
		item := cborEncode(map[any]any{"digestID": int64(i), "random": salt, "elementIdentifier": e.name, "elementValue": e.value})
		wrapped := cborTag{Num: 24, V: item}
		sum := sha256.Sum256(cborEncode(wrapped))
		digests[int64(i)] = sum[:]
		if m.tamperValue && e.name == "family_name" {
			wrapped = cborTag{Num: 24, V: cborEncode(map[any]any{"digestID": int64(i), "random": salt, "elementIdentifier": e.name, "elementValue": "Musterfrau"})}
		}
		items = append(items, wrapped)
	}
	ts := func(t time.Time) cborTag { return cborTag{Num: 0, V: t.UTC().Format(time.RFC3339)} }
	pub := m.deviceKey.PublicKey
	if m.devicePub != nil {
		pub = *m.devicePub
	}
	mso := map[any]any{"version": "1.0", "digestAlgorithm": "SHA-256", "docType": "org.iso.18013.5.1.mDL",
		"valueDigests": map[any]any{ns: digests},
		"deviceKeyInfo": map[any]any{"deviceKey": map[any]any{int64(1): int64(2), int64(-1): int64(1),
			int64(-2): pub.X.FillBytes(make([]byte, 32)), int64(-3): pub.Y.FillBytes(make([]byte, 32))}},
		"validityInfo": map[any]any{"signed": ts(time.Now().Add(-time.Minute)), "validFrom": ts(time.Now().Add(-time.Minute)), "validUntil": ts(m.validUntil)}}
	payload := cborEncode(cborTag{Num: 24, V: cborEncode(mso)})
	protected := cborEncode(map[any]any{int64(1): int64(-7)})
	sum := sha256.Sum256(cborEncode([]any{"Signature1", protected, []byte{}, payload}))
	r, s, err := ecdsa.Sign(rand.Reader, m.dsKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	auth := []any{protected, map[any]any{int64(33): m.ds.Raw}, payload, sig}
	return cborEncode(map[any]any{"nameSpaces": map[any]any{ns: items}, "issuerAuth": auth})
}

func TestMdocDecode(t *testing.T) {
	m := newTestMdocIssuer(t)
	iacaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.iaca.Raw}))
	is := m.issuerSigned(t)
	b64 := base64.RawURLEncoding.EncodeToString(is) // as OID4VCI returns mso_mdoc

	res := run(t, "mdoc.decode", M{"credential": b64, "trust_anchors": iacaPEM, "doc_type": "org.iso.18013.5.1.mDL"}, nil)
	noFailures(t, res)
	for _, n := range []string{"issuer signature", "document signer certificate purpose", "document signer chains to a trusted IACA", "MSO version",
		"MSO valid from", "MSO not expired", "device key present", "every data element matches its MSO digest"} {
		wantStatus(t, res, n, "pass")
	}
	doc := res["documents"].([]M)[0]
	claims := doc["namespaces"].(M)["org.iso.18013.5.1"].(M)
	if res["kind"] != "IssuerSigned" || claims["family_name"] != "Mustermann" || claims["birth_date"] != "1984-01-26" || claims["age_over_18"] != true {
		t.Errorf("decoded: %v %v", res["kind"], claims)
	}

	// The same inside a Document and a DeviceResponse, as hex.
	document := cborEncode(map[any]any{"docType": "org.iso.18013.5.1.mDL", "issuerSigned": mustCBOR(t, is)})
	if r := run(t, "mdoc.decode", M{"credential": hex.EncodeToString(document), "trust_anchors": iacaPEM}, nil); r["kind"] != "Document" {
		t.Errorf("document: %v", r["kind"])
	} else {
		noFailures(t, r)
	}
	resp := cborEncode(map[any]any{"version": "1.0", "status": int64(0), "documents": []any{mustCBOR(t, document)}})
	r := run(t, "mdoc.decode", M{"credential": hex.EncodeToString(resp), "trust_anchors": iacaPEM}, nil)
	noFailures(t, r)
	wantStatus(t, r, "DeviceResponse status OK", "pass")

	// What must fail.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherCA := &x509.Certificate{SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "Other IACA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	oder, _ := x509.CreateCertificate(rand.Reader, otherCA, otherCA, &other.PublicKey, other)
	oc, _ := x509.ParseCertificate(oder)
	wantStatus(t, run(t, "mdoc.decode", M{"credential": b64, "trust_anchors": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: oc.Raw}))}, nil),
		"document signer chains to a trusted IACA", "fail")
	wantStatus(t, run(t, "mdoc.decode", M{"credential": b64}, nil), "document signer chains to a trusted IACA", "warn")
	wantStatus(t, run(t, "mdoc.decode", M{"credential": b64, "doc_type": "eu.europa.ec.eudi.pid.1"}, nil), "MSO docType", "fail") // the expected docType is held against the MSO

	tampered := &testMdoc{iaca: m.iaca, ds: m.ds, dsKey: m.dsKey, deviceKey: m.deviceKey, validUntil: m.validUntil, tamperValue: true}
	r = run(t, "mdoc.decode", M{"credential": b64url(tampered.issuerSigned(t))}, nil)
	wantStatus(t, r, "org.iso.18013.5.1/family_name: digest", "fail")
	wantStatus(t, r, "every data element matches its MSO digest", "fail")

	forged := *m
	forged.dsKey = other // the DS certificate's key did not sign it
	wantStatus(t, run(t, "mdoc.decode", M{"credential": b64url(forged.issuerSigned(t))}, nil), "issuer signature", "fail")

	expired := *m
	expired.validUntil = time.Now().Add(-time.Hour)
	wantStatus(t, run(t, "mdoc.decode", M{"credential": b64url(expired.issuerSigned(t))}, nil), "MSO not expired", "fail")
}

func mustCBOR(t *testing.T, b []byte) any {
	t.Helper()
	v, _, err := cborDecodeTagged(b)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// The DeviceResponse sample of ISO/IEC 18013-5 Annex D.
func TestMdocISOSample(t *testing.T) {
	b, err := os.ReadFile("testdata/mdoc/iso-18013-5-annex-d-device-response.hex")
	if err != nil {
		t.Fatal(err)
	}
	sample := strings.TrimSpace(string(b))
	res := run(t, "mdoc.decode", M{"credential": sample, "at": "2021-01-01T00:00:00Z", "doc_type": "org.iso.18013.5.1.mDL"}, nil)
	noFailures(t, res)
	wantStatus(t, res, "issuer signature", "pass")
	wantStatus(t, res, "every data element matches its MSO digest", "pass")
	wantStatus(t, res, "device authentication", "info")
	doc := res["documents"].([]M)[0]
	if fam := doc["namespaces"].(M)["org.iso.18013.5.1"].(M)["family_name"]; fam != "Doe" {
		t.Errorf("family_name: %v", fam)
	}
	// Today the sample has expired.
	wantStatus(t, run(t, "mdoc.decode", M{"credential": sample}, nil), "MSO not expired", "fail")
	// "Doe" changed to "Dog": the element no longer matches its digest.
	doe := hex.EncodeToString([]byte("Doe"))
	if !strings.Contains(sample, doe) {
		t.Fatal("no family name in the sample")
	}
	r := run(t, "mdoc.decode", M{"credential": strings.Replace(sample, doe, hex.EncodeToString([]byte("Dog")), 1), "at": "2021-01-01T00:00:00Z"}, nil)
	wantStatus(t, r, "every data element matches its MSO digest", "fail")

	// Its device MAC, with the session transcript and reader key of Annex D.
	read := func(name string) string {
		b, err := os.ReadFile("testdata/mdoc/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
	st, key := read("iso-18013-5-annex-d-session-transcript.hex"), read("iso-18013-5-annex-d-reader-key-d.hex")
	args := M{"credential": sample, "at": "2021-01-01T00:00:00Z", "session_transcript": st, "reader_key": key}
	r = run(t, "mdoc.decode", args, nil)
	noFailures(t, r)
	wantStatus(t, r, "device MAC", "pass")
	args["session_transcript"] = strings.Replace(st, "a20063312e30", "a20063312e31", 1) // another session
	wantStatus(t, run(t, "mdoc.decode", args, nil), "device MAC", "fail")
	args["session_transcript"], args["reader_key"] = st, strings.Repeat("11", 32) // another reader
	wantStatus(t, run(t, "mdoc.decode", args, nil), "device MAC", "fail")
	delete(args, "reader_key")
	wantStatus(t, run(t, "mdoc.decode", args, nil), "device MAC", "info")
}

// A device signature over a session transcript, as a holder makes it.
func TestMdocDeviceSignature(t *testing.T) {
	m := newTestMdocIssuer(t)
	is := mustCBOR(t, m.issuerSigned(t))
	transcript := cborEncode([]any{nil, nil, []any{"TestHandover", []byte("session-1")}})
	nsBytes := cborTag{Num: 24, V: cborEncode(map[any]any{})}
	dab := deviceAuthenticationBytes(transcript, "org.iso.18013.5.1.mDL", cborEncode(nsBytes))
	protected := cborEncode(map[any]any{int64(1): int64(-7)})
	sum := sha256.Sum256(cborEncode([]any{"Signature1", protected, []byte{}, dab}))
	r, s, _ := ecdsa.Sign(rand.Reader, m.deviceKey, sum[:])
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	resp := cborEncode(map[any]any{"version": "1.0", "status": int64(0), "documents": []any{map[any]any{"docType": "org.iso.18013.5.1.mDL", "issuerSigned": is,
		"deviceSigned": map[any]any{"nameSpaces": nsBytes, "deviceAuth": map[any]any{"deviceSignature": []any{protected, map[any]any{}, nil, sig}}}}}})
	args := M{"credential": hex.EncodeToString(resp), "session_transcript": hex.EncodeToString(transcript)}
	res := run(t, "mdoc.decode", args, nil)
	noFailures(t, res)
	wantStatus(t, res, "device signature", "pass")
	args["session_transcript"] = hex.EncodeToString(cborEncode([]any{nil, nil, []any{"TestHandover", []byte("session-2")}}))
	wantStatus(t, run(t, "mdoc.decode", args, nil), "device signature", "fail")
	delete(args, "session_transcript")
	wantStatus(t, run(t, "mdoc.decode", args, nil), "device authentication", "info")
}
