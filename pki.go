package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// X.509: decoding, chain verification, and a throwaway CA hierarchy.

var (
	oidTLSFeature   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	mustStapleValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
)

var ekuNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny: "any", x509.ExtKeyUsageServerAuth: "serverAuth", x509.ExtKeyUsageClientAuth: "clientAuth",
	x509.ExtKeyUsageCodeSigning: "codeSigning", x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping: "timeStamping", x509.ExtKeyUsageOCSPSigning: "OCSPSigning",
}

var kuNames = []struct {
	ku   x509.KeyUsage
	name string
}{
	{x509.KeyUsageDigitalSignature, "digitalSignature"}, {x509.KeyUsageContentCommitment, "contentCommitment"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"}, {x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"}, {x509.KeyUsageCertSign, "keyCertSign"}, {x509.KeyUsageCRLSign, "cRLSign"},
	{x509.KeyUsageEncipherOnly, "encipherOnly"}, {x509.KeyUsageDecipherOnly, "decipherOnly"},
}

func keyDescription(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", pub)
}

func selfSignedCert(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String() && c.CheckSignatureFrom(c) == nil
}

func certDetail(c *x509.Certificate) M {
	s256 := sha256.Sum256(c.Raw)
	s1 := sha1.Sum(c.Raw)
	out := M{
		"subject": c.Subject.String(), "issuer": c.Issuer.String(), "serial": hex.EncodeToString(c.SerialNumber.Bytes()),
		"not_before": c.NotBefore.UTC().Format(time.RFC3339), "not_after": c.NotAfter.UTC().Format(time.RFC3339) + " (" + relTime(c.NotAfter) + ")",
		"key": keyDescription(c.PublicKey), "signature_algorithm": c.SignatureAlgorithm.String(),
		"sha256_fingerprint": hex.EncodeToString(s256[:]), "sha1_fingerprint": hex.EncodeToString(s1[:]),
		"self_signed": selfSignedCert(c),
	}
	sans := M{}
	if len(c.DNSNames) > 0 {
		sans["dns"] = c.DNSNames
	}
	if len(c.IPAddresses) > 0 {
		var ips []string
		for _, ip := range c.IPAddresses {
			ips = append(ips, ip.String())
		}
		sans["ip"] = ips
	}
	if len(c.EmailAddresses) > 0 {
		sans["email"] = c.EmailAddresses
	}
	if len(c.URIs) > 0 {
		var us []string
		for _, u := range c.URIs {
			us = append(us, u.String())
		}
		sans["uri"] = us
	}
	if len(sans) > 0 {
		out["subject_alt_names"] = sans
	}
	if c.BasicConstraintsValid {
		bc := M{"ca": c.IsCA}
		if c.IsCA && (c.MaxPathLen > 0 || c.MaxPathLenZero) {
			bc["max_path_len"] = c.MaxPathLen
		}
		out["basic_constraints"] = bc
	}
	var ku []string
	for _, k := range kuNames {
		if c.KeyUsage&k.ku != 0 {
			ku = append(ku, k.name)
		}
	}
	if len(ku) > 0 {
		out["key_usage"] = ku
	}
	var eku []string
	for _, e := range c.ExtKeyUsage {
		if n := ekuNames[e]; n != "" {
			eku = append(eku, n)
		} else {
			eku = append(eku, fmt.Sprint(e))
		}
	}
	for _, o := range c.UnknownExtKeyUsage {
		eku = append(eku, o.String())
	}
	if len(eku) > 0 {
		out["extended_key_usage"] = eku
	}
	if len(c.SubjectKeyId) > 0 {
		out["subject_key_id"] = hex.EncodeToString(c.SubjectKeyId)
	}
	if len(c.AuthorityKeyId) > 0 {
		out["authority_key_id"] = hex.EncodeToString(c.AuthorityKeyId)
	}
	if len(c.OCSPServer) > 0 {
		out["ocsp"] = c.OCSPServer
	}
	if len(c.IssuingCertificateURL) > 0 {
		out["ca_issuers"] = c.IssuingCertificateURL
	}
	if len(c.CRLDistributionPoints) > 0 {
		out["crl_distribution_points"] = c.CRLDistributionPoints
	}
	if len(c.Policies) > 0 {
		var ps []string
		for _, p := range c.Policies {
			ps = append(ps, p.String())
		}
		out["policies"] = ps
	}
	if len(c.PermittedDNSDomains) > 0 || len(c.ExcludedDNSDomains) > 0 {
		out["name_constraints"] = M{"permitted_dns": c.PermittedDNSDomains, "excluded_dns": c.ExcludedDNSDomains, "critical": c.PermittedDNSDomainsCritical}
	}
	for _, e := range c.Extensions {
		if e.Id.Equal(oidTLSFeature) {
			out["must_staple"] = string(e.Value) == string(mustStapleValue)
		}
	}
	return out
}

// certChecks reviews one certificate. role is leaf, ca, root, or signing (a
// self-signed key holder such as an IdP or STS signing certificate: no CA or
// SAN rules apply).
func certChecks(cs *Checks, c *x509.Certificate, role string) {
	who := role + " " + c.Subject.CommonName
	now := time.Now()
	switch {
	case now.Before(c.NotBefore):
		cs.add(who+": validity", "fail", "not valid until "+c.NotBefore.UTC().Format(time.RFC3339), "RFC 5280 §4.1.2.5")
	case now.After(c.NotAfter):
		cs.add(who+": validity", "fail", "expired "+relTime(c.NotAfter), "RFC 5280 §4.1.2.5")
	case c.NotAfter.Sub(now) < 30*24*time.Hour:
		cs.add(who+": validity", "warn", "expires "+relTime(c.NotAfter), "RFC 5280 §4.1.2.5")
	default:
		cs.add(who+": validity", "pass", "until "+c.NotAfter.UTC().Format(time.RFC3339), "RFC 5280 §4.1.2.5")
	}
	if k, ok := c.PublicKey.(*rsa.PublicKey); ok && k.N.BitLen() < 2048 {
		cs.add(who+": key size", "fail", fmt.Sprintf("RSA %d bits", k.N.BitLen()), "NIST SP 800-131A")
	}
	switch c.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		if role == "root" {
			cs.add(who+": signature algorithm", "info", c.SignatureAlgorithm.String()+" on a root's self-signature does not weaken trust", "")
		} else {
			cs.add(who+": signature algorithm", "fail", c.SignatureAlgorithm.String()+" is no longer collision-resistant", "CA/B Forum BR §7.1.3")
		}
	}
	if role == "signing" {
		return
	}
	if role == "leaf" || role == "client" {
		// Only TLS server certificates need their names in the SAN; client
		// certificates (PIV, PKINIT, smart card logon) are mapped otherwise.
		tlsServer := role == "leaf" && (len(c.ExtKeyUsage) == 0 || contains(stringsOf(c.ExtKeyUsage), "serverAuth"))
		if tlsServer && len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) == 0 {
			cs.add(who+": subjectAltName present", "fail", "names only in the subject CN are ignored by modern clients", "RFC 6125 §6.4.4")
		}
		if c.BasicConstraintsValid && c.IsCA {
			cs.add(who+": not a CA", "warn", "an end-entity certificate with CA:TRUE", "RFC 5280 §4.2.1.9")
		}
		if contains(stringsOf(c.ExtKeyUsage), "serverAuth") && c.NotAfter.Sub(c.NotBefore) > 398*24*time.Hour {
			cs.add(who+": lifetime", "warn", fmt.Sprintf("%d days; publicly trusted TLS certificates may not exceed 398", int(c.NotAfter.Sub(c.NotBefore).Hours()/24)), "CA/B Forum BR §6.3.2")
		}
	} else {
		cs.ok(c.BasicConstraintsValid && c.IsCA, who+": basicConstraints CA:TRUE", "", "RFC 5280 §4.2.1.9")
		if c.KeyUsage != 0 {
			cs.ok(c.KeyUsage&x509.KeyUsageCertSign != 0, who+": keyUsage includes keyCertSign", "", "RFC 5280 §4.2.1.3")
		}
	}
}

func stringsOf(e []x509.ExtKeyUsage) []string {
	var out []string
	for _, u := range e {
		out = append(out, ekuNames[u])
	}
	return out
}

// pkiObjects splits input into certificates, CSRs and CRLs. Input may be PEM
// (any number of blocks), or a single DER object in base64.
type pkiObjects struct {
	Certs []*x509.Certificate
	CSRs  []*x509.CertificateRequest
	CRLs  []*x509.RevocationList
	Keys  int
}

func parsePKI(s string) (*pkiObjects, error) {
	o := &pkiObjects{}
	add := func(kind string, der []byte) error {
		switch kind {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(der)
			if err != nil {
				return err
			}
			o.Certs = append(o.Certs, c)
		case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
			r, err := x509.ParseCertificateRequest(der)
			if err != nil {
				return err
			}
			o.CSRs = append(o.CSRs, r)
		case "X509 CRL":
			l, err := x509.ParseRevocationList(der)
			if err != nil {
				return err
			}
			o.CRLs = append(o.CRLs, l)
		default:
			if strings.Contains(kind, "PRIVATE KEY") {
				o.Keys++
			}
		}
		return nil
	}
	b := []byte(s)
	if strings.Contains(s, "-----BEGIN") {
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			if err := add(blk.Type, blk.Bytes); err != nil {
				return nil, fmt.Errorf("%s: %w", blk.Type, err)
			}
		}
	} else {
		der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
		if err != nil {
			return nil, errors.New("input is neither PEM nor base64 DER")
		}
		for _, kind := range []string{"CERTIFICATE", "CERTIFICATE REQUEST", "X509 CRL"} {
			if add(kind, der) == nil {
				break
			}
		}
	}
	if len(o.Certs)+len(o.CSRs)+len(o.CRLs) == 0 {
		if o.Keys > 0 {
			return nil, errors.New("the input holds only private keys; idpdbg does not display key material")
		}
		return nil, errors.New("no certificate, CSR or CRL found")
	}
	return o, nil
}

func runPKIDecode(c *Ctx) (M, error) {
	o, err := parsePKI(c.Str("input"))
	if err != nil {
		return nil, err
	}
	var cs Checks
	out := M{}
	if o.Keys > 0 {
		cs.add("private keys", "info", fmt.Sprintf("%d private key block(s) in the input were skipped and not shown", o.Keys), "")
	}
	if len(o.Certs) > 0 {
		var certs []M
		for i, cert := range o.Certs {
			certs = append(certs, certDetail(cert))
			role := "leaf"
			switch {
			case selfSignedCert(cert):
				role = "root"
			case cert.IsCA:
				role = "ca"
			}
			certChecks(&cs, cert, role)
			if i+1 < len(o.Certs) {
				next := o.Certs[i+1]
				cs.ok(cert.CheckSignatureFrom(next) == nil, fmt.Sprintf("chain: certificate %d is signed by certificate %d", i+1, i+2),
					cert.Issuer.String()+" <- "+next.Subject.String(), "RFC 5246 §7.4.2 / RFC 8446 §4.4.2")
			}
		}
		out["certificates"] = certs
		if h := c.Str("hostname"); h != "" {
			cs.ok(o.Certs[0].VerifyHostname(h) == nil, "first certificate is valid for "+h, detailOr(o.Certs[0].VerifyHostname(h), ""), "RFC 6125 §6")
		}
	}
	for _, r := range o.CSRs {
		d := M{"subject": r.Subject.String(), "key": keyDescription(r.PublicKey), "signature_algorithm": r.SignatureAlgorithm.String(),
			"dns": r.DNSNames, "email": r.EmailAddresses}
		out["csrs"] = append(asList(out["csrs"]), d)
		cs.ok(r.CheckSignature() == nil, "CSR "+r.Subject.CommonName+": self-signature (proof of possession)", detailOr(r.CheckSignature(), ""), "RFC 2986 §4.2")
	}
	var issuers []*x509.Certificate
	if s := c.Str("issuer_cert"); s != "" {
		io, err := parsePKI(s)
		if err != nil || len(io.Certs) == 0 {
			return nil, fmt.Errorf("issuer_cert: %v", err)
		}
		issuers = io.Certs
	}
	issuers = append(issuers, o.Certs...)
	for _, l := range o.CRLs {
		var revoked []M
		for i, r := range l.RevokedCertificateEntries {
			if i == 50 {
				break
			}
			revoked = append(revoked, M{"serial": hex.EncodeToString(r.SerialNumber.Bytes()), "revoked_at": r.RevocationTime.UTC().Format(time.RFC3339), "reason": r.ReasonCode})
		}
		d := M{"issuer": l.Issuer.String(), "this_update": l.ThisUpdate.UTC().Format(time.RFC3339), "next_update": l.NextUpdate.UTC().Format(time.RFC3339),
			"revoked_count": len(l.RevokedCertificateEntries), "revoked": revoked}
		if l.Number != nil {
			d["crl_number"] = l.Number.String()
		}
		out["crls"] = append(asList(out["crls"]), d)
		cs.ok(!l.NextUpdate.IsZero() && time.Now().Before(l.NextUpdate), "CRL: nextUpdate in the future", "next update "+relTime(l.NextUpdate), "RFC 5280 §5.1.2.5")
		verified := false
		for _, is := range issuers {
			if l.CheckSignatureFrom(is) == nil {
				verified = true
				cs.add("CRL: signature", "pass", "signed by "+is.Subject.String(), "RFC 5280 §5.1.1.3")
			}
		}
		if !verified {
			cs.add("CRL: signature", "warn", "not verified: pass issuer_cert", "RFC 5280 §5.1.1.3")
		}
		if c.Str("check_serial") != "" {
			// Compare as numbers: hex renderings differ in leading zeros and colons.
			want, ok := new(big.Int).SetString(strings.NewReplacer(":", "", " ", "", "0x", "").Replace(c.Str("check_serial")), 16)
			if !ok {
				return nil, fmt.Errorf("check_serial: %q is not a hex serial number", c.Str("check_serial"))
			}
			hit := false
			for _, r := range l.RevokedCertificateEntries {
				hit = hit || r.SerialNumber.Cmp(want) == 0
			}
			cs.add("serial "+c.Str("check_serial")+" not revoked", map[bool]string{true: "fail", false: "pass"}[hit], "", "RFC 5280 §5.3")
		}
	}
	out["checks"] = cs
	return out, nil
}

func asList(v any) []M {
	l, _ := v.([]M)
	return l
}

func runPKIVerify(c *Ctx) (M, error) {
	o, err := parsePKI(c.Str("chain"))
	if err != nil {
		return nil, err
	}
	if len(o.Certs) == 0 {
		return nil, errors.New("chain holds no certificates")
	}
	opts := x509.VerifyOptions{Intermediates: x509.NewCertPool(), DNSName: c.Str("hostname")}
	for _, ic := range o.Certs[1:] {
		opts.Intermediates.AddCert(ic)
	}
	rootsFrom := "the system trust store"
	if s := c.Str("roots"); s != "" {
		ro, err := parsePKI(s)
		if err != nil || len(ro.Certs) == 0 {
			return nil, fmt.Errorf("roots: %v", err)
		}
		opts.Roots = x509.NewCertPool()
		for _, r := range ro.Certs {
			opts.Roots.AddCert(r)
		}
		rootsFrom = fmt.Sprintf("%d supplied root(s)", len(ro.Certs))
	}
	switch c.Str("usage") {
	case "server":
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	default:
		opts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	if at := c.Str("at_time"); at != "" {
		t, err := time.Parse(time.RFC3339, at)
		if err != nil {
			return nil, fmt.Errorf("at_time: %w", err)
		}
		opts.CurrentTime = t
	}
	var cs Checks
	leaf := o.Certs[0]
	chains, verr := leaf.Verify(opts)
	cs.ok(verr == nil, "chain verifies against "+rootsFrom, detailOr(verr, fmt.Sprintf("%d path(s) found", len(chains))), "RFC 5280 §6")
	var paths [][]string
	for _, ch := range chains {
		var names []string
		for _, ce := range ch {
			names = append(names, ce.Subject.String())
		}
		paths = append(paths, names)
	}
	for i, ce := range o.Certs {
		role := "ca"
		if i == 0 {
			role = "leaf"
		} else if selfSignedCert(ce) {
			role = "root"
			cs.add("chain: root certificate included", "info", "servers should not send the root; clients ignore it", "RFC 8446 §4.4.2")
		}
		certChecks(&cs, ce, role)
	}
	return M{"leaf": certDetail(leaf), "paths": paths, "checks": cs}, nil
}

// ---- issuing ----

func generateKey(kind string) (crypto.Signer, error) {
	switch kind {
	case "", "ecdsa-p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa-2048":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	case "ed25519":
		_, k, err := ed25519.GenerateKey(rand.Reader)
		return k, err
	}
	return nil, fmt.Errorf("unknown key_type %q", kind)
}

var keyTypes = []string{"ecdsa-p256", "ecdsa-p384", "rsa-2048", "rsa-3072", "rsa-4096", "ed25519"}

func serialNumber() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n.Add(n, big.NewInt(1))
}

func keyPEM(k crypto.Signer) string {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func sign(tmpl, parent *x509.Certificate, pub any, signer crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func caTemplate(cn string, years, pathLen int) *x509.Certificate {
	t := &x509.Certificate{
		SerialNumber: serialNumber(), Subject: pkix.Name{CommonName: cn, Organization: []string{"idpdbg test PKI"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(years, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	if pathLen >= 0 {
		t.MaxPathLen, t.MaxPathLenZero = pathLen, pathLen == 0
	}
	return t
}

// leafTemplate builds an end-entity template from the operation's parameters.
func leafTemplate(c *Ctx) (*x509.Certificate, error) {
	cn := c.Str("cn")
	t := &x509.Certificate{
		SerialNumber: serialNumber(), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Duration(c.Int("validity_days")) * 24 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		DNSNames: c.List("dns_names"), EmailAddresses: c.List("emails"),
		OCSPServer: c.List("ocsp_urls"), IssuingCertificateURL: c.List("ca_issuers_urls"), CRLDistributionPoints: c.List("crl_urls"),
	}
	if o := c.Str("organization"); o != "" {
		t.Subject.Organization = []string{o}
	}
	for _, ip := range c.List("ip_addresses") {
		p := net.ParseIP(ip)
		if p == nil {
			return nil, fmt.Errorf("ip_addresses: %q is not an IP address", ip)
		}
		t.IPAddresses = append(t.IPAddresses, p)
	}
	for _, s := range c.List("uris") {
		u, err := url.Parse(s)
		if err != nil {
			return nil, fmt.Errorf("uris: %w", err)
		}
		t.URIs = append(t.URIs, u)
	}
	switch c.Str("usage") {
	case "server":
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case "both":
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	case "email":
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		t.KeyUsage |= x509.KeyUsageContentCommitment
	case "code":
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
	}
	for _, p := range c.List("policies") {
		oid, err := x509.ParseOID(p)
		if err != nil {
			return nil, fmt.Errorf("policies: %q is not an OID", p)
		}
		t.Policies = append(t.Policies, oid)
	}
	if c.Bool("must_staple") {
		t.ExtraExtensions = append(t.ExtraExtensions, pkix.Extension{Id: oidTLSFeature, Value: mustStapleValue})
	}
	if cn != "" && len(t.DNSNames)+len(t.IPAddresses)+len(t.EmailAddresses)+len(t.URIs) == 0 && strings.Contains(cn, ".") {
		t.DNSNames = []string{cn} // a host name in the CN also goes where clients look for it
	}
	return t, nil
}

func issueLeaf(c *Ctx, issuer *x509.Certificate, issuerKey crypto.Signer, chain []*x509.Certificate) (M, error) {
	tmpl, err := leafTemplate(c)
	if err != nil {
		return nil, err
	}
	key, err := generateKey(c.Str("key_type"))
	if err != nil {
		return nil, err
	}
	if _, isRSA := key.(*rsa.PrivateKey); isRSA && contains(stringsOf(tmpl.ExtKeyUsage), "serverAuth") {
		tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	cert, err := sign(tmpl, issuer, key.Public(), issuerKey)
	if err != nil {
		return nil, err
	}
	full := certPEM(cert)
	for _, ch := range chain {
		full += certPEM(ch)
	}
	return M{"certificate": certDetail(cert), "cert_pem": certPEM(cert), "key_pem": keyPEM(key), "chain_pem": full}, nil
}

var leafParams = []Param{
	{Name: "cn", Type: "string", Desc: "Subject common name", Default: "localhost"},
	{Name: "organization", Type: "string", Desc: "Subject organization"},
	{Name: "dns_names", Type: "list", Desc: "DNS subjectAltNames", Default: "localhost"},
	{Name: "ip_addresses", Type: "list", Desc: "IP subjectAltNames", Default: "127.0.0.1,::1"},
	{Name: "emails", Type: "list", Desc: "Email subjectAltNames"},
	{Name: "uris", Type: "list", Desc: "URI subjectAltNames, e.g. spiffe://example.org/workload"},
	{Name: "usage", Type: "string", Enum: []string{"server", "client", "both", "email", "code"}, Desc: "Extended key usage", Default: "server"},
	{Name: "validity_days", Type: "int", Desc: "Lifetime in days", Default: 90},
	{Name: "key_type", Type: "string", Enum: keyTypes, Desc: "Key algorithm", Default: "ecdsa-p256"},
	{Name: "crl_urls", Type: "list", Desc: "CRL distribution point URLs"},
	{Name: "ocsp_urls", Type: "list", Desc: "OCSP responder URLs (authorityInfoAccess)"},
	{Name: "ca_issuers_urls", Type: "list", Desc: "caIssuers URLs (authorityInfoAccess)"},
	{Name: "policies", Type: "list", Desc: "Certificate policy OIDs, e.g. 2.23.140.1.2.1"},
	{Name: "must_staple", Type: "bool", Desc: "Add the TLS Feature (OCSP must-staple) extension"},
}

func writeOutDir(c *Ctx, files map[string]string) (string, error) {
	dir := c.Str("out_dir")
	if dir == "" {
		return "", nil
	}
	if !c.CLI {
		return "", errors.New("out_dir is only available from the CLI; over MCP the PEM is returned in the result")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for name := range files {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return "", fmt.Errorf("%s already exists; refusing to overwrite", filepath.Join(dir, name))
		}
	}
	for name, content := range files {
		mode := os.FileMode(0o644)
		if strings.HasSuffix(name, ".key") {
			mode = 0o600
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func init() {
	register(
		&Op{
			Name:    "pki.decode",
			Summary: "Decode X.509 certificates, chains, CSRs and CRLs (PEM or base64 DER): subject, SANs, key, every common extension, fingerprints. Checks validity, key size, signature algorithm, SAN presence, CA flags, chain order, CSR self-signature and CRL freshness and signature.",
			Params: []Param{
				{Name: "input", Type: "string", Required: true, Path: true, File: true, Desc: "PEM (any number of blocks) or base64 DER; a path from the CLI or a profile; - for stdin"},
				{Name: "hostname", Type: "string", Desc: "Check that the first certificate is valid for this host name or IP"},
				{Name: "issuer_cert", Type: "string", Path: true, Desc: "Issuer certificate, to verify a CRL's signature"},
				{Name: "check_serial", Type: "string", Desc: "Serial number (hex) to look up in the CRL"}},
			Run: runPKIDecode,
		},
		&Op{
			Name:    "pki.verify",
			Summary: "Verify a certificate chain (leaf first, then intermediates) against the system trust store or supplied roots, for a host name and key usage, now or at a given time. Returns every valid path.",
			Params: []Param{
				{Name: "chain", Type: "string", Required: true, Path: true, File: true, Desc: "PEM chain, leaf first"},
				{Name: "roots", Type: "string", Path: true, Desc: "PEM root certificates to trust instead of the system store"},
				{Name: "hostname", Type: "string", Desc: "Host name or IP the leaf must be valid for"},
				{Name: "usage", Type: "string", Enum: []string{"server", "client", "any"}, Desc: "Required extended key usage", Default: "server"},
				{Name: "at_time", Type: "string", Desc: "Verify as of this RFC 3339 time"}},
			Run: runPKIVerify,
		},
		&Op{
			Name:    "pki.ca",
			Summary: "Create a throwaway test PKI: a root CA, optionally an intermediate and an issuing CA, and an end-entity certificate (server, client or both) with chosen SANs and extensions. Returns PEM certificates and private keys; with out_dir (CLI only) also writes them to files. For testing only.",
			Params: append([]Param{
				{Name: "levels", Type: "int", Desc: "CA levels: 1 (root signs leaves), 2 (root and issuing CA) or 3 (root, intermediate, issuing)", Default: 3},
				{Name: "root_cn", Type: "string", Desc: "Root CA common name", Default: "idpdbg Test Root CA"},
				{Name: "ca_key_type", Type: "string", Enum: keyTypes, Desc: "Key algorithm for the CAs", Default: "ecdsa-p384"},
				{Name: "permitted_dns", Type: "list", Desc: "Name constraint: DNS domains the issuing CA may issue for"},
				{Name: "out_dir", Type: "string", Desc: "CLI only: write the PEM files here (existing files are never overwritten)"},
			}, leafParams...),
			Run: func(c *Ctx) (M, error) {
				levels := c.Int("levels")
				if levels < 1 || levels > 3 {
					return nil, errors.New("levels must be 1, 2 or 3")
				}
				names := []string{c.Str("root_cn"), "idpdbg Test Intermediate CA", "idpdbg Test Issuing CA"}
				if levels == 2 {
					names = []string{c.Str("root_cn"), "idpdbg Test Issuing CA"}
				}
				out := M{}
				files := map[string]string{}
				var parent *x509.Certificate
				var parentKey crypto.Signer
				var chain []*x509.Certificate // issuing CA first, root last
				for i := 0; i < levels; i++ {
					key, err := generateKey(c.Str("ca_key_type"))
					if err != nil {
						return nil, err
					}
					tmpl := caTemplate(names[i], 10-2*i, levels-i-1)
					if i == levels-1 && len(c.List("permitted_dns")) > 0 {
						tmpl.PermittedDNSDomains, tmpl.PermittedDNSDomainsCritical = c.List("permitted_dns"), true
					}
					p, pk := parent, parentKey
					if p == nil {
						p, pk = tmpl, key
					}
					cert, err := sign(tmpl, p, key.Public(), pk)
					if err != nil {
						return nil, err
					}
					label := []string{"root", "intermediate", "issuing"}[map[bool]int{true: 0, false: i + 3 - levels}[i == 0]]
					out[label] = M{"certificate": certDetail(cert), "cert_pem": certPEM(cert), "key_pem": keyPEM(key)}
					files[label+".crt"], files[label+".key"] = certPEM(cert), keyPEM(key)
					parent, parentKey = cert, key
					chain = append([]*x509.Certificate{cert}, chain...)
				}
				leaf, err := issueLeaf(c, parent, parentKey, chain[:len(chain)-1])
				if err != nil {
					return nil, err
				}
				out["leaf"] = leaf
				files["leaf.crt"], files["leaf.key"], files["leaf-chain.crt"] = str(leaf["cert_pem"]), str(leaf["key_pem"]), str(leaf["chain_pem"])
				var cs Checks
				pool := x509.NewCertPool()
				pool.AddCert(chain[len(chain)-1])
				inter := x509.NewCertPool()
				for _, ch := range chain[:len(chain)-1] {
					inter.AddCert(ch)
				}
				lc, _ := x509.ParseCertificate(pemDER(str(leaf["cert_pem"])))
				_, verr := lc.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
				cs.ok(verr == nil, "leaf verifies up to the new root", detailOr(verr, ""), "RFC 5280 §6")
				if dir, err := writeOutDir(c, files); err != nil {
					return nil, err
				} else if dir != "" {
					out["written_to"] = dir
				}
				out["checks"] = cs
				return out, nil
			},
		},
		&Op{
			Name:    "pki.issue",
			Summary: "Issue an end-entity certificate from an existing CA certificate and key, with chosen SANs, key usage and extensions (CRL, OCSP, caIssuers, policies, must-staple). Returns the certificate, a new private key and the chain.",
			Params: append([]Param{
				{Name: "issuer_cert", Type: "string", Required: true, Path: true, Desc: "Issuing CA certificate (PEM; may include its own chain after it)"},
				{Name: "issuer_key", Type: "string", Required: true, Path: true, Explicit: true, Desc: "Issuing CA private key (PEM)"},
				{Name: "out_dir", Type: "string", Desc: "CLI only: write the PEM files here (existing files are never overwritten)"},
			}, leafParams...),
			Run: func(c *Ctx) (M, error) {
				io, err := parsePKI(c.Str("issuer_cert"))
				if err != nil || len(io.Certs) == 0 {
					return nil, fmt.Errorf("issuer_cert: %v", err)
				}
				key, err := loadSigner(c.Str("issuer_key"))
				if err != nil {
					return nil, fmt.Errorf("issuer_key: %w", err)
				}
				if !io.Certs[0].IsCA {
					return nil, errors.New("issuer_cert is not a CA certificate")
				}
				leaf, err := issueLeaf(c, io.Certs[0], key, io.Certs)
				if err != nil {
					return nil, err
				}
				if dir, err := writeOutDir(c, map[string]string{"leaf.crt": str(leaf["cert_pem"]), "leaf.key": str(leaf["key_pem"]), "leaf-chain.crt": str(leaf["chain_pem"])}); err != nil {
					return nil, err
				} else if dir != "" {
					leaf["written_to"] = dir
				}
				return leaf, nil
			},
		},
	)
}

func pemDER(s string) []byte {
	blk, _ := pem.Decode([]byte(s))
	if blk == nil {
		return nil
	}
	return blk.Bytes
}
