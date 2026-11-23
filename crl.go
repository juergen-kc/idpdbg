package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CRLs (RFC 5280 §5, §6.3): download the CRLs a certificate names, or
// check a supplied one, and say whether the certificate is on it.

var (
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidFreshestCRL              = asn1.ObjectIdentifier{2, 5, 29, 46}
)

// issuingDistPoint is the decoded IDP extension: it scopes a CRL (a shard
// of a partitioned CRL, or one for only CA or only end-entity certificates).
type issuingDistPoint struct {
	URIs                       []string
	OnlyUser, OnlyCA, OnlyAttr bool
	SomeReasons, Indirect      bool
}

func parseIDP(der []byte) (*issuingDistPoint, error) {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &seq); err != nil || len(rest) > 0 || seq.Tag != asn1.TagSequence {
		return nil, errors.New("issuingDistributionPoint is not a SEQUENCE")
	}
	idp := &issuingDistPoint{}
	for b := seq.Bytes; len(b) > 0; {
		var f asn1.RawValue
		var err error
		if b, err = asn1.Unmarshal(b, &f); err != nil {
			return nil, err
		}
		if f.Class != asn1.ClassContextSpecific {
			return nil, errors.New("unexpected field in issuingDistributionPoint")
		}
		isTrue := len(f.Bytes) == 1 && f.Bytes[0] != 0
		switch f.Tag {
		case 0: // distributionPoint: [0] EXPLICIT DistributionPointName
			var name asn1.RawValue
			if _, err := asn1.Unmarshal(f.Bytes, &name); err != nil {
				return nil, err
			}
			if name.Tag != 0 { // nameRelativeToCRLIssuer: no URIs to compare
				continue
			}
			for g := name.Bytes; len(g) > 0; {
				var gn asn1.RawValue
				if g, err = asn1.Unmarshal(g, &gn); err != nil {
					return nil, err
				}
				if gn.Class == asn1.ClassContextSpecific && gn.Tag == 6 { // uniformResourceIdentifier
					idp.URIs = append(idp.URIs, string(gn.Bytes))
				}
			}
		case 1:
			idp.OnlyUser = isTrue
		case 2:
			idp.OnlyCA = isTrue
		case 3:
			idp.SomeReasons = true
		case 4:
			idp.Indirect = isTrue
		case 5:
			idp.OnlyAttr = isTrue
		}
	}
	return idp, nil
}

func parseCRLBytes(b []byte) (*x509.RevocationList, error) {
	if blk, _ := pem.Decode(b); blk != nil {
		b = blk.Bytes
	} else if !bytes.HasPrefix(b, []byte{0x30}) { // base64 DER pasted as text
		if d, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(b)), "")); err == nil {
			b = d
		}
	}
	return x509.ParseRevocationList(b)
}

// checkCRL validates one CRL for cert and reports whether cert is on it.
// fetchedFrom is the URL it came from ("" for a supplied CRL).
func checkCRL(cs *Checks, prefix string, l *x509.RevocationList, cert, issuer *x509.Certificate, fetchedFrom string) M {
	out := M{"issuer": l.Issuer.String(), "this_update": l.ThisUpdate.UTC().Format(time.RFC3339), "entries": len(l.RevokedCertificateEntries)}
	if fetchedFrom != "" {
		out["url"] = fetchedFrom
	}
	if l.Number != nil {
		out["crl_number"] = l.Number.String()
	}

	// Who issued it, and is the signature good.
	cs.ok(bytes.Equal(l.RawIssuer, cert.RawIssuer), prefix+"CRL issuer is the certificate's issuer", l.Issuer.String(), "RFC 5280 §6.3.3(b)(1)")
	if err := l.CheckSignatureFrom(issuer); err != nil {
		cs.add(prefix+"CRL signature", "fail", err.Error(), "RFC 5280 §6.3.3(f)")
		return out
	}
	cs.add(prefix+"CRL signature", "pass", "signed by "+issuer.Subject.String(), "RFC 5280 §6.3.3(f)")
	if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCRLSign == 0 {
		cs.add(prefix+"CRL issuer may sign CRLs (cRLSign)", "fail", "the issuer's keyUsage lacks cRLSign", "RFC 5280 §4.2.1.3")
	}
	if len(l.AuthorityKeyId) > 0 && len(issuer.SubjectKeyId) > 0 && !bytes.Equal(l.AuthorityKeyId, issuer.SubjectKeyId) {
		cs.add(prefix+"CRL authorityKeyIdentifier matches the issuer", "warn", "the CRL names a different key; a rekeyed CA?", "RFC 5280 §5.2.1")
	}

	// Freshness.
	now := time.Now()
	cs.ok(!l.ThisUpdate.After(now.Add(ocspSkew)), prefix+"CRL thisUpdate not in the future", "this update "+relTime(l.ThisUpdate), "RFC 5280 §5.1.2.4")
	if l.NextUpdate.IsZero() {
		cs.add(prefix+"CRL nextUpdate", "fail", "absent; CAs must include it", "RFC 5280 §5.1.2.5")
	} else {
		out["next_update"] = l.NextUpdate.UTC().Format(time.RFC3339)
		cs.ok(now.Before(l.NextUpdate.Add(ocspSkew)), prefix+"CRL fresh (before nextUpdate)", "next update "+relTime(l.NextUpdate), "RFC 5280 §6.3.3(a)")
	}

	// Scope: a delta CRL is incomplete on its own; an IDP narrows what the
	// CRL covers and, for a fetched shard, must name where it came from.
	scopeOK := true
	for _, e := range l.Extensions {
		switch {
		case e.Id.Equal(oidDeltaCRLIndicator):
			cs.add(prefix+"complete CRL", "fail", "this is a delta CRL; it only lists changes since a base CRL", "RFC 5280 §5.2.4")
			scopeOK = false
		case e.Id.Equal(oidFreshestCRL):
			cs.add(prefix+"delta CRLs", "info", "the CA also publishes delta CRLs (freshestCRL)", "RFC 5280 §5.2.6")
		case e.Id.Equal(oidIssuingDistributionPoint):
			idp, err := parseIDP(e.Value)
			if err != nil {
				cs.add(prefix+"CRL issuingDistributionPoint", "fail", err.Error(), "RFC 5280 §5.2.5")
				scopeOK = false
				continue
			}
			out["distribution_point"] = idp.URIs
			isCA := cert.BasicConstraintsValid && cert.IsCA
			switch {
			case idp.OnlyCA && !isCA, idp.OnlyUser && isCA, idp.OnlyAttr:
				cs.add(prefix+"CRL scope covers this certificate", "fail", "the CRL's issuingDistributionPoint limits it to other kinds of certificate", "RFC 5280 §6.3.3(b)(2)")
				scopeOK = false
			case idp.Indirect:
				cs.add(prefix+"CRL scope covers this certificate", "warn", "an indirect CRL; entries may belong to other issuers (not evaluated)", "RFC 5280 §5.2.5")
			case idp.SomeReasons:
				cs.add(prefix+"CRL scope covers this certificate", "warn", "covers only some revocation reasons (onlySomeReasons); other reasons are on another CRL", "RFC 5280 §5.2.5")
			}
			if fetchedFrom != "" && len(idp.URIs) > 0 && !contains(idp.URIs, fetchedFrom) {
				cs.add(prefix+"CRL distribution point matches", "fail", fmt.Sprintf("fetched from %s, but the CRL says it is %s", fetchedFrom, strings.Join(idp.URIs, ", ")), "RFC 5280 §6.3.3(b)(2)(i)")
				scopeOK = false
			}
		}
	}

	// The answer.
	for _, r := range l.RevokedCertificateEntries {
		if r.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			continue
		}
		reason := revocationReasons[r.ReasonCode]
		out["cert_status"] = "revoked"
		out["revoked_at"] = r.RevocationTime.UTC().Format(time.RFC3339)
		out["revocation_reason"] = reason
		detail := fmt.Sprintf("revoked %s (%s)", relTime(r.RevocationTime), reason)
		if r.ReasonCode == 6 {
			detail = fmt.Sprintf("on hold since %s (certificateHold): treat as revoked until released", relTime(r.RevocationTime))
		}
		cs.add(prefix+"certificate status", "fail", detail, "RFC 5280 §5.3.1")
		return out
	}
	if scopeOK {
		out["cert_status"] = "good"
		cs.add(prefix+"certificate status", "pass", fmt.Sprintf("serial %X is not on the CRL", cert.SerialNumber), "RFC 5280 §6.3.3(i)")
	} else {
		out["cert_status"] = "undetermined"
		cs.add(prefix+"certificate status", "warn", "not listed, but this CRL cannot vouch for the certificate (see above)", "RFC 5280 §6.3.3")
	}
	return out
}

// fetchCRLs downloads and checks the certificate's CRLs from http(s) and
// ldap(s) distribution points (at most two, public addresses only unless
// allowPrivate), with the delta CRL where the CA publishes one.
func fetchCRLs(c *Ctx, cs *Checks, prefix string, cert, issuer *x509.Certificate, allowPrivate bool) []M {
	var urls []string
	for _, u := range cert.CRLDistributionPoints {
		switch scheme, _, _ := strings.Cut(strings.ToLower(u), "://"); scheme {
		case "http", "https", "ldap", "ldaps":
			urls = append(urls, u)
		default:
			cs.add(prefix+"CRL distribution point", "info", "skipped "+u+" (only http, https, ldap and ldaps are fetched)", "RFC 5280 §4.2.1.13")
		}
	}
	if len(urls) == 0 {
		cs.add(prefix+"CRL distribution point named", "info", "the certificate names no CRL location; check OCSP instead", "RFC 5280 §4.2.1.13")
		return nil
	}
	if len(urls) > 2 {
		urls = urls[:2]
	}
	var out []M
	for _, u := range urls {
		b, where, err := fetchCRLBytes(c, u, allowPrivate)
		if err != nil {
			cs.add(prefix+"CRL download", "fail", err.Error(), "RFC 5280 §4.2.1.13")
			continue
		}
		cs.add(prefix+"CRL download", "pass", where, "RFC 5280 §4.2.1.13")
		l, err := parseCRLBytes(b)
		if err != nil {
			cs.add(prefix+"CRL parses", "fail", err.Error(), "RFC 5280 §5.1")
			continue
		}
		out = append(out, checkCRLWithDelta(c, cs, prefix, l, cert, issuer, u, allowPrivate))
		// One complete, valid CRL that covers the certificate answers it.
		if r := out[len(out)-1]["cert_status"]; r == "good" || r == "revoked" {
			break
		}
	}
	return out
}

func runCRL(c *Ctx) (M, error) {
	o, err := parsePKI(c.Str("cert"))
	if err != nil {
		return nil, err
	}
	if len(o.Certs) == 0 {
		return nil, errors.New("cert: no certificate found")
	}
	cert := o.Certs[0]
	candidates := o.Certs[1:]
	if s := c.Str("issuer"); s != "" {
		io, err := parsePKI(s)
		if err != nil {
			return nil, fmt.Errorf("issuer: %w", err)
		}
		candidates = append(io.Certs, candidates...)
	}
	allowPrivate := c.Bool("allow_private_urls")
	var cs Checks
	out := M{"certificate": certSummary(cert)}
	issuer, err := issuerFor(c, &cs, cert, candidates, true, allowPrivate)
	if err != nil {
		return nil, err
	}
	out["issuer"] = certSummary(issuer)
	var crls []M
	if s := c.Str("crl"); s != "" {
		l, err := parseCRLBytes([]byte(s))
		if err != nil {
			return nil, fmt.Errorf("crl: %w", err)
		}
		crls = []M{checkCRLWithDelta(c, &cs, "", l, cert, issuer, "", allowPrivate)}
		out["source"] = "supplied CRL"
	} else {
		crls = fetchCRLs(c, &cs, "", cert, issuer, allowPrivate)
		out["source"] = "downloaded"
	}
	out["crls"] = crls
	out["cert_status"] = "undetermined"
	for _, r := range crls {
		if s := r["cert_status"]; s == "good" || s == "revoked" {
			out["cert_status"] = s
		}
	}
	out["checks"] = cs
	return out, nil
}

func init() {
	register(&Op{
		Name: "pki.crl",
		Summary: "Check a certificate's revocation status against its CRL (RFC 5280): finds the issuer, downloads the CRL from the certificate's distribution points over http(s) or from a directory over ldap(s) (Active Directory Certificate Services' ldap:/// locations included), or takes a supplied one, and checks the CRL's issuer and signature, freshness, scope (issuingDistributionPoint shards: only CA or end-entity certificates, some reasons, the URL it was fetched from), then whether the serial is listed, with time and reason. " +
			"Where the CA publishes delta CRLs (freshestCRL), fetches the delta, checks that it belongs to the base CRL, and merges it: newer revocations, and certificates released from hold. " +
			"For CAs that publish no OCSP (Let's Encrypt, Google Trust Services).",
		Params: []Param{
			{Name: "cert", Type: "string", Path: true, Required: true, File: true, Desc: "Certificate (PEM or base64 DER); a PEM chain may follow it"},
			{Name: "issuer", Type: "string", Path: true, File: true, Desc: "Issuer certificate, if not in the chain or fetchable"},
			{Name: "crl", Type: "string", Path: true, File: true, Desc: "A CRL (PEM or base64 DER) to check instead of downloading"},
			{Name: "delta_crl", Type: "string", Path: true, File: true, Desc: "A delta CRL (PEM or base64 DER) to apply instead of downloading the one the CRL or certificate names (freshestCRL)"},
			{Name: "ldap_url", Type: "string", Desc: "Directory for ldap:/// CRL locations that name no host, as Active Directory Certificate Services writes them, e.g. ldaps://dc1.corp.example; default: the domain in the entry's DN"},
			{Name: "starttls", Type: "bool", Desc: "Upgrade ldap:// connections for CRLs with StartTLS"},
			{Name: "bind_dn", Type: "string", Desc: "DN to bind as to read CRLs from a directory (needs ldaps:// or starttls); omit for an anonymous bind"},
			{Name: "ldap_password", Type: "string", Secret: true, Desc: "Bind password (prefer env IDPDBG_LDAP_PASSWORD or a profile)"},
			allowPrivateURLs,
		},
		Run: runCRL,
	})
}
