package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// CRLs published in a directory (ldap:// distribution points, as Active
// Directory Certificate Services writes them by default), and delta CRLs
// (RFC 5280 §5.2.4, §5.2.6).

var oidCRLNumber = asn1.ObjectIdentifier{2, 5, 29, 20}

// ldapCRLURL is an RFC 4516 LDAP URL as used in CRL distribution points:
// ldap://host:port/dn?attributes?scope?filter. AD CS leaves the host out
// (ldap:///CN=…), meaning the client's own directory.
type ldapCRLURL struct {
	Scheme, Host, Port string
	DN, Attr, Filter   string
	Scope              int
}

func parseLDAPCRLURL(raw string) (*ldapCRLURL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ldap" && u.Scheme != "ldaps" {
		return nil, fmt.Errorf("%s is not an LDAP URL", raw)
	}
	l := &ldapCRLURL{Scheme: u.Scheme, Host: u.Hostname(), Port: u.Port(), Attr: "certificateRevocationList", Filter: "(objectClass=*)", Scope: ldap.ScopeBaseObject}
	if l.DN, err = url.PathUnescape(strings.TrimPrefix(u.EscapedPath(), "/")); err != nil {
		return nil, err
	}
	if l.DN == "" {
		return nil, fmt.Errorf("%s names no entry", raw)
	}
	q := strings.SplitN(u.RawQuery, "?", 4) // attributes ? scope ? filter ? extensions
	if len(q) > 0 && q[0] != "" {
		a, _ := url.QueryUnescape(strings.Split(q[0], ",")[0])
		l.Attr = a
	}
	if len(q) > 1 && q[1] != "" {
		switch strings.ToLower(q[1]) {
		case "base":
		case "one":
			l.Scope = ldap.ScopeSingleLevel
		case "sub":
			l.Scope = ldap.ScopeWholeSubtree
		default:
			return nil, fmt.Errorf("%s: unknown scope %q", raw, q[1])
		}
	}
	if len(q) > 2 && q[2] != "" {
		f, err := url.QueryUnescape(q[2])
		if err != nil {
			return nil, fmt.Errorf("%s: filter: %w", raw, err)
		}
		if !strings.HasPrefix(f, "(") { // RFC 4516 §2 allows a bare filter
			f = "(" + f + ")"
		}
		l.Filter = f
	}
	return l, nil
}

// domainOfDN turns the DC components of a DN into a DNS name:
// CN=…,DC=corp,DC=example → corp.example.
func domainOfDN(dn string) string {
	parsed, err := ldap.ParseDN(dn)
	if err != nil {
		return ""
	}
	var labels []string
	for _, rdn := range parsed.RDNs {
		for _, a := range rdn.Attributes {
			if strings.EqualFold(a.Type, "DC") {
				labels = append(labels, a.Value)
			}
		}
	}
	return strings.Join(labels, ".")
}

// fetchLDAPCRL reads a CRL from a directory. A URL without a host goes to
// ldap_url, or to the domain named by the DN's DC components. The host is
// held to the rules for URLs taken from certificates: public addresses
// only unless allowPrivate, and the stored-secret guard for a bind.
func fetchLDAPCRL(c *Ctx, raw string, allowPrivate bool) ([]byte, string, error) {
	l, err := parseLDAPCRLURL(raw)
	if err != nil {
		return nil, "", err
	}
	scheme, host, port := l.Scheme, l.Host, l.Port
	if host == "" {
		if lu := c.Str("ldap_url"); lu != "" {
			pu, err := url.Parse(lu)
			if err != nil || (pu.Scheme != "ldap" && pu.Scheme != "ldaps") {
				return nil, "", fmt.Errorf("ldap_url %q must be an ldap:// or ldaps:// URL", lu)
			}
			scheme, host, port = pu.Scheme, pu.Hostname(), pu.Port()
		} else if host = domainOfDN(l.DN); host == "" {
			return nil, "", fmt.Errorf("%s names no host and its DN has no DC components; pass ldap_url", raw)
		}
	}
	if port == "" {
		port = map[string]string{"ldap": "389", "ldaps": "636"}[scheme]
	}
	target := scheme + "://" + net.JoinHostPort(host, port)
	var ips []net.IP
	if allowPrivate {
		addrs, err := net.DefaultResolver.LookupIPAddr(c, host)
		if err != nil {
			return nil, target, err
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	} else if ips, err = publicIPs(c, host); err != nil {
		return nil, target, err
	}
	if len(ips) == 0 {
		return nil, target, fmt.Errorf("%s does not resolve", host)
	}
	if c.Str("bind_dn") != "" {
		if err := c.allowDestination("the LDAP bind for the CRL", target); err != nil {
			return nil, target, err
		}
	}
	// Dial the vetted address itself, so DNS cannot change it in between,
	// and verify TLS against the host name.
	cfg := c.tlsConfig()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	timeout := time.Duration(c.Int("timeout")) * time.Second
	var conn *ldap.Conn
	for _, ip := range ips {
		if conn, err = ldap.DialURL(scheme+"://"+net.JoinHostPort(ip.String(), port), ldap.DialWithTLSConfig(cfg), ldap.DialWithDialer(&net.Dialer{Timeout: timeout})); err == nil {
			break
		}
	}
	if err != nil {
		return nil, target, fmt.Errorf("connect to %s: %w", target, err)
	}
	defer conn.Close()
	conn.SetTimeout(timeout)
	if c.Bool("starttls") && scheme == "ldap" {
		if err := conn.StartTLS(cfg); err != nil {
			return nil, target, fmt.Errorf("StartTLS with %s: %w", target, err)
		}
	}
	if dn := c.Str("bind_dn"); dn != "" {
		if _, encrypted := conn.TLSConnectionState(); !encrypted {
			return nil, target, fmt.Errorf("refusing to send the bind password for the CRL over unencrypted %s; use ldaps://, starttls, or no bind_dn", target)
		}
		if err := conn.Bind(dn, c.Str("ldap_password")); err != nil {
			return nil, target, fmt.Errorf("bind as %s: %w", dn, err)
		}
	}
	attrs := []string{l.Attr}
	if !strings.Contains(l.Attr, ";") {
		attrs = append(attrs, l.Attr+";binary") // AD stores it with the binary option
	}
	res, err := conn.Search(ldap.NewSearchRequest(l.DN, l.Scope, ldap.NeverDerefAliases, 2, int(timeout.Seconds()), false, l.Filter, attrs, nil))
	if err != nil {
		return nil, target, fmt.Errorf("search %s on %s: %w", l.DN, target, err)
	}
	for _, e := range res.Entries {
		for _, a := range e.Attributes {
			if strings.EqualFold(strings.Split(a.Name, ";")[0], strings.Split(l.Attr, ";")[0]) && len(a.ByteValues) > 0 && len(a.ByteValues[0]) > 0 {
				return a.ByteValues[0], target, nil
			}
		}
	}
	return nil, target, fmt.Errorf("%s on %s has no %s value (or the bind may not read it)", l.DN, target, l.Attr)
}

// fetchCRLBytes downloads a CRL from an http(s) or ldap(s) distribution
// point and says where it came from.
func fetchCRLBytes(c *Ctx, u string, allowPrivate bool) ([]byte, string, error) {
	if strings.HasPrefix(u, "ldap://") || strings.HasPrefix(u, "ldaps://") {
		b, target, err := fetchLDAPCRL(c, u, allowPrivate)
		if err == nil {
			return b, fmt.Sprintf("LDAP %s (%d bytes)", target, len(b)), nil
		}
		return nil, "", err
	}
	res, err := c.doPublic(allowPrivate, "GET", u, nil, nil)
	if err != nil {
		return nil, "", err
	}
	if res.Status != 200 {
		return nil, "", fmt.Errorf("HTTP %d from %s", res.Status, u)
	}
	return res.Body, fmt.Sprintf("HTTP %d from %s (%d bytes)", res.Status, u, len(res.Body)), nil
}

// distributionPointURIs reads the URIs of a CRLDistributionPoints-shaped
// extension (also the syntax of freshestCRL).
func distributionPointURIs(der []byte) ([]string, error) {
	type dpName struct {
		FullName []asn1.RawValue `asn1:"optional,tag:0"`
	}
	type distPoint struct {
		DistributionPoint dpName         `asn1:"optional,tag:0"`
		Reasons           asn1.BitString `asn1:"optional,tag:1"`
		CRLIssuer         asn1.RawValue  `asn1:"optional,tag:2"`
	}
	var dps []distPoint
	if rest, err := asn1.Unmarshal(der, &dps); err != nil {
		return nil, err
	} else if len(rest) > 0 {
		return nil, errors.New("trailing data after the distribution points")
	}
	var uris []string
	for _, dp := range dps {
		for _, n := range dp.DistributionPoint.FullName {
			if n.Class == asn1.ClassContextSpecific && n.Tag == 6 {
				uris = append(uris, string(n.Bytes))
			}
		}
	}
	return uris, nil
}

// deltaURIs are where the delta CRLs for a base CRL are published: the
// base CRL's freshestCRL, else the certificate's.
func deltaURIs(base *x509.RevocationList, cert *x509.Certificate) []string {
	for _, exts := range [][]pkix.Extension{base.Extensions, cert.Extensions} {
		for _, e := range exts {
			if e.Id.Equal(oidFreshestCRL) {
				if u, err := distributionPointURIs(e.Value); err == nil && len(u) > 0 {
					return u
				}
			}
		}
	}
	return nil
}

// crlBigNumber reads an INTEGER extension value (CRL number, BaseCRLNumber).
func crlBigNumber(l *x509.RevocationList, oid asn1.ObjectIdentifier) *big.Int {
	if oid.Equal(oidCRLNumber) && l.Number != nil {
		return l.Number
	}
	for _, e := range l.Extensions {
		if e.Id.Equal(oid) {
			n := new(big.Int)
			if _, err := asn1.Unmarshal(e.Value, &n); err == nil {
				return n
			}
		}
	}
	return nil
}

// applyDelta checks a delta CRL against its base and merges the verdict
// into base's result (out): a serial on the delta is revoked, unless the
// delta removes it (removeFromCRL), which releases a certificate on hold.
func applyDelta(cs *Checks, prefix string, delta, base *x509.RevocationList, cert, issuer *x509.Certificate, out M, from string) M {
	d := M{"this_update": delta.ThisUpdate.UTC().Format(time.RFC3339), "entries": len(delta.RevokedCertificateEntries)}
	if from != "" {
		d["url"] = from
	}
	p := prefix + "delta CRL: "
	baseNum, deltaNum := crlBigNumber(base, oidCRLNumber), crlBigNumber(delta, oidCRLNumber)
	indicator := crlBigNumber(delta, oidDeltaCRLIndicator)
	if !cs.ok(indicator != nil, p+"is a delta CRL (deltaCRLIndicator)", "", "RFC 5280 §5.2.4") {
		return d
	}
	d["base_crl_number"] = indicator.String()
	if !cs.ok(bytes.Equal(delta.RawIssuer, base.RawIssuer), p+"same issuer as the base CRL", delta.Issuer.String(), "RFC 5280 §5.2.4") {
		return d
	}
	if err := delta.CheckSignatureFrom(issuer); err != nil {
		cs.add(p+"signature", "fail", err.Error(), "RFC 5280 §6.3.3(f)")
		return d
	}
	cs.add(p+"signature", "pass", "signed by "+issuer.Subject.String(), "RFC 5280 §6.3.3(f)")
	now := time.Now()
	if delta.NextUpdate.IsZero() || now.After(delta.NextUpdate.Add(ocspSkew)) {
		cs.add(p+"fresh (before nextUpdate)", "fail", "next update "+relTime(delta.NextUpdate), "RFC 5280 §6.3.3(a)")
		return d
	}
	cs.add(p+"fresh (before nextUpdate)", "pass", "next update "+relTime(delta.NextUpdate), "RFC 5280 §6.3.3(a)")
	if baseNum == nil || indicator.Cmp(baseNum) > 0 {
		cs.add(p+"applies to this base CRL", "fail", fmt.Sprintf("it needs a base CRL numbered %s or later; the base is %v", indicator, baseNum), "RFC 5280 §5.2.4")
		return d
	}
	if deltaNum == nil || deltaNum.Cmp(baseNum) <= 0 {
		cs.add(p+"newer than the base CRL", "warn", fmt.Sprintf("delta CRL number %v is not above the base's %s", deltaNum, baseNum), "RFC 5280 §5.2.4")
	} else {
		cs.add(p+"applies to this base CRL", "pass", fmt.Sprintf("base %s, delta %s", baseNum, deltaNum), "RFC 5280 §5.2.4")
	}
	for _, r := range delta.RevokedCertificateEntries {
		if r.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			continue
		}
		if r.ReasonCode == 8 { // removeFromCRL
			d["cert_status"] = "removed"
			if out["cert_status"] == "revoked" && out["revocation_reason"] == revocationReasons[6] {
				out["cert_status"] = "good"
				delete(out, "revoked_at")
				delete(out, "revocation_reason")
				cs.add(prefix+"certificate status with delta CRL", "pass", "released from hold by the delta CRL (removeFromCRL)", "RFC 5280 §5.3.1")
			} else {
				cs.add(prefix+"certificate status with delta CRL", "info", "the delta CRL removes this serial (removeFromCRL)", "RFC 5280 §5.3.1")
			}
			return d
		}
		reason := revocationReasons[r.ReasonCode]
		d["cert_status"] = "revoked"
		out["cert_status"] = "revoked"
		out["revoked_at"] = r.RevocationTime.UTC().Format(time.RFC3339)
		out["revocation_reason"] = reason
		cs.add(prefix+"certificate status with delta CRL", "fail", fmt.Sprintf("revoked %s (%s), listed on the delta CRL", relTime(r.RevocationTime), reason), "RFC 5280 §5.3.1")
		return d
	}
	if out["cert_status"] == "good" {
		cs.add(prefix+"certificate status with delta CRL", "pass", fmt.Sprintf("serial %X is on neither the base nor the delta CRL", cert.SerialNumber), "RFC 5280 §6.3.3(i)")
	}
	return d
}

// fetchAndApplyDelta finds the delta CRL for base (or takes the supplied
// one), and merges it into out.
func fetchAndApplyDelta(c *Ctx, cs *Checks, prefix string, base *x509.RevocationList, cert, issuer *x509.Certificate, out M, allowPrivate bool) {
	if s := c.Str("delta_crl"); s != "" {
		delta, err := parseCRLBytes([]byte(s))
		if err != nil {
			cs.add(prefix+"delta CRL parses", "fail", err.Error(), "RFC 5280 §5.1")
			return
		}
		out["delta_crl"] = applyDelta(cs, prefix, delta, base, cert, issuer, out, "")
		return
	}
	uris := deltaURIs(base, cert)
	if len(uris) == 0 {
		return
	}
	if len(uris) > 2 {
		uris = uris[:2]
	}
	for _, u := range uris {
		b, where, err := fetchCRLBytes(c, u, allowPrivate)
		if err != nil {
			cs.add(prefix+"delta CRL download", "warn", err.Error()+"; newer revocations may be missing", "RFC 5280 §5.2.6")
			continue
		}
		cs.add(prefix+"delta CRL download", "pass", where, "RFC 5280 §5.2.6")
		delta, err := parseCRLBytes(b)
		if err != nil {
			cs.add(prefix+"delta CRL parses", "fail", err.Error(), "RFC 5280 §5.1")
			continue
		}
		out["delta_crl"] = applyDelta(cs, prefix, delta, base, cert, issuer, out, u)
		return
	}
}

// checkCRLWithDelta checks a base CRL and, where it leaves the certificate
// good or on hold, applies the delta CRL.
func checkCRLWithDelta(c *Ctx, cs *Checks, prefix string, l *x509.RevocationList, cert, issuer *x509.Certificate, from string, allowPrivate bool) M {
	out := checkCRL(cs, prefix, l, cert, issuer, from)
	if crlBigNumber(l, oidDeltaCRLIndicator) != nil {
		return out
	}
	if out["cert_status"] == "good" || (out["cert_status"] == "revoked" && out["revocation_reason"] == revocationReasons[6]) {
		fetchAndApplyDelta(c, cs, prefix, l, cert, issuer, out, allowPrivate)
	}
	return out
}
