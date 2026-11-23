package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSP (RFC 6960): ask a certificate's responder whether it is revoked, or
// check a response captured elsewhere (a TLS server's stapled one, say).

var ocspStatusNames = map[ocsp.ResponseStatus]string{ocsp.Malformed: "malformedRequest", ocsp.InternalError: "internalError",
	ocsp.TryLater: "tryLater", ocsp.SignatureRequired: "sigRequired", ocsp.Unauthorized: "unauthorized"}

var revocationReasons = map[int]string{0: "unspecified", 1: "keyCompromise", 2: "cACompromise", 3: "affiliationChanged", 4: "superseded",
	5: "cessationOfOperation", 6: "certificateHold", 8: "removeFromCRL", 9: "privilegeWithdrawn", 10: "aACompromise"}

const ocspSkew = 5 * time.Minute

// queryOCSP sends a request for cert to its responder (or url) and returns
// the raw response.
// A url the caller gave is fetched as is; one taken from the certificate is
// public-only unless allowPrivate.
func queryOCSP(c *Ctx, cs *Checks, prefix string, cert, issuer *x509.Certificate, url string, hash crypto.Hash, allowPrivate bool) ([]byte, string, error) {
	fromCert := url == ""
	if url == "" {
		if len(cert.OCSPServer) == 0 {
			cs.add(prefix+"OCSP responder named", "info", "the certificate has no OCSP URL (authorityInfoAccess); check its CRL instead", "RFC 5280 §4.2.2.1")
			return nil, "", nil
		}
		url = cert.OCSPServer[0]
	}
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return nil, url, fmt.Errorf("OCSP URL %q is not http(s)", url)
	}
	req, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: hash})
	if err != nil {
		return nil, url, err
	}
	res, err := c.doPublic(allowPrivate || !fromCert, "POST", url, map[string]string{"Content-Type": "application/ocsp-request", "Accept": "application/ocsp-response"}, req)
	if err != nil {
		return nil, url, err
	}
	if !cs.ok(res.Status == 200, prefix+"OCSP responder answers", fmt.Sprintf("HTTP %d from %s", res.Status, url), "RFC 6960 §A.1") {
		return nil, url, nil
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/ocsp-response") {
		cs.add(prefix+"OCSP Content-Type", "warn", "Content-Type "+ct+", expected application/ocsp-response", "RFC 6960 §A.1")
	}
	return res.Body, url, nil
}

// checkOCSPResponse validates a response for cert, issued by issuer, and
// returns its summary. Every finding goes into cs under prefix.
func checkOCSPResponse(cs *Checks, prefix string, raw []byte, cert, issuer *x509.Certificate) M {
	out := M{}
	resp, err := ocsp.ParseResponseForCert(raw, cert, issuer)
	var re ocsp.ResponseError
	switch {
	case errors.As(err, &re):
		cs.add(prefix+"OCSP response status", "fail", ocspStatusNames[re.Status]+": the responder gave no answer for this certificate", "RFC 6960 §4.2.1")
		out["response_status"] = ocspStatusNames[re.Status]
		return out
	case err != nil:
		cs.add(prefix+"OCSP response valid", "fail", err.Error(), "RFC 6960 §3.2")
		return out
	}
	out["response_status"] = "successful"
	cs.add(prefix+"OCSP response signature", "pass", "verified with "+responderName(resp, issuer), "RFC 6960 §3.2")

	// A delegated responder must be issued by the CA for OCSP signing
	// (x/crypto/ocsp checks the issuer's signature, not the purpose).
	if rc := resp.Certificate; rc != nil && !bytes.Equal(rc.Raw, issuer.Raw) {
		out["responder"] = certSummary(rc)
		ekuOK := false
		for _, u := range rc.ExtKeyUsage {
			ekuOK = ekuOK || u == x509.ExtKeyUsageOCSPSigning
		}
		cs.ok(ekuOK, prefix+"delegated responder authorized (id-kp-OCSPSigning)", rc.Subject.String(), "RFC 6960 §4.2.2.2")
		now := time.Now()
		cs.ok(!now.Before(rc.NotBefore) && !now.After(rc.NotAfter), prefix+"delegated responder certificate valid now",
			fmt.Sprintf("%s to %s", rc.NotBefore.UTC().Format(time.RFC3339), rc.NotAfter.UTC().Format(time.RFC3339)), "RFC 6960 §4.2.2.2")
		noCheck := false
		for _, e := range rc.Extensions {
			noCheck = noCheck || e.Id.String() == "1.3.6.1.5.5.7.48.1.5"
		}
		if !noCheck {
			cs.add(prefix+"delegated responder has id-pkix-ocsp-nocheck", "info", "without it, clients may try to check the responder's own revocation status", "RFC 6960 §4.2.2.2.1")
		}
	}

	switch resp.Status {
	case ocsp.Good:
		out["cert_status"] = "good"
		cs.add(prefix+"certificate status", "pass", "good", "RFC 6960 §2.2")
	case ocsp.Revoked:
		out["cert_status"] = "revoked"
		out["revoked_at"] = resp.RevokedAt.UTC().Format(time.RFC3339)
		reason := revocationReasons[resp.RevocationReason]
		out["revocation_reason"] = reason
		cs.add(prefix+"certificate status", "fail", fmt.Sprintf("revoked %s (%s)", relTime(resp.RevokedAt), reason), "RFC 6960 §2.2")
	default:
		out["cert_status"] = "unknown"
		cs.add(prefix+"certificate status", "fail", "unknown: the responder does not know this certificate (wrong issuer or responder?)", "RFC 6960 §2.2")
	}

	now := time.Now()
	out["produced_at"] = resp.ProducedAt.UTC().Format(time.RFC3339)
	out["this_update"] = resp.ThisUpdate.UTC().Format(time.RFC3339)
	cs.ok(!resp.ThisUpdate.After(now.Add(ocspSkew)), prefix+"OCSP thisUpdate not in the future", "this update "+relTime(resp.ThisUpdate), "RFC 6960 §3.2")
	if resp.NextUpdate.IsZero() {
		cs.add(prefix+"OCSP nextUpdate", "warn", "absent: the responder claims newer information is always available, so clients cannot cache it", "RFC 6960 §4.2.2.1")
	} else {
		out["next_update"] = resp.NextUpdate.UTC().Format(time.RFC3339)
		if cs.ok(now.Before(resp.NextUpdate.Add(ocspSkew)), prefix+"OCSP response fresh (before nextUpdate)", "next update "+relTime(resp.NextUpdate), "RFC 6960 §3.2") {
			if v := resp.NextUpdate.Sub(resp.ThisUpdate); v > 10*24*time.Hour {
				cs.add(prefix+"OCSP validity interval", "warn", fmt.Sprintf("%d days; the CA/B Forum limit is 10", int(v.Hours()/24)), "CA/B Forum BR §4.9.10")
			}
		}
	}
	if resp.IssuerHash != 0 {
		out["cert_id_hash"] = resp.IssuerHash.String()
	}
	return out
}

func responderName(r *ocsp.Response, issuer *x509.Certificate) string {
	if r.Certificate == nil || bytes.Equal(r.Certificate.Raw, issuer.Raw) {
		return "the issuing CA's key (" + issuer.Subject.CommonName + ")"
	}
	return "delegated responder " + r.Certificate.Subject.CommonName
}

func certSummary(c *x509.Certificate) M {
	return M{"subject": c.Subject.String(), "issuer": c.Issuer.String(), "serial": fmt.Sprintf("%X", c.SerialNumber),
		"not_after": c.NotAfter.UTC().Format(time.RFC3339)}
}

// issuerFor finds cert's issuer among candidates or, when fetch is set,
// downloads it from the certificate's caIssuers URLs (at most two, public
// addresses only unless allowPrivate).
func issuerFor(c *Ctx, cs *Checks, cert *x509.Certificate, candidates []*x509.Certificate, fetch, allowPrivate bool) (*x509.Certificate, error) {
	for _, ic := range candidates {
		if ic != cert && cert.CheckSignatureFrom(ic) == nil {
			return ic, nil
		}
	}
	if !fetch {
		return nil, errors.New("issuer certificate not in the chain the server sent")
	}
	tried := 0
	for _, u := range cert.IssuingCertificateURL {
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		if tried++; tried > 2 {
			break
		}
		res, err := c.doPublic(allowPrivate, "GET", u, nil, nil)
		if err != nil {
			cs.add("issuer certificate fetch", "warn", err.Error(), "RFC 5280 §4.2.2.1")
			continue
		}
		if res.Status != 200 {
			continue
		}
		ic, err := parseIssuerDownload(res.Body)
		if err == nil && cert.CheckSignatureFrom(ic) == nil {
			cs.add("issuer certificate fetched", "info", "from "+u, "RFC 5280 §4.2.2.1")
			return ic, nil
		}
	}
	return nil, errors.New("issuer certificate not found: pass issuer (or the chain), or the certificate needs a caIssuers URL")
}

// parseIssuerDownload reads a caIssuers download: DER or PEM. (A PKCS#7
// bundle is not supported.)
func parseIssuerDownload(b []byte) (*x509.Certificate, error) {
	if blk, _ := pem.Decode(b); blk != nil {
		b = blk.Bytes
	}
	return x509.ParseCertificate(b)
}

var allowPrivateURLs = Param{Name: "allow_private_urls", Type: "bool", Explicit: true,
	Desc: "Let URLs that certificates or servers supply (OCSP responders, CRL locations, a provider's jwks_uri and endpoints) reach loopback, private or link-local addresses. Server-supplied URLs already may when the URL you passed points at such an address"}

func runOCSP(c *Ctx) (M, error) {
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
	var cs Checks
	out := M{"certificate": certSummary(cert)}
	allowPrivate := c.Bool("allow_private_urls")
	issuer, err := issuerFor(c, &cs, cert, candidates, true, allowPrivate)
	if err != nil {
		return nil, err
	}
	out["issuer"] = certSummary(issuer)
	hash := crypto.SHA1 // what responders universally accept for CertID
	if c.Str("hash") == "sha256" {
		hash = crypto.SHA256
	}
	var raw []byte
	if r := c.Str("response"); r != "" {
		if raw, err = base64.StdEncoding.DecodeString(strings.Join(strings.Fields(r), "")); err != nil {
			return nil, errors.New("response must be base64 DER")
		}
		out["source"] = "supplied response"
	} else {
		var url string
		raw, url, err = queryOCSP(c, &cs, "", cert, issuer, c.Str("url"), hash, allowPrivate)
		if err != nil {
			return nil, err
		}
		out["responder_url"] = url
		out["source"] = "live query"
	}
	if raw != nil {
		for k, v := range checkOCSPResponse(&cs, "", raw, cert, issuer) {
			out[k] = v
		}
	}
	out["checks"] = cs
	return out, nil
}

func init() {
	register(&Op{
		Name: "pki.ocsp",
		Summary: "Check a certificate's revocation status over OCSP (RFC 6960): finds the issuer (from the chain, issuer, or the caIssuers URL), asks the responder named in the certificate (or url), and checks the response signature, a delegated responder's authorization, the certificate status with revocation time and reason, and freshness (thisUpdate/nextUpdate). " +
			"Can instead check a captured response, such as a TLS server's stapled one.",
		Params: []Param{
			{Name: "cert", Type: "string", Path: true, Required: true, File: true, Desc: "Certificate (PEM or base64 DER); a PEM chain may follow it"},
			{Name: "issuer", Type: "string", Path: true, File: true, Desc: "Issuer certificate, if not in the chain or fetchable"},
			{Name: "url", Type: "string", Desc: "Responder URL instead of the certificate's own"},
			{Name: "response", Type: "string", File: true, Desc: "A captured OCSP response (base64 DER) to check instead of querying"},
			{Name: "hash", Type: "string", Enum: []string{"sha1", "sha256"}, Default: "sha1", Desc: "Hash for the request's CertID"},
		},
		Run: runOCSP,
	})
}
