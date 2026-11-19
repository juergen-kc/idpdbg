package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SPIFFE: IDs, X509-SVIDs and JWT-SVIDs checked against the specifications,
// trust bundles, and the Workload API.

func describeSPIFFEID(id spiffeid.ID) M {
	return M{"id": id.String(), "trust_domain": id.TrustDomain().Name(), "path": id.Path()}
}

// spiffeBundle is the trust material for one trust domain.
type spiffeBundle struct {
	TD       spiffeid.TrustDomain
	X509     []*x509.Certificate
	JWT      map[string]crypto.PublicKey
	Sequence any
	Refresh  any
}

// parseSPIFFEBundle reads a SPIFFE bundle (JWKS with x509-svid and jwt-svid
// keys), a plain JWKS (JWT authorities) or PEM certificates (X.509 authorities).
func parseSPIFFEBundle(td spiffeid.TrustDomain, s string) (*spiffeBundle, error) {
	b := &spiffeBundle{TD: td, JWT: map[string]crypto.PublicKey{}}
	if looksLikeJSON(s) {
		sb, err := spiffebundle.Parse(td, []byte(s))
		if err != nil {
			return nil, fmt.Errorf("not a SPIFFE bundle: %w", err)
		}
		b.X509, b.JWT = sb.X509Authorities(), sb.JWTAuthorities()
		if n, ok := sb.SequenceNumber(); ok {
			b.Sequence = n
		}
		if r, ok := sb.RefreshHint(); ok {
			b.Refresh = r.String()
		}
		return b, nil
	}
	o, err := parsePKI(s)
	if err != nil {
		return nil, err
	}
	b.X509 = o.Certs
	return b, nil
}

func (b *spiffeBundle) describe() M {
	var x []M
	for _, c := range b.X509 {
		x = append(x, M{"subject": c.Subject.String(), "not_after": c.NotAfter.UTC().Format(time.RFC3339) + " (" + relTime(c.NotAfter) + ")", "key": keyDescription(c.PublicKey)})
	}
	var kids []string
	for k := range b.JWT {
		kids = append(kids, k)
	}
	out := M{"trust_domain": b.TD.Name(), "x509_authorities": x, "jwt_authority_kids": kids}
	if b.Sequence != nil {
		out["sequence"] = b.Sequence
	}
	if b.Refresh != nil {
		out["refresh_hint"] = b.Refresh
	}
	return out
}

// checkX509SVID applies the X509-SVID rules (SPIFFE X509-SVID §4, §5).
func checkX509SVID(cs *Checks, chain []*x509.Certificate, bundle *spiffeBundle, expectedID string) M {
	const ref = "SPIFFE X509-SVID"
	out := M{}
	leaf := chain[0]
	var uris []string
	for _, u := range leaf.URIs {
		uris = append(uris, u.String())
	}
	if !cs.ok(len(uris) == 1, "leaf has exactly one URI SAN", strings.Join(uris, ", "), ref+" §2") {
		return out
	}
	id, err := spiffeid.FromString(uris[0])
	if !cs.ok(err == nil, "URI SAN is a valid SPIFFE ID", detailOr(err, uris[0]), "SPIFFE ID §2") {
		return out
	}
	out["spiffe_id"] = describeSPIFFEID(id)
	cs.ok(id.Path() != "", "leaf SPIFFE ID names a workload (has a path)", id.String(), ref+" §2")
	cs.ok(!(leaf.BasicConstraintsValid && leaf.IsCA), "leaf is not a CA", "", ref+" §4.1")
	cs.ok(leaf.KeyUsage&x509.KeyUsageDigitalSignature != 0, "leaf key usage includes digitalSignature", "", ref+" §4.3")
	cs.ok(leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) == 0, "leaf key usage excludes keyCertSign and cRLSign", "", ref+" §4.3")
	if len(leaf.ExtKeyUsage) > 0 {
		eku := stringsOf(leaf.ExtKeyUsage)
		cs.warn(contains(eku, "serverAuth") && contains(eku, "clientAuth"), "leaf extended key usage has serverAuth and clientAuth", strings.Join(eku, ", "), ref+" §4.4")
	}
	now := time.Now()
	cs.ok(now.After(leaf.NotBefore) && now.Before(leaf.NotAfter), "leaf is within its validity period", "until "+leaf.NotAfter.UTC().Format(time.RFC3339)+" ("+relTime(leaf.NotAfter)+")", "RFC 5280 §4.1.2.5")
	for _, ca := range chain[1:] {
		cs.ok(ca.BasicConstraintsValid && ca.IsCA && ca.KeyUsage&x509.KeyUsageCertSign != 0, "signing certificate "+ca.Subject.CommonName+" is a CA with keyCertSign", "", ref+" §4.1, §4.3")
	}
	if expectedID != "" {
		cs.ok(id.String() == expectedID, "SPIFFE ID is the expected one", "expected "+expectedID, "")
	}
	if bundle == nil {
		cs.add("chain verifies against the trust bundle", "warn", "no bundle supplied", ref+" §5")
		return out
	}
	cs.ok(id.TrustDomain() == bundle.TD, "SPIFFE ID is in the bundle's trust domain", id.TrustDomain().Name()+" vs "+bundle.TD.Name(), ref+" §5")
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, r := range bundle.X509 {
		roots.AddCert(r)
	}
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	cs.ok(verr == nil, "chain verifies against the trust bundle", detailOr(verr, fmt.Sprintf("%d X.509 authorities for %s", len(bundle.X509), bundle.TD.Name())), ref+" §5")
	return out
}

var jwtSVIDAlgs = map[string]bool{"RS256": true, "RS384": true, "RS512": true, "ES256": true, "ES384": true, "ES512": true, "PS256": true, "PS384": true, "PS512": true}

// checkJWTSVID applies the JWT-SVID rules (SPIFFE JWT-SVID §2, §3, §4).
func checkJWTSVID(cs *Checks, token string, bundle *spiffeBundle, audience, expectedID string) M {
	const ref = "SPIFFE JWT-SVID"
	p, err := parseJWT(token)
	if err != nil {
		cs.add("JWT-SVID is a JWS", "fail", err.Error(), ref+" §2")
		return nil
	}
	out := describeJWT(p)
	alg := str(p.Header["alg"])
	cs.ok(jwtSVIDAlgs[alg], "algorithm is an allowed asymmetric one", "alg="+alg, ref+" §2.1")
	if typ := str(p.Header["typ"]); typ != "" {
		cs.ok(typ == "JWT" || typ == "JOSE", "typ is JWT or JOSE", "typ="+typ, ref+" §2.3")
	}
	kid := str(p.Header["kid"])
	cs.ok(kid != "", "kid present", "", ref+" §2.2")
	if p.Claims == nil {
		cs.add("claims", "fail", "payload is not a JSON object", ref+" §3")
		return out
	}
	id, err := spiffeid.FromString(str(p.Claims["sub"]))
	if cs.ok(err == nil, "sub is a SPIFFE ID", detailOr(err, str(p.Claims["sub"])), ref+" §3.1") {
		out["spiffe_id"] = describeSPIFFEID(id)
		if expectedID != "" {
			cs.ok(id.String() == expectedID, "SPIFFE ID is the expected one", "expected "+expectedID, "")
		}
	}
	auds := audList(p.Claims)
	cs.ok(len(auds) > 0, "aud present", strings.Join(auds, " "), ref+" §3.2")
	if audience != "" {
		cs.ok(contains(auds, audience), "aud contains the expected audience", "aud="+strings.Join(auds, " "), ref+" §3.2")
	} else if len(auds) > 1 {
		cs.add("single audience", "warn", "several audiences widen where the token can be replayed", ref+" §3.2")
	}
	if _, ok := claimTime(p.Claims, "exp"); ok {
		timeChecks(cs, p.Claims, 30)
	} else {
		cs.add("exp present", "fail", "JWT-SVIDs must expire", ref+" §3.3")
	}
	if bundle == nil {
		cs.add("signature", "warn", "not verified: no bundle supplied", ref+" §4")
		return out
	}
	if err == nil {
		cs.ok(id.TrustDomain() == bundle.TD, "SPIFFE ID is in the bundle's trust domain", id.TrustDomain().Name(), ref+" §4")
	}
	key, ok := bundle.JWT[kid]
	if !cs.ok(ok, "kid is a JWT authority of the trust domain", "kid="+kid, ref+" §4") {
		return out
	}
	verr := verifySig(alg, key, p.SigningInput, p.Sig)
	cs.ok(verr == nil, "signature", detailOr(verr, "verified with JWT authority "+kid), ref+" §4")
	return out
}

func bundleFromParams(c *Ctx, fallbackTD string) (*spiffeBundle, error) {
	s := c.Str("bundle")
	if s == "" {
		return nil, nil
	}
	tdName := c.Str("trust_domain")
	if tdName == "" {
		tdName = fallbackTD
	}
	if tdName == "" {
		return nil, errors.New("pass trust_domain with bundle")
	}
	td, err := spiffeid.TrustDomainFromString(tdName)
	if err != nil {
		return nil, fmt.Errorf("trust_domain: %w", err)
	}
	return parseSPIFFEBundle(td, s)
}

func runSVID(c *Ctx) (M, error) {
	in := strings.TrimSpace(c.Str("svid"))
	var cs Checks
	out := M{}
	defer func() { out["checks"] = cs }()
	if looksLikeJWT(in) {
		out["type"] = "JWT-SVID"
		td := ""
		if p, err := parseJWT(in); err == nil && p.Claims != nil {
			if id, err := spiffeid.FromString(str(p.Claims["sub"])); err == nil {
				td = id.TrustDomain().Name()
			}
		}
		b, err := bundleFromParams(c, td)
		if err != nil {
			return out, err
		}
		out["jwt"] = checkJWTSVID(&cs, in, b, c.Str("audience"), c.Str("expected_id"))
		return out, nil
	}
	o, err := parsePKI(in)
	if err != nil || len(o.Certs) == 0 {
		return nil, errors.New("svid must be a PEM certificate chain (X509-SVID) or a JWT (JWT-SVID)")
	}
	out["type"] = "X509-SVID"
	td := ""
	if len(o.Certs[0].URIs) > 0 {
		if id, err := spiffeid.FromURI(o.Certs[0].URIs[0]); err == nil {
			td = id.TrustDomain().Name()
		}
	}
	b, err := bundleFromParams(c, td)
	if err != nil {
		return out, err
	}
	var chain []M
	for _, ce := range o.Certs {
		chain = append(chain, certDetail(ce))
	}
	out["chain"] = chain
	for k, v := range checkX509SVID(&cs, o.Certs, b, c.Str("expected_id")) {
		out[k] = v
	}
	return out, nil
}

func runSPIFFEBundle(c *Ctx) (M, error) {
	td, err := spiffeid.TrustDomainFromString(c.Str("trust_domain"))
	if err != nil {
		return nil, fmt.Errorf("trust_domain: %w", err)
	}
	var cs Checks
	content := c.Str("bundle")
	out := M{}
	if u := c.Str("endpoint"); u != "" {
		res, err := c.do("GET", u, map[string]string{"Accept": "application/json"}, nil)
		if err != nil {
			return nil, err
		}
		cs.ok(res.Status == 200, "bundle endpoint responds", fmt.Sprintf("HTTP %d", res.Status), "SPIFFE Trust Domain and Bundle §5")
		if res.Status != 200 {
			out["checks"] = cs
			return out, nil
		}
		content, out["endpoint"] = string(res.Body), u
	}
	if content == "" {
		return nil, errors.New("pass bundle or endpoint")
	}
	b, err := parseSPIFFEBundle(td, content)
	if !cs.ok(err == nil, "bundle parses", detailOr(err, ""), "SPIFFE Trust Domain and Bundle §4") {
		out["checks"] = cs
		return out, nil
	}
	out["bundle"] = b.describe()
	if looksLikeJSON(content) {
		var raw struct {
			Keys []M `json:"keys"`
		}
		json.Unmarshal([]byte(content), &raw)
		for i, k := range raw.Keys {
			use := str(k["use"])
			cs.ok(use == "x509-svid" || use == "jwt-svid", fmt.Sprintf("key %d has use x509-svid or jwt-svid", i+1), "use="+use, "SPIFFE Trust Domain and Bundle §4.2.1")
			if use == "jwt-svid" {
				cs.ok(str(k["kid"]) != "", fmt.Sprintf("key %d (jwt-svid) has a kid", i+1), "", "SPIFFE Trust Domain and Bundle §4.2.2")
			}
		}
		cs.warn(b.Refresh != nil, "refresh hint present", fmt.Sprint(b.Refresh), "SPIFFE Trust Domain and Bundle §4.1.2")
	}
	cs.ok(len(b.X509)+len(b.JWT) > 0, "bundle has authorities", fmt.Sprintf("%d X.509, %d JWT", len(b.X509), len(b.JWT)), "SPIFFE Trust Domain and Bundle §4")
	for _, a := range b.X509 {
		certChecks(&cs, a, "root")
	}
	out["checks"] = cs
	return out, nil
}

func runSPIFFEFetch(c *Ctx) (M, error) {
	addr := c.Str("socket")
	if addr == "" {
		addr = os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	}
	if addr == "" {
		return nil, errors.New("pass socket, or set SPIFFE_ENDPOINT_SOCKET")
	}
	if !strings.Contains(addr, "://") {
		addr = "unix://" + addr
	}
	ctx, cancel := context.WithTimeout(c, time.Duration(c.Int("timeout"))*time.Second)
	defer cancel()
	var cs Checks
	out := M{"socket": addr}
	defer func() { out["checks"] = cs }()
	x, err := workloadapi.FetchX509Context(ctx, workloadapi.WithAddr(addr))
	if !cs.ok(err == nil, "Workload API: X.509 context fetched", detailOr(err, ""), "SPIFFE Workload API §5.2") {
		return out, nil
	}
	var svids []M
	for i, s := range x.SVIDs {
		var sub Checks
		var b *spiffeBundle
		if xb, err := x.Bundles.GetX509BundleForTrustDomain(s.ID.TrustDomain()); err == nil {
			b = &spiffeBundle{TD: s.ID.TrustDomain(), X509: xb.X509Authorities()}
		}
		d := checkX509SVID(&sub, s.Certificates, b, "")
		d["hint"] = s.Hint
		d["leaf"] = certDetail(s.Certificates[0])
		for _, ck := range sub {
			ck.Name = fmt.Sprintf("SVID %d: %s", i+1, ck.Name)
			cs = append(cs, ck)
		}
		svids = append(svids, d)
	}
	out["x509_svids"] = svids
	var tds []string
	for _, b := range x.Bundles.Bundles() {
		tds = append(tds, b.TrustDomain().Name())
	}
	out["bundles_for"] = tds
	cs.ok(len(x.SVIDs) > 0, "at least one X509-SVID issued", fmt.Sprint(len(x.SVIDs)), "SPIFFE Workload API §5.2")
	if aud := c.Str("audience"); aud != "" {
		js, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: aud}, workloadapi.WithAddr(addr))
		if cs.ok(err == nil, "Workload API: JWT-SVID fetched", detailOr(err, ""), "SPIFFE Workload API §6") {
			jb, err := workloadapi.FetchJWTBundles(ctx, workloadapi.WithAddr(addr))
			var b *spiffeBundle
			if err == nil {
				if bb, err := jb.GetJWTBundleForTrustDomain(js.ID.TrustDomain()); err == nil {
					b = &spiffeBundle{TD: js.ID.TrustDomain(), JWT: bb.JWTAuthorities()}
				}
			}
			out["jwt_svid"] = checkJWTSVID(&cs, js.Marshal(), b, aud, "")
		}
	}
	return out, nil
}

func init() {
	register(
		&Op{
			Name:    "spiffe.id",
			Summary: "Validate a SPIFFE ID against the SPIFFE ID specification and show its trust domain and path.",
			Params:  []Param{{Name: "id", Type: "string", Required: true, Desc: "e.g. spiffe://example.org/ns/prod/sa/web"}},
			Run: func(c *Ctx) (M, error) {
				var cs Checks
				id, err := spiffeid.FromString(c.Str("id"))
				out := M{}
				if cs.ok(err == nil, "valid SPIFFE ID", detailOr(err, ""), "SPIFFE ID §2") {
					out = describeSPIFFEID(id)
					if id.Path() == "" {
						cs.add("names a workload", "info", "no path: this identifies the trust domain itself", "SPIFFE ID §2.2")
					}
				}
				out["checks"] = cs
				return out, nil
			},
		},
		&Op{
			Name:    "spiffe.svid",
			Summary: "Check an X509-SVID (PEM chain) or JWT-SVID against the SPIFFE specifications: one SPIFFE URI SAN, leaf and CA constraints and key usage, chain to the trust bundle; or JWT algorithm, kid, sub, audience and expiry with the signature verified against the bundle's JWT authorities.",
			Params: []Param{
				{Name: "svid", Type: "string", Required: true, File: true, Desc: "PEM certificate chain or a JWT-SVID (CLI: @file or - for stdin)"},
				{Name: "bundle", Type: "string", Path: true, Desc: "Trust bundle: SPIFFE bundle JSON, a JWKS, or PEM CA certificates"},
				{Name: "trust_domain", Type: "string", Desc: "Trust domain of the bundle; default from the SVID"},
				{Name: "audience", Type: "string", Desc: "Audience a JWT-SVID must carry"},
				{Name: "expected_id", Type: "string", Desc: "SPIFFE ID the SVID must assert"}},
			Run: runSVID,
		},
		&Op{
			Name:    "spiffe.bundle",
			Summary: "Fetch (from a bundle endpoint) or read a SPIFFE trust bundle and describe its X.509 and JWT authorities, sequence number and refresh hint; check every key's use and kid and each authority's validity.",
			Params: []Param{
				{Name: "trust_domain", Type: "string", Required: true, Desc: "Trust domain, e.g. example.org"},
				{Name: "endpoint", Type: "string", Desc: "Bundle endpoint URL (https_web profile)"},
				{Name: "bundle", Type: "string", Path: true, Desc: "Bundle content instead of an endpoint"}},
			Run: runSPIFFEBundle,
		},
		&Op{
			Name:    "spiffe.fetch",
			Summary: "Ask a SPIFFE Workload API (SPIRE agent, etc.) for this workload's X509-SVIDs and trust bundles, and optionally a JWT-SVID for an audience; check every SVID against the specifications and the bundles it came with.",
			Params: []Param{
				{Name: "socket", Type: "string", Desc: "Workload API address, e.g. unix:///run/spire/agent.sock (default env SPIFFE_ENDPOINT_SOCKET)"},
				{Name: "audience", Type: "string", Desc: "Also fetch and check a JWT-SVID for this audience"}},
			Run: runSPIFFEFetch,
		},
	)
}
