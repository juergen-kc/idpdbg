package main

import (
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	stdasn1 "encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// The FIDO Metadata Service (MDS3): a signed BLOB listing every published
// authenticator model with its AAGUID (or U2F attestation key IDs), its
// attestation root certificates and its certification and security status.
// Relying parties and IdPs base attestation policies on it.

const mdsURL = "https://mds3.fidoalliance.org/"

var (
	mdsRootsPEM   = []string{mdsRootR3, mdsRootR46} // the tests replace these
	mdsSignerName = "mds.fidoalliance.org"
	mdsFetchURL   = mdsURL
	mdsCachePath  = func() (string, error) {
		d, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(d, "idpdbg", "fido-mds3.jwt"), nil
	}
)

type mdsStatusReport struct {
	Status                  string `json:"status"`
	EffectiveDate           string `json:"effectiveDate"`
	CertificationDescriptor string `json:"certificationDescriptor,omitempty"`
	CertificateNumber       string `json:"certificateNumber,omitempty"`
	URL                     string `json:"url,omitempty"`
}

type mdsEntry struct {
	AAGUID                 string            `json:"aaguid"`
	AAID                   string            `json:"aaid"`
	KeyIDs                 []string          `json:"attestationCertificateKeyIdentifiers"`
	Statement              map[string]any    `json:"metadataStatement"`
	StatusReports          []mdsStatusReport `json:"statusReports"`
	TimeOfLastStatusChange string            `json:"timeOfLastStatusChange"`
}

type mdsBlob struct {
	LegalHeader string     `json:"legalHeader"`
	No          int        `json:"no"`
	NextUpdate  string     `json:"nextUpdate"`
	Entries     []mdsEntry `json:"entries"`
	chain       []*x509.Certificate
	alg         string
}

// verifyMDSBlob checks the BLOB's JWS: its x5c chain reaches a pinned root,
// the signing certificate is valid for the MDS host (a pinned root alone
// would let any certificate from that CA sign), and the signature holds.
func verifyMDSBlob(raw []byte, now time.Time) (*mdsBlob, error) {
	parts := strings.Split(strings.TrimSpace(string(raw)), ".")
	if len(parts) != 3 {
		return nil, errors.New("the metadata BLOB is not a JWS")
	}
	hb, err := b64urlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("BLOB header: %w", err)
	}
	var hdr struct {
		Alg string   `json:"alg"`
		X5c []string `json:"x5c"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, fmt.Errorf("BLOB header: %w", err)
	}
	if len(hdr.X5c) == 0 {
		return nil, errors.New("BLOB header has no x5c chain")
	}
	var certs []*x509.Certificate
	for i, s := range hdr.X5c {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d]: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("x5c[%d]: %w", i, err)
		}
		certs = append(certs, cert)
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	for _, p := range mdsRootsPEM {
		roots.AppendCertsFromPEM([]byte(p))
	}
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, DNSName: mdsSignerName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return nil, fmt.Errorf("BLOB signing certificate: %w", err)
	}
	switch hdr.Alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512":
	default:
		return nil, fmt.Errorf("BLOB signed with %q", hdr.Alg)
	}
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("BLOB signature: %w", err)
	}
	if err := verifySig(hdr.Alg, certs[0].PublicKey, parts[0]+"."+parts[1], sig); err != nil {
		return nil, fmt.Errorf("BLOB signature: %w", err)
	}
	pb, err := b64urlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("BLOB payload: %w", err)
	}
	var b mdsBlob
	if err := json.Unmarshal(pb, &b); err != nil {
		return nil, fmt.Errorf("BLOB payload: %w", err)
	}
	b.chain, b.alg = chains[0], hdr.Alg
	return &b, nil
}

func (b *mdsBlob) stale(now time.Time) bool {
	t, err := time.Parse("2006-01-02", b.NextUpdate)
	return err != nil || now.After(t.Add(24*time.Hour))
}

func fetchMDS(c *Ctx) ([]byte, string, error) {
	u := mdsFetchURL
	for hop := 0; hop < 3; hop++ {
		res, err := c.do("GET", u, nil, nil)
		if err != nil {
			return nil, u, err
		}
		if res.Status >= 300 && res.Status < 400 {
			loc, err := url.Parse(res.Header.Get("Location"))
			if err != nil || loc.Scheme != "https" || !(loc.Host == "fidoalliance.org" || strings.HasSuffix(loc.Host, ".fidoalliance.org")) {
				return nil, u, fmt.Errorf("the metadata service redirected to %q; only https on fidoalliance.org is followed", res.Header.Get("Location"))
			}
			u = loc.String()
			continue
		}
		if res.Status == 429 {
			wait := res.Header.Get("Retry-After")
			if wait == "" {
				wait = "a while"
			} else {
				wait += " seconds"
			}
			return nil, u, fmt.Errorf("HTTP 429 from %s: the metadata service limits downloads; try again in %s (once downloaded, the BLOB is cached until its next update)", u, wait)
		}
		if res.Status != 200 {
			return nil, u, fmt.Errorf("HTTP %d from %s", res.Status, u)
		}
		return res.Body, u, nil
	}
	return nil, u, errors.New("too many redirects")
}

// loadMDS returns the verified BLOB: from the cache while it is current,
// otherwise downloaded (and its signing chain checked against CRLs).
func loadMDS(c *Ctx, cs *Checks, refresh bool) (*mdsBlob, M, error) {
	info := M{}
	now := time.Now()
	path, _ := mdsCachePath()
	var blob *mdsBlob
	if !refresh && path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			if b, err := verifyMDSBlob(raw, now); err == nil && !b.stale(now) {
				blob = b
				info["source"] = "cache: " + path
			}
		}
	}
	if blob == nil {
		raw, from, err := fetchMDS(c)
		if err != nil {
			cs.add("metadata BLOB downloaded", "fail", err.Error(), "FIDO MDS3 §3.1.8")
			return nil, info, err
		}
		b, err := verifyMDSBlob(raw, now)
		if err != nil {
			cs.add("metadata BLOB signature and chain", "fail", err.Error(), "FIDO MDS3 §3.2")
			return nil, info, err
		}
		blob = b
		info["source"] = fmt.Sprintf("downloaded from %s (%d bytes)", from, len(raw))
		for i := 0; i+1 < len(b.chain); i++ {
			fetchCRLs(c, cs, "metadata signer "+b.chain[i].Subject.CommonName+": ", b.chain[i], b.chain[i+1], false)
		}
		if path != "" {
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
				tmp := path + ".tmp"
				if os.WriteFile(tmp, raw, 0o600) == nil {
					os.Rename(tmp, path)
				}
			}
		}
	}
	root := blob.chain[len(blob.chain)-1]
	cs.add("metadata BLOB signature and chain", "pass", fmt.Sprintf("%s by %s, chains to %s", blob.alg, blob.chain[0].Subject.CommonName, root.Subject.CommonName), "FIDO MDS3 §3.2")
	if blob.stale(now) {
		cs.add("metadata BLOB current", "warn", "nextUpdate "+blob.NextUpdate+" has passed", "FIDO MDS3 §3.1.6")
	} else {
		cs.add("metadata BLOB current", "pass", "BLOB no. "+fmt.Sprint(blob.No)+", next update "+blob.NextUpdate, "FIDO MDS3 §3.1.6")
	}
	info["no"], info["next_update"], info["entries"], info["legal_header"] = blob.No, blob.NextUpdate, len(blob.Entries), blob.LegalHeader
	return blob, info, nil
}

func normAAGUID(s string) string {
	s = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
	if b, err := hex.DecodeString(s); err == nil && len(b) == 16 {
		return uuidString(b)
	}
	return s
}

func (b *mdsBlob) byAAGUID(aaguid string) *mdsEntry {
	want := normAAGUID(aaguid)
	for i := range b.Entries {
		if b.Entries[i].AAGUID != "" && normAAGUID(b.Entries[i].AAGUID) == want {
			return &b.Entries[i]
		}
	}
	return nil
}

func (b *mdsBlob) byKeyID(kid string) *mdsEntry {
	kid = strings.ToLower(kid)
	for i := range b.Entries {
		for _, k := range b.Entries[i].KeyIDs {
			if strings.ToLower(k) == kid {
				return &b.Entries[i]
			}
		}
	}
	return nil
}

// attestationKeyID is how MDS names U2F authenticators: the hex SHA-1 of
// the attestation certificate's subjectPublicKey (RFC 5280 §4.2.1.2 (1)).
func attestationKeyID(cert *x509.Certificate) string {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey stdasn1.BitString
	}
	if _, err := stdasn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return ""
	}
	h := sha1.Sum(spki.PublicKey.Bytes)
	return hex.EncodeToString(h[:])
}

func (e *mdsEntry) description() string {
	if d := str(e.Statement["description"]); d != "" {
		return d
	}
	return "(no description)"
}

func (e *mdsEntry) roots() []*x509.Certificate {
	var out []*x509.Certificate
	for _, r := range anyList(e.Statement["attestationRootCertificates"]) {
		if der, err := base64.StdEncoding.DecodeString(str(r)); err == nil {
			if cert, err := x509.ParseCertificate(der); err == nil {
				out = append(out, cert)
			}
		}
	}
	return out
}

func describeMDSEntry(e *mdsEntry) M {
	out := M{"description": e.description(), "time_of_last_status_change": e.TimeOfLastStatusChange, "status_reports": e.StatusReports}
	if e.AAGUID != "" {
		out["aaguid"] = e.AAGUID
	}
	if len(e.KeyIDs) > 0 {
		out["attestation_key_ids"] = len(e.KeyIDs)
	}
	for _, k := range []string{"protocolFamily", "authenticatorVersion", "schema", "attestationTypes", "keyProtection", "matcherProtection",
		"attachmentHint", "authenticationAlgorithms", "cryptoStrength", "isKeyRestricted", "isFreshUserVerificationRequired"} {
		if v, ok := e.Statement[k]; ok {
			out[k] = v
		}
	}
	var uv []string
	seen := map[string]bool{}
	for _, combo := range anyList(e.Statement["userVerificationDetails"]) {
		var parts []string
		for _, m := range anyList(combo) {
			mm, _ := m.(map[string]any)
			parts = append(parts, str(mm["userVerificationMethod"]))
		}
		if s := strings.Join(parts, " + "); s != "" && !seen[s] {
			seen[s] = true
			uv = append(uv, s)
		}
	}
	out["user_verification"] = uv
	var roots []string
	for _, r := range e.roots() {
		roots = append(roots, r.Subject.String())
	}
	out["attestation_roots"] = roots
	return out
}

// Statuses that mean the authenticator should no longer be trusted.
var mdsBadStatus = map[string]string{
	"REVOKED":                      "FIDO revoked the certification",
	"USER_VERIFICATION_BYPASS":     "user verification can be bypassed",
	"ATTESTATION_KEY_COMPROMISE":   "the attestation key is compromised: attestations from this model prove nothing",
	"USER_KEY_REMOTE_COMPROMISE":   "user keys can be extracted remotely",
	"USER_KEY_PHYSICAL_COMPROMISE": "user keys can be extracted with physical access",
}

var mdsLevels = []string{"FIDO_CERTIFIED", "FIDO_CERTIFIED_L1", "FIDO_CERTIFIED_L1plus", "FIDO_CERTIFIED_L2", "FIDO_CERTIFIED_L2plus", "FIDO_CERTIFIED_L3", "FIDO_CERTIFIED_L3plus"}

func mdsStatusChecks(cs *Checks, e *mdsEntry) {
	reports := append([]mdsStatusReport{}, e.StatusReports...)
	sort.SliceStable(reports, func(i, j int) bool { return reports[i].EffectiveDate < reports[j].EffectiveDate })
	if len(reports) == 0 {
		cs.add("certification status", "warn", "the metadata lists no status reports", "FIDO MDS3 §3.1.3")
		return
	}
	level, number := -1, ""
	for _, r := range reports {
		for i, l := range mdsLevels {
			if r.Status == l && i > level {
				level, number = i, r.CertificateNumber
			}
		}
	}
	latest := reports[len(reports)-1]
	switch {
	case mdsBadStatus[latest.Status] != "":
		cs.add("security status", "fail", fmt.Sprintf("%s since %s: %s", latest.Status, latest.EffectiveDate, mdsBadStatus[latest.Status]), "FIDO MDS3 §3.1.4")
	default:
		bad := ""
		for _, r := range reports {
			if mdsBadStatus[r.Status] != "" {
				bad = fmt.Sprintf("%s on %s (%s); the latest status is %s", r.Status, r.EffectiveDate, mdsBadStatus[r.Status], latest.Status)
			}
		}
		if bad != "" {
			cs.add("security status", "warn", bad, "FIDO MDS3 §3.1.4")
		} else {
			cs.add("security status", "pass", "no compromise or revocation reported", "FIDO MDS3 §3.1.4")
		}
	}
	if latest.Status == "UPDATE_AVAILABLE" {
		cs.add("firmware update", "warn", "the vendor reported an update on "+latest.EffectiveDate+": "+latest.URL, "FIDO MDS3 §3.1.4")
	}
	if level >= 0 {
		d := mdsLevels[level]
		if number != "" {
			d += " (" + number + ")"
		}
		cs.add("FIDO certification", "pass", d, "FIDO MDS3 §3.1.4")
	} else {
		cs.add("FIDO certification", "info", "not FIDO certified (latest status "+latest.Status+")", "FIDO MDS3 §3.1.4")
	}
}

// mdsAttestationTrust verifies an attestation certificate chain against the
// roots the metadata lists for that model.
func mdsAttestationTrust(cs *Checks, e *mdsEntry, certs []*x509.Certificate) {
	if len(certs) == 0 {
		cs.add("attestation chains to the model's root in the FIDO metadata", "info", "no attestation certificate to check (self or no attestation)", "FIDO MDS3 §3.1.5")
		return
	}
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	rs := e.roots()
	for _, r := range rs {
		roots.AddCert(r)
	}
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if len(rs) == 0 {
		cs.add("attestation chains to the model's root in the FIDO metadata", "warn", "the metadata lists no attestation roots for this model", "FIDO MDS3 §3.1.5")
		return
	}
	chains, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	detail := ""
	if err == nil {
		detail = "via " + chains[0][len(chains[0])-1].Subject.String()
	}
	cs.ok(err == nil, "attestation chains to the model's root in the FIDO metadata", detailOr(err, detail), "FIDO MDS3 §3.1.5")
}

func attestationCerts(stmt map[any]any) []*x509.Certificate {
	var certs []*x509.Certificate
	for _, raw := range anyList(stmt["x5c"]) {
		if der, ok := raw.([]byte); ok {
			if cert, err := x509.ParseCertificate(der); err == nil {
				certs = append(certs, cert)
			}
		}
	}
	return certs
}

// mdsForAttestation looks the authenticator up (AAGUID, or for U2F the
// attestation key ID) and checks status and attestation trust.
func mdsForAttestation(c *Ctx, cs *Checks, ad *authData, certs []*x509.Certificate, attested bool) M {
	blob, info, err := loadMDS(c, cs, false)
	if err != nil {
		return M{"error": err.Error()}
	}
	out := M{"blob": info}
	var e *mdsEntry
	key := ""
	switch {
	case ad != nil && !allZero(ad.AAGUID):
		key = "AAGUID " + uuidString(ad.AAGUID)
		e = blob.byAAGUID(uuidString(ad.AAGUID))
	case len(certs) > 0:
		kid := attestationKeyID(certs[0])
		key = "attestation key ID " + kid
		e = blob.byKeyID(kid)
	default:
		cs.add("authenticator in the FIDO metadata", "info", "nothing to look up: the AAGUID is zero and there is no attestation certificate", "FIDO MDS3 §3.1")
		return out
	}
	if e == nil {
		cs.add("authenticator in the FIDO metadata", "warn", key+" is not listed: the model is not FIDO certified or its vendor publishes no metadata", "FIDO MDS3 §3.1")
		return out
	}
	cs.add("authenticator in the FIDO metadata", "pass", e.description()+" ("+key+")", "FIDO MDS3 §3.1")
	out["entry"] = describeMDSEntry(e)
	mdsStatusChecks(cs, e)
	if attested {
		mdsAttestationTrust(cs, e, certs)
	}
	return out
}

func runFIDOMetadata(c *Ctx) (M, error) {
	var cs Checks
	out := M{}
	defer func() { out["checks"] = cs }()
	blob, info, err := loadMDS(c, &cs, c.Bool("refresh"))
	out["blob"] = info
	if err != nil {
		return out, nil
	}
	var e *mdsEntry
	var certs []*x509.Certificate
	switch {
	case c.Str("aaguid") != "":
		e = blob.byAAGUID(c.Str("aaguid"))
	case c.Str("key_identifier") != "":
		e = blob.byKeyID(c.Str("key_identifier"))
	case c.Str("attestation_certificate") != "":
		cert, err := parseCertParam(c.Str("attestation_certificate"))
		if err != nil {
			return nil, fmt.Errorf("attestation_certificate: %w", err)
		}
		certs = []*x509.Certificate{cert}
		for _, x := range cert.Extensions {
			if x.Id.String() == "1.3.6.1.4.1.45724.1.1.4" {
				var v []byte
				if _, err := stdasn1.Unmarshal(x.Value, &v); err == nil && len(v) == 16 {
					e = blob.byAAGUID(uuidString(v))
				}
			}
		}
		if e == nil {
			out["attestation_key_id"] = attestationKeyID(cert)
			e = blob.byKeyID(attestationKeyID(cert))
		}
	case c.Str("search") != "":
		q := strings.ToLower(c.Str("search"))
		var hits []M
		for i := range blob.Entries {
			if en := &blob.Entries[i]; strings.Contains(strings.ToLower(en.description()), q) {
				h := M{"description": en.description()}
				if en.AAGUID != "" {
					h["aaguid"] = en.AAGUID
				}
				if len(en.StatusReports) > 0 {
					h["latest_status"] = en.StatusReports[len(en.StatusReports)-1].Status
				}
				hits = append(hits, h)
			}
		}
		sort.Slice(hits, func(i, j int) bool { return str(hits[i]["description"]) < str(hits[j]["description"]) })
		if len(hits) > 50 {
			hits = hits[:50]
		}
		out["matches"] = hits
		return out, nil
	default:
		return out, nil // just the BLOB's state
	}
	if e == nil {
		cs.add("authenticator in the FIDO metadata", "warn", "not listed: the model is not FIDO certified or its vendor publishes no metadata", "FIDO MDS3 §3.1")
		return out, nil
	}
	cs.add("authenticator in the FIDO metadata", "pass", e.description(), "FIDO MDS3 §3.1")
	out["entry"] = describeMDSEntry(e)
	mdsStatusChecks(&cs, e)
	if certs != nil {
		mdsAttestationTrust(&cs, e, certs)
	}
	return out, nil
}

func init() {
	register(&Op{
		Name: "fido.metadata",
		Summary: "Look an authenticator model up in the FIDO Metadata Service (MDS3): by AAGUID, U2F attestation key ID, attestation certificate, or a search on the description. " +
			"Reports the model, its certification level, security status (revoked, compromised attestation or user keys, UV bypass), attestation types and roots, and checks a given attestation certificate against those roots. " +
			"The BLOB (about 11 MB) is downloaded from mds3.fidoalliance.org, verified (signature, chain to the FIDO MDS root, CRLs) and cached until its next update.",
		Params: []Param{
			{Name: "aaguid", Type: "string", Desc: "AAGUID to look up (FIDO2 authenticators)"},
			{Name: "key_identifier", Type: "string", Desc: "Attestation certificate key ID, hex SHA-1 of its public key (U2F authenticators)"},
			{Name: "attestation_certificate", Type: "string", File: true, Desc: "An attestation certificate (PEM or base64 DER): looked up by its AAGUID extension or key ID, and its chain checked"},
			{Name: "search", Type: "string", Desc: "List models whose description contains this text"},
			{Name: "refresh", Type: "bool", Desc: "Download the BLOB even if the cached one is current"},
		},
		Run: runFIDOMetadata,
	})
}

// parseCertParam reads one certificate: PEM, or base64 / base64url DER.
func parseCertParam(s string) (*x509.Certificate, error) {
	if certs := parsePEMCerts([]byte(s)); len(certs) > 0 {
		return certs[0], nil
	}
	t := strings.Join(strings.Fields(s), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if der, err := enc.DecodeString(t); err == nil {
			return x509.ParseCertificate(der)
		}
	}
	return nil, errors.New("not a PEM or base64 DER certificate")
}
