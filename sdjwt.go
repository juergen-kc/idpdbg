package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"
)

// SD-JWT (RFC 9901) and SD-JWT VC: disclosures, digests, the reconstructed
// claims, issuer signature and key binding.

var sdHashes = map[string]func() hash.Hash{"sha-256": sha256.New, "sha-384": sha512.New384, "sha-512": sha512.New}

func sdDigest(alg, s string) string {
	h := sdHashes[alg]()
	h.Write([]byte(s))
	return b64url(h.Sum(nil))
}

type disclosure struct {
	Raw, Digest, Salt, Name string
	Value                   any
	ArrayElement            bool
	Path                    string
	used                    bool
}

func parseDisclosure(alg, raw string) (*disclosure, error) {
	b, err := b64urlDecode(raw)
	if err != nil {
		return nil, errors.New("not base64url")
	}
	var arr []any
	if err := json.Unmarshal(b, &arr); err != nil {
		return nil, errors.New("not a JSON array")
	}
	d := &disclosure{Raw: raw, Digest: sdDigest(alg, raw)}
	switch len(arr) {
	case 3:
		d.Name = str(arr[1])
		if _, ok := arr[1].(string); !ok {
			return nil, errors.New("the claim name is not a string")
		}
		d.Value = arr[2]
	case 2:
		d.ArrayElement, d.Value = true, arr[1]
	default:
		return nil, fmt.Errorf("a disclosure has 2 or 3 elements, this one %d", len(arr))
	}
	salt, ok := arr[0].(string)
	if !ok {
		return nil, errors.New("the salt is not a string")
	}
	d.Salt = salt
	return d, nil
}

type sdProcessor struct {
	byDigest map[string]*disclosure
	seen     map[string]bool
	decoys   int
	cs       *Checks
}

func (sp *sdProcessor) process(v any, path string) any {
	switch t := v.(type) {
	case map[string]any:
		out := M{}
		for k, val := range t {
			if k == "_sd" || k == "_sd_alg" {
				continue
			}
			out[k] = sp.process(val, path+"."+k)
		}
		digests, _ := t["_sd"].([]any)
		for _, dg := range digests {
			ds := str(dg)
			if sp.seen[ds] {
				sp.cs.add("digests are unique", "fail", "digest "+ds+" appears more than once", "RFC 9901 §7.1")
				continue
			}
			sp.seen[ds] = true
			d := sp.byDigest[ds]
			if d == nil {
				sp.decoys++
				continue
			}
			d.used, d.Path = true, strings.TrimPrefix(path+"."+d.Name, ".")
			switch {
			case d.ArrayElement:
				sp.cs.add("disclosure "+d.Digest[:8]+": shape", "fail", "an array-element disclosure is referenced from an object's _sd", "RFC 9901 §7.1")
			case d.Name == "_sd" || d.Name == "...":
				sp.cs.add("disclosure "+d.Name+": name", "fail", "the claim name may not be _sd or ...", "RFC 9901 §4.2.1")
			case out[d.Name] != nil:
				sp.cs.add("disclosure "+d.Name+": no collision", "fail", "the claim already exists in the payload", "RFC 9901 §7.1")
			default:
				out[d.Name] = sp.process(d.Value, path+"."+d.Name)
			}
		}
		return out
	case []any:
		out := []any{}
		for i, el := range t {
			if m, ok := el.(map[string]any); ok && len(m) == 1 && m["..."] != nil {
				ds := str(m["..."])
				if sp.seen[ds] {
					sp.cs.add("digests are unique", "fail", "digest "+ds+" appears more than once", "RFC 9901 §7.1")
					continue
				}
				sp.seen[ds] = true
				d := sp.byDigest[ds]
				if d == nil {
					sp.decoys++
					continue
				}
				d.used, d.Path = true, fmt.Sprintf("%s[%d]", strings.TrimPrefix(path, "."), i)
				if !d.ArrayElement {
					sp.cs.add("disclosure "+d.Name+": shape", "fail", "an object-property disclosure is referenced from an array", "RFC 9901 §7.1")
					continue
				}
				out = append(out, sp.process(d.Value, d.Path))
				continue
			}
			out = append(out, sp.process(el, fmt.Sprintf("%s[%d]", path, i)))
		}
		return out
	}
	return v
}

// issuerKeys finds the keys that may have signed an issuer JWT, from the
// operation's parameters or the issuer's published metadata.
func issuerKeys(c *Ctx, p *jwtParts, cs *Checks) (keys []M, direct any, source string, err error) {
	if s := c.Str("pem"); s != "" {
		k, err := loadPublicKeyPEM(s)
		return nil, k, "PEM key", err
	}
	if s := c.Str("jwks"); s != "" {
		var v any
		if err := json.Unmarshal([]byte(s), &v); err != nil {
			return nil, nil, "", fmt.Errorf("jwks: %w", err)
		}
		return jwksKeys(v), nil, "supplied JWKS", nil
	}
	if u := c.Str("jwks_uri"); u != "" {
		k, err := fetchJWKS(c, u)
		return k, nil, u, err
	}
	iss := c.Str("issuer")
	if iss == "" && p.Claims != nil {
		if iss = str(p.Claims["iss"]); iss != "" {
			cs.add("issuer key source", "warn", "keys were looked up from the token's own iss ("+iss+"); pass issuer to pin whom you trust", "RFC 8725 §3.8")
		}
	}
	if iss == "" {
		return nil, nil, "", nil
	}
	// SD-JWT VC issuer metadata: /.well-known/jwt-vc-issuer inserted before the path.
	if u, perr := url.Parse(iss); perr == nil && u.Host != "" {
		mu := u.Scheme + "://" + u.Host + "/.well-known/jwt-vc-issuer" + strings.TrimSuffix(u.Path, "/")
		if res, err := c.do("GET", mu, map[string]string{"Accept": "application/json"}, nil); err == nil && res.Status == 200 && res.obj() != nil {
			md := res.obj()
			if str(md["issuer"]) != iss {
				cs.add("jwt-vc-issuer metadata: issuer matches", "fail", "metadata issuer="+str(md["issuer"]), "SD-JWT VC §4")
			}
			if j, ok := md["jwks"]; ok {
				return jwksKeys(j), nil, mu, nil
			}
			if ju := str(md["jwks_uri"]); ju != "" {
				k, err := fetchJWKS(c, ju)
				return k, nil, ju, err
			}
		}
	}
	meta, _, err := fetchMeta(c, iss)
	if err != nil {
		return nil, nil, "", fmt.Errorf("no jwt-vc-issuer or OAuth metadata found for %s", iss)
	}
	k, err := fetchJWKS(c, str(meta["jwks_uri"]))
	return k, nil, str(meta["jwks_uri"]), err
}

func runSDJWT(c *Ctx) (M, error) {
	in := strings.TrimSpace(c.Str("token"))
	if !strings.Contains(in, "~") {
		return nil, errors.New("not an SD-JWT: no ~ separators (a plain JWT goes to jwt decode)")
	}
	parts := strings.Split(in, "~")
	kb := parts[len(parts)-1]
	discRaw := parts[1 : len(parts)-1]
	ip, err := parseJWT(parts[0])
	if err != nil {
		return nil, fmt.Errorf("issuer-signed JWT: %w", err)
	}
	if ip.Claims == nil {
		return nil, errors.New("the issuer-signed JWT's payload is not a JSON object")
	}
	var cs Checks
	out := M{"issuer_jwt": describeJWT(ip)}
	defer func() { out["checks"] = cs }()

	typ := str(ip.Header["typ"])
	switch typ {
	case "dc+sd-jwt", "vc+sd-jwt":
		cs.add("SD-JWT VC", "info", "typ="+typ, "SD-JWT VC §3.2.1")
		if typ == "vc+sd-jwt" {
			cs.add("typ is current", "warn", "vc+sd-jwt is the earlier media type; dc+sd-jwt replaces it", "SD-JWT VC §3.2.1")
		}
		cs.ok(str(ip.Claims["vct"]) != "", "vct present", "vct="+str(ip.Claims["vct"]), "SD-JWT VC §3.2.2.1.1")
	default:
		cs.add("typ", "info", "typ="+typ, "RFC 9901 §9.11")
	}
	alg := "sha-256"
	if a := str(ip.Claims["_sd_alg"]); a != "" {
		alg = a
	}
	if sdHashes[alg] == nil {
		cs.add("_sd_alg supported", "fail", alg, "RFC 9901 §4.1.1")
		return out, nil
	}

	// Disclosures.
	sp := &sdProcessor{byDigest: map[string]*disclosure{}, seen: map[string]bool{}, cs: &cs}
	var ds []*disclosure
	for i, raw := range discRaw {
		d, err := parseDisclosure(alg, raw)
		if err != nil {
			cs.add(fmt.Sprintf("disclosure %d: well-formed", i+1), "fail", err.Error(), "RFC 9901 §4.2")
			continue
		}
		if sp.byDigest[d.Digest] != nil {
			cs.add("disclosures are unique", "fail", "the same disclosure appears twice", "RFC 9901 §7.1")
		}
		sp.byDigest[d.Digest] = d
		ds = append(ds, d)
		bits := len(d.Salt) * 6
		if b, err := b64urlDecode(d.Salt); err == nil {
			bits = len(b) * 8
		}
		if bits < 128 {
			cs.add("disclosure salt entropy", "warn", fmt.Sprintf("a salt carries about %d bits; at least 128 are recommended", bits), "RFC 9901 §9.3")
		}
	}
	claims := sp.process(map[string]any(ip.Claims), "").(M)
	var list []M
	for _, d := range ds {
		e := M{"digest": d.Digest, "salt": d.Salt, "value": d.Value, "path": d.Path}
		if !d.ArrayElement {
			e["name"] = d.Name
		}
		list = append(list, e)
		label := d.Name
		if d.ArrayElement {
			label = "array element"
		}
		cs.ok(d.used, "disclosure "+label+": referenced by the issuer", map[bool]string{true: "at " + d.Path, false: "digest " + d.Digest + " is in no _sd array or ... element (altered, or for another credential)"}[d.used], "RFC 9901 §7.1")
	}
	out["disclosures"], out["claims"] = list, claims
	if sp.decoys > 0 {
		out["undisclosed_digests"] = sp.decoys
		cs.add("undisclosed claims", "info", fmt.Sprintf("%d digest(s) without a disclosure: withheld claims or decoys", sp.decoys), "RFC 9901 §4.2.5")
	}
	timeChecks(&cs, claims, c.Int("leeway"))

	// Issuer signature.
	keys, direct, source, kerr := issuerKeys(c, ip, &cs)
	switch {
	case kerr != nil:
		cs.add("issuer signature", "fail", kerr.Error(), "RFC 9901 §7.1")
	case direct != nil:
		verr := verifySig(str(ip.Header["alg"]), direct, ip.SigningInput, ip.Sig)
		cs.ok(verr == nil, "issuer signature", detailOr(verr, "verified with "+source), "RFC 9901 §7.1")
	case len(keys) > 0:
		used, verr := verifyWithJWKS(ip, keys)
		cs.ok(verr == nil, "issuer signature", detailOr(verr, "verified with key "+used+" from "+source), "RFC 9901 §7.1")
	default:
		if x5c, _ := ip.Header["x5c"].([]any); len(x5c) > 0 {
			der, _ := base64.StdEncoding.DecodeString(str(x5c[0]))
			if cert, err := x509.ParseCertificate(der); err == nil {
				verr := verifySig(str(ip.Header["alg"]), cert.PublicKey, ip.SigningInput, ip.Sig)
				cs.ok(verr == nil, "issuer signature (x5c)", detailOr(verr, "valid for the embedded certificate "+cert.Subject.String()+"; trust in that certificate is not established"), "SD-JWT VC §3.5")
				break
			}
		}
		cs.add("issuer signature", "warn", "not verified: pass issuer, jwks_uri, jwks or pem", "RFC 9901 §7.1")
	}

	// Key binding.
	cnf, _ := ip.Claims["cnf"].(map[string]any)
	if kb == "" {
		if cnf != nil {
			cs.add("key binding JWT present", "warn", "the credential is holder-bound (cnf) but this presentation carries no KB-JWT", "RFC 9901 §7.3")
		}
		return out, nil
	}
	kp, err := parseJWT(kb)
	if err != nil {
		cs.add("KB-JWT well-formed", "fail", err.Error(), "RFC 9901 §4.3")
		return out, nil
	}
	out["key_binding"] = describeJWT(kp)
	cs.ok(str(kp.Header["typ"]) == "kb+jwt", "KB-JWT typ is kb+jwt", "typ="+str(kp.Header["typ"]), "RFC 9901 §4.3")
	if jwk, _ := cnf["jwk"].(map[string]any); jwk != nil {
		pub, err := jwkPublicKey(jwk)
		if err == nil {
			err = verifySig(str(kp.Header["alg"]), pub, kp.SigningInput, kp.Sig)
		}
		cs.ok(err == nil, "KB-JWT signed by the holder key in cnf.jwk", detailOr(err, ""), "RFC 9901 §7.3")
	} else {
		cs.add("KB-JWT signature", "warn", "the issuer JWT has no cnf.jwk to check it against", "RFC 9901 §7.3")
	}
	if kp.Claims != nil {
		cs.ok(str(kp.Claims["sd_hash"]) == sdDigest(alg, in[:len(in)-len(kb)]), "KB-JWT sd_hash covers this presentation", "", "RFC 9901 §4.3.1")
		if iat, ok := claimTime(kp.Claims, "iat"); ok {
			age := time.Since(iat)
			max := time.Duration(c.Int("max_kb_age")) * time.Second
			cs.ok(age > -time.Duration(c.Int("leeway"))*time.Second && age < max, "KB-JWT iat is recent", "issued "+relTime(iat), "RFC 9901 §7.3")
		} else {
			cs.add("KB-JWT iat present", "fail", "", "RFC 9901 §4.3")
		}
		if a := c.Str("expected_aud"); a != "" {
			cs.ok(contains(audList(kp.Claims), a), "KB-JWT aud is the verifier", "aud="+strings.Join(audList(kp.Claims), " "), "RFC 9901 §7.3")
		}
		if n := c.Str("expected_nonce"); n != "" {
			cs.ok(str(kp.Claims["nonce"]) == n, "KB-JWT nonce matches", "nonce="+str(kp.Claims["nonce"]), "RFC 9901 §7.3")
		}
	}
	return out, nil
}

func init() {
	register(&Op{
		Name:    "sdjwt.decode",
		Summary: "Decode and check an SD-JWT or SD-JWT VC presentation (RFC 9901): every disclosure with its digest and where it lands, the reconstructed claims, undisclosed digests, the issuer signature (keys from jwt-vc-issuer or OAuth metadata, a JWKS, a PEM key, or x5c), and the key binding JWT (holder signature, sd_hash, nonce, audience, freshness).",
		Params: []Param{
			{Name: "token", Type: "string", Required: true, File: true, Desc: "The SD-JWT: issuer JWT~disclosure~…~[KB-JWT] (CLI: @file or - for stdin)"},
			{Name: "issuer", Type: "string", Desc: "Trusted issuer; keys come from its /.well-known/jwt-vc-issuer or OAuth metadata"},
			{Name: "jwks_uri", Type: "string", Desc: "Issuer JWKS URL"},
			{Name: "jwks", Type: "string", Path: true, Desc: "Issuer JWKS, inline JSON or a path"},
			{Name: "pem", Type: "string", Path: true, Desc: "Issuer public key or certificate (PEM)"},
			{Name: "expected_aud", Type: "string", Desc: "Verifier identifier the KB-JWT aud must contain"},
			{Name: "expected_nonce", Type: "string", Desc: "Nonce the KB-JWT must carry"},
			{Name: "max_kb_age", Type: "int", Desc: "Oldest acceptable KB-JWT, in seconds", Default: 300},
			{Name: "leeway", Type: "int", Desc: "Clock skew allowance in seconds", Default: 60}},
		Run: runSDJWT,
	})
}
