package main

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Encoding and hashing helpers that identity debugging keeps needing.

func inputBytes(c *Ctx) ([]byte, error) {
	s := c.Str("input")
	switch c.Str("from") {
	case "hex":
		return hex.DecodeString(strings.Join(strings.Fields(strings.ReplaceAll(s, ":", "")), ""))
	case "base64":
		return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	case "base64url":
		return b64urlDecode(strings.TrimSpace(s))
	}
	return []byte(s), nil
}

func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func show(b []byte) M {
	out := M{"bytes": len(b), "hex": hex.EncodeToString(b)}
	if printable(b) {
		out["text"] = string(b)
	}
	return out
}

func deflateB64(b []byte) string {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(b)
	w.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

var hashFuncs = map[string]func() hash.Hash{
	"md5": md5.New, "sha1": sha1.New, "sha224": sha256.New224, "sha256": sha256.New, "sha384": sha512.New384,
	"sha512": sha512.New, "sha512-256": sha512.New512_256,
	"sha3-256": func() hash.Hash { return sha3.New256() }, "sha3-384": func() hash.Hash { return sha3.New384() }, "sha3-512": func() hash.Hash { return sha3.New512() },
}

func init() {
	register(
		&Op{
			Name:    "tools.encode",
			Summary: "Encode input every way identity protocols use: base64, base64url (unpadded, as in JOSE), hex, URL query escaping, and DEFLATE+base64 (SAML HTTP-Redirect).",
			Params: []Param{
				{Name: "input", Type: "string", Required: true, File: true, Desc: "Input (CLI: @file or - for stdin)"},
				{Name: "from", Type: "string", Enum: []string{"text", "hex", "base64", "base64url"}, Desc: "How the input is given", Default: "text"}},
			Run: func(c *Ctx) (M, error) {
				b, err := inputBytes(c)
				if err != nil {
					return nil, fmt.Errorf("input is not valid %s: %w", c.Str("from"), err)
				}
				return M{"bytes": len(b), "base64": base64.StdEncoding.EncodeToString(b), "base64url": b64url(b), "hex": hex.EncodeToString(b),
					"url": url.QueryEscape(string(b)), "deflate_base64": deflateB64(b)}, nil
			},
		},
		&Op{
			Name:    "tools.decode",
			Summary: "Work out what an opaque string is and decode it: URL escaping, base64 or base64url, hex, and DEFLATE (SAML Redirect) are tried in turn; JWTs, JWEs, SD-JWTs and SAML messages are recognised and pointed to the right command.",
			Params:  []Param{{Name: "input", Type: "string", Required: true, File: true, Desc: "The string to decode (CLI: @file or - for stdin)"}},
			Run: func(c *Ctx) (M, error) {
				s := strings.TrimSpace(c.Str("input"))
				out := M{}
				var found []M
				hint := func(what, cmd string) { out["looks_like"], out["use"] = what, cmd }
				switch {
				case strings.Contains(s, "~") && looksLikeJWT(strings.Split(s, "~")[0]):
					hint("SD-JWT", "sdjwt decode")
				case looksLikeJWT(s):
					hint("JWT (JWS)", "jwt decode")
				case strings.Count(s, ".") == 4 && strings.HasPrefix(s, "eyJ"):
					hint("JWE", "jwe decrypt")
				case strings.Contains(s, "SAMLRequest=") || strings.Contains(s, "SAMLResponse="):
					hint("SAML HTTP-Redirect/POST message", "saml decode")
				case strings.Contains(s, "-----BEGIN"):
					hint("PEM", "pki decode")
				}
				cur := s
				if strings.Contains(cur, "%") {
					if u, err := url.QueryUnescape(cur); err == nil && u != cur {
						found = append(found, M{"step": "URL unescape", "result": u})
						cur = u
					}
				}
				compact := strings.Join(strings.Fields(cur), "")
				var raw []byte
				if b, err := base64.StdEncoding.DecodeString(compact); err == nil && len(compact) > 0 {
					raw = b
					found = append(found, M{"step": "base64", "result": show(b)})
				} else if b, err := b64urlDecode(compact); err == nil && len(compact) > 0 {
					raw = b
					found = append(found, M{"step": "base64url", "result": show(b)})
				}
				if b, err := hex.DecodeString(strings.ReplaceAll(compact, ":", "")); err == nil && len(b) > 0 {
					found = append(found, M{"step": "hex", "result": show(b)})
				}
				if raw != nil {
					if inf, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 16<<20)); err == nil && len(inf) > 0 {
						found = append(found, M{"step": "DEFLATE (after base64)", "result": show(inf)})
						if bytes.HasPrefix(bytes.TrimSpace(inf), []byte("<")) {
							hint("SAML message (HTTP-Redirect encoding)", "saml decode")
						}
					} else if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("<")) && out["use"] == nil {
						hint("XML (SAML HTTP-POST encoding?)", "saml decode")
					}
				}
				if len(found) == 0 && out["use"] == nil {
					return nil, errors.New("no decoding applied: the input is not URL-escaped, base64, base64url or hex")
				}
				out["decodings"] = found
				return out, nil
			},
		},
		&Op{
			Name:    "tools.hash",
			Summary: "Hash input with MD5, SHA-1, SHA-2 (224/256/384/512/512-256) or SHA-3 (256/384/512), or compute an HMAC with a key; results in hex, base64 and base64url. Also the left-half hash used for at_hash/c_hash.",
			Params: []Param{
				{Name: "input", Type: "string", Required: true, File: true, Desc: "Input (CLI: @file or - for stdin)"},
				{Name: "from", Type: "string", Enum: []string{"text", "hex", "base64", "base64url"}, Desc: "How the input is given", Default: "text"},
				{Name: "algorithms", Type: "list", Desc: "md5, sha1, sha224, sha256, sha384, sha512, sha512-256, sha3-256, sha3-384, sha3-512", Default: "sha256"},
				{Name: "hmac_key", Type: "string", Secret: true, Explicit: true, Desc: "Key for an HMAC instead of a plain hash (prefer env IDPDBG_HMAC_KEY)"}},
			Run: func(c *Ctx) (M, error) {
				b, err := inputBytes(c)
				if err != nil {
					return nil, fmt.Errorf("input is not valid %s: %w", c.Str("from"), err)
				}
				var cs Checks
				results := M{}
				for _, name := range c.List("algorithms") {
					name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
					f := hashFuncs[name]
					if f == nil {
						return nil, fmt.Errorf("unknown algorithm %q", name)
					}
					var sum []byte
					if k := c.Str("hmac_key"); k != "" {
						m := hmac.New(f, []byte(k))
						m.Write(b)
						sum = m.Sum(nil)
					} else {
						h := f()
						h.Write(b)
						sum = h.Sum(nil)
					}
					results[name] = M{"hex": hex.EncodeToString(sum), "base64": base64.StdEncoding.EncodeToString(sum), "base64url": b64url(sum),
						"left_half_base64url": b64url(sum[:len(sum)/2])}
					if name == "md5" || name == "sha1" {
						cs.add(name+" collision resistance", "warn", name+" is broken for collision resistance; fine for checksums and HMAC only", "RFC 6151 / RFC 6194")
					}
				}
				out := M{"input_bytes": len(b), "hashes": results}
				if c.Str("hmac_key") != "" {
					out["mode"] = "HMAC"
				}
				if len(cs) > 0 {
					out["checks"] = cs
				}
				return out, nil
			},
		},
	)
}
