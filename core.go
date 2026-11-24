package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"
)

// version is set at release time with -ldflags "-X main.version=v1.2.3".
// Otherwise it is the module version recorded in the binary ("go install
// module@version", or a VCS pseudo-version for a local build), else "dev".
var version = ""

func init() {
	if version != "" {
		return
	}
	version = "dev"
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		version = v
		return
	}
	var rev, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if len(rev) >= 12 {
		version = "dev-" + rev[:12] + dirty
	}
}

// M is the JSON object every operation returns.
type M = map[string]any

// Param describes one input of an operation. The CLI turns it into a flag and
// the MCP server into a JSON-schema property, so both stay in step.
type Param struct {
	Name     string
	Type     string // string | bool | int | list | json
	Desc     string
	Required bool
	Secret   bool // falls back to env IDPDBG_<NAME>; redacted in traces
	File     bool // CLI only: "@path" reads a file, "-" reads stdin
	Path     bool // value may be a file path instead of inline content (CLI or profile only)
	Explicit bool // signs or decrypts: over MCP it must be passed in the call, never taken from a profile or the environment
	Default  any
	Enum     []string
}

// Op is one debugger operation, exposed as `idpdbg <group> <name>` and as the
// MCP tool `<group>_<name>`.
type Op struct {
	Name     string // "group.name"
	Summary  string
	Params   []Param
	Mutating bool // changes state at the remote system
	Browser  bool // opens a browser and waits for a person
	Run      func(c *Ctx) (M, error)
}

var commonParams = []Param{
	{Name: "profile", Type: "string", Desc: "Named profile from ~/.config/idpdbg/config.json supplying defaults (or env IDPDBG_PROFILE)"},
	{Name: "trace", Type: "bool", Desc: "Include every HTTP request and response in the result (secrets in requests are redacted)"},
	{Name: "insecure", Type: "bool", Desc: "Skip TLS certificate verification"},
	{Name: "ca_cert", Type: "string", Path: true, Desc: "Also trust these CA certificates (PEM or base64 DER), e.g. an internal or Active Directory CA: inline, or a path from the CLI or a profile"},
	{Name: "timeout", Type: "int", Desc: "Per-request network timeout in seconds", Default: 30},
	allowPrivateURLs,
}

var registry []*Op

func register(ops ...*Op) { registry = append(registry, ops...) }

func (o *Op) group() string { g, _, _ := strings.Cut(o.Name, "."); return g }
func (o *Op) short() string { _, n, _ := strings.Cut(o.Name, "."); return n }
func (o *Op) tool() string  { return strings.ReplaceAll(o.Name, ".", "_") }

func (o *Op) allParams() []Param {
	ps := append(append([]Param{}, o.Params...), groupParams[o.group()]...)
	return append(ps, commonParams...)
}

func findOp(name string) *Op {
	name = strings.ReplaceAll(strings.ReplaceAll(name, "_", "."), "-", ".")
	for _, o := range registry {
		if strings.ReplaceAll(strings.ReplaceAll(o.Name, "_", "."), "-", ".") == name {
			return o
		}
	}
	return nil
}

// Ctx is what an operation runs with.
type Ctx struct {
	context.Context
	Op    *Op
	Args  M
	Rec   *Recorder
	TLS   *tls.Config // base TLS client configuration: insecure and ca_cert applied
	CLI   bool
	dpop  crypto.Signer                 // DPoP key for this run, created on first use
	guard *secretGuard                  // where stored credentials may go, when one is in use
	Log   func(format string, a ...any) // progress for a person (stderr / MCP log notification)
}

func (c *Ctx) Str(n string) string {
	if v, ok := c.Args[n].(string); ok {
		return v
	}
	return ""
}
func (c *Ctx) Bool(n string) bool { v, _ := c.Args[n].(bool); return v }
func (c *Ctx) Int(n string) int   { v, _ := c.Args[n].(int); return v }
func (c *Ctx) List(n string) []string {
	v, _ := c.Args[n].([]string)
	return v
}
func (c *Ctx) Has(n string) bool { _, ok := c.Args[n]; return ok }

// ---- checks ----

// Check is one spec-conformance finding attached to a result.
type Check struct {
	Name   string `json:"check"`
	Status string `json:"status"` // pass | fail | warn | info
	Detail string `json:"detail,omitempty"`
	Ref    string `json:"ref,omitempty"`
	bcp    bool   // an unmet OAuth 2.0 Security BCP recommendation: strict mode fails it
}

type Checks []Check

func (cs *Checks) add(name, status, detail, ref string) {
	*cs = append(*cs, Check{Name: name, Status: status, Detail: detail, Ref: ref})
}

// bcp records an OAuth 2.0 Security BCP (RFC 9700) requirement or
// recommendation: pass with okDetail when met, otherwise level ("warn" or
// "info") with badDetail, marked so that strict mode turns it into a failure.
func (cs *Checks) bcp(met bool, name, okDetail, badDetail, ref, level string) bool {
	if met {
		cs.add(name, "pass", okDetail, ref)
		return true
	}
	*cs = append(*cs, Check{Name: name, Status: level, Detail: badDetail, Ref: ref, bcp: true})
	return false
}

// pStrict is taken by every oidc operation.
var pStrict = Param{Name: "strict", Type: "bool", Desc: "Judge against the OAuth 2.0 Security BCP (RFC 9700): every recommendation it makes that is not met becomes a failure, so exit status 2 means the server or client setup falls short of it"}

// groupParams are taken by every operation of a group, after its own.
var groupParams = map[string][]Param{"oidc": {pStrict, pFAPI}}

// applyStrict fails every unmet BCP recommendation in res, including those in
// nested results, and returns how many it changed.
func applyStrict(v any) int {
	n := 0
	switch x := v.(type) {
	case M:
		for _, k := range sortedKeys(x) {
			if cs, ok := x[k].(Checks); ok {
				for i := range cs {
					if cs[i].bcp && cs[i].Status != "fail" && cs[i].Status != "pass" {
						cs[i].Status = "fail"
						cs[i].Detail = "strict: " + cs[i].Detail
						n++
					}
				}
				continue
			}
			n += applyStrict(x[k])
		}
	case []any:
		for _, e := range x {
			n += applyStrict(e)
		}
	case []M:
		for _, e := range x {
			n += applyStrict(e)
		}
	}
	return n
}

// ok records pass when cond holds, otherwise fail.
func (cs *Checks) ok(cond bool, name, detail, ref string) bool {
	if cond {
		cs.add(name, "pass", detail, ref)
	} else {
		cs.add(name, "fail", detail, ref)
	}
	return cond
}

// warn records pass when cond holds, otherwise warn.
func (cs *Checks) warn(cond bool, name, detail, ref string) {
	if cond {
		cs.add(name, "pass", detail, ref)
	} else {
		cs.add(name, "warn", detail, ref)
	}
}

func hasFailure(res M) bool {
	cs, _ := res["checks"].(Checks)
	for _, c := range cs {
		if c.Status == "fail" {
			return true
		}
	}
	return false
}

// ---- argument preparation ----

func coerce(p Param, v any, cli bool) (any, error) {
	bad := func() (any, error) {
		return nil, fmt.Errorf("parameter %q: expected %s, got %v", p.Name, p.Type, v)
	}
	switch p.Type {
	case "string":
		s, ok := v.(string)
		if !ok {
			if v == nil {
				return bad()
			}
			s = fmt.Sprint(v)
		}
		if cli && p.File {
			if s == "-" {
				b, err := io.ReadAll(os.Stdin)
				if err != nil {
					return nil, err
				}
				s = strings.TrimSpace(string(b))
			} else if strings.HasPrefix(s, "@") {
				b, err := os.ReadFile(s[1:])
				if err != nil {
					return nil, fmt.Errorf("parameter %q: %w", p.Name, err)
				}
				s = strings.TrimSpace(string(b))
			}
		}
		if len(p.Enum) > 0 && s != "" {
			found := false
			for _, e := range p.Enum {
				found = found || e == s
			}
			if !found {
				return nil, fmt.Errorf("parameter %q: must be one of %s", p.Name, strings.Join(p.Enum, ", "))
			}
		}
		return s, nil
	case "bool":
		switch t := v.(type) {
		case bool:
			return t, nil
		case string:
			b, err := strconv.ParseBool(t)
			if err != nil {
				return bad()
			}
			return b, nil
		}
		return bad()
	case "int":
		switch t := v.(type) {
		case int:
			return t, nil
		case float64:
			return int(t), nil
		case string:
			i, err := strconv.Atoi(t)
			if err != nil {
				return bad()
			}
			return i, nil
		}
		return bad()
	case "list":
		switch t := v.(type) {
		case []string:
			return t, nil
		case []any:
			out := make([]string, 0, len(t))
			for _, e := range t {
				out = append(out, fmt.Sprint(e))
			}
			return out, nil
		case string:
			if t == "" {
				return []string{}, nil
			}
			parts := strings.Split(t, ",")
			for i := range parts {
				parts[i] = strings.TrimSpace(parts[i])
			}
			return parts, nil
		}
		return bad()
	case "json":
		if s, ok := v.(string); ok {
			if cli && strings.HasPrefix(s, "@") {
				b, err := os.ReadFile(s[1:])
				if err != nil {
					return nil, fmt.Errorf("parameter %q: %w", p.Name, err)
				}
				s = string(b)
			}
			var out any
			if err := json.Unmarshal([]byte(s), &out); err != nil {
				return nil, fmt.Errorf("parameter %q: not valid JSON: %w", p.Name, err)
			}
			return out, nil
		}
		return v, nil
	}
	return v, nil
}

func configPath() string {
	if p := os.Getenv("IDPDBG_CONFIG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "idpdbg", "config.json")
}

func loadProfiles() (map[string]M, error) {
	b, err := os.ReadFile(configPath())
	if errors.Is(err, os.ErrNotExist) {
		return map[string]M{}, nil
	}
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Profiles map[string]M `json:"profiles"`
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", configPath(), err)
	}
	return cfg.Profiles, nil
}

// prepare resolves arguments: explicit > profile > env (secrets) > default.
// stored reports which values came from the profile or the environment, that
// is, were configured by the person rather than chosen by the caller.
func prepare(op *Op, raw M, cli bool) (args M, stored map[string]string, err error) {
	args, stored, _, err = prepareGuarded(op, raw, cli)
	return args, stored, err
}

// secretGuard remembers, for the length of a run, which origins a stored
// credential may reach, so destinations resolved later (from metadata, say)
// are held to the same rule as the ones passed in.
type secretGuard struct {
	active  bool
	secret  string
	allowed map[string]bool
}

// allowDestination refuses to send what to u when a stored credential is in
// use and u's origin is not allowed.
func (c *Ctx) allowDestination(what, u string) error {
	g := c.guard
	if g == nil || !g.active {
		return nil
	}
	o := targetOrigin(u)
	if o == "" || !g.allowed[o] {
		return fmt.Errorf("refusing to send %s to %s while the stored credential %q is in use: its origin is not named in the active profile or in IDPDBG_ALLOWED_HOSTS", what, u, g.secret)
	}
	return nil
}

func prepareGuarded(op *Op, raw M, cli bool) (M, map[string]string, *secretGuard, error) {
	args, stored, prof, err := resolveArgs(op, raw, cli)
	if err != nil {
		return nil, nil, nil, err
	}
	guard, err := guardStoredSecrets(op, args, raw, prof, stored, cli)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := resolvePaths(op, args, stored, cli); err != nil {
		return nil, nil, nil, err
	}
	return args, stored, guard, nil
}

var defaultPorts = map[string]string{"http": "80", "https": "443", "ldap": "389", "ldaps": "636", "kerberos": "88", "spire": "8081"}

// targetOrigin is the scheme://host:port of a URL-valued argument, or "".
func targetOrigin(v any) string {
	s, _ := v.(string)
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		port = defaultPorts[scheme]
	}
	if port == "" {
		return "" // not a scheme this tool connects to
	}
	return scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

// notDestinations are parameters whose values may look like URLs but are
// identifiers or this tool's own listeners, never somewhere a stored secret is
// sent. Every other string parameter is treated as a possible destination, so
// a parameter added later is guarded unless it is deliberately listed here.
var notDestinations = map[string]bool{
	"redirect_uri": true, "acs_url": true, "post_logout_redirect_uri": true,
	"scope": true, "audience": true, "resource": true, "client_id": true, "client_assertion_aud": true,
	"sp_entity_id": true, "filter": true, "username": true, "login_hint": true,
	"endpoint_url": true, "applies_to": true, "wtrealm": true, "events": true, // where others send data, or identifiers
}

// credentialParams hold private keys. They are not Secret (they carry no
// environment fallback and may be file paths), but whatever they sign is a
// credential, so when they come from a profile they are guarded like secrets.
var credentialParams = map[string]bool{"client_key": true, "mtls_key": true, "dpop_key": true, "sp_key": true, "keytab": true, "armor_keytab": true, "pkinit_key": true, "holder_key": true, "svid_key": true}

// guardStoredSecrets stops a stored secret (profile or environment) from being
// sent anywhere the caller picked. A profile's secrets only go to the exact
// origins (scheme, host and port) named in that profile or in
// IDPDBG_ALLOWED_HOSTS, so neither a downgrade from https to http nor another
// port on the same host gets through. Over MCP the same holds for environment
// secrets, and TLS verification cannot be switched off, because there the
// caller is a model whose arguments may have been steered by untrusted content.
func guardStoredSecrets(op *Op, args, raw, prof M, stored map[string]string, cli bool) (*secretGuard, error) {
	secret, fromProfile := "", false
	for _, p := range op.allParams() {
		if (p.Secret || credentialParams[p.Name]) && stored[p.Name] != "" {
			secret = p.Name
			fromProfile = fromProfile || stored[p.Name] == "profile"
		}
	}
	if secret == "" {
		return nil, nil
	}
	// An MCP caller may not weaken the transport a stored secret travels over.
	if !cli {
		if _, explicit := raw["insecure"]; explicit && args["insecure"] == true {
			return nil, fmt.Errorf("refusing insecure=true while the stored secret %q is in use: TLS verification can only be disabled from the CLI or in the profile", secret)
		}
		if _, explicit := raw["ca_cert"]; explicit {
			return nil, fmt.Errorf("refusing a caller-supplied ca_cert while the stored secret %q is in use: extra trust anchors can only be added from the CLI or in the profile", secret)
		}
		// The SPIRE server is verified against bundle and trust_domain, so
		// they are trust anchors too.
		for _, n := range []string{"bundle", "trust_domain"} {
			if _, explicit := raw[n]; explicit && op.group() == "spire" {
				return nil, fmt.Errorf("refusing a caller-supplied %s while the stored credential %q is in use: it decides which server is trusted, so it can only come from the CLI or the profile", n, secret)
			}
		}
		if _, explicit := raw["client_assertion_aud"]; explicit {
			return nil, fmt.Errorf("refusing a caller-supplied client_assertion_aud while the stored credential %q is in use: set it in the profile instead", secret)
		}
		if _, explicit := raw["starttls"]; explicit && args["starttls"] != true {
			return nil, fmt.Errorf("refusing starttls=false while the stored secret %q is in use: StartTLS can only be switched off from the CLI or in the profile", secret)
		}
	}
	if cli && !fromProfile {
		return nil, nil
	}
	allowed := map[string]bool{}
	for k, v := range prof {
		if o := targetOrigin(v); o != "" {
			allowed[o] = true
		}
		// A profile's SPIRE server is host[:port], with or without a scheme.
		if k == "server" {
			if o, _ := spireOrigin(str(v)); o != "" {
				allowed[o] = true
			}
		}
		// A profile's KDCs are host[:port] without a scheme.
		if k == "kdc" {
			kdcs, _ := coerce(Param{Name: k, Type: "list"}, v, false)
			l, _ := kdcs.([]string)
			for _, h := range l {
				if !strings.Contains(h, ":") {
					h += ":88"
				}
				if o := targetOrigin("kerberos://" + h); o != "" {
					allowed[o] = true
				}
			}
		}
	}
	// Entries are full origins (https://host:8443) or bare hosts, which mean
	// the encrypted default ports only.
	for _, h := range strings.Split(os.Getenv("IDPDBG_ALLOWED_HOSTS"), ",") {
		h = strings.TrimSpace(h)
		switch {
		case h == "":
		case strings.Contains(h, "://"):
			if o := targetOrigin(h); o != "" {
				allowed[o] = true
			}
		default:
			allowed["https://"+strings.ToLower(h)+":443"] = true
			allowed["ldaps://"+strings.ToLower(h)+":636"] = true
			allowed["kerberos://"+strings.ToLower(h)+":88"] = true
			allowed["spire://"+strings.ToLower(h)+":8081"] = true
		}
	}
	params := map[string]Param{}
	for _, p := range op.allParams() {
		params[p.Name] = p
	}
	for name := range raw {
		if notDestinations[name] {
			continue
		}
		s, isStr := args[name].(string)
		if !isStr || !strings.Contains(s, "://") {
			continue
		}
		// Anything that reads as an http(s) or ldap(s) URL is checked, whatever
		// the parameter. Only parameters that carry content (a file, inline
		// XML/PEM/JSON) may hold other text with "://" in it; the URLs inside
		// such content are checked when they are about to be used.
		o := targetOrigin(s)
		if p := params[name]; o == "" && (p.Path || p.File || p.Type == "json") {
			continue
		}
		// Fail closed: a URL this guard cannot place (unknown scheme, parse
		// error) is refused rather than waved through.
		if o == "" {
			return nil, fmt.Errorf("refusing to use the stored secret %q with %s=%v: only http, https, ldap and ldaps URLs are accepted while a stored secret is in use", secret, name, s)
		}
		if !allowed[o] {
			return nil, fmt.Errorf("refusing to use the stored secret %q with %s=%v: the origin %s is not named in the active profile or in IDPDBG_ALLOWED_HOSTS. Pass the secret explicitly, or add the origin", secret, name, s, o)
		}
	}
	return &secretGuard{active: true, secret: secret, allowed: allowed}, nil
}

func looksInline(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "<") || strings.HasPrefix(s, "{") || strings.Contains(s, "-----BEGIN") ||
		strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// looksLikePath reports whether a value is written the way file paths are.
func looksLikePath(s string) bool {
	s = strings.TrimSpace(s)
	if strings.ContainsAny(s, "\n\r") {
		return false
	}
	return strings.HasPrefix(s, "@") || strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "~") ||
		strings.HasPrefix(s, `.\`) || strings.HasPrefix(s, `..\`) || strings.HasPrefix(s, `\\`) || // Windows relative and UNC paths
		(len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/'))
}

// resolvePaths replaces file-path values of Path parameters with the file's
// contents. Only the CLI and profiles may name files; over MCP a value that
// looks like a path is refused and anything else (base64, say) is content,
// so the server cannot be used to read arbitrary local files.
func resolvePaths(op *Op, args M, stored map[string]string, cli bool) error {
	for _, p := range op.allParams() {
		s, ok := args[p.Name].(string)
		if !p.Path || !ok || looksInline(s) {
			continue
		}
		if !cli && stored[p.Name] != "profile" {
			if looksLikePath(s) {
				return fmt.Errorf("parameter %q: a file path is only accepted from the CLI or a profile; over MCP pass the content inline", p.Name)
			}
			continue
		}
		b, err := os.ReadFile(strings.TrimPrefix(s, "@"))
		if err != nil {
			if looksLikePath(s) {
				return fmt.Errorf("parameter %q: %w", p.Name, err)
			}
			continue // not a file: inline content such as base64
		}
		args[p.Name] = string(b)
	}
	return nil
}

func resolveArgs(op *Op, raw M, cli bool) (M, map[string]string, M, error) {
	params := op.allParams()
	known := map[string]Param{}
	for _, p := range params {
		known[p.Name] = p
	}
	for k := range raw {
		if _, ok := known[k]; !ok {
			return nil, nil, nil, fmt.Errorf("unknown parameter %q for %s", k, op.Name)
		}
	}
	profName, _ := raw["profile"].(string)
	if profName == "" {
		profName = os.Getenv("IDPDBG_PROFILE")
	}
	var prof M
	if profName != "" {
		all, err := loadProfiles()
		if err != nil {
			return nil, nil, nil, err
		}
		var ok bool
		if prof, ok = all[profName]; !ok {
			return nil, nil, nil, fmt.Errorf("profile %q not found in %s", profName, configPath())
		}
	}
	args := M{}
	stored := map[string]string{}
	for _, p := range params {
		source := ""
		v, ok := raw[p.Name]
		if s, isStr := v.(string); ok && isStr && s == "" && p.Type != "string" {
			ok = false
		}
		if !ok && prof != nil && (cli || !p.Explicit) {
			if v, ok = prof[p.Name]; ok {
				source = "profile"
			}
		}
		if !ok && p.Secret && (cli || !p.Explicit) {
			if e := os.Getenv("IDPDBG_" + strings.ToUpper(p.Name)); e != "" {
				v, ok, source = e, true, "env"
			}
		}
		if !ok && p.Default != nil {
			v, ok = p.Default, true
		}
		if !ok {
			if p.Required {
				return nil, nil, nil, fmt.Errorf("missing required parameter %q", p.Name)
			}
			continue
		}
		cv, err := coerce(p, v, cli)
		if err != nil {
			return nil, nil, nil, err
		}
		if s, isStr := cv.(string); isStr && s == "" {
			if p.Required {
				return nil, nil, nil, fmt.Errorf("missing required parameter %q", p.Name)
			}
			continue
		}
		args[p.Name] = cv
		if source != "" {
			stored[p.Name] = source
		}
	}
	return args, stored, prof, nil
}

// runOp prepares arguments, runs the operation and attaches the HTTP trace.
func runOp(ctx context.Context, op *Op, raw M, cli bool, log func(string, ...any)) (M, error) {
	args, _, guard, err := prepareGuarded(op, raw, cli)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = func(string, ...any) {}
	}
	c := &Ctx{Context: ctx, Op: op, Args: args, CLI: cli, Log: log, guard: guard}
	if c.TLS, err = baseTLSConfig(c.Bool("insecure"), c.Str("ca_cert")); err != nil {
		return nil, err
	}
	c.Rec = newRecorder(c.TLS)
	c.Rec.serverNamed = serverNamedPolicy(c)
	for _, p := range op.allParams() {
		if s, ok := args[p.Name].(string); ok && (p.Secret || p.Explicit) {
			c.Rec.secrets = append(c.Rec.secrets, s)
		}
	}
	if err := applyMTLS(c); err != nil {
		return nil, err
	}
	res, err := safeRun(op, c)
	if res == nil && err == nil {
		res = M{}
	}
	if res != nil && c.Bool("fapi") {
		fapiSummary(res)
	}
	if res != nil && (c.Bool("strict") || c.Bool("fapi")) {
		n := applyStrict(res)
		if cs, ok := res["checks"].(Checks); ok {
			cs.add("strict mode (RFC 9700)", map[bool]string{true: "fail", false: "pass"}[n > 0],
				fmt.Sprintf("%d recommendation(s) of the OAuth 2.0 Security BCP not met", n), "RFC 9700")
			res["checks"] = cs
		}
	}
	if res != nil && c.Bool("trace") {
		res["http_trace"] = c.Rec.Items
	}
	return res, err
}

// safeRun turns a panic in an operation into an error, so malformed input
// cannot take down a long-running MCP server.
func safeRun(op *Op, c *Ctx) (res M, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("internal error in %s: %v (please report this with the input that caused it)", op.Name, r)
		}
	}()
	return op.Run(c)
}

// ---- small helpers ----

// joinParams concatenates parameter lists into a new slice.
func joinParams(groups ...[]Param) []Param {
	var out []Param
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b64url(b)
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func relTime(t time.Time) string {
	d := time.Until(t).Round(time.Second)
	if d >= 0 {
		return "in " + d.String()
	}
	return (-d).String() + " ago"
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// inlineContent returns s when it is the expected kind of inline content.
// File paths have already been resolved (and policed) by resolvePaths, so
// nothing here touches the filesystem.
func inlineContent(s string, inline func(string) bool) ([]byte, error) {
	if inline(s) {
		return []byte(s), nil
	}
	return nil, errors.New("value is neither valid inline content nor a readable file")
}

// baseTLSConfig is where every TLS connection starts: the system roots plus
// ca_cert, or no verification at all with insecure.
func baseTLSConfig(insecure bool, caCert string) (*tls.Config, error) {
	cfg := &tls.Config{InsecureSkipVerify: insecure}
	if strings.TrimSpace(caCert) == "" {
		return cfg, nil
	}
	o, err := parsePKI(caCert)
	if err != nil || len(o.Certs) == 0 {
		return nil, fmt.Errorf("ca_cert: no certificate found (%v)", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, ca := range o.Certs {
		pool.AddCert(ca)
	}
	cfg.RootCAs = pool
	return cfg, nil
}

// tlsConfig returns a copy of the base TLS configuration to modify.
func (c *Ctx) tlsConfig() *tls.Config {
	if c.TLS == nil {
		return &tls.Config{InsecureSkipVerify: c.Bool("insecure")}
	}
	return c.TLS.Clone()
}
