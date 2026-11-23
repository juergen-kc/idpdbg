package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Exchange is one recorded HTTP request/response pair.
type Exchange struct {
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	RequestBody     string            `json:"request_body,omitempty"`
	Status          int               `json:"status,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	ResponseBody    string            `json:"response_body,omitempty"`
	DurationMs      int64             `json:"duration_ms"`
	Error           string            `json:"error,omitempty"`
}

// Recorder is an http.RoundTripper that keeps what went over the wire.
type Recorder struct {
	mu      sync.Mutex
	Items   []*Exchange
	base    http.RoundTripper
	public  http.RoundTripper // for public-only requests: no proxy, no reuse, pinned dial
	secrets []string          // values never to appear in a recorded exchange
	// withholdResponses keeps response bodies and cookies out of the
	// exchanges recorded from now on (see withholdSigned).
	withholdResponses bool
	// serverNamed, when set, says whether a URL came from a server rather
	// than from the caller; such URLs are fetched public-only.
	serverNamed func(*url.URL) bool
}

var xmlPassword = regexp.MustCompile(`(<(?:[A-Za-z0-9_]+:)?Password\b[^>]*>)[^<]*(</)`)

// scrub removes every known secret value, and XML passwords, from s.
func (r *Recorder) scrub(s string) string {
	for _, v := range r.secrets {
		if len(v) >= 3 {
			s = strings.ReplaceAll(s, v, "<redacted>")
			if e := url.QueryEscape(v); e != v {
				s = strings.ReplaceAll(s, e, "<redacted>")
			}
		}
	}
	return xmlPassword.ReplaceAllString(s, "${1}<redacted>${2}")
}

func newRecorder(base *tls.Config) *Recorder {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = base.Clone()

	// URLs that a certificate or server supplies get their own transport. A
	// proxy would resolve the name again (DNS could then point it anywhere)
	// and a pooled connection would skip the dial check, so: no proxy, no
	// keep-alive, and every connection dialed to the address just vetted.
	pub := http.DefaultTransport.(*http.Transport).Clone()
	pub.TLSClientConfig = base.Clone()
	pub.Proxy = nil
	pub.DisableKeepAlives = true
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	pub.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := publicIPs(ctx, host)
		if err != nil {
			return nil, err
		}
		var conn net.Conn
		for _, ip := range ips { // each vetted address in turn, as a normal dial would
			if conn, err = dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port)); err == nil {
				return conn, nil
			}
		}
		return nil, err
	}
	return &Recorder{base: t, public: pub, Items: []*Exchange{}}
}

// URLs that a certificate or a server supplies (OCSP responders, caIssuers,
// a provider's jwks_uri and endpoints) are fetched public-only unless the
// caller allows otherwise, or itself pointed idpdbg at a non-public address.
type ctxKey int

const (
	publicOnlyKey ctxKey = 1
	builtinURLKey ctxKey = 2 // a URL built into idpdbg (the FIDO MDS), not one a server supplied
)

// Special-purpose ranges (IANA IPv4/IPv6 special-purpose registries) that a
// public-only request may not reach, on top of non-global-unicast space.
var nonPublic = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/96",          // IPv4-compatible (deprecated) and ::, ::1
		"64:ff9b:1::/48", // local-use NAT64
		"100::/64",       // discard
		"2001::/23",      // IETF protocol assignments, Teredo among them
		"2001:db8::/32",  // documentation
		"2002::/16",      // 6to4, which embeds an IPv4 address
		"3fff::/20",      // documentation
		"5f00::/16",      // SRv6 SIDs
		"fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
	} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// blockedIP is an allow-list in effect: only global unicast addresses
// outside the special-purpose ranges pass. IPv4 embedded in IPv6 (mapped,
// NAT64) is judged as the IPv4 address.
func blockedIP(ip net.IP) bool {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	a = a.Unmap()
	if a.Is6() && nat64.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if !a.IsGlobalUnicast() {
		return true
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func publicIPs(ctx context.Context, host string) ([]net.IP, error) {
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s does not resolve", host)
	}
	for _, ip := range ips {
		if blockedIP(ip) {
			return nil, fmt.Errorf("%s resolves to %s, a non-public address; a URL taken from a certificate or a server's answer may not reach it (allow_private_urls permits it)", host, ip)
		}
	}
	return ips, nil
}

// nonPublicHost says whether host is, or resolves to, a non-public
// address. A name that does not resolve here (behind a proxy that resolves
// it) is not counted as private.
func nonPublicHost(ctx context.Context, host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return blockedIP(ip)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if blockedIP(a.IP) {
			return true
		}
	}
	return false
}

// doPublic is c.do for a URL that came from a certificate or a server
// rather than from the caller. allow lifts the restriction.
func (c *Ctx) doPublic(allow bool, method, u string, headers map[string]string, body []byte) (*httpResult, error) {
	if allow {
		return c.do(method, u, headers, body)
	}
	pu, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	if pu.Scheme != "http" && pu.Scheme != "https" {
		return nil, fmt.Errorf("%s: only http and https URLs are fetched", u)
	}
	// The dial on the public transport checks again and pins the address;
	// this earlier check gives a clear error before any request is built.
	if _, err := publicIPs(c, pu.Hostname()); err != nil {
		return nil, err
	}
	return c.doCtx(context.WithValue(c, publicOnlyKey, true), method, u, headers, body)
}

// maxResponseBody bounds what one response may make idpdbg hold in memory;
// it is far above the largest federation metadata aggregates.
var maxResponseBody int64 = 256 << 20

// Request fields and headers that carry credentials; redacted in traces.
var secretFields = map[string]bool{"client_secret": true, "password": true, "client_assertion": true, "assertion": true,
	"refresh_token": true, "token": true, "subject_token": true, "actor_token": true,
	"code": true, "code_verifier": true, "device_code": true}

func secretHeader(name string) bool {
	n := strings.ToLower(name)
	for _, part := range []string{"auth", "cookie", "token", "secret", "key", "password", "credential"} {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}

func redactBody(contentType string, b []byte) string {
	if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		if vals, err := url.ParseQuery(string(b)); err == nil {
			for k := range vals {
				if secretFields[k] {
					vals.Set(k, "<redacted>")
				}
			}
			return vals.Encode()
		}
	}
	return string(b)
}

func flatHeaders(h http.Header, redact bool) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		val := strings.Join(v, ", ")
		if redact && secretHeader(k) {
			// Keep the scheme ("Bearer", "Basic") when there is one.
			if scheme, _, ok := strings.Cut(val, " "); ok && k == "Authorization" {
				val = scheme + " <redacted>"
			} else {
				val = "<redacted>"
			}
		}
		out[k] = val
	}
	return out
}

func (r *Recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	ex := &Exchange{Method: req.Method, URL: req.URL.String(), RequestHeaders: flatHeaders(req.Header, true)}
	if r.withholdResponses {
		// A request after a withheld answer may follow a redirect that
		// carries a session anywhere in its URL: keep only the origin.
		ex.URL = req.URL.Scheme + "://" + req.URL.Host + "/[withheld]"
	}
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(b))
		ex.RequestBody = redactBody(req.Header.Get("Content-Type"), b)
	}
	start := time.Now()
	rt := r.base
	var resp *http.Response
	var err error
	builtin := req.Context().Value(builtinURLKey) != nil
	if req.Context().Value(publicOnlyKey) != nil || (!builtin && r.serverNamed != nil && r.serverNamed(req.URL)) {
		if r.public == nil {
			return nil, errors.New("no public-only transport")
		}
		rt = r.public
	}
	resp, err = rt.RoundTrip(req)
	if err != nil && rt == r.public {
		// A proxy would resolve the name again, out of reach of the check,
		// so public-only requests never use one. Say so when one is set.
		if p, perr := http.ProxyFromEnvironment(req); perr == nil && p != nil {
			err = fmt.Errorf("%w (URLs from certificates and server answers are fetched directly, not through the HTTP proxy, so their address can be checked; allow_private_urls sends them through it)", err)
		}
	}
	ex.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		ex.Error = err.Error()
	} else {
		// Read the whole body for the caller (only the recorded copy is cut),
		// up to a bound a hostile server cannot push past: more is an error,
		// never a silent truncation.
		b, rerr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
		resp.Body.Close()
		if rerr == nil && int64(len(b)) > maxResponseBody {
			rerr = fmt.Errorf("response from %s exceeds %d MiB; refusing to read more", req.URL.Host, maxResponseBody>>20)
		}
		if rerr != nil {
			ex.Error = "reading the response body: " + rerr.Error()
			r.mu.Lock()
			r.Items = append(r.Items, ex)
			r.mu.Unlock()
			return nil, rerr
		}
		resp.Body = io.NopCloser(bytes.NewReader(b))
		ex.Status = resp.StatusCode
		ex.ResponseHeaders = flatHeaders(resp.Header, false)
		ex.ResponseBody = string(b)
		if r.withholdResponses {
			// Only the shape: any header value (Location, cookies, custom
			// token headers) or the body may hold a session.
			for k, v := range ex.ResponseHeaders {
				if mt, _, err := mime.ParseMediaType(v); strings.EqualFold(k, "Content-Type") && err == nil {
					ex.ResponseHeaders[k] = mt
				} else {
					ex.ResponseHeaders[k] = "[withheld]"
				}
			}
			if len(b) > 0 {
				ex.ResponseBody = "[withheld over MCP: answer to a real security key's response]"
			}
		}
		if len(ex.ResponseBody) > 64<<10 {
			ex.ResponseBody = ex.ResponseBody[:64<<10] + "…[truncated]"
		}
	}
	ex.URL, ex.RequestBody, ex.ResponseBody = r.scrub(ex.URL), r.scrub(ex.RequestBody), r.scrub(ex.ResponseBody)
	for k, v := range ex.RequestHeaders {
		ex.RequestHeaders[k] = r.scrub(v)
	}
	r.mu.Lock()
	r.Items = append(r.Items, ex)
	r.mu.Unlock()
	return resp, err
}

type httpResult struct {
	Status int
	Header http.Header
	Body   []byte
	JSON   any // nil when the body is not JSON
}

// obj returns the body as a JSON object, or nil.
func (r *httpResult) obj() M {
	m, _ := r.JSON.(map[string]any)
	return m
}

// payload is the parsed JSON body, or the raw text when it is not JSON.
func (r *httpResult) payload() any {
	if r.JSON != nil {
		return r.JSON
	}
	return string(r.Body)
}

// serverNamedPolicy decides which URLs came from a server: every origin the
// caller did not name (in an argument or a profile, defaults and idpdbg's
// own listeners aside), all of them when it named none. They are held to
// public addresses, so a hostile discovery document, metadata or token
// cannot point idpdbg at the network it runs in, unless the caller itself
// pointed idpdbg at a non-public address (an internal IdP, a test server on
// localhost) or allows private URLs.
func serverNamedPolicy(c *Ctx) func(*url.URL) bool {
	if c.Bool("allow_private_urls") || c.Op == nil {
		return nil
	}
	caller := map[string]bool{}
	var hosts []string
	for _, p := range c.Op.allParams() {
		if notDestinations[p.Name] {
			continue
		}
		var vals []string
		switch v := c.Args[p.Name].(type) {
		case string:
			vals = []string{v}
		case []string:
			vals = v
		}
		for _, s := range vals {
			if p.Default != nil && fmt.Sprint(p.Default) == s {
				continue
			}
			if o := targetOrigin(s); o != "" {
				caller[o] = true
				if u, err := url.Parse(strings.TrimSpace(s)); err == nil {
					hosts = append(hosts, u.Hostname())
				}
			}
		}
	}
	var once sync.Once
	callerPrivate := false
	return func(u *url.URL) bool {
		if caller[targetOrigin(u.String())] {
			return false
		}
		once.Do(func() {
			for _, h := range hosts {
				callerPrivate = callerPrivate || callerNamedPrivate(c, h)
			}
		})
		return !callerPrivate
	}
}

// callerNamedPrivate says whether a host the caller named is a non-public
// address. On the command line a name counts by what it resolves to, as the
// person typed it. Over MCP, where a model may have been steered to a name
// whose DNS its owner controls, only an address literal or a localhost name
// counts: an attacker's DNS answer must not lift the rule.
func callerNamedPrivate(c *Ctx, host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	if ip := net.ParseIP(h); ip != nil {
		return blockedIP(ip)
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	return c.CLI && nonPublicHost(c, h)
}

func (c *Ctx) client() *http.Client {
	return &http.Client{
		Transport: c.Rec,
		Timeout:   time.Duration(c.Int("timeout")) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // a debugger shows redirects, it does not follow them
		},
	}
}

func (c *Ctx) do(method, u string, headers map[string]string, body []byte) (*httpResult, error) {
	return c.doCtx(c, method, u, headers, body)
}

func (c *Ctx) doCtx(ctx context.Context, method, u string, headers map[string]string, body []byte) (*httpResult, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "idpdbg/"+version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	res := &httpResult{Status: resp.StatusCode, Header: resp.Header, Body: b}
	var v any
	if json.Unmarshal(b, &v) == nil {
		res.JSON = v
	}
	return res, nil
}

func (c *Ctx) postForm(u string, form url.Values, headers map[string]string) (*httpResult, error) {
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
	for k, v := range headers {
		h[k] = v
	}
	return c.do("POST", u, h, []byte(form.Encode()))
}

// ---- loopback listener for browser flows ----

// safeBrowserURL reports whether u may be handed to the system's URL
// opener: only http(s) URLs with a host, since other schemes launch
// arbitrary applications and these URLs often come from remote parties.
func safeBrowserURL(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "https" || p.Scheme == "http") && p.Host != "" && !strings.HasPrefix(u, "-")
}

func openBrowser(u string) error {
	if !safeBrowserURL(u) {
		return fmt.Errorf("not opening %q: only http(s) URLs are opened automatically", u)
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", u).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", u).Start()
	default:
		return exec.Command("xdg-open", u).Start()
	}
}

// serveLoopback serves mux on 127.0.0.1 and ::1 at port until stop is called.
func serveLoopback(port int, mux *http.ServeMux) (stop func(), err error) {
	return serveLoopbackTLS(port, mux, nil)
}

// serveLoopbackTLS is serveLoopback over TLS when cert is set.
func serveLoopbackTLS(port int, mux *http.ServeMux, cert *tls.Certificate) (stop func(), err error) {
	listen := func(addr string) (net.Listener, error) {
		l, err := net.Listen("tcp", addr)
		if err != nil || cert == nil {
			return l, err
		}
		return tls.NewListener(l, &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12}), nil
	}
	l4, err := listen(fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("cannot listen on port %d: %w", port, err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(l4)
	// Browsers try localhost on ::1 first. If another process already holds
	// that port, it would receive the redirect (and the code) instead of
	// idpdbg, so that is an error; a machine without IPv6 is fine.
	// Fail closed: only a machine without IPv6 may skip ::1.
	if l6, err := listen(fmt.Sprintf("[::1]:%d", port)); err == nil {
		go srv.Serve(l6)
	} else if !noIPv6(err) {
		srv.Close()
		return nil, fmt.Errorf("cannot listen on [::1]:%d (%v); the port is probably in use by another process, which would receive the browser's redirect: free it or choose another port", port, err)
	}
	// Shut down gracefully, so the page the browser is still receiving
	// (the "you can close this tab" answer) is not cut off.
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if srv.Shutdown(ctx) != nil {
			srv.Close()
		}
	}, nil
}

// noIPv6 reports whether a listen error means the machine has no IPv6
// loopback, as opposed to the port being taken. Windows reports Winsock
// error numbers, which the syscall constants do not match.
func noIPv6(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.EADDRNOTAVAIL, syscall.EAFNOSUPPORT, syscall.EPROTONOSUPPORT:
		return true
	}
	if runtime.GOOS == "windows" {
		switch errno {
		case 10047, 10049, 10043: // WSAEAFNOSUPPORT, WSAEADDRNOTAVAIL, WSAEPROTONOSUPPORT
			return true
		}
	}
	return false
}

// loopbackCert makes a throwaway self-signed certificate for localhost,
// 127.0.0.1 and ::1, for a redirect URI that must use https.
func loopbackCert() (*tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "idpdbg loopback"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, fmt.Sprintf("%X", sum[:]), nil
}

const donePage = `<!doctype html><meta charset="utf-8"><title>idpdbg</title>
<body style="font:16px system-ui;margin:3em"><h3>idpdbg captured the response.</h3><p>You can close this tab and return to the terminal.</p></body>`

// fragmentPage forwards a URL fragment (implicit / hybrid responses) to the listener.
const fragmentPage = `<!doctype html><meta charset="utf-8"><title>idpdbg</title>
<body style="font:16px system-ui;margin:3em"><p id="m">Forwarding the response…</p><script>
var m=document.getElementById('m');
if(location.hash.length>1){fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:location.hash.slice(1)})
.then(function(){m.textContent='idpdbg captured the response. You can close this tab.'})}
else{m.textContent='No response parameters were received.'}
</script></body>`

// awaitBrowser shows the person the URL, optionally opens it, and waits for
// the listener to deliver the captured parameters.
func awaitBrowser(c *Ctx, startURL string, ch <-chan url.Values) (url.Values, error) {
	c.Log("Open this URL to continue:\n  %s", startURL)
	if c.Bool("open_browser") {
		if err := openBrowser(startURL); err != nil {
			c.Log("could not open a browser (%v); open the URL manually", err)
		}
	}
	wait := time.Duration(c.Int("wait")) * time.Second
	c.Log("Waiting up to %s for the response…", wait)
	select {
	case v := <-ch:
		return v, nil
	case <-time.After(wait):
		return nil, fmt.Errorf("timed out after %s waiting for the browser response", wait)
	case <-c.Done():
		return nil, c.Err()
	}
}

var browserParams = []Param{
	{Name: "open_browser", Type: "bool", Desc: "Open the system browser automatically", Default: true},
	{Name: "wait", Type: "int", Desc: "Seconds to wait for the person to finish in the browser", Default: 180},
}
