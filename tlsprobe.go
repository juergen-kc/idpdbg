package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// A TLS client that reports what the server does rather than just whether
// the connection worked.

type probeTarget struct {
	Host, Port, StartTLS string
}

func parseProbeTarget(c *Ctx) (*probeTarget, error) {
	t := &probeTarget{StartTLS: c.Str("starttls"), Port: strconv.Itoa(c.Int("port"))}
	h := strings.TrimSpace(c.Str("host"))
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err != nil {
			return nil, err
		}
		h = u.Host
		if u.Port() == "" {
			switch u.Scheme {
			case "https":
				h += ":443"
			case "ldaps":
				h += ":636"
			case "ldap":
				h += ":389"
				if t.StartTLS == "" || t.StartTLS == "none" {
					t.StartTLS = "ldap"
				}
			case "smtp":
				h += ":587"
				if t.StartTLS == "" || t.StartTLS == "none" {
					t.StartTLS = "smtp"
				}
			}
		}
	}
	if host, port, err := net.SplitHostPort(h); err == nil {
		t.Host, t.Port = host, port
	} else {
		t.Host = strings.Trim(h, "[]")
	}
	if t.Host == "" {
		return nil, errors.New("host is empty")
	}
	if t.StartTLS == "" {
		t.StartTLS = "none"
	}
	return t, nil
}

type clientCertRequest struct {
	Requested     bool
	AcceptableCAs []string
	Sent          bool
}

func distinguishedName(der []byte) string {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdn); err != nil {
		return fmt.Sprintf("(unparseable name, %d bytes)", len(der))
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdn)
	return n.String()
}

// handshake opens the connection the target asks for and completes TLS.
func handshake(c *Ctx, t *probeTarget, cfg *tls.Config) (tls.ConnectionState, func(), error) {
	addr := net.JoinHostPort(t.Host, t.Port)
	timeout := time.Duration(c.Int("timeout")) * time.Second
	switch t.StartTLS {
	case "ldap":
		conn, err := ldap.DialURL("ldap://"+addr, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
		if err != nil {
			return tls.ConnectionState{}, nil, err
		}
		if err := conn.StartTLS(cfg); err != nil {
			conn.Close()
			return tls.ConnectionState{}, nil, fmt.Errorf("LDAP StartTLS: %w", err)
		}
		st, _ := conn.TLSConnectionState()
		return st, func() { conn.Close() }, nil
	case "smtp":
		raw, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return tls.ConnectionState{}, nil, err
		}
		raw.SetDeadline(time.Now().Add(timeout))
		sc, err := smtp.NewClient(raw, t.Host)
		if err != nil {
			raw.Close()
			return tls.ConnectionState{}, nil, err
		}
		if ok, _ := sc.Extension("STARTTLS"); !ok {
			sc.Close()
			return tls.ConnectionState{}, nil, errors.New("the SMTP server does not offer STARTTLS")
		}
		if err := sc.StartTLS(cfg); err != nil {
			sc.Close()
			return tls.ConnectionState{}, nil, fmt.Errorf("SMTP STARTTLS: %w", err)
		}
		st, _ := sc.TLSConnectionState()
		return st, func() { sc.Close() }, nil
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, cfg)
	if err != nil {
		return tls.ConnectionState{}, nil, err
	}
	// In TLS 1.3 a server that rejects the client certificate says so only
	// after the client's handshake has finished; a short read surfaces it.
	conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	one := make([]byte, 1)
	if _, rerr := conn.Read(one); rerr != nil {
		var ne net.Error
		if !(errors.As(rerr, &ne) && ne.Timeout()) && !strings.Contains(rerr.Error(), "EOF") {
			conn.Close()
			return conn.ConnectionState(), nil, fmt.Errorf("the server closed the connection after the handshake: %w", rerr)
		}
	}
	return conn.ConnectionState(), func() { conn.Close() }, nil
}

var tlsVersions = []struct {
	v    uint16
	name string
}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}, {tls.VersionTLS12, "TLS 1.2"}, {tls.VersionTLS13, "TLS 1.3"}}

func runTLSProbe(c *Ctx) (M, error) {
	t, err := parseProbeTarget(c)
	if err != nil {
		return nil, err
	}
	if c.Str("mtls_cert") != "" {
		if err := c.allowDestination("the client certificate", "https://"+net.JoinHostPort(t.Host, t.Port)); err != nil {
			return nil, err
		}
	}
	sni := c.Str("sni")
	if sni == "" && net.ParseIP(t.Host) == nil {
		sni = t.Host
	}
	var clientCert *tls.Certificate
	if c.Str("mtls_cert") != "" {
		pair, err := tls.X509KeyPair([]byte(c.Str("mtls_cert")), []byte(c.Str("mtls_key")))
		if err != nil {
			return nil, fmt.Errorf("mtls_cert/mtls_key: %w", err)
		}
		clientCert = &pair
	}
	req := &clientCertRequest{}
	cfg := &tls.Config{
		ServerName: sni, InsecureSkipVerify: true, NextProtos: c.List("alpn"), MinVersion: tls.VersionTLS10,
		GetClientCertificate: func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			req.Requested = true
			for _, ca := range info.AcceptableCAs {
				req.AcceptableCAs = append(req.AcceptableCAs, distinguishedName(ca))
			}
			if clientCert != nil {
				req.Sent = true
				return clientCert, nil
			}
			return &tls.Certificate{}, nil
		},
	}
	var cs Checks
	out := M{"target": net.JoinHostPort(t.Host, t.Port), "sni": sni, "starttls": t.StartTLS}
	defer func() {
		if req.Requested {
			out["client_certificate_request"] = M{"acceptable_cas": req.AcceptableCAs, "certificate_sent": req.Sent}
		}
		out["checks"] = cs
	}()

	start := time.Now()
	st, closeFn, herr := handshake(c, t, cfg)
	if closeFn != nil {
		defer closeFn()
	}
	out["handshake_ms"] = time.Since(start).Milliseconds()
	if req.Requested {
		detail := "acceptable CAs: " + strings.Join(req.AcceptableCAs, "; ")
		if len(req.AcceptableCAs) == 0 {
			detail = "the server named no acceptable CAs"
		}
		if !req.Sent {
			detail = "no client certificate was sent (pass mtls_cert/mtls_key); " + detail
		}
		cs.add("server requested a client certificate", "info", detail, "RFC 8446 §4.3.2")
	}
	if !cs.ok(herr == nil, "handshake", detailOr(herr, "completed"), "RFC 8446 §4") {
		if msg := herr.Error(); !req.Requested && (strings.Contains(msg, "EOF") || strings.Contains(msg, "protocol version") || strings.Contains(msg, "handshake failure")) {
			cs.add("handshake failure cause", "info", "the server ended the handshake without saying why; usually it only offers legacy TLS versions or cipher suites (TLS 1.0, RC4, 3DES, finite-field DHE) that this client no longer implements. Cross-check with: openssl s_client -connect "+net.JoinHostPort(t.Host, t.Port)+" -tls1", "RFC 8996")
		}
		if len(st.PeerCertificates) == 0 {
			return out, nil
		}
	}
	out["version"] = tls.VersionName(st.Version)
	out["cipher_suite"] = tls.CipherSuiteName(st.CipherSuite)
	if st.NegotiatedProtocol != "" {
		out["alpn"] = st.NegotiatedProtocol
	}
	for _, s := range tls.InsecureCipherSuites() {
		if s.ID == st.CipherSuite {
			cs.add("cipher suite", "warn", s.Name+" is considered insecure", "RFC 9325 §4.2")
		}
	}
	if st.Version < tls.VersionTLS12 && herr == nil {
		cs.add("negotiated version", "warn", tls.VersionName(st.Version)+" is deprecated", "RFC 8996")
	}

	// The chain, judged against the trust store or the supplied roots.
	var chain []M
	for _, pc := range st.PeerCertificates {
		chain = append(chain, certDetail(pc))
	}
	out["chain"] = chain
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		opts := x509.VerifyOptions{Intermediates: x509.NewCertPool(), DNSName: t.Host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		if sni != "" && sni != t.Host {
			opts.DNSName = sni
		}
		for _, ic := range st.PeerCertificates[1:] {
			opts.Intermediates.AddCert(ic)
		}
		from := "the system trust store"
		if s := c.Str("roots"); s != "" {
			ro, err := parsePKI(s)
			if err != nil || len(ro.Certs) == 0 {
				return out, fmt.Errorf("roots: %v", err)
			}
			opts.Roots = x509.NewCertPool()
			for _, r := range ro.Certs {
				opts.Roots.AddCert(r)
			}
			from = "the supplied roots"
		} else if c.Str("ca_cert") != "" && c.TLS != nil {
			opts.Roots = c.TLS.RootCAs
			from = "the system trust store and ca_cert"
		}
		chains, verr := leaf.Verify(opts)
		cs.ok(verr == nil, "server certificate chain verifies against "+from+" for "+opts.DNSName, detailOr(verr, fmt.Sprintf("%d path(s)", len(chains))), "RFC 6125 / RFC 5280 §6")
		certChecks(&cs, leaf, "leaf")
		for _, ic := range st.PeerCertificates[1:] {
			if selfSignedCert(ic) {
				cs.add("chain: root certificate sent", "info", "the server sends its root; clients ignore it", "RFC 8446 §4.4.2")
			} else {
				certChecks(&cs, ic, "ca")
			}
		}
		mustStaple := false
		for _, e := range leaf.Extensions {
			mustStaple = mustStaple || e.Id.Equal(oidTLSFeature)
		}
		stapled := len(st.OCSPResponse) > 0
		out["ocsp_stapled"] = stapled
		switch {
		case mustStaple && !stapled:
			cs.add("OCSP stapling", "fail", "the certificate demands stapling (must-staple) but no OCSP response was stapled", "RFC 7633 §4.2.3.1")
		case stapled:
			cs.add("OCSP stapling", "pass", fmt.Sprintf("%d-byte OCSP response stapled", len(st.OCSPResponse)), "RFC 6066 §8")
		default:
			cs.add("OCSP stapling", "info", "no OCSP response stapled", "RFC 6066 §8")
		}
		if stapled || c.Bool("ocsp") || c.Bool("crl") {
			// The issuer: from the verified path, else from what was sent.
			var cands []*x509.Certificate
			if len(chains) > 0 {
				cands = chains[0][1:]
			}
			cands = append(cands, st.PeerCertificates[1:]...)
			var ocspCS Checks
			// Downloading the issuer (caIssuers) only when OCSP was asked for:
			// the URL comes from the server's certificate.
			issuer, ierr := issuerFor(c, &ocspCS, leaf, cands, c.Bool("ocsp") || c.Bool("crl"), c.Bool("allow_private_urls"))
			switch {
			case ierr != nil:
				cs.add("revocation: issuer certificate", "warn", ierr.Error(), "RFC 5280 §6.3.3")
			default:
				if stapled {
					out["ocsp_stapled_response"] = checkOCSPResponse(&ocspCS, "stapled ", st.OCSPResponse, leaf, issuer)
				}
				if c.Bool("ocsp") {
					raw, url, qerr := queryOCSP(c, &ocspCS, "live ", leaf, issuer, "", crypto.SHA1, c.Bool("allow_private_urls"))
					switch {
					case qerr != nil:
						ocspCS.add("live OCSP query", "fail", qerr.Error(), "RFC 6960 §A.1")
					case raw != nil:
						r := checkOCSPResponse(&ocspCS, "live ", raw, leaf, issuer)
						r["responder_url"] = url
						out["ocsp_live"] = r
					}
				}
				if c.Bool("crl") {
					out["crl"] = fetchCRLs(c, &ocspCS, "leaf ", leaf, issuer, c.Bool("allow_private_urls"))
				}
			}
			cs = append(cs, ocspCS...)
		}
	}

	// Which protocol versions the server accepts, each in its own handshake.
	if c.Bool("versions") && t.StartTLS == "none" {
		support := M{}
		for _, v := range tlsVersions {
			vc := cfg.Clone()
			vc.MinVersion, vc.MaxVersion = v.v, v.v
			vc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				if clientCert != nil {
					return clientCert, nil
				}
				return &tls.Certificate{}, nil
			}
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(c.Int("timeout")) * time.Second}, "tcp", net.JoinHostPort(t.Host, t.Port), vc)
			ok := err == nil
			if ok {
				conn.Close()
			}
			support[v.name] = ok
			switch {
			case v.v <= tls.VersionTLS11 && ok:
				cs.add(v.name+" refused", "warn", v.name+" is accepted; it is deprecated", "RFC 8996")
			case v.v <= tls.VersionTLS11:
				cs.add(v.name+" refused", "pass", "", "RFC 8996")
			case v.v == tls.VersionTLS13:
				cs.add("TLS 1.3 supported", map[bool]string{true: "pass", false: "info"}[ok], map[bool]string{true: "accepted", false: "not offered: the server stops at TLS 1.2"}[ok], "RFC 8446")
			}
		}
		out["versions"] = support
	}
	return out, nil
}

func init() {
	register(&Op{
		Name:    "tls.probe",
		Summary: "Connect to a TLS server (directly, or via LDAP or SMTP StartTLS) and report the negotiated version, cipher and ALPN, the certificate chain and whether it verifies for the host, OCSP stapling (the stapled response is validated; ocsp=true also queries the responder, crl=true checks the CRL), which TLS versions are accepted, and whether the server asks for a client certificate and from which CAs. Can present a client certificate for mutual TLS.",
		Params: []Param{
			{Name: "host", Type: "string", Required: true, Desc: "host, host:port, or a URL (https://, ldaps://, ldap://, smtp://)"},
			{Name: "port", Type: "int", Desc: "Port when host has none", Default: 443},
			{Name: "starttls", Type: "string", Enum: []string{"none", "ldap", "smtp"}, Desc: "Upgrade a plain connection first", Default: "none"},
			{Name: "sni", Type: "string", Desc: "Server name to send and verify, if not the host"},
			{Name: "alpn", Type: "list", Desc: "ALPN protocols to offer", Default: "h2,http/1.1"},
			{Name: "roots", Type: "string", Path: true, Desc: "PEM roots to trust instead of the system store"},
			{Name: "mtls_cert", Type: "string", Path: true, Desc: "Client certificate (PEM, may include its chain) for mutual TLS"},
			{Name: "mtls_key", Type: "string", Path: true, Desc: "Private key for mtls_cert"},
			{Name: "versions", Type: "bool", Desc: "Also test which TLS versions the server accepts (direct TLS only)", Default: true},
			{Name: "ocsp", Type: "bool", Desc: "Also ask the leaf certificate's OCSP responder for its status (a stapled response is always checked)"},
			{Name: "crl", Type: "bool", Desc: "Also download the leaf certificate's CRL and check it is not listed"},
		},
		Run: runTLSProbe,
	})
}
