package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	agentv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/agent/v1"
	bundlev1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/bundle/v1"
	debugv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/debug/v1"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	localauthorityv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/localauthority/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	trustdomainv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/trustdomain/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// The SPIRE Server API (gRPC): over the admin Unix socket, where the caller
// is trusted as an administrator, or over TCP with mTLS, where the client
// X509-SVID's SPIFFE ID must be one of the server's admin_ids or have an
// admin entry. idpdbg reads what the server knows (entries, agents,
// bundles, federation, its CA), mints SVIDs and checks them, and creates or
// deletes entries and join tokens.

const (
	spireRef           = "SPIRE Server API"
	spireDefaultSocket = "/tmp/spire-server/private/api.sock"
	spirePageSize      = 500
	spireMaxPages      = 200
)

type spireClient struct {
	conn  *grpc.ClientConn
	ctx   context.Context
	via   string
	unix  bool
	td    spiffeid.TrustDomain // known up front over TCP, else from GetBundle
	close func()
}

type staticSVID struct{ s *x509svid.SVID }

func (s staticSVID) GetX509SVID() (*x509svid.SVID, error) { return s.s, nil }

// spireDial connects to the admin socket, or with mTLS to server.
func spireDial(c *Ctx, cs *Checks, out M) (*spireClient, error) {
	ctx, cancel := context.WithTimeout(c, time.Duration(c.Int("timeout"))*time.Second)
	sc := &spireClient{ctx: ctx}
	var closers []func()
	sc.close = func() {
		for _, f := range closers {
			f()
		}
		cancel()
	}
	fail := func(err error) (*spireClient, error) { sc.close(); return nil, err }

	if c.Str("server") == "" {
		path := strings.TrimPrefix(c.Str("socket"), "unix://")
		if path == "" {
			path = spireDefaultSocket
		}
		conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fail(err)
		}
		closers = append(closers, func() { conn.Close() })
		sc.conn, sc.via, sc.unix = conn, "admin socket "+path, true
		out["via"] = sc.via
		return sc, nil
	}

	origin, addr := spireOrigin(c.Str("server"))
	if origin == "" {
		return fail(fmt.Errorf("server %q: write host:port", c.Str("server")))
	}
	if err := c.allowDestination("the SPIRE client SVID", origin); err != nil {
		return fail(err)
	}
	var src x509svid.Source
	var bundles x509bundle.Source
	var client *x509svid.SVID
	switch {
	case c.Str("svid") != "":
		if c.Str("svid_key") == "" {
			return fail(errors.New("svid_key is required with svid"))
		}
		s, err := x509svid.Parse([]byte(c.Str("svid")), []byte(c.Str("svid_key")))
		if err != nil {
			return fail(fmt.Errorf("svid: %w", err))
		}
		client, src = s, staticSVID{s}
	case c.Str("workload_socket") != "":
		ws := c.Str("workload_socket")
		if !strings.Contains(ws, "://") {
			ws = "unix://" + ws
		}
		xs, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(ws)))
		if err != nil {
			return fail(fmt.Errorf("workload_socket: %w", err))
		}
		closers = append(closers, func() { xs.Close() })
		if client, err = xs.GetX509SVID(); err != nil {
			return fail(err)
		}
		src, bundles = xs, xs
	default:
		return fail(errors.New("the server API over TCP needs a client X509-SVID: svid and svid_key (for example one minted over the admin socket for an ID in admin_ids), or workload_socket"))
	}
	td := client.ID.TrustDomain()
	if s := c.Str("trust_domain"); s != "" {
		t, err := spiffeid.TrustDomainFromString(s)
		if err != nil {
			return fail(fmt.Errorf("trust_domain: %w", err))
		}
		td = t
	}
	sc.td = td
	if b := c.Str("bundle"); b != "" {
		pb, err := parseSPIFFEBundle(td, b)
		if err != nil {
			return fail(fmt.Errorf("bundle: %w", err))
		}
		bundles = x509bundle.FromX509Authorities(td, pb.X509)
	}
	serverID, _ := spiffeid.FromSegments(td, "spire", "server")
	out["client_id"] = client.ID.String()
	var tlsConf *tls.Config
	switch {
	case c.Bool("insecure"):
		cert := tls.Certificate{PrivateKey: client.PrivateKey}
		for _, x := range client.Certificates {
			cert.Certificate = append(cert.Certificate, x.Raw)
		}
		tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
		cs.add("server authenticated as "+serverID.String(), "warn", "not checked: insecure", spireRef)
	case bundles == nil:
		return fail(errors.New("pass bundle (the trust domain's X.509 authorities) to verify the server, or workload_socket"))
	default:
		tlsConf = tlsconfig.MTLSClientConfig(src, bundles, tlsconfig.AuthorizeID(serverID))
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConf)))
	if err != nil {
		return fail(err)
	}
	closers = append(closers, func() { conn.Close() })
	sc.conn, sc.via = conn, addr
	out["via"] = addr
	return sc, nil
}

// spireErr says what a gRPC error means here.
func (sc *spireClient) err(what string, err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return fmt.Errorf("%s: %w", what, err)
	}
	msg := fmt.Sprintf("%s: %s: %s", what, st.Code(), st.Message())
	switch st.Code() {
	case codes.Unavailable:
		if sc.unix {
			return errors.New(msg + " (is a SPIRE server running with this socket_path? the default is " + spireDefaultSocket + ")")
		}
		return errors.New(msg + " (the server is unreachable, or the TLS handshake failed: check bundle and that the server's SPIFFE ID is spiffe://<trust domain>/spire/server)")
	case codes.PermissionDenied, codes.Unauthenticated:
		return errors.New(msg + " (over TCP the client SVID's SPIFFE ID must be in the server's admin_ids or have an admin entry; the admin socket allows everything)")
	}
	return errors.New(msg)
}

// listDetail is prefix and the items, or nothing when there are none.
func listDetail(prefix string, items []string, sep string) string {
	if len(items) == 0 {
		return ""
	}
	return prefix + strings.Join(items, sep)
}

// spireOrigin is spire://host:port for a server written as host[:port] or
// as a URL, and the address to dial; "" when it names no host.
func spireOrigin(s string) (origin, addr string) {
	s = strings.TrimSpace(s)
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		s = u.Host
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = strings.Trim(s, "[]"), "8081"
	}
	if host == "" || strings.ContainsAny(host, "/@?#[]") {
		return "", ""
	}
	addr = net.JoinHostPort(host, port)
	return targetOrigin("spire://" + addr), addr
}

func spiffeIDOf(id *types.SPIFFEID) string {
	if id == nil {
		return ""
	}
	return "spiffe://" + id.TrustDomain + id.Path
}

func spiffeIDProto(s string) (*types.SPIFFEID, error) {
	id, err := spiffeid.FromString(s)
	if err != nil {
		return nil, err
	}
	return &types.SPIFFEID{TrustDomain: id.TrustDomain().Name(), Path: id.Path()}, nil
}

func unixTime(sec int64) string {
	t := time.Unix(sec, 0)
	return t.UTC().Format(time.RFC3339) + " (" + relTime(t) + ")"
}

func parseSelectors(l []string) ([]*types.Selector, error) {
	var out []*types.Selector
	for _, s := range l {
		t, v, ok := strings.Cut(s, ":")
		if !ok || t == "" || v == "" {
			return nil, fmt.Errorf("selector %q: write type:value, e.g. unix:uid:1000 or k8s:ns:prod", s)
		}
		out = append(out, &types.Selector{Type: t, Value: v})
	}
	return out, nil
}

func selectorStrings(l []*types.Selector) []string {
	var out []string
	for _, s := range l {
		out = append(out, s.Type+":"+s.Value)
	}
	return out
}

// bundle fetches the server's own bundle and learns the trust domain.
func (sc *spireClient) bundle() (*types.Bundle, error) {
	b, err := bundlev1.NewBundleClient(sc.conn).GetBundle(sc.ctx, &bundlev1.GetBundleRequest{})
	if err != nil {
		return nil, sc.err("GetBundle", err)
	}
	if td, err := spiffeid.TrustDomainFromString(b.TrustDomain); err == nil {
		sc.td = td
	}
	return b, nil
}

// describeBundle checks a SPIRE bundle's authorities and turns it into the
// trust material the SVID checks use.
func describeBundle(cs *Checks, b *types.Bundle, prefix string) (M, *spiffeBundle) {
	td, _ := spiffeid.TrustDomainFromString(b.TrustDomain)
	sb := &spiffeBundle{TD: td, JWT: map[string]crypto.PublicKey{}}
	out := M{"trust_domain": b.TrustDomain, "sequence_number": b.SequenceNumber}
	if b.RefreshHint > 0 {
		out["refresh_hint"] = (time.Duration(b.RefreshHint) * time.Second).String()
	}
	now := time.Now()
	var xs []M
	var pemText strings.Builder
	for i, a := range b.X509Authorities {
		cert, err := x509.ParseCertificate(a.Asn1)
		if err != nil {
			cs.add(fmt.Sprintf("%sX.509 authority %d parses", prefix, i+1), "fail", err.Error(), "SPIFFE Trust Domain and Bundle §4")
			continue
		}
		sb.X509 = append(sb.X509, cert)
		pem.Encode(&pemText, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		e := M{"subject": cert.Subject.String(), "not_after": unixTime(cert.NotAfter.Unix()), "key": keyDescription(cert.PublicKey)}
		if a.Tainted {
			e["tainted"] = true
			cs.add(fmt.Sprintf("%sX.509 authority %d", prefix, i+1), "warn", "tainted: being rotated out, and SVIDs it signed are being replaced", "SPIRE forced rotation")
		}
		cs.ok(now.Before(cert.NotAfter) && now.After(cert.NotBefore), fmt.Sprintf("%sX.509 authority %d is within its validity period", prefix, i+1), "until "+unixTime(cert.NotAfter.Unix()), "RFC 5280 §4.1.2.5")
		xs = append(xs, e)
	}
	var js []M
	for _, k := range b.JwtAuthorities {
		e := M{"kid": k.KeyId}
		if pub, err := x509.ParsePKIXPublicKey(k.PublicKey); err == nil {
			sb.JWT[k.KeyId] = pub
			e["key"] = keyDescription(pub)
		}
		if k.ExpiresAt > 0 {
			e["expires_at"] = unixTime(k.ExpiresAt)
			if time.Unix(k.ExpiresAt, 0).Before(now) {
				cs.add(prefix+"JWT authority "+k.KeyId, "warn", "expired: JWT-SVIDs it signed no longer verify", "SPIFFE JWT-SVID §4")
			}
		}
		if k.Tainted {
			e["tainted"] = true
			cs.add(prefix+"JWT authority "+k.KeyId, "warn", "tainted: being rotated out", "SPIRE forced rotation")
		}
		js = append(js, e)
	}
	out["x509_authorities"], out["jwt_authorities"] = xs, js
	if pemText.Len() > 0 {
		out["x509_pem"] = pemText.String()
	}
	cs.ok(len(sb.X509)+len(sb.JWT) > 0, prefix+"bundle has authorities", fmt.Sprintf("%d X.509, %d JWT", len(sb.X509), len(sb.JWT)), "SPIFFE Trust Domain and Bundle §4")
	return out, sb
}

func describeEntry(e *types.Entry) M {
	m := M{"id": e.Id, "spiffe_id": spiffeIDOf(e.SpiffeId), "parent_id": spiffeIDOf(e.ParentId), "selectors": selectorStrings(e.Selectors),
		"revision": e.RevisionNumber}
	if e.X509SvidTtl > 0 {
		m["x509_svid_ttl"] = (time.Duration(e.X509SvidTtl) * time.Second).String()
	}
	if e.JwtSvidTtl > 0 {
		m["jwt_svid_ttl"] = (time.Duration(e.JwtSvidTtl) * time.Second).String()
	}
	for k, v := range map[string]bool{"admin": e.Admin, "downstream": e.Downstream, "store_svid": e.StoreSvid} {
		if v {
			m[k] = true
		}
	}
	if len(e.FederatesWith) > 0 {
		m["federates_with"] = e.FederatesWith
	}
	if len(e.DnsNames) > 0 {
		m["dns_names"] = e.DnsNames
	}
	if e.Hint != "" {
		m["hint"] = e.Hint
	}
	if e.ExpiresAt > 0 {
		m["expires_at"] = unixTime(e.ExpiresAt)
	}
	if e.CreatedAt > 0 {
		m["created_at"] = unixTime(e.CreatedAt)
	}
	return m
}

func describeAgent(a *types.Agent) M {
	m := M{"id": spiffeIDOf(a.Id), "attestation_type": a.AttestationType, "selectors": selectorStrings(a.Selectors), "can_reattest": a.CanReattest}
	if a.X509SvidExpiresAt > 0 {
		m["svid_expires_at"] = unixTime(a.X509SvidExpiresAt)
	}
	if a.Banned {
		m["banned"] = true
	}
	if a.AgentVersion != "" {
		m["version"] = a.AgentVersion
	}
	return m
}

func (sc *spireClient) listEntries(f *entryv1.ListEntriesRequest_Filter) ([]*types.Entry, error) {
	cl := entryv1.NewEntryClient(sc.conn)
	var all []*types.Entry
	tok := ""
	for range spireMaxPages {
		r, err := cl.ListEntries(sc.ctx, &entryv1.ListEntriesRequest{Filter: f, PageSize: spirePageSize, PageToken: tok})
		if err != nil {
			return all, sc.err("ListEntries", err)
		}
		all = append(all, r.Entries...)
		if tok = r.NextPageToken; tok == "" {
			return all, nil
		}
	}
	return all, fmt.Errorf("ListEntries: more than %d pages", spireMaxPages)
}

func (sc *spireClient) listAgents(f *agentv1.ListAgentsRequest_Filter) ([]*types.Agent, error) {
	cl := agentv1.NewAgentClient(sc.conn)
	var all []*types.Agent
	tok := ""
	for range spireMaxPages {
		r, err := cl.ListAgents(sc.ctx, &agentv1.ListAgentsRequest{Filter: f, PageSize: spirePageSize, PageToken: tok})
		if err != nil {
			return all, sc.err("ListAgents", err)
		}
		all = append(all, r.Agents...)
		if tok = r.NextPageToken; tok == "" {
			return all, nil
		}
	}
	return all, fmt.Errorf("ListAgents: more than %d pages", spireMaxPages)
}

// withSPIRE runs f with a connection, collecting checks into out.
func withSPIRE(c *Ctx, f func(sc *spireClient, cs *Checks, out M) error) (M, error) {
	var cs Checks
	out := M{}
	sc, err := spireDial(c, &cs, out)
	if err != nil {
		return nil, err
	}
	defer sc.close()
	err = f(sc, &cs, out)
	if err == nil && !sc.unix && !c.Bool("insecure") {
		cs = append(Checks{{Name: "server authenticated as spiffe://" + sc.td.Name() + "/spire/server", Status: "pass", Detail: "mTLS with the trust domain's X.509 authorities", Ref: spireRef}}, cs...)
	}
	out["checks"] = cs
	return out, err
}

// authorityStates describes a local authority's slots, leaving out the empty ones.
func authorityStates(active, prepared, old *localauthorityv1.AuthorityState) M {
	out := M{}
	for name, s := range map[string]*localauthorityv1.AuthorityState{"active": active, "prepared": prepared, "old": old} {
		if s == nil {
			continue
		}
		m := M{"authority_id": s.AuthorityId, "expires_at": unixTime(s.ExpiresAt)}
		if s.UpstreamAuthoritySubjectKeyId != "" {
			m["upstream_authority_subject_key_id"] = s.UpstreamAuthoritySubjectKeyId
		}
		out[name] = m
	}
	return out
}

func runSPIREInfo(c *Ctx) (M, error) {
	return withSPIRE(c, func(sc *spireClient, cs *Checks, out M) error {
		b, err := sc.bundle()
		if err != nil {
			return err
		}
		out["trust_domain"] = b.TrustDomain
		if h, err := healthpb.NewHealthClient(sc.conn).Check(sc.ctx, &healthpb.HealthCheckRequest{}); err == nil {
			cs.ok(h.Status == healthpb.HealthCheckResponse_SERVING, "server is serving", h.Status.String(), "gRPC health checking")
		}
		info, err := debugv1.NewDebugClient(sc.conn).GetInfo(sc.ctx, &debugv1.GetInfoRequest{})
		if err != nil {
			cs.add("debug information", "info", "not available here ("+status.Code(err).String()+"): the debug API is served on the admin socket", spireRef)
		} else {
			out["uptime"] = (time.Duration(info.Uptime) * time.Second).String()
			out["agents"], out["entries"], out["federated_bundles"] = info.AgentsCount, info.EntriesCount, info.FederatedBundlesCount
			var chain []M
			for i, ce := range info.SvidChain {
				chain = append(chain, M{"id": spiffeIDOf(ce.Id), "subject": ce.Subject, "expires_at": unixTime(ce.ExpiresAt)})
				cs.ok(time.Unix(ce.ExpiresAt, 0).After(time.Now()), fmt.Sprintf("server SVID chain certificate %d is unexpired", i+1), unixTime(ce.ExpiresAt), "SPIFFE X509-SVID §4")
			}
			out["server_svid_chain"] = chain
			if len(info.SvidChain) > 0 {
				want := "spiffe://" + b.TrustDomain + "/spire/server"
				cs.ok(spiffeIDOf(info.SvidChain[0].Id) == want, "server SVID is "+want, spiffeIDOf(info.SvidChain[0].Id), spireRef)
			}
		}
		if _, ok := out["entries"]; !ok {
			if n, err := entryv1.NewEntryClient(sc.conn).CountEntries(sc.ctx, &entryv1.CountEntriesRequest{}); err == nil {
				out["entries"] = n.Count
			}
			if n, err := agentv1.NewAgentClient(sc.conn).CountAgents(sc.ctx, &agentv1.CountAgentsRequest{}); err == nil {
				out["agents"] = n.Count
			}
		}
		la := localauthorityv1.NewLocalAuthorityClient(sc.conn)
		authorities := M{}
		if x, err := la.GetX509AuthorityState(sc.ctx, &localauthorityv1.GetX509AuthorityStateRequest{}); err == nil {
			authorities["x509"] = authorityStates(x.Active, x.Prepared, x.Old)
			cs.ok(x.Active != nil && time.Unix(x.Active.ExpiresAt, 0).After(time.Now()), "an unexpired X.509 authority is active", "", "SPIRE CA rotation")
		} else {
			cs.add("X.509 authority state", "info", status.Code(err).String(), spireRef)
		}
		if j, err := la.GetJWTAuthorityState(sc.ctx, &localauthorityv1.GetJWTAuthorityStateRequest{}); err == nil {
			authorities["jwt"] = authorityStates(j.Active, j.Prepared, j.Old)
			cs.ok(j.Active != nil && time.Unix(j.Active.ExpiresAt, 0).After(time.Now()), "an unexpired JWT authority is active", "", "SPIRE CA rotation")
		}
		if len(authorities) > 0 {
			out["local_authorities"] = authorities
		}
		bd, _ := describeBundle(cs, b, "")
		out["bundle"] = bd
		return nil
	})
}

func runSPIREBundles(c *Ctx) (M, error) {
	return withSPIRE(c, func(sc *spireClient, cs *Checks, out M) error {
		b, err := sc.bundle()
		if err != nil {
			return err
		}
		out["bundle"], _ = describeBundle(cs, b, "")
		cl := bundlev1.NewBundleClient(sc.conn)
		var feds []M
		tok := ""
		for range spireMaxPages {
			r, err := cl.ListFederatedBundles(sc.ctx, &bundlev1.ListFederatedBundlesRequest{PageSize: spirePageSize, PageToken: tok})
			if err != nil {
				return sc.err("ListFederatedBundles", err)
			}
			for _, fb := range r.Bundles {
				d, _ := describeBundle(cs, fb, fb.TrustDomain+": ")
				feds = append(feds, d)
			}
			if tok = r.NextPageToken; tok == "" {
				break
			}
		}
		out["federated_bundles"] = feds
		tc := trustdomainv1.NewTrustDomainClient(sc.conn)
		var rels []M
		haveBundle := map[string]bool{}
		for _, f := range feds {
			haveBundle[str(f["trust_domain"])] = true
		}
		tok = ""
		for range spireMaxPages {
			r, err := tc.ListFederationRelationships(sc.ctx, &trustdomainv1.ListFederationRelationshipsRequest{PageSize: spirePageSize, PageToken: tok})
			if err != nil {
				return sc.err("ListFederationRelationships", err)
			}
			for _, fr := range r.FederationRelationships {
				m := M{"trust_domain": fr.TrustDomain, "bundle_endpoint_url": fr.BundleEndpointUrl}
				switch p := fr.BundleEndpointProfile.(type) {
				case *types.FederationRelationship_HttpsWeb:
					m["profile"] = "https_web"
				case *types.FederationRelationship_HttpsSpiffe:
					m["profile"], m["endpoint_spiffe_id"] = "https_spiffe", p.HttpsSpiffe.EndpointSpiffeId
				}
				u, err := url.Parse(fr.BundleEndpointUrl)
				cs.ok(err == nil && u.Scheme == "https", fr.TrustDomain+": bundle endpoint is https", fr.BundleEndpointUrl, "SPIFFE Federation §5")
				cs.ok(haveBundle[fr.TrustDomain], fr.TrustDomain+": the server holds a bundle for it", map[bool]string{true: "fetched", false: "not fetched yet: workloads cannot verify its SVIDs"}[haveBundle[fr.TrustDomain]], "SPIFFE Federation §4")
				rels = append(rels, m)
			}
			if tok = r.NextPageToken; tok == "" {
				break
			}
		}
		out["federation_relationships"] = rels
		return nil
	})
}

func runSPIREEntries(c *Ctx) (M, error) {
	return withSPIRE(c, func(sc *spireClient, cs *Checks, out M) error {
		b, err := sc.bundle()
		if err != nil {
			return err
		}
		var entries []*types.Entry
		filtered := false
		if id := c.Str("id"); id != "" {
			e, err := entryv1.NewEntryClient(sc.conn).GetEntry(sc.ctx, &entryv1.GetEntryRequest{Id: id})
			if err != nil {
				return sc.err("GetEntry", err)
			}
			entries, filtered = []*types.Entry{e}, true
		} else {
			f := &entryv1.ListEntriesRequest_Filter{}
			if s := c.Str("spiffe_id"); s != "" {
				if f.BySpiffeId, err = spiffeIDProto(s); err != nil {
					return fmt.Errorf("spiffe_id: %w", err)
				}
			}
			if s := c.Str("parent_id"); s != "" {
				if f.ByParentId, err = spiffeIDProto(s); err != nil {
					return fmt.Errorf("parent_id: %w", err)
				}
			}
			if l := c.List("selectors"); len(l) > 0 {
				sel, err := parseSelectors(l)
				if err != nil {
					return err
				}
				match := map[string]types.SelectorMatch_MatchBehavior{"exact": types.SelectorMatch_MATCH_EXACT, "subset": types.SelectorMatch_MATCH_SUBSET,
					"superset": types.SelectorMatch_MATCH_SUPERSET, "any": types.SelectorMatch_MATCH_ANY}[c.Str("match")]
				f.BySelectors = &types.SelectorMatch{Selectors: sel, Match: match}
			}
			if s := c.Str("hint"); s != "" {
				f.ByHint = wrapperspb.String(s)
			}
			filtered = f.BySpiffeId != nil || f.ByParentId != nil || f.BySelectors != nil || f.ByHint != nil
			if entries, err = sc.listEntries(f); err != nil {
				return err
			}
		}
		var list []M
		serverID := "spiffe://" + b.TrustDomain + "/spire/server"
		// Parents: the server (node entries), attested agents, or another
		// entry's SPIFFE ID (node aliases). Only known when listing all.
		parents := map[string]bool{serverID: true}
		if !filtered {
			agents, err := sc.listAgents(nil)
			if err != nil {
				return err
			}
			for _, a := range agents {
				parents[spiffeIDOf(a.Id)] = true
			}
			for _, e := range entries {
				parents[spiffeIDOf(e.SpiffeId)] = true
			}
		}
		var orphans, expired, long, admins, foreign []string
		now := time.Now().Unix()
		for _, e := range entries {
			list = append(list, describeEntry(e))
			sid := spiffeIDOf(e.SpiffeId)
			if e.SpiffeId != nil && e.SpiffeId.TrustDomain != b.TrustDomain {
				foreign = append(foreign, sid)
			}
			if !filtered && !parents[spiffeIDOf(e.ParentId)] {
				orphans = append(orphans, sid+" (parent "+spiffeIDOf(e.ParentId)+")")
			}
			if e.ExpiresAt > 0 && e.ExpiresAt < now {
				expired = append(expired, sid)
			}
			if e.X509SvidTtl > 24*3600 {
				long = append(long, fmt.Sprintf("%s (%s)", sid, time.Duration(e.X509SvidTtl)*time.Second))
			}
			if e.Admin {
				admins = append(admins, sid)
			}
		}
		out["entries"], out["count"] = list, len(list)
		cs.ok(len(foreign) == 0, "entries are in the server's trust domain", strings.Join(foreign, ", "), "SPIFFE ID §2.1")
		if !filtered {
			cs.warn(len(orphans) == 0, "every entry's parent is the server, an agent or another entry", listDetail("no workload can get these until an agent with that ID attests (a join token not used yet, or a deleted agent): ", orphans, "; "), "SPIRE registration")
		}
		cs.warn(len(expired) == 0, "no entry has expired", strings.Join(expired, ", "), "SPIRE registration")
		cs.warn(len(long) == 0, "X509-SVID TTLs are at most 24h", strings.Join(long, ", "), "SPIFFE X509-SVID (short-lived SVIDs)")
		if len(admins) > 0 {
			cs.add("admin entries", "info", "workloads with these IDs may use the whole server API: "+strings.Join(admins, ", "), spireRef)
		}
		return nil
	})
}

func runSPIREAgents(c *Ctx) (M, error) {
	return withSPIRE(c, func(sc *spireClient, cs *Checks, out M) error {
		var f *agentv1.ListAgentsRequest_Filter
		if t := c.Str("attestation_type"); t != "" {
			f = &agentv1.ListAgentsRequest_Filter{ByAttestationType: t}
		}
		agents, err := sc.listAgents(f)
		if err != nil {
			return err
		}
		var list []M
		var expired, banned, noReattest []string
		now := time.Now().Unix()
		for _, a := range agents {
			list = append(list, describeAgent(a))
			id := spiffeIDOf(a.Id)
			if a.X509SvidExpiresAt > 0 && a.X509SvidExpiresAt < now {
				expired = append(expired, id)
			}
			if a.Banned {
				banned = append(banned, id)
			}
			if !a.CanReattest {
				noReattest = append(noReattest, id)
			}
		}
		out["agents"], out["count"] = list, len(list)
		cs.warn(len(expired) == 0, "every agent's SVID is unexpired", listDetail("expired (the agent is down or cannot renew): ", expired, ", "), "SPIRE agent lifecycle")
		if len(banned) > 0 {
			cs.add("banned agents", "info", strings.Join(banned, ", "), "SPIRE agent lifecycle")
		}
		if len(noReattest) > 0 {
			cs.add("agents that cannot re-attest", "info", "if their SVID lapses they need a new attestation (e.g. a new join token): "+strings.Join(noReattest, ", "), "SPIRE agent lifecycle")
		}
		return nil
	})
}

func runSPIREMint(c *Ctx) (M, error) {
	id, err := spiffeid.FromString(c.Str("spiffe_id"))
	if err != nil {
		return nil, fmt.Errorf("spiffe_id: %w", err)
	}
	return withSPIRE(c, func(sc *spireClient, cs *Checks, out M) error {
		b, err := sc.bundle()
		if err != nil {
			return err
		}
		_, sb := describeBundle(&Checks{}, b, "")
		cl := svidv1.NewSVIDClient(sc.conn)
		ttl := int32(c.Int("ttl"))
		if c.Str("type") == "jwt" {
			aud := c.List("audience")
			if len(aud) == 0 {
				return errors.New("audience is required for a JWT-SVID")
			}
			r, err := cl.MintJWTSVID(sc.ctx, &svidv1.MintJWTSVIDRequest{Id: &types.SPIFFEID{TrustDomain: id.TrustDomain().Name(), Path: id.Path()}, Audience: aud, Ttl: ttl})
			if err != nil {
				return sc.err("MintJWTSVID", err)
			}
			if c.Rec != nil {
				c.Rec.secrets = append(c.Rec.secrets, r.Svid.Token)
			}
			out["token"], out["expires_at"] = r.Svid.Token, unixTime(r.Svid.ExpiresAt)
			out["jwt"] = checkJWTSVID(cs, r.Svid.Token, sb, aud[0], id.String())
			return nil
		}
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{URIs: []*url.URL{id.URL()}, DNSNames: c.List("dns_names")}, key)
		if err != nil {
			return err
		}
		r, err := cl.MintX509SVID(sc.ctx, &svidv1.MintX509SVIDRequest{Csr: csr, Ttl: ttl})
		if err != nil {
			return sc.err("MintX509SVID", err)
		}
		var chain []*x509.Certificate
		var chainPEM strings.Builder
		for _, der := range r.Svid.CertChain {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return fmt.Errorf("MintX509SVID: certificate: %w", err)
			}
			chain = append(chain, cert)
			chainPEM.WriteString(certPEM(cert))
		}
		if len(chain) == 0 {
			return errors.New("MintX509SVID: no certificate in the answer")
		}
		var details []M
		for _, ce := range chain {
			details = append(details, certDetail(ce))
		}
		out["chain"], out["chain_pem"], out["key_pem"] = details, chainPEM.String(), keyPEM(key)
		if c.Rec != nil {
			c.Rec.secrets = append(c.Rec.secrets, keyPEM(key))
		}
		for k, v := range checkX509SVID(cs, chain, sb, id.String()) {
			out[k] = v
		}
		if ttl > 0 {
			got := chain[0].NotAfter.Sub(chain[0].NotBefore)
			if got < time.Duration(ttl)*time.Second-time.Minute {
				cs.add("lifetime as requested", "info", fmt.Sprintf("%s instead of %s: the server caps SVIDs at its CA's remaining lifetime", got.Round(time.Second), time.Duration(ttl)*time.Second), spireRef)
			}
		}
		var dns []string
		dns = append(dns, chain[0].DNSNames...)
		sort.Strings(dns)
		if want := c.List("dns_names"); len(want) > 0 {
			sort.Strings(want)
			cs.ok(strings.Join(dns, ",") == strings.Join(want, ","), "DNS names as requested", strings.Join(dns, ", "), spireRef)
		}
		return nil
	})
}

func runSPIREEntryCreate(c *Ctx) (M, error) {
	sid, err := spiffeIDProto(c.Str("spiffe_id"))
	if err != nil {
		return nil, fmt.Errorf("spiffe_id: %w", err)
	}
	pid, err := spiffeIDProto(c.Str("parent_id"))
	if err != nil {
		return nil, fmt.Errorf("parent_id: %w", err)
	}
	sel, err := parseSelectors(c.List("selectors"))
	if err != nil {
		return nil, err
	}
	if len(sel) == 0 {
		return nil, errors.New("selectors: at least one, e.g. unix:uid:1000")
	}
	e := &types.Entry{SpiffeId: sid, ParentId: pid, Selectors: sel, X509SvidTtl: int32(c.Int("x509_svid_ttl")), JwtSvidTtl: int32(c.Int("jwt_svid_ttl")),
		FederatesWith: c.List("federates_with"), Admin: c.Bool("admin"), Downstream: c.Bool("downstream"), DnsNames: c.List("dns_names"), Hint: c.Str("hint")}
	return withSPIRE(c, func(sc *spireClient, cs *Checks, out M) error {
		r, err := entryv1.NewEntryClient(sc.conn).BatchCreateEntry(sc.ctx, &entryv1.BatchCreateEntryRequest{Entries: []*types.Entry{e}})
		if err != nil {
			return sc.err("BatchCreateEntry", err)
		}
		if len(r.Results) != 1 {
			return fmt.Errorf("BatchCreateEntry: %d results for one entry", len(r.Results))
		}
		res := r.Results[0]
		code := codes.Code(res.Status.GetCode())
		if res.Entry != nil {
			out["entry"] = describeEntry(res.Entry)
		}
		switch code {
		case codes.OK:
			cs.add("server created the entry", "pass", "id "+res.Entry.GetId(), spireRef)
		case codes.AlreadyExists:
			cs.add("server created the entry", "info", "an identical entry exists already: "+res.Status.GetMessage(), spireRef)
		default:
			cs.add("server created the entry", "fail", code.String()+": "+res.Status.GetMessage(), spireRef)
		}
		if e.Admin {
			cs.add("admin entry", "info", "workloads with this ID may use the whole server API", spireRef)
		}
		return nil
	})
}

func runSPIREEntryDelete(c *Ctx) (M, error) {
	ids := c.List("ids")
	if len(ids) == 0 {
		return nil, errors.New("ids: the entry IDs to delete (from spire.entries)")
	}
	return withSPIRE(c, func(sc *spireClient, cs *Checks, out M) error {
		r, err := entryv1.NewEntryClient(sc.conn).BatchDeleteEntry(sc.ctx, &entryv1.BatchDeleteEntryRequest{Ids: ids})
		if err != nil {
			return sc.err("BatchDeleteEntry", err)
		}
		var deleted []string
		for _, res := range r.Results {
			code := codes.Code(res.Status.GetCode())
			if code == codes.OK {
				deleted = append(deleted, res.Id)
				cs.add("deleted "+res.Id, "pass", "", spireRef)
			} else {
				cs.add("deleted "+res.Id, "fail", code.String()+": "+res.Status.GetMessage(), spireRef)
			}
		}
		out["deleted"] = deleted
		return nil
	})
}

func runSPIREJoinToken(c *Ctx) (M, error) {
	var agentID *types.SPIFFEID
	if s := c.Str("agent_id"); s != "" {
		var err error
		if agentID, err = spiffeIDProto(s); err != nil {
			return nil, fmt.Errorf("agent_id: %w", err)
		}
	}
	return withSPIRE(c, func(sc *spireClient, cs *Checks, out M) error {
		t, err := agentv1.NewAgentClient(sc.conn).CreateJoinToken(sc.ctx, &agentv1.CreateJoinTokenRequest{Ttl: int32(c.Int("ttl")), AgentId: agentID})
		if err != nil {
			return sc.err("CreateJoinToken", err)
		}
		if c.Rec != nil {
			c.Rec.secrets = append(c.Rec.secrets, t.Value)
		}
		out["token"], out["expires_at"] = t.Value, unixTime(t.ExpiresAt)
		if sc.td.Name() == "" {
			sc.bundle()
		}
		out["agent_id"] = "spiffe://" + sc.td.Name() + "/spire/agent/join_token/" + t.Value
		if agentID != nil {
			out["alias"] = spiffeIDOf(agentID)
			cs.add("node alias", "info", "the server also made an entry that gives the agent "+spiffeIDOf(agentID)+" once it attests", spireRef)
		}
		cs.add("join token", "info", "single use: the first agent that attests with it gets the agent ID above", "SPIRE join_token node attestor")
		return nil
	})
}

func init() {
	conn := []Param{
		{Name: "socket", Type: "string", Desc: "The server's admin Unix socket (default " + spireDefaultSocket + "); the caller is an administrator"},
		{Name: "server", Type: "string", Desc: "Instead of the socket: the server API over TCP with mTLS, host:port (default port 8081)"},
		{Name: "svid", Type: "string", Path: true, Desc: "Over TCP: the client X509-SVID (PEM chain) whose SPIFFE ID is in the server's admin_ids"},
		{Name: "svid_key", Type: "string", Path: true, Desc: "Its private key (PEM)"},
		{Name: "workload_socket", Type: "string", Desc: "Over TCP: take the client SVID and the bundle from this Workload API (a SPIRE agent) instead"},
		{Name: "trust_domain", Type: "string", Desc: "The server's trust domain (default: the client SVID's)"},
		{Name: "bundle", Type: "string", Path: true, Desc: "Over TCP: the trust domain's X.509 authorities to verify the server with (PEM or a SPIFFE bundle)"},
	}
	register(
		&Op{
			Name:    "spire.info",
			Summary: "Ask a SPIRE server about itself: health, uptime, entry and agent counts, its own SVID chain, the active, prepared and old X.509 and JWT authorities, and its trust bundle, with checks on expiry and rotation.",
			Params:  conn,
			Run:     runSPIREInfo,
		},
		&Op{
			Name:    "spire.bundles",
			Summary: "The SPIRE server's trust bundle and the federated bundles it holds, each authority checked (validity, tainted, expired JWT keys), and its federation relationships (bundle endpoint URL and profile, whether a bundle was fetched).",
			Params:  conn,
			Run:     runSPIREBundles,
		},
		&Op{
			Name:    "spire.entries",
			Summary: "List or look up SPIRE registration entries (by ID, SPIFFE ID, parent ID, selectors or hint) and check them: in the trust domain, parent is the server, an agent or another entry, not expired, X509-SVID TTL at most 24h, admin entries named.",
			Params: joinParams(conn, []Param{
				{Name: "id", Type: "string", Desc: "One entry by its ID"},
				{Name: "spiffe_id", Type: "string", Desc: "Entries for this SPIFFE ID"},
				{Name: "parent_id", Type: "string", Desc: "Entries with this parent (an agent's ID, or the server's for node entries)"},
				{Name: "selectors", Type: "list", Desc: "Entries with these selectors, type:value (e.g. unix:uid:1000)"},
				{Name: "match", Type: "string", Default: "superset", Enum: []string{"exact", "subset", "superset", "any"}, Desc: "How selectors match"},
				{Name: "hint", Type: "string", Desc: "Entries with this hint"},
			}),
			Run: runSPIREEntries,
		},
		&Op{
			Name:    "spire.agents",
			Summary: "List the agents a SPIRE server has attested: SPIFFE ID, attestation type, selectors, SVID expiry, banned, whether it can re-attest, version; warns about agents whose SVID has expired.",
			Params: joinParams(conn, []Param{
				{Name: "attestation_type", Type: "string", Desc: "Only agents attested this way (join_token, k8s_psat, aws_iid...)"},
			}),
			Run: runSPIREAgents,
		},
		&Op{
			Name:     "spire.mint",
			Mutating: true, // it issues credentials for any identity
			Summary:  "Have a SPIRE server mint an X509-SVID (for a key idpdbg makes, returned with it) or a JWT-SVID for any SPIFFE ID in its trust domain, and check it against the specifications and the server's bundle. Needs administrator access.",
			Params: joinParams(conn, []Param{
				{Name: "spiffe_id", Type: "string", Required: true, Desc: "The SPIFFE ID to mint for"},
				{Name: "type", Type: "string", Default: "x509", Enum: []string{"x509", "jwt"}, Desc: "X509-SVID or JWT-SVID"},
				{Name: "audience", Type: "list", Desc: "JWT-SVID audiences (required for jwt)"},
				{Name: "ttl", Type: "int", Desc: "Lifetime in seconds (default: the server's)"},
				{Name: "dns_names", Type: "list", Desc: "X509-SVID DNS names"},
			}),
			Run: runSPIREMint,
		},
		&Op{
			Name:     "spire.entry_create",
			Mutating: true,
			Summary:  "Create a SPIRE registration entry: which workloads (selectors, under a parent agent) get which SPIFFE ID, with optional TTLs, DNS names, federation, admin and downstream flags.",
			Params: joinParams(conn, []Param{
				{Name: "spiffe_id", Type: "string", Required: true, Desc: "The SPIFFE ID workloads get"},
				{Name: "parent_id", Type: "string", Required: true, Desc: "The agent (or node alias) the workloads run under; spiffe://<td>/spire/server for a node entry"},
				{Name: "selectors", Type: "list", Required: true, Desc: "type:value selectors, e.g. unix:uid:1000 or k8s:ns:prod"},
				{Name: "x509_svid_ttl", Type: "int", Desc: "X509-SVID lifetime in seconds (default: the server's)"},
				{Name: "jwt_svid_ttl", Type: "int", Desc: "JWT-SVID lifetime in seconds (default: the server's)"},
				{Name: "dns_names", Type: "list", Desc: "DNS names for the X509-SVIDs"},
				{Name: "federates_with", Type: "list", Desc: "Trust domains whose bundles the workloads also get"},
				{Name: "admin", Type: "bool", Desc: "Workloads with this ID may use the whole server API"},
				{Name: "downstream", Type: "bool", Desc: "Workloads with this ID may run a downstream SPIRE server (get an intermediate CA)"},
				{Name: "hint", Type: "string", Desc: "Hint for workloads with several SVIDs"},
			}),
			Run: runSPIREEntryCreate,
		},
		&Op{
			Name:     "spire.entry_delete",
			Mutating: true,
			Summary:  "Delete SPIRE registration entries by ID; the workloads lose those SVIDs when they expire.",
			Params: joinParams(conn, []Param{
				{Name: "ids", Type: "list", Required: true, Desc: "Entry IDs (from spire.entries)"},
			}),
			Run: runSPIREEntryDelete,
		},
		&Op{
			Name:     "spire.join_token",
			Mutating: true,
			Summary:  "Create a join token an agent attests with (join_token node attestor), optionally with a node alias SPIFFE ID for the agent.",
			Params: joinParams(conn, []Param{
				{Name: "ttl", Type: "int", Default: 600, Desc: "Lifetime in seconds"},
				{Name: "agent_id", Type: "string", Desc: "Also give the agent this SPIFFE ID (a node alias entry)"},
			}),
			Run: runSPIREJoinToken,
		},
	)
}
