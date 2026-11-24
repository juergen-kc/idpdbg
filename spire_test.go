package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

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
	"google.golang.org/grpc/status"
)

// fakeSPIRE is a SPIRE server in memory, on an admin socket: a CA that mints
// for real, entries, agents and federation.
type fakeSPIRE struct {
	bundlev1.UnimplementedBundleServer
	entryv1.UnimplementedEntryServer
	agentv1.UnimplementedAgentServer
	svidv1.UnimplementedSVIDServer
	debugv1.UnimplementedDebugServer
	localauthorityv1.UnimplementedLocalAuthorityServer
	trustdomainv1.UnimplementedTrustDomainServer

	mu       sync.Mutex
	socket   string
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	jwtKey   *ecdsa.PrivateKey
	entries  []*types.Entry
	agents   []*types.Agent
	denyMint bool
	tokens   int
}

func spireID(path string) *types.SPIFFEID {
	return &types.SPIFFEID{TrustDomain: "spire.test", Path: path}
}

func newFakeSPIRE(t *testing.T) *fakeSPIRE {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sockets")
	}
	f := &fakeSPIRE{}
	f.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.jwtKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	td, _ := url.Parse("spiffe://spire.test")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{Organization: []string{"SPIFFE"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, URIs: []*url.URL{td}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, f.caKey.Public(), f.caKey)
	f.ca, _ = x509.ParseCertificate(der)
	now := time.Now().Unix()
	agent := "/spire/agent/join_token/abc"
	f.agents = []*types.Agent{
		{Id: spireID(agent), AttestationType: "join_token", X509SvidExpiresAt: now + 3600},
		{Id: spireID("/spire/agent/x509pop/old"), AttestationType: "x509pop", X509SvidExpiresAt: now - 3600, CanReattest: true, Banned: true},
	}
	f.entries = []*types.Entry{
		{Id: "e1", SpiffeId: spireID("/node"), ParentId: spireID("/spire/server"), Selectors: []*types.Selector{{Type: "spiffe_id", Value: "spiffe://spire.test" + agent}}},
		{Id: "e2", SpiffeId: spireID("/web"), ParentId: spireID("/node"), Selectors: []*types.Selector{{Type: "unix", Value: "uid:1000"}}, X509SvidTtl: 3600},
		{Id: "e3", SpiffeId: spireID("/batch"), ParentId: spireID("/spire/agent/gone"), Selectors: []*types.Selector{{Type: "unix", Value: "uid:1001"}}, ExpiresAt: now - 60, X509SvidTtl: 7 * 24 * 3600},
		{Id: "e4", SpiffeId: spireID("/ops"), ParentId: spireID(agent), Selectors: []*types.Selector{{Type: "unix", Value: "uid:0"}}, Admin: true},
	}
	dir, err := os.MkdirTemp("", "spire")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f.socket = filepath.Join(dir, "api.sock")
	l, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	bundlev1.RegisterBundleServer(s, f)
	entryv1.RegisterEntryServer(s, f)
	agentv1.RegisterAgentServer(s, f)
	svidv1.RegisterSVIDServer(s, f)
	debugv1.RegisterDebugServer(s, f)
	localauthorityv1.RegisterLocalAuthorityServer(s, f)
	trustdomainv1.RegisterTrustDomainServer(s, f)
	go s.Serve(l)
	t.Cleanup(s.Stop)
	return f
}

func (f *fakeSPIRE) GetBundle(context.Context, *bundlev1.GetBundleRequest) (*types.Bundle, error) {
	pub, _ := x509.MarshalPKIXPublicKey(f.jwtKey.Public())
	return &types.Bundle{TrustDomain: "spire.test", SequenceNumber: 3, RefreshHint: 300, X509Authorities: []*types.X509Certificate{{Asn1: f.ca.Raw}},
		JwtAuthorities: []*types.JWTKey{{KeyId: "k1", PublicKey: pub, ExpiresAt: time.Now().Add(time.Hour).Unix()}}}, nil
}

func (f *fakeSPIRE) ListFederatedBundles(context.Context, *bundlev1.ListFederatedBundlesRequest) (*bundlev1.ListFederatedBundlesResponse, error) {
	pub, _ := x509.MarshalPKIXPublicKey(f.jwtKey.Public())
	return &bundlev1.ListFederatedBundlesResponse{Bundles: []*types.Bundle{{TrustDomain: "partner.test", X509Authorities: []*types.X509Certificate{{Asn1: f.ca.Raw, Tainted: true}},
		JwtAuthorities: []*types.JWTKey{{KeyId: "old", PublicKey: pub, ExpiresAt: time.Now().Add(-time.Hour).Unix()}}}}}, nil
}

func (f *fakeSPIRE) ListFederationRelationships(context.Context, *trustdomainv1.ListFederationRelationshipsRequest) (*trustdomainv1.ListFederationRelationshipsResponse, error) {
	return &trustdomainv1.ListFederationRelationshipsResponse{FederationRelationships: []*types.FederationRelationship{
		{TrustDomain: "partner.test", BundleEndpointUrl: "https://partner.test/bundle", BundleEndpointProfile: &types.FederationRelationship_HttpsWeb{HttpsWeb: &types.HTTPSWebProfile{}}},
		{TrustDomain: "lab.test", BundleEndpointUrl: "http://lab.test:8443", BundleEndpointProfile: &types.FederationRelationship_HttpsSpiffe{HttpsSpiffe: &types.HTTPSSPIFFEProfile{EndpointSpiffeId: "spiffe://lab.test/spire/server"}}},
	}}, nil
}

func (f *fakeSPIRE) GetInfo(context.Context, *debugv1.GetInfoRequest) (*debugv1.GetInfoResponse, error) {
	return &debugv1.GetInfoResponse{Uptime: 90, AgentsCount: int32(len(f.agents)), EntriesCount: int32(len(f.entries)),
		SvidChain: []*debugv1.GetInfoResponse_Cert{{Id: spireID("/spire/server"), ExpiresAt: time.Now().Add(time.Hour).Unix(), Subject: "O=SPIRE"}}}, nil
}

func (f *fakeSPIRE) GetX509AuthorityState(context.Context, *localauthorityv1.GetX509AuthorityStateRequest) (*localauthorityv1.GetX509AuthorityStateResponse, error) {
	return &localauthorityv1.GetX509AuthorityStateResponse{Active: &localauthorityv1.AuthorityState{AuthorityId: "x1", ExpiresAt: f.ca.NotAfter.Unix()}}, nil
}

func (f *fakeSPIRE) GetJWTAuthorityState(context.Context, *localauthorityv1.GetJWTAuthorityStateRequest) (*localauthorityv1.GetJWTAuthorityStateResponse, error) {
	return &localauthorityv1.GetJWTAuthorityStateResponse{Active: &localauthorityv1.AuthorityState{AuthorityId: "k1", ExpiresAt: time.Now().Add(time.Hour).Unix()}}, nil
}

func (f *fakeSPIRE) ListEntries(_ context.Context, r *entryv1.ListEntriesRequest) (*entryv1.ListEntriesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	// Two pages, to exercise paging.
	var match []*types.Entry
	for _, e := range f.entries {
		if r.Filter.GetBySpiffeId() != nil && spiffeIDOf(e.SpiffeId) != spiffeIDOf(r.Filter.BySpiffeId) {
			continue
		}
		match = append(match, e)
	}
	if r.PageToken == "" && len(match) > 2 {
		return &entryv1.ListEntriesResponse{Entries: match[:2], NextPageToken: "2"}, nil
	}
	if r.PageToken == "2" {
		match = match[2:]
	}
	return &entryv1.ListEntriesResponse{Entries: match}, nil
}

func (f *fakeSPIRE) GetEntry(_ context.Context, r *entryv1.GetEntryRequest) (*types.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.Id == r.Id {
			return e, nil
		}
	}
	return nil, status.Error(codes.NotFound, "entry not found")
}

func (f *fakeSPIRE) BatchCreateEntry(_ context.Context, r *entryv1.BatchCreateEntryRequest) (*entryv1.BatchCreateEntryResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var res []*entryv1.BatchCreateEntryResponse_Result
	for _, e := range r.Entries {
		dup := false
		for _, x := range f.entries {
			if spiffeIDOf(x.SpiffeId) == spiffeIDOf(e.SpiffeId) && spiffeIDOf(x.ParentId) == spiffeIDOf(e.ParentId) {
				res = append(res, &entryv1.BatchCreateEntryResponse_Result{Status: &types.Status{Code: int32(codes.AlreadyExists), Message: "similar entry already exists"}, Entry: x})
				dup = true
			}
		}
		if !dup {
			e.Id = "new-" + e.SpiffeId.Path
			f.entries = append(f.entries, e)
			res = append(res, &entryv1.BatchCreateEntryResponse_Result{Status: &types.Status{}, Entry: e})
		}
	}
	return &entryv1.BatchCreateEntryResponse{Results: res}, nil
}

func (f *fakeSPIRE) BatchDeleteEntry(_ context.Context, r *entryv1.BatchDeleteEntryRequest) (*entryv1.BatchDeleteEntryResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var res []*entryv1.BatchDeleteEntryResponse_Result
	for _, id := range r.Ids {
		st := &types.Status{Code: int32(codes.NotFound), Message: "entry not found"}
		for i, e := range f.entries {
			if e.Id == id {
				f.entries = append(f.entries[:i], f.entries[i+1:]...)
				st = &types.Status{}
				break
			}
		}
		res = append(res, &entryv1.BatchDeleteEntryResponse_Result{Id: id, Status: st})
	}
	return &entryv1.BatchDeleteEntryResponse{Results: res}, nil
}

func (f *fakeSPIRE) ListAgents(context.Context, *agentv1.ListAgentsRequest) (*agentv1.ListAgentsResponse, error) {
	return &agentv1.ListAgentsResponse{Agents: f.agents}, nil
}

func (f *fakeSPIRE) CreateJoinToken(_ context.Context, r *agentv1.CreateJoinTokenRequest) (*types.JoinToken, error) {
	f.tokens++
	return &types.JoinToken{Value: "tok-123", ExpiresAt: time.Now().Add(time.Duration(r.Ttl) * time.Second).Unix()}, nil
}

func (f *fakeSPIRE) MintX509SVID(_ context.Context, r *svidv1.MintX509SVIDRequest) (*svidv1.MintX509SVIDResponse, error) {
	if f.denyMint {
		return nil, status.Error(codes.PermissionDenied, "authorization denied for method /spire.api.server.svid.v1.SVID/MintX509SVID")
	}
	csr, err := x509.ParseCertificateRequest(r.Csr)
	if err != nil || len(csr.URIs) != 1 {
		return nil, status.Error(codes.InvalidArgument, "bad CSR")
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Duration(r.Ttl) * time.Second),
		URIs: csr.URIs, DNSNames: csr.DNSNames, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true}
	if r.Ttl == 0 || r.Ttl > 1800 {
		tmpl.NotAfter = time.Now().Add(30 * time.Minute) // capped, as by the CA's lifetime
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, f.ca, csr.PublicKey, f.caKey)
	return &svidv1.MintX509SVIDResponse{Svid: &types.X509SVID{CertChain: [][]byte{der}, ExpiresAt: tmpl.NotAfter.Unix()}}, nil
}

func (f *fakeSPIRE) MintJWTSVID(_ context.Context, r *svidv1.MintJWTSVIDRequest) (*svidv1.MintJWTSVIDResponse, error) {
	aud := []any{}
	for _, a := range r.Audience {
		aud = append(aud, a)
	}
	exp := time.Now().Add(5 * time.Minute).Unix()
	tok, err := signJWS(f.jwtKey, "ES256", M{"kid": "k1", "typ": "JWT"}, M{"sub": spiffeIDOf(r.Id), "aud": aud, "exp": exp, "iat": time.Now().Unix()})
	if err != nil {
		return nil, err
	}
	return &svidv1.MintJWTSVIDResponse{Svid: &types.JWTSVID{Token: tok, Id: r.Id, ExpiresAt: exp}}, nil
}

func TestSPIREAdminSocket(t *testing.T) {
	f := newFakeSPIRE(t)
	sock := M{"socket": f.socket}

	info := run(t, "spire.info", sock, nil)
	wantStatus(t, info, "server SVID is spiffe://spire.test/spire/server", "pass")
	wantStatus(t, info, "an unexpired X.509 authority is active", "pass")
	wantStatus(t, info, "bundle has authorities", "pass")
	if info["uptime"] != "1m30s" || info["entries"] != int32(4) || info["via"] != "admin socket "+f.socket {
		t.Errorf("info: %v", info)
	}
	if checkOf(info, "server authenticated as") != nil {
		t.Error("an mTLS check on the admin socket")
	}

	b := run(t, "spire.bundles", sock, nil)
	wantStatus(t, b, "partner.test: X.509 authority 1", "warn") // tainted
	wantStatus(t, b, "partner.test: JWT authority old", "warn") // expired
	wantStatus(t, b, "partner.test: bundle endpoint is https", "pass")
	wantStatus(t, b, "lab.test: bundle endpoint is https", "fail")
	wantStatus(t, b, "lab.test: the server holds a bundle for it", "fail")

	all := run(t, "spire.entries", sock, nil)
	if all["count"] != 4 {
		t.Fatalf("entries (paged): %v", all["count"])
	}
	wantStatus(t, all, "every entry's parent is the server, an agent or another entry", "warn")
	if c := checkOf(all, "every entry's parent"); !strings.Contains(c.Detail, "/batch") || strings.Contains(c.Detail, "/web") || strings.Contains(c.Detail, "/ops") {
		t.Errorf("orphans: %s", c.Detail)
	}
	wantStatus(t, all, "no entry has expired", "warn")
	wantStatus(t, all, "X509-SVID TTLs are at most 24h", "warn")
	wantStatus(t, all, "admin entries", "info")
	one := run(t, "spire.entries", merge(sock, M{"spiffe_id": "spiffe://spire.test/web"}), nil)
	if one["count"] != 1 || checkOf(one, "every entry's parent") != nil {
		t.Errorf("filtered: %v", one)
	}
	if _, err := tryOp(t, "spire.entries", merge(sock, M{"id": "nope"})); err == nil || !strings.Contains(err.Error(), "NotFound") {
		t.Errorf("GetEntry: %v", err)
	}

	ag := run(t, "spire.agents", sock, nil)
	wantStatus(t, ag, "every agent's SVID is unexpired", "warn")
	wantStatus(t, ag, "banned agents", "info")
	wantStatus(t, ag, "agents that cannot re-attest", "info")

	x := run(t, "spire.mint", merge(sock, M{"spiffe_id": "spiffe://spire.test/web", "dns_names": "web.spire.test", "ttl": 3600}), nil)
	noFailures(t, x)
	wantStatus(t, x, "chain verifies against the trust bundle", "pass")
	wantStatus(t, x, "SPIFFE ID is the expected one", "pass")
	wantStatus(t, x, "DNS names as requested", "pass")
	wantStatus(t, x, "lifetime as requested", "info")
	if !strings.Contains(str(x["key_pem"]), "PRIVATE KEY") {
		t.Error("no key returned with the minted SVID")
	}
	j := run(t, "spire.mint", merge(sock, M{"spiffe_id": "spiffe://spire.test/web", "type": "jwt", "audience": "api"}), nil)
	noFailures(t, j)
	wantStatus(t, j, "signature", "pass")
	wantStatus(t, j, "aud contains the expected audience", "pass")
	if _, err := tryOp(t, "spire.mint", merge(sock, M{"spiffe_id": "spiffe://spire.test/web", "type": "jwt"})); err == nil {
		t.Error("JWT-SVID without audience")
	}
	f.denyMint = true
	if _, err := tryOp(t, "spire.mint", merge(sock, M{"spiffe_id": "spiffe://spire.test/web"})); err == nil || !strings.Contains(err.Error(), "admin_ids") {
		t.Errorf("permission denied: %v", err)
	}

	cr := run(t, "spire.entry_create", merge(sock, M{"spiffe_id": "spiffe://spire.test/api", "parent_id": "spiffe://spire.test/node", "selectors": "unix:uid:1002,unix:gid:50"}), nil)
	wantStatus(t, cr, "server created the entry", "pass")
	if e := cr["entry"].(M); e["id"] != "new-/api" || len(e["selectors"].([]string)) != 2 {
		t.Fatalf("created: %v", e)
	}
	dup := run(t, "spire.entry_create", merge(sock, M{"spiffe_id": "spiffe://spire.test/api", "parent_id": "spiffe://spire.test/node", "selectors": "unix:uid:1002"}), nil)
	wantStatus(t, dup, "server created the entry", "info")
	if _, err := tryOp(t, "spire.entry_create", merge(sock, M{"spiffe_id": "spiffe://spire.test/x", "parent_id": "spiffe://spire.test/node", "selectors": "uid1000"})); err == nil {
		t.Error("selector without a type")
	}
	del := run(t, "spire.entry_delete", merge(sock, M{"ids": "new-/api,nope"}), nil)
	wantStatus(t, del, "deleted new-/api", "pass")
	wantStatus(t, del, "deleted nope", "fail")
	if len(f.entries) != 4 {
		t.Errorf("%d entries after the delete", len(f.entries))
	}

	jt := run(t, "spire.join_token", sock, nil)
	if jt["agent_id"] != "spiffe://spire.test/spire/agent/join_token/tok-123" || f.tokens != 1 {
		t.Errorf("join token: %v", jt)
	}

	// No server on the socket: says so.
	if _, err := tryOp(t, "spire.info", M{"socket": filepath.Join(filepath.Dir(f.socket), "none.sock"), "timeout": 2}); err == nil || !strings.Contains(err.Error(), "socket_path") {
		t.Errorf("no server: %v", err)
	}
}

func TestSPIRETCPNeedsClientSVID(t *testing.T) {
	if _, err := tryOp(t, "spire.info", M{"server": "localhost:1"}); err == nil || !strings.Contains(err.Error(), "client X509-SVID") {
		t.Errorf("no client SVID: %v", err)
	}
	if _, err := tryOp(t, "spire.info", M{"server": "localhost:1", "svid": "x"}); err == nil || !strings.Contains(err.Error(), "svid_key") {
		t.Errorf("no key: %v", err)
	}
}

// A stored client SVID key only goes to the profile's SPIRE server, and an
// MCP caller cannot swap the trust anchors the server is verified with.
func TestSPIREStoredKeyGuard(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir())
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := os.WriteFile(dir+"/svid.key", []byte(keyPEM(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("IDPDBG_CONFIG", dir+"/config.json")
	t.Setenv("IDPDBG_ALLOWED_HOSTS", "")
	cfg := `{"profiles":{"spire":{"server":"spire.example:8081","svid":"x","svid_key":"` + dir + `/svid.key","bundle":"x"}}}`
	if err := os.WriteFile(dir+"/config.json", []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		args M
		want string
	}{
		{M{"profile": "spire", "server": "evil.example:8081"}, "not named in the active profile"},
		{M{"profile": "spire", "server": "spire.example:9999"}, "not named in the active profile"},
		{M{"profile": "spire", "server": "https://evil.example"}, "not named"},
		{M{"profile": "spire", "bundle": "x"}, "caller-supplied bundle"},
		{M{"profile": "spire", "trust_domain": "evil.test"}, "caller-supplied trust_domain"},
	} {
		_, err := runOp(context.Background(), findOp("spire.info"), c.args, false, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v: %v", c.args, err)
		}
	}
	// The profile's own server gets past the guard (and fails later on the
	// placeholder SVID).
	_, err := runOp(context.Background(), findOp("spire.info"), M{"profile": "spire"}, false, nil)
	if err == nil || strings.Contains(err.Error(), "refusing") {
		t.Errorf("profile server: %v", err)
	}
	if o, a := spireOrigin("[::1]:8081"); o != "spire://::1:8081" || a != "[::1]:8081" {
		t.Errorf("IPv6: %s %s", o, a)
	}
	if !findOp("spire.mint").Mutating {
		t.Error("spire.mint is marked read-only, yet issues credentials")
	}
}
