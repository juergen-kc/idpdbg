package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type spiffeFixture struct {
	rootKey, leafKey, jwtKey *ecdsa.PrivateKey
	root, leaf               *x509.Certificate
	bundleJSON, rootPEM      string
}

func newSPIFFEFixture(t *testing.T, leafURIs []string, leafIsCA bool) *spiffeFixture {
	f := &spiffeFixture{}
	f.rootKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.leafKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.jwtKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	td, _ := url.Parse("spiffe://example.org")
	rootT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.org root"}, URIs: []*url.URL{td},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	f.root, _ = sign(rootT, rootT, f.rootKey.Public(), f.rootKey)
	leafT := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: leafIsCA, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	if leafIsCA {
		leafT.KeyUsage |= x509.KeyUsageCertSign
	}
	for _, u := range leafURIs {
		pu, _ := url.Parse(u)
		leafT.URIs = append(leafT.URIs, pu)
	}
	f.leaf, _ = sign(leafT, f.root, f.leafKey.Public(), f.rootKey)
	f.rootPEM = certPEM(f.root)
	jwk, _ := publicJWK(f.jwtKey.Public())
	jwk["kid"], jwk["use"] = "jwt-1", "jwt-svid"
	x5, _ := publicJWK(f.rootKey.Public())
	x5["use"], x5["x5c"] = "x509-svid", []string{base64.StdEncoding.EncodeToString(f.root.Raw)}
	b, _ := json.Marshal(M{"keys": []M{x5, jwk}, "spiffe_sequence": 7, "spiffe_refresh_hint": 300})
	f.bundleJSON = string(b)
	return f
}

func (f *spiffeFixture) jwt(t *testing.T, claims M, header M) string {
	if header == nil {
		header = M{"kid": "jwt-1", "typ": "JWT"}
	}
	tok, err := signJWS(f.jwtKey, "ES256", header, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestSPIFFE(t *testing.T) {
	const wl = "spiffe://example.org/ns/prod/sa/web"
	f := newSPIFFEFixture(t, []string{wl}, false)

	t.Run("IDs", func(t *testing.T) {
		noFailures(t, run(t, "spiffe.id", M{"id": wl}, nil))
		for _, bad := range []string{"spiffe://Example.org/x", "spiffe://example.org/a/../b", "https://example.org/x", "spiffe://example.org:443/x", "spiffe://example.org/x?q=1", "spiffe://example.org/"} {
			wantStatus(t, run(t, "spiffe.id", M{"id": bad}, nil), "valid SPIFFE ID", "fail")
		}
	})

	t.Run("X509-SVID", func(t *testing.T) {
		chain := certPEM(f.leaf)
		res := run(t, "spiffe.svid", M{"svid": chain, "bundle": f.bundleJSON, "expected_id": wl}, nil)
		noFailures(t, res)
		wantStatus(t, res, "chain verifies against the trust bundle", "pass")
		wantStatus(t, run(t, "spiffe.svid", M{"svid": chain, "bundle": f.rootPEM}, nil), "chain verifies", "pass")
		other := newSPIFFEFixture(t, []string{wl}, false)
		wantStatus(t, run(t, "spiffe.svid", M{"svid": chain, "bundle": other.bundleJSON}, nil), "chain verifies", "fail")
		wantStatus(t, run(t, "spiffe.svid", M{"svid": chain, "bundle": f.bundleJSON, "expected_id": "spiffe://example.org/other"}, nil), "expected one", "fail")
		two := newSPIFFEFixture(t, []string{wl, "spiffe://example.org/second"}, false)
		wantStatus(t, run(t, "spiffe.svid", M{"svid": certPEM(two.leaf)}, nil), "exactly one URI SAN", "fail")
		ca := newSPIFFEFixture(t, []string{wl}, true)
		r := run(t, "spiffe.svid", M{"svid": certPEM(ca.leaf)}, nil)
		wantStatus(t, r, "leaf is not a CA", "fail")
		wantStatus(t, r, "excludes keyCertSign", "fail")
	})

	t.Run("JWT-SVID", func(t *testing.T) {
		good := f.jwt(t, M{"sub": wl, "aud": "payments", "exp": time.Now().Add(5 * time.Minute).Unix()}, nil)
		res := run(t, "spiffe.svid", M{"svid": good, "bundle": f.bundleJSON, "audience": "payments"}, nil)
		noFailures(t, res)
		wantStatus(t, res, "signature", "pass")
		for name, tc := range map[string]struct {
			args  M
			check string
		}{
			"wrong audience": {M{"svid": good, "bundle": f.bundleJSON, "audience": "billing"}, "aud contains"},
			"unknown kid":    {M{"svid": f.jwt(t, M{"sub": wl, "aud": "payments", "exp": time.Now().Add(time.Minute).Unix()}, M{"kid": "nope"}), "bundle": f.bundleJSON}, "kid is a JWT authority"},
			"no expiry":      {M{"svid": f.jwt(t, M{"sub": wl, "aud": "payments"}, nil), "bundle": f.bundleJSON}, "exp present"},
			"non-SPIFFE sub": {M{"svid": f.jwt(t, M{"sub": "alice", "aud": "payments", "exp": time.Now().Add(time.Minute).Unix()}, nil), "bundle": f.bundleJSON, "trust_domain": "example.org"}, "sub is a SPIFFE ID"},
			"HMAC":           {M{"svid": signHS([]byte("k"), "HS256", M{"kid": "jwt-1"}, M{"sub": wl, "aud": "x", "exp": time.Now().Add(time.Minute).Unix()}), "bundle": f.bundleJSON}, "allowed asymmetric"},
		} {
			t.Run(name, func(t *testing.T) { wantStatus(t, run(t, "spiffe.svid", tc.args, nil), tc.check, "fail") })
		}
	})

	t.Run("bundle endpoint", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(f.bundleJSON)) }))
		defer srv.Close()
		res := run(t, "spiffe.bundle", M{"trust_domain": "example.org", "endpoint": srv.URL}, nil)
		noFailures(t, res)
		b := res["bundle"].(M)
		if b["sequence"] != uint64(7) || len(b["jwt_authority_kids"].([]string)) != 1 {
			t.Errorf("bundle: %v", b)
		}
	})

	t.Run("Workload API", func(t *testing.T) {
		// A unix socket on POSIX; go-spiffe only takes tcp or npipe on Windows.
		var l net.Listener
		var socket string
		if runtime.GOOS == "windows" {
			var err error
			if l, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
				t.Fatal(err)
			}
			socket = "tcp://" + l.Addr().String()
		} else {
			dir, _ := os.MkdirTemp("/tmp", "spf") // unix socket paths must be short
			defer os.RemoveAll(dir)
			sock := dir + "/agent.sock"
			var err error
			if l, err = net.Listen("unix", sock); err != nil {
				t.Fatal(err)
			}
			socket = "unix://" + sock
		}
		gs := grpc.NewServer()
		workload.RegisterSpiffeWorkloadAPIServer(gs, &fakeWorkloadAPI{f: f, id: wl, t: t})
		go gs.Serve(l)
		defer gs.Stop()
		res := run(t, "spiffe.fetch", M{"socket": socket, "audience": "payments", "timeout": 5}, nil)
		noFailures(t, res)
		for _, n := range []string{"X.509 context fetched", "SVID 1: chain verifies against the trust bundle", "JWT-SVID fetched", "signature"} {
			wantStatus(t, res, n, "pass")
		}
		if res["x509_svids"].([]M)[0]["spiffe_id"].(M)["id"] != wl {
			t.Errorf("svid: %v", res["x509_svids"])
		}
	})
}

// fakeWorkloadAPI serves one identity the way a SPIRE agent would, and like
// one refuses calls without the workload.spiffe.io security header.
type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	f  *spiffeFixture
	id string
	t  *testing.T
}

func headerOK(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("workload.spiffe.io"); len(v) != 1 || v[0] != "true" {
		return status.Error(codes.InvalidArgument, "security header missing from request")
	}
	return nil
}

func (a *fakeWorkloadAPI) FetchX509SVID(_ *workload.X509SVIDRequest, s grpc.ServerStreamingServer[workload.X509SVIDResponse]) error {
	if err := headerOK(s.Context()); err != nil {
		return err
	}
	key, _ := x509.MarshalPKCS8PrivateKey(a.f.leafKey)
	s.Send(&workload.X509SVIDResponse{Svids: []*workload.X509SVID{{SpiffeId: a.id, X509Svid: a.f.leaf.Raw, X509SvidKey: key, Bundle: a.f.root.Raw, Hint: "internal"}}})
	<-s.Context().Done()
	return nil
}

func (a *fakeWorkloadAPI) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	if err := headerOK(ctx); err != nil {
		return nil, err
	}
	tok := a.f.jwt(a.t, M{"sub": a.id, "aud": strings.Join(req.Audience, ","), "exp": time.Now().Add(5 * time.Minute).Unix()}, nil)
	return &workload.JWTSVIDResponse{Svids: []*workload.JWTSVID{{SpiffeId: a.id, Svid: tok}}}, nil
}

func (a *fakeWorkloadAPI) FetchJWTBundles(_ *workload.JWTBundlesRequest, s grpc.ServerStreamingServer[workload.JWTBundlesResponse]) error {
	if err := headerOK(s.Context()); err != nil {
		return err
	}
	jwk, _ := publicJWK(a.f.jwtKey.Public())
	jwk["kid"], jwk["use"] = "jwt-1", "jwt-svid"
	b, _ := json.Marshal(M{"keys": []M{jwk}})
	s.Send(&workload.JWTBundlesResponse{Bundles: map[string][]byte{"spiffe://example.org": b}})
	<-s.Context().Done()
	return nil
}
