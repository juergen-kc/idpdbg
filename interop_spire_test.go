//go:build interop

// Interop tests against a SPIRE server (and one agent), run by the
// "interop" CI jobs. Locally:
//
//	scripts/spire.sh
//	go test -tags interop -run SPIRE -v .
//
// scripts/spire.sh mints an admin X509-SVID (spiffe://spire.test/idpdbg-admin,
// in the server's admin_ids) for the TCP API and writes it, its key and the
// trust bundle to testdata/spire/run. On Linux the admin socket is there too.
package main

import (
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	spireServer = smbEnv("IDPDBG_SPIRE_SERVER", "localhost:18081")
	spireDir    = smbEnv("IDPDBG_SPIRE_DIR", "testdata/spire/run")
)

func spireFile(t *testing.T, name string) string {
	b, err := os.ReadFile(filepath.Join(spireDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSPIREInterop(t *testing.T) {
	if c, err := net.DialTimeout("tcp", spireServer, 3*time.Second); err != nil {
		t.Fatalf("SPIRE server not reachable at %s: %v (run scripts/spire.sh)", spireServer, err)
	} else {
		c.Close()
	}
	tcp := M{"server": spireServer, "svid": spireFile(t, "admin-svid.pem"), "svid_key": spireFile(t, "admin-key.pem"), "bundle": spireFile(t, "bundle.pem")}

	t.Run("spire info over mTLS", func(t *testing.T) {
		res := kcRun(t, "spire.info", tcp, nil)
		kcClean(t, res)
		kcWant(t, res, "server authenticated as spiffe://spire.test/spire/server", "pass")
		kcWant(t, res, "an unexpired X.509 authority is active", "pass")
		kcWant(t, res, "an unexpired JWT authority is active", "pass")
		if res["trust_domain"] != "spire.test" {
			t.Errorf("trust domain: %v", res["trust_domain"])
		}
	})

	t.Run("spire agents: the join token agent", func(t *testing.T) {
		res := kcRun(t, "spire.agents", tcp, nil)
		kcClean(t, res)
		found := false
		for _, a := range res["agents"].([]M) {
			found = found || a["attestation_type"] == "join_token" && strings.HasPrefix(str(a["id"]), "spiffe://spire.test/spire/agent/join_token/")
		}
		if !found {
			t.Errorf("no join_token agent: %v", res["agents"])
		}
	})

	t.Run("spire entry create, list, mint, delete", func(t *testing.T) {
		id := "spiffe://spire.test/idpdbg-interop/" + hex.EncodeToString(randomBytes(4))
		cr := kcRun(t, "spire.entry_create", merge(tcp, M{"spiffe_id": id, "parent_id": "spiffe://spire.test/agent/ci", "selectors": "unix:uid:4242", "dns_names": "interop.spire.test"}), nil)
		kcClean(t, cr)
		kcWant(t, cr, "server created the entry", "pass")
		eid := str(cr["entry"].(M)["id"])
		again := kcRun(t, "spire.entry_create", merge(tcp, M{"spiffe_id": id, "parent_id": "spiffe://spire.test/agent/ci", "selectors": "unix:uid:4242", "dns_names": "interop.spire.test"}), nil)
		kcWant(t, again, "server created the entry", "info")

		ls := kcRun(t, "spire.entries", merge(tcp, M{"spiffe_id": id}), nil)
		kcClean(t, ls)
		if ls["count"] != 1 || ls["entries"].([]M)[0]["id"] != eid {
			t.Fatalf("entries for %s: %v", id, ls["entries"])
		}
		all := kcRun(t, "spire.entries", tcp, nil)
		if c := checkOf(all, "every entry's parent is the server, an agent or another entry"); c == nil || strings.Contains(c.Detail, id) {
			t.Errorf("parent check: %+v", c)
		}

		x := kcRun(t, "spire.mint", merge(tcp, M{"spiffe_id": id, "dns_names": "interop.spire.test", "ttl": 600}), nil)
		kcClean(t, x)
		kcWant(t, x, "chain verifies against the trust bundle", "pass")
		kcWant(t, x, "DNS names as requested", "pass")
		j := kcRun(t, "spire.mint", merge(tcp, M{"spiffe_id": id, "type": "jwt", "audience": "interop"}), nil)
		kcClean(t, j)
		kcWant(t, j, "signature", "pass")

		// The minted SVID is not an admin: the server refuses it.
		notAdmin := merge(tcp, M{"svid": x["chain_pem"], "svid_key": x["key_pem"]})
		if _, err := tryOp(t, "spire.entries", notAdmin); err == nil || !strings.Contains(err.Error(), "PermissionDenied") {
			t.Errorf("non-admin SVID: %v", err)
		}

		del := kcRun(t, "spire.entry_delete", merge(tcp, M{"ids": eid}), nil)
		kcClean(t, del)
		if ls := kcRun(t, "spire.entries", merge(tcp, M{"spiffe_id": id}), nil); ls["count"] != 0 {
			t.Errorf("entry still there after the delete: %v", ls["entries"])
		}
	})

	t.Run("spire join token", func(t *testing.T) {
		res := kcRun(t, "spire.join_token", merge(tcp, M{"ttl": 60}), nil)
		kcClean(t, res)
		if !strings.HasPrefix(str(res["agent_id"]), "spiffe://spire.test/spire/agent/join_token/") || str(res["token"]) == "" {
			t.Errorf("join token: %v", res)
		}
	})

	t.Run("spire bundles", func(t *testing.T) {
		res := kcRun(t, "spire.bundles", tcp, nil)
		kcClean(t, res)
		kcWant(t, res, "bundle has authorities", "pass")
	})

	t.Run("spire: a server outside the bundle is refused", func(t *testing.T) {
		other := spireFile(t, "admin-svid.pem") // a leaf, not the trust domain's CA
		if _, err := tryOp(t, "spire.info", merge(tcp, M{"bundle": other, "timeout": 5})); err == nil {
			t.Error("server accepted without its CA in the bundle")
		}
	})

	t.Run("spire info over the admin socket", func(t *testing.T) {
		sock := filepath.Join(spireDir, "admin", "api.sock")
		if _, err := os.Stat(sock); err != nil {
			t.Skip("no admin socket here (Docker Desktop cannot share it)")
		}
		res := kcRun(t, "spire.info", M{"socket": sock}, nil)
		kcClean(t, res)
		kcWant(t, res, "server SVID is spiffe://spire.test/spire/server", "pass")
		kcWant(t, res, "server is serving", "pass")
		if res["uptime"] == nil {
			t.Errorf("no debug information over the admin socket: %v", res)
		}
	})
}
