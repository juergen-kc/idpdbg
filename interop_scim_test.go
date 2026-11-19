//go:build interop

// Interop tests against a real SCIM 2.0 server (i2scim), run by the
// "interop" CI jobs. Locally:
//
//	scripts/scim.sh
//	go test -tags interop -run SCIM -v .
package main

import (
	"encoding/base64"
	"net/http"
	"testing"
)

func scimBase() string { return smbEnv("IDPDBG_SCIM_URL", "http://localhost:8090") }

func scimArgs(extra ...M) M {
	basic := base64.StdEncoding.EncodeToString([]byte("admin:idpdbg-interop")) // fixture from scripts/scim.sh
	return merge(M{"base_url": scimBase(), "headers": M{"Authorization": "Basic " + basic}}, extra...)
}

func TestSCIMInterop(t *testing.T) {
	if resp, err := http.Get(scimBase() + "/ServiceProviderConfig"); err != nil {
		t.Fatalf("SCIM server not reachable at %s: %v (run scripts/scim.sh)", scimBase(), err)
	} else {
		resp.Body.Close()
	}

	t.Run("scim discover", func(t *testing.T) {
		res := kcRun(t, "scim.discover", scimArgs(), nil)
		kcWant(t, res, "GET /ServiceProviderConfig", "pass")
		kcWant(t, res, "GET /ResourceTypes", "pass")
		kcWant(t, res, "GET /Schemas", "pass")
		if f, _ := find(res, "features", "patch").(bool); !f {
			t.Errorf("PATCH not reported as supported")
		}
		// What i2scim 0.10.6 does differently from RFC 7643/7644:
		// no Content-Type header, and no etag member in ServiceProviderConfig.
		kcWant(t, res, "/ServiceProviderConfig Content-Type is application/scim+json", "warn")
		kcWant(t, res, "ServiceProviderConfig: etag present", "fail")
	})

	t.Run("scim scenario user_lifecycle", func(t *testing.T) {
		res := kcRun(t, "scim.scenario", scimArgs(M{"scenario": "user_lifecycle"}), nil)
		for _, step := range []string{"create user", "read user", "filter by userName", "update name (PATCH replace)", "verify patch",
			"replace user (PUT)", "deactivate (PATCH active=false)", "verify deactivation", "delete user", "verify deletion"} {
			kcWant(t, res, step, "pass")
		}
		kcWant(t, res, "duplicate userName refused", "pass")
		// i2scim 0.10.6 creates a User without the required userName.
		kcWant(t, res, "user without userName refused", "fail")
	})

	for _, sc := range []string{"user_lifecycle", "group_lifecycle"} {
		t.Run("scim scenario "+sc+": protocol details", func(t *testing.T) {
			res := kcRun(t, "scim.scenario", scimArgs(M{"scenario": sc}), nil)
			if sc == "group_lifecycle" {
				kcClean(t, res)
			}
			kcWant(t, res, "created resources have a Location header matching meta.location", "pass")
			kcWant(t, res, "ETag headers match meta.version", "pass")
			kcWant(t, res, "verify deletion", "pass")
			// i2scim gives "status" as a number in its error messages.
			kcWant(t, res, "error responses are SCIM error messages", "warn")
		})
	}

	t.Run("scim request: filter", func(t *testing.T) {
		res := kcRun(t, "scim.request", scimArgs(M{"path": `/Users?filter=userName sw "idpdbg-"`}), nil)
		kcWant(t, res, "response status", "pass")
	})

	t.Run("scim request: wrong credentials", func(t *testing.T) {
		basic := base64.StdEncoding.EncodeToString([]byte("admin:wrong"))
		res := kcRun(t, "scim.request", M{"base_url": scimBase(), "headers": M{"Authorization": "Basic " + basic}, "path": "/Users"}, nil)
		if c := checkOf(res, "response status"); c == nil || c.Detail != "HTTP 401" {
			t.Errorf("wrong credentials: want HTTP 401, got %+v", c)
		}
	})

	t.Run("scim bulk: not advertised", func(t *testing.T) {
		res := kcRun(t, "scim.bulk", scimArgs(M{"operations": []any{M{"method": "POST", "path": "/Users", "bulkId": "u1",
			"data": M{"schemas": []any{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "idpdbg-bulk@example.com"}}}}), nil)
		kcWant(t, res, "bulk supported", "warn")
	})
}
