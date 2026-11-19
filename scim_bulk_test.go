package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// mockBulkSCIM handles /Bulk, resolving bulkId references the way RFC 7644
// §3.7.2 describes, and records what it created.
func mockBulkSCIM(t *testing.T, supported bool) (*httptest.Server, map[string]M) {
	var mu sync.Mutex
	created := map[string]M{}
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", scimJSON)
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/ServiceProviderConfig":
			json.NewEncoder(w).Encode(M{"bulk": M{"supported": supported, "maxOperations": 3, "maxPayloadSize": 1048576}})
		case "/Bulk":
			var req struct {
				Operations   []M `json:"Operations"`
				FailOnErrors int `json:"failOnErrors"`
			}
			json.NewDecoder(r.Body).Decode(&req)
			mu.Lock()
			defer mu.Unlock()
			ids := map[string]string{}
			results := []M{}
			failures := 0
			for _, op := range req.Operations {
				if req.FailOnErrors > 0 && failures >= req.FailOnErrors {
					break
				}
				data, _ := json.Marshal(op["data"])
				body := string(data)
				unresolved := false
				for bid, id := range ids {
					body = strings.ReplaceAll(body, `"bulkId:`+bid+`"`, `"`+id+`"`)
				}
				unresolved = strings.Contains(body, `"bulkId:`)
				res := M{"method": op["method"]}
				if b := str(op["bulkId"]); b != "" {
					res["bulkId"] = b
				}
				var obj M
				json.Unmarshal([]byte(body), &obj)
				switch {
				case unresolved:
					res["status"], res["response"] = "409", M{"detail": "unresolved bulkId reference"}
					failures++
				case str(op["method"]) == "POST" && obj["userName"] == "dup":
					res["status"], res["response"] = "409", M{"detail": "userName already exists"}
					failures++
				case str(op["method"]) == "POST":
					n++
					id := fmt.Sprintf("id%d", n)
					obj["id"] = id
					created[id] = obj
					if b := str(op["bulkId"]); b != "" {
						ids[b] = id
					}
					res["status"], res["location"] = "201", "http://"+r.Host+str(op["path"])+"/"+id
				default:
					res["status"] = "200"
				}
				results = append(results, res)
			}
			json.NewEncoder(w).Encode(M{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:BulkResponse"}, "Operations": results})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, created
}

func TestSCIMBulk(t *testing.T) {
	srv, created := mockBulkSCIM(t, true)
	ops := []any{
		M{"method": "POST", "path": "/Users", "bulkId": "u1", "data": M{"userName": "bulk-user"}},
		M{"method": "POST", "path": "/Groups", "bulkId": "g1", "data": M{"displayName": "G", "members": []M{{"value": "bulkId:u1"}}}},
	}
	res := run(t, "scim.bulk", M{"base_url": srv.URL, "scim_token": "tok", "operations": ops}, nil)
	noFailures(t, res)
	wantStatus(t, res, "bulk supported", "pass")
	wantStatus(t, res, "operation 2: POST /Groups: location returned", "pass")
	// The group's member must point at the user created in the same request.
	var group M
	for _, o := range created {
		if o["displayName"] == "G" {
			group = o
		}
	}
	if members, _ := group["members"].([]any); len(members) != 1 || members[0].(map[string]any)["value"] == "bulkId:u1" {
		t.Errorf("bulkId reference not resolved: %v", group)
	}

	// failOnErrors stops processing; the tool reports what never ran.
	bad := []any{
		M{"method": "POST", "path": "/Users", "data": M{"userName": "dup"}},
		M{"method": "POST", "path": "/Users", "data": M{"userName": "dup"}},
		M{"method": "POST", "path": "/Users", "data": M{"userName": "fine"}},
		M{"method": "POST", "path": "/Users", "data": M{"userName": "fine2"}},
	}
	res = run(t, "scim.bulk", M{"base_url": srv.URL, "scim_token": "tok", "operations": bad, "fail_on_errors": 1}, nil)
	wantStatus(t, res, "operation 1: POST /Users", "fail")
	wantStatus(t, res, "operation 2: POST /Users", "warn")
	wantStatus(t, res, "within maxOperations", "warn")
	if res["failed"] != 1 {
		t.Errorf("failed=%v", res["failed"])
	}

	unsupported, _ := mockBulkSCIM(t, false)
	wantStatus(t, run(t, "scim.bulk", M{"base_url": unsupported.URL, "scim_token": "tok", "operations": ops[:1]}, nil), "bulk supported", "warn")
}
