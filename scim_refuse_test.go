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

// returningSCIM answers a duplicate userName with the existing user (200),
// as some servers do, accepts a user without userName (201), and gives a
// relative Location. idpdbg must not delete the scenario's own user.
func returningSCIM(t *testing.T) (*httptest.Server, *[]string) {
	var mu sync.Mutex
	users := map[string]M{}
	var deleted []string
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/SCIM+json") // case differs: still fine
		id := strings.TrimPrefix(r.URL.Path, "/Users/")
		switch {
		case r.Method == "POST" && r.URL.Path == "/Users":
			var body M
			json.NewDecoder(r.Body).Decode(&body)
			for uid, u := range users {
				if u["userName"] == body["userName"] && body["userName"] != nil {
					json.NewEncoder(w).Encode(merge(u, M{"id": uid}))
					return
				}
			}
			n++
			uid := fmt.Sprintf("u%d", n)
			body["id"] = uid
			body["meta"] = M{"location": "http://" + r.Host + "/Users/" + uid, "resourceType": "User"}
			users[uid] = body
			w.Header().Set("Location", "/Users/"+uid)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(body)
		case r.Method == "GET" && r.URL.Path == "/Users":
			res := []M{}
			for uid, u := range users {
				if strings.Contains(r.URL.Query().Get("filter"), fmt.Sprint(u["userName"])) {
					res = append(res, merge(u, M{"id": uid}))
				}
			}
			json.NewEncoder(w).Encode(M{"totalResults": len(res), "Resources": res})
		case users[id] == nil:
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(M{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:Error"}, "status": "404"})
		case r.Method == "DELETE":
			deleted = append(deleted, id)
			delete(users, id)
			w.WriteHeader(204)
		case r.Method == "PATCH":
			var body M
			json.NewDecoder(r.Body).Decode(&body)
			for _, o := range body["Operations"].([]any) {
				op := o.(map[string]any)
				switch op["path"] {
				case "name.givenName":
					users[id]["name"] = M{"givenName": op["value"]}
				case "active":
					users[id]["active"] = op["value"]
				}
			}
			json.NewEncoder(w).Encode(merge(users[id], M{"id": id}))
		case r.Method == "PUT":
			var body M
			json.NewDecoder(r.Body).Decode(&body)
			users[id] = body
			json.NewEncoder(w).Encode(merge(body, M{"id": id}))
		default:
			json.NewEncoder(w).Encode(merge(users[id], M{"id": id}))
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &deleted
}

func TestSCIMRefusalsNeverDeleteTheScenarioUser(t *testing.T) {
	srv, deleted := returningSCIM(t)
	res := run(t, "scim.scenario", M{"base_url": srv.URL, "scenario": "user_lifecycle"}, nil)
	c := checkOf(res, "duplicate userName refused")
	if c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "nothing was deleted") {
		t.Errorf("duplicate answered with 200: %+v", c)
	}
	c = checkOf(res, "user without userName refused")
	if c == nil || c.Status != "fail" || !strings.Contains(c.Detail, "was deleted again") {
		t.Errorf("user without userName: %+v", c)
	}
	// The scenario's own user (u1) survives until its own deletion at the end.
	for i, id := range *deleted {
		if id == "u1" && i != len(*deleted)-1 {
			t.Errorf("the scenario's user was deleted early: %v", *deleted)
		}
	}
	for _, step := range []string{"update name (PATCH replace)", "verify patch", "delete user", "verify deletion"} {
		wantStatus(t, res, step, "pass")
	}
	// A relative Location resolves to meta.location; the media type's case
	// does not matter.
	wantStatus(t, res, "created resources have a Location header matching meta.location", "pass")
	wantStatus(t, res, "responses use application/scim+json", "pass")
	wantStatus(t, res, "ETag headers match meta.version", "info") // no ETags sent
	wantStatus(t, res, "error responses are SCIM error messages", "pass")
}
