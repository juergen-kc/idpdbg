package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseSRVRData(t *testing.T) {
	// priority 0, weight 100, port 88, dc1.idpdbg.test.
	b := []byte{0, 0, 0, 100, 0, 88, 3, 'd', 'c', '1', 6, 'i', 'd', 'p', 'd', 'b', 'g', 4, 't', 'e', 's', 't', 0}
	r, err := parseSRVRData(b)
	if err != nil || r != (srvRecord{Target: "dc1.idpdbg.test.", Port: 88, Priority: 0, Weight: 100}) {
		t.Fatalf("%+v %v", r, err)
	}
	for name, bad := range map[string][]byte{
		"short":      b[:5],
		"unended":    b[:len(b)-1],
		"overlong":   {0, 0, 0, 0, 0, 88, 9, 'a', 'b', 0},
		"compressed": {0, 0, 0, 0, 0, 88, 0xc0, 12},
		"dot inside": {0, 0, 0, 0, 0, 88, 11, 'e', 'v', 'i', 'l', '.', 'x', ':', '9', '9', '9', '9', 0},
		"slash":      {0, 0, 0, 0, 0, 88, 3, 'a', '/', 'b', 0},
		"at sign":    {0, 0, 0, 0, 0, 88, 3, 'a', '@', 'b', 0},
	} {
		if _, err := parseSRVRData(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOrderSRV(t *testing.T) {
	got := orderSRV([]srvRecord{
		{Target: "b.", Priority: 10, Weight: 5}, {Target: ".", Priority: 0}, {Target: "c.", Priority: 0, Weight: 1},
		{Target: "a.", Priority: 0, Weight: 50}, {Target: "d.", Priority: 10, Weight: 60},
	})
	var names []string
	for _, r := range got {
		names = append(names, r.Target)
	}
	if want := []string{"a.", "c.", "d.", "b."}; !reflect.DeepEqual(names, want) {
		t.Errorf("order %v, want %v", names, want)
	}
	if r, err := parseSRVRData([]byte{0, 0, 0, 0, 0, 0, 0}); err != nil || r.Target != "." || len(orderSRV([]srvRecord{r})) != 0 {
		t.Errorf("root target: %+v %v", r, err)
	}
}

func TestDiscoverKDCs(t *testing.T) {
	saved := srvResolvers
	t.Cleanup(func() { srvResolvers = saved })
	notFound := func(name string) error { return &net.DNSError{Err: "no such record", Name: name, IsNotFound: true} }
	var asked []string
	fake := func(label string, answers map[string][]srvRecord, fail error) srvResolver {
		return srvResolver{label, func(_ context.Context, name string) ([]srvRecord, error) {
			asked = append(asked, label+" "+name)
			if fail != nil {
				return nil, fail
			}
			if r, ok := answers[name]; ok {
				return r, nil
			}
			return nil, notFound(name)
		}}
	}

	// Only UDP records: their hosts are used (idpdbg talks TCP to them).
	asked = nil
	srvResolvers = func() []srvResolver {
		return []srvResolver{fake("system", map[string][]srvRecord{"_kerberos._udp.EX.TEST": {
			{Target: "kdc2.ex.test.", Port: 88, Priority: 1}, {Target: "kdc1.ex.test.", Port: 750, Priority: 0}}}, nil)}
	}
	kdcs, info, err := discoverKDCs(context.Background(), "EX.TEST", time.Second)
	if err != nil || !reflect.DeepEqual(kdcs, []string{"kdc1.ex.test:750", "kdc2.ex.test:88"}) || info["query"] != "_kerberos._udp.EX.TEST" || info["resolver"] != "system" {
		t.Errorf("udp: %v %v %v", kdcs, info, err)
	}

	// A definite "no such name" from the system resolver is final: the realm
	// name does not go on to the public resolver.
	asked = nil
	srvResolvers = func() []srvResolver {
		return []srvResolver{fake("system", nil, nil), fake("go", map[string][]srvRecord{"_kerberos._tcp.EX.TEST": {{Target: "public.example.", Port: 88}}}, nil)}
	}
	if _, _, err := discoverKDCs(context.Background(), "EX.TEST", time.Second); err == nil || !strings.Contains(err.Error(), "pass kdc") {
		t.Errorf("not found: %v", err)
	}
	for _, a := range asked {
		if strings.HasPrefix(a, "go ") {
			t.Errorf("asked the next resolver after a definite answer: %v", asked)
		}
	}

	// Whatever a resolver returns, only names a kdc parameter would accept
	// are dialed.
	srvResolvers = func() []srvResolver {
		return []srvResolver{fake("go", map[string][]srvRecord{"_kerberos._tcp.EX.TEST": {
			{Target: "evil/x@y.", Port: 88}, {Target: "kdc.ex.test.", Port: 0}, {Target: "ok.ex.test.", Port: 88}}}, nil)}
	}
	if kdcs, _, err := discoverKDCs(context.Background(), "EX.TEST", time.Second); err != nil || !reflect.DeepEqual(kdcs, []string{"ok.ex.test:88"}) {
		t.Errorf("unsafe names: %v %v", kdcs, err)
	}

	// A resolver that cannot answer (timeout, no daemon) hands over.
	asked = nil
	srvResolvers = func() []srvResolver {
		return []srvResolver{fake("system", nil, errors.New("daemon not running")), fake("go", map[string][]srvRecord{"_kerberos._tcp.EX.TEST": {{Target: "kdc.ex.test.", Port: 88}}}, nil)}
	}
	kdcs, info, err = discoverKDCs(context.Background(), "EX.TEST", time.Second)
	if err != nil || !reflect.DeepEqual(kdcs, []string{"kdc.ex.test:88"}) || info["resolver"] != "go" || len(info["tried_first"].([]string)) != 2 {
		t.Errorf("fallback: %v %v %v", kdcs, info, err)
	}
}
