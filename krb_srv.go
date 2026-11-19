package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// KDC discovery through DNS SRV records (RFC 4120 §7.2.3.2, RFC 2782).
//
// Go answers SRV queries from /etc/resolv.conf. On macOS that misses
// per-domain resolvers (/etc/resolver/<domain>, VPN split DNS), which only
// the system resolver honours, so where a build can reach it (darwin with
// cgo) it is asked first and Go's resolver second.

type srvRecord struct {
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
}

type srvResolver struct {
	name   string
	lookup func(ctx context.Context, name string) ([]srvRecord, error)
}

// systemSRV is the platform resolver, where this build has one.
var systemSRV *srvResolver

func goSRV(ctx context.Context, name string) ([]srvRecord, error) {
	_, addrs, err := net.DefaultResolver.LookupSRV(ctx, "", "", name)
	var out []srvRecord
	for _, a := range addrs {
		out = append(out, srvRecord{Target: a.Target, Port: a.Port, Priority: a.Priority, Weight: a.Weight})
	}
	return out, err
}

// srvResolvers lists the resolvers to try, in order. Tests replace it.
var srvResolvers = func() []srvResolver {
	var rs []srvResolver
	if systemSRV != nil {
		rs = append(rs, *systemSRV)
	}
	return append(rs, srvResolver{"Go resolver", goSRV})
}

// parseSRVRData decodes the RDATA of an SRV record: priority, weight and
// port, then the target as uncompressed DNS labels.
func parseSRVRData(b []byte) (srvRecord, error) {
	if len(b) < 7 {
		return srvRecord{}, errors.New("SRV record too short")
	}
	r := srvRecord{Priority: binary.BigEndian.Uint16(b), Weight: binary.BigEndian.Uint16(b[2:]), Port: binary.BigEndian.Uint16(b[4:])}
	var labels []string
	for i := 6; ; {
		if i >= len(b) {
			return srvRecord{}, errors.New("SRV target runs past the record")
		}
		n := int(b[i])
		if n == 0 {
			break
		}
		if n&0xc0 != 0 || i+1+n > len(b) {
			return srvRecord{}, errors.New("SRV target is compressed or malformed")
		}
		label := string(b[i+1 : i+1+n])
		// DNS labels may hold any byte; a hostname's may not. A '.', ':' or
		// '/' inside one would make the name read differently later.
		if !hostLabelRe.MatchString(label) {
			return srvRecord{}, fmt.Errorf("SRV target label %q is not a hostname label", label)
		}
		labels = append(labels, label)
		i += 1 + n
	}
	if len(labels) == 0 {
		r.Target = "." // "service not offered here" (RFC 2782)
		return r, nil
	}
	r.Target = strings.Join(labels, ".") + "."
	return r, nil
}

// hostLabelRe is one label of a hostname: letters, digits and hyphens, and
// the underscore some DNS names carry; 1 to 63 characters.
var hostLabelRe = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)

// orderSRV drops "service not offered" records (target ".") and orders the
// rest by priority, then by weight, highest first. RFC 2782 picks among
// equal priorities at random in proportion to weight; a fixed order keeps
// runs comparable.
func orderSRV(recs []srvRecord) []srvRecord {
	var out []srvRecord
	for _, r := range recs {
		if r.Target != "." && r.Target != "" {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		return out[i].Weight > out[j].Weight
	})
	return out
}

// discoverKDCs finds a realm's KDCs: _kerberos._tcp, then _kerberos._udp
// (whose hosts idpdbg also reaches over TCP), from each resolver in turn.
// A resolver that says the names do not exist is believed: asking the next
// one would only send an internal realm name to the public DNS servers.
func discoverKDCs(ctx context.Context, realm string, timeout time.Duration) ([]string, M, error) {
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	var tried []string
	for _, res := range srvResolvers() {
		notFound := true
		for _, proto := range []string{"tcp", "udp"} {
			name := "_kerberos._" + proto + "." + realm
			lctx, cancel := context.WithTimeout(ctx, timeout)
			recs, err := res.lookup(lctx, name)
			cancel()
			recs = orderSRV(recs)
			if len(recs) == 0 {
				var de *net.DNSError
				if err == nil {
					err = errors.New("no records")
				} else if !errors.As(err, &de) || !de.IsNotFound {
					notFound = false
				}
				tried = append(tried, fmt.Sprintf("%s via %s: %v", name, res.name, err))
				continue
			}
			var kdcs []string
			for _, r := range recs {
				// The same rule as a kdc given by hand, whichever resolver answered.
				if k := net.JoinHostPort(strings.TrimSuffix(r.Target, "."), strconv.Itoa(int(r.Port))); krbKDCRe.MatchString(k) && r.Port != 0 {
					kdcs = append(kdcs, k)
				}
			}
			if len(kdcs) == 0 {
				tried = append(tried, fmt.Sprintf("%s via %s: no record names a usable host", name, res.name))
				continue
			}
			info := M{"source": "DNS SRV", "resolver": res.name, "query": name, "records": recs}
			if len(tried) > 0 {
				info["tried_first"] = tried
			}
			return kdcs, info, nil
		}
		if notFound {
			break
		}
	}
	return nil, M{"source": "DNS SRV", "tried": tried}, fmt.Errorf("no kdc given and no DNS SRV records found for %s (%s); pass kdc", realm, strings.Join(tried, "; "))
}
