//go:build darwin && cgo

package main

/*
#include <dns_sd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>

#define SRV_MAX 32
#define SRV_LEN 512

typedef struct {
	unsigned char rdata[SRV_MAX][SRV_LEN];
	int len[SRV_MAX];
	int n, err, done;
} srv_result;

static void DNSSD_API srv_cb(DNSServiceRef ref, DNSServiceFlags flags, uint32_t ifi, DNSServiceErrorType err,
		const char *fullname, uint16_t rrtype, uint16_t rrclass, uint16_t rdlen, const void *rdata, uint32_t ttl, void *ctx) {
	srv_result *r = ctx;
	if (err != kDNSServiceErr_NoError) {
		r->err = err;
		r->done = 1;
		return;
	}
	if (rrtype == kDNSServiceType_SRV && (flags & kDNSServiceFlagsAdd) && rdlen <= SRV_LEN && r->n < SRV_MAX) {
		memcpy(r->rdata[r->n], rdata, rdlen);
		r->len[r->n] = rdlen;
		r->n++;
	}
	if (!(flags & kDNSServiceFlagsMoreComing)) r->done = 1;
}

// srv_query asks the system resolver (mDNSResponder) for SRV records,
// waiting at most timeout_ms. Intermediate results make a missing name
// answer at once instead of at the timeout.
static int srv_query(const char *name, int timeout_ms, srv_result *r) {
	DNSServiceRef ref;
	DNSServiceErrorType e = DNSServiceQueryRecord(&ref, kDNSServiceFlagsReturnIntermediates | kDNSServiceFlagsTimeout, 0,
		name, kDNSServiceType_SRV, kDNSServiceClass_IN, srv_cb, r);
	if (e != kDNSServiceErr_NoError) return e;
	int fd = DNSServiceRefSockFD(ref);
	struct timeval end, now, wait;
	gettimeofday(&end, NULL);
	end.tv_sec += timeout_ms / 1000;
	end.tv_usec += (timeout_ms % 1000) * 1000;
	if (end.tv_usec >= 1000000) { end.tv_sec++; end.tv_usec -= 1000000; }
	while (!r->done) {
		gettimeofday(&now, NULL);
		timersub(&end, &now, &wait);
		if (wait.tv_sec < 0) { r->err = kDNSServiceErr_Timeout; break; }
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		int n = select(fd + 1, &fds, NULL, NULL, &wait);
		if (n == 0) { r->err = kDNSServiceErr_Timeout; break; }
		if (n < 0) continue;
		e = DNSServiceProcessResult(ref);
		if (e != kDNSServiceErr_NoError) { r->err = e; break; }
	}
	DNSServiceRefDeallocate(ref);
	return r->n > 0 ? 0 : r->err;
}
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"time"
	"unsafe"
)

func init() {
	systemSRV = &srvResolver{"macOS system resolver", darwinSRV}
}

func darwinSRV(ctx context.Context, name string) ([]srvRecord, error) {
	timeout := 5 * time.Second
	if d, ok := ctx.Deadline(); ok {
		timeout = time.Until(d)
	}
	r := (*C.srv_result)(C.calloc(1, C.sizeof_srv_result))
	defer C.free(unsafe.Pointer(r))
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	switch rc := C.srv_query(cname, C.int(timeout.Milliseconds()), r); rc {
	case 0:
	case C.kDNSServiceErr_NoSuchRecord, C.kDNSServiceErr_NoSuchName:
		return nil, &net.DNSError{Err: "no such record", Name: name, IsNotFound: true}
	case C.kDNSServiceErr_Timeout:
		return nil, &net.DNSError{Err: "timed out", Name: name, IsTimeout: true}
	default:
		return nil, fmt.Errorf("DNSServiceQueryRecord %s: error %d", name, int(rc))
	}
	var out []srvRecord
	for i := 0; i < int(r.n); i++ {
		rec, err := parseSRVRData(C.GoBytes(unsafe.Pointer(&r.rdata[i][0]), r.len[i]))
		if err == nil {
			out = append(out, rec)
		}
	}
	return out, nil
}
