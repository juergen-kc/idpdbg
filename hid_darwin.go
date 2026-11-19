//go:build darwin && cgo

package main

/*
#cgo LDFLAGS: -framework IOKit -framework CoreFoundation
#include <IOKit/IOKitLib.h>
#include <IOKit/hid/IOHIDManager.h>
#include <IOKit/hid/IOHIDDevice.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

// Input reports arrive through a callback on the run loop of the thread
// that opened the device; reads run that loop in a private mode until one
// is queued. Every call for one device must come from the same OS thread.

#define FIDO_MODE CFSTR("dev.idpdbg.fido")
#define FIDO_Q 64

typedef struct {
	IOHIDDeviceRef dev;
	uint8_t inbuf[64];
	uint8_t q[FIDO_Q][64];
	int head, count, removed;
} fido_hid;

typedef struct {
	uint64_t id;
	int32_t vid, pid;
	char product[128], manufacturer[128];
} fido_info;

static void fido_input_cb(void *ctx, IOReturn result, void *sender, IOHIDReportType type, uint32_t id, uint8_t *report, CFIndex len) {
	fido_hid *h = ctx;
	if (result != kIOReturnSuccess || type != kIOHIDReportTypeInput || h->count == FIDO_Q) return;
	int i = (h->head + h->count) % FIDO_Q;
	memset(h->q[i], 0, 64);
	memcpy(h->q[i], report, len > 64 ? 64 : len);
	h->count++;
}

static void fido_removal_cb(void *ctx, IOReturn result, void *sender) { ((fido_hid *)ctx)->removed = 1; }

static int fido_get_int(IOHIDDeviceRef d, CFStringRef key, int32_t *out) {
	CFTypeRef ref = IOHIDDeviceGetProperty(d, key);
	if (ref == NULL || CFGetTypeID(ref) != CFNumberGetTypeID()) return -1;
	return CFNumberGetValue((CFNumberRef)ref, kCFNumberSInt32Type, out) ? 0 : -1;
}

static void fido_get_str(IOHIDDeviceRef d, CFStringRef key, char *buf, int n) {
	buf[0] = 0;
	CFTypeRef ref = IOHIDDeviceGetProperty(d, key);
	if (ref != NULL && CFGetTypeID(ref) == CFStringGetTypeID())
		CFStringGetCString((CFStringRef)ref, buf, n, kCFStringEncodingUTF8);
}

static int fido_enumerate(fido_info *out, int max) {
	IOHIDManagerRef m = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDManagerOptionNone);
	if (m == NULL) return -1;
	IOHIDManagerSetDeviceMatching(m, NULL);
	CFSetRef set = IOHIDManagerCopyDevices(m);
	int n = 0;
	if (set != NULL) {
		CFIndex c = CFSetGetCount(set);
		IOHIDDeviceRef *devs = calloc(c > 0 ? c : 1, sizeof(*devs));
		CFSetGetValues(set, (const void **)devs);
		for (CFIndex i = 0; i < c && n < max; i++) {
			int32_t page = 0, usage = 0;
			if (fido_get_int(devs[i], CFSTR(kIOHIDPrimaryUsagePageKey), &page) || page != 0xF1D0) continue;
			if (fido_get_int(devs[i], CFSTR(kIOHIDPrimaryUsageKey), &usage) || usage != 1) continue;
			fido_info *f = &out[n];
			memset(f, 0, sizeof(*f));
			io_service_t svc = IOHIDDeviceGetService(devs[i]);
			if (svc == MACH_PORT_NULL || IORegistryEntryGetRegistryEntryID(svc, &f->id) != KERN_SUCCESS) continue;
			fido_get_int(devs[i], CFSTR(kIOHIDVendorIDKey), &f->vid);
			fido_get_int(devs[i], CFSTR(kIOHIDProductIDKey), &f->pid);
			fido_get_str(devs[i], CFSTR(kIOHIDProductKey), f->product, sizeof(f->product));
			fido_get_str(devs[i], CFSTR(kIOHIDManufacturerKey), f->manufacturer, sizeof(f->manufacturer));
			n++;
		}
		free(devs);
		CFRelease(set);
	}
	CFRelease(m);
	return n;
}

static fido_hid *fido_open(uint64_t id, int *err) {
	io_service_t svc = IOServiceGetMatchingService(MACH_PORT_NULL, IORegistryEntryIDMatching(id));
	if (svc == MACH_PORT_NULL) { *err = -1; return NULL; }
	IOHIDDeviceRef d = IOHIDDeviceCreate(kCFAllocatorDefault, svc);
	IOObjectRelease(svc);
	if (d == NULL) { *err = -2; return NULL; }
	IOReturn r = IOHIDDeviceOpen(d, kIOHIDOptionsTypeNone);
	if (r != kIOReturnSuccess) { CFRelease(d); *err = (int)r; return NULL; }
	fido_hid *h = calloc(1, sizeof(*h));
	h->dev = d;
	IOHIDDeviceRegisterInputReportCallback(d, h->inbuf, sizeof(h->inbuf), fido_input_cb, h);
	IOHIDDeviceRegisterRemovalCallback(d, fido_removal_cb, h);
	IOHIDDeviceScheduleWithRunLoop(d, CFRunLoopGetCurrent(), FIDO_MODE);
	return h;
}

static int fido_write(fido_hid *h, const uint8_t *buf, int n) {
	IOReturn r = IOHIDDeviceSetReport(h->dev, kIOHIDReportTypeOutput, 0, buf, n);
	return r == kIOReturnSuccess ? 0 : (int)r;
}

// fido_read: 64 on a report, 0 on timeout, -1 when the key was removed.
static int fido_read(fido_hid *h, uint8_t *out, int ms) {
	CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + ms / 1000.0;
	while (h->count == 0 && !h->removed) {
		double left = deadline - CFAbsoluteTimeGetCurrent();
		if (left <= 0) return 0;
		if (CFRunLoopRunInMode(FIDO_MODE, left, true) == kCFRunLoopRunFinished) return -1;
	}
	if (h->count == 0) return -1;
	memcpy(out, h->q[h->head], 64);
	h->head = (h->head + 1) % FIDO_Q;
	h->count--;
	return 64;
}

static void fido_close(fido_hid *h) {
	IOHIDDeviceRegisterInputReportCallback(h->dev, h->inbuf, sizeof(h->inbuf), NULL, NULL);
	IOHIDDeviceRegisterRemovalCallback(h->dev, NULL, NULL);
	IOHIDDeviceUnscheduleFromRunLoop(h->dev, CFRunLoopGetCurrent(), FIDO_MODE);
	IOHIDDeviceClose(h->dev, kIOHIDOptionsTypeNone);
	CFRelease(h->dev);
	free(h);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

func init() {
	hidUnavailable = ""
	hidEnumerate = func() ([]hidInfo, error) {
		infos := make([]C.fido_info, 32)
		n := C.fido_enumerate(&infos[0], C.int(len(infos)))
		if n < 0 {
			return nil, errors.New("IOHIDManager unavailable")
		}
		var out []hidInfo
		for _, f := range infos[:n] {
			out = append(out, hidInfo{Path: fmt.Sprintf("IOService:%d", uint64(f.id)), VendorID: uint16(f.vid), ProductID: uint16(f.pid),
				Product: C.GoString(&f.product[0]), Manufacturer: C.GoString(&f.manufacturer[0])})
		}
		return out, nil
	}
	hidOpen = func(path string) (hidDevice, error) {
		id, err := strconv.ParseUint(strings.TrimPrefix(path, "IOService:"), 10, 64)
		if err != nil || !strings.HasPrefix(path, "IOService:") {
			return nil, fmt.Errorf("%q is not a device path (IOService:<id>)", path)
		}
		var cerr C.int
		h := C.fido_open(C.uint64_t(id), &cerr)
		if h == nil {
			return nil, fmt.Errorf("cannot open %s (IOKit error 0x%x)", path, uint32(cerr))
		}
		return &darwinHID{h: h}, nil
	}
}

type darwinHID struct{ h *C.fido_hid }

func (d *darwinHID) Write(report []byte) error {
	buf := make([]byte, hidReportSize)
	copy(buf, report)
	if r := C.fido_write(d.h, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.int(len(buf))); r != 0 {
		return fmt.Errorf("HID write failed (IOKit error 0x%x)", uint32(r))
	}
	return nil
}

func (d *darwinHID) Read(timeout time.Duration) ([]byte, error) {
	buf := make([]byte, hidReportSize)
	switch n := C.fido_read(d.h, (*C.uint8_t)(unsafe.Pointer(&buf[0])), C.int(timeout.Milliseconds())); {
	case n < 0:
		return nil, errors.New("the security key was removed")
	case n == 0:
		return nil, nil
	}
	return buf, nil
}

func (d *darwinHID) Close() error {
	C.fido_close(d.h)
	return nil
}
