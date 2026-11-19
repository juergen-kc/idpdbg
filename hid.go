package main

import "time"

// USB HID access to FIDO security keys (usage page 0xF1D0, usage 1). The
// platform files fill in hidEnumerate and hidOpen; where there is no
// implementation they stay nil and hidUnavailable says why.

type hidInfo struct {
	Path         string
	VendorID     uint16
	ProductID    uint16
	Manufacturer string
	Product      string
}

type hidDevice interface {
	// Write sends one 64-byte output report (without a report ID).
	Write(report []byte) error
	// Read returns the next 64-byte input report, or nil after timeout.
	Read(timeout time.Duration) ([]byte, error)
	Close() error
}

var (
	hidEnumerate   func() ([]hidInfo, error)
	hidOpen        func(path string) (hidDevice, error)
	hidUnavailable = "USB security keys are not supported on this platform"
)

const hidReportSize = 64

// isFIDOReportDescriptor reads a HID report descriptor's short items and
// reports whether it declares the FIDO usage page (0xF1D0) with usage 1
// (CTAPHID) at the top level.
func isFIDOReportDescriptor(rd []byte) bool {
	page, usage := uint32(0), uint32(0)
	for i := 0; i < len(rd); {
		b := rd[i]
		if b == 0xFE { // long item: skip
			if i+2 >= len(rd) {
				return false
			}
			i += 3 + int(rd[i+1])
			continue
		}
		size := int(b & 3)
		if size == 3 {
			size = 4
		}
		if i+1+size > len(rd) {
			return false
		}
		var v uint32
		for j := 0; j < size; j++ {
			v |= uint32(rd[i+1+j]) << (8 * j)
		}
		switch b & 0xFC {
		case 0x04: // global: usage page
			page = v
		case 0x08: // local: usage
			usage = v
		case 0xA0: // main: collection
			return page == 0xF1D0 && usage == 1
		}
		i += 1 + size
	}
	return false
}
