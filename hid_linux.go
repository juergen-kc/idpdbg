//go:build linux

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Linux: /dev/hidraw*, found through sysfs. Reading a security key needs
// read/write access to its hidraw node, which distributions grant through
// udev rules (systemd's 70-uaccess for FIDO devices, or libfido2's rules).

func init() {
	hidUnavailable = ""
	hidEnumerate = func() ([]hidInfo, error) {
		nodes, _ := filepath.Glob("/sys/class/hidraw/hidraw*")
		var out []hidInfo
		for _, n := range nodes {
			rd, err := os.ReadFile(filepath.Join(n, "device", "report_descriptor"))
			if err != nil || !isFIDOReportDescriptor(rd) {
				continue
			}
			info := hidInfo{Path: "/dev/" + filepath.Base(n)}
			if ue, err := os.ReadFile(filepath.Join(n, "device", "uevent")); err == nil {
				sc := bufio.NewScanner(bytes.NewReader(ue))
				for sc.Scan() {
					k, v, _ := strings.Cut(sc.Text(), "=")
					switch k {
					case "HID_ID": // bus:vendor:product, hex
						if f := strings.Split(v, ":"); len(f) == 3 {
							vid, _ := strconv.ParseUint(f[1], 16, 32)
							pid, _ := strconv.ParseUint(f[2], 16, 32)
							info.VendorID, info.ProductID = uint16(vid), uint16(pid)
						}
					case "HID_NAME":
						info.Product = v
					}
				}
			}
			out = append(out, info)
		}
		return out, nil
	}
	hidOpen = func(path string) (hidDevice, error) {
		if !strings.HasPrefix(path, "/dev/hidraw") || strings.ContainsAny(path[len("/dev/hidraw"):], "/.") {
			return nil, fmt.Errorf("%q is not a hidraw device path", path)
		}
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			return nil, fmt.Errorf("%w (the udev rules for FIDO devices grant access to the logged-in user)", err)
		}
		return &linuxHID{f: f}, nil
	}
}

type linuxHID struct{ f *os.File }

func (d *linuxHID) Write(report []byte) error {
	buf := make([]byte, 1+hidReportSize) // report ID 0, then the report
	copy(buf[1:], report)
	_, err := d.f.Write(buf)
	return err
}

func (d *linuxHID) Read(timeout time.Duration) ([]byte, error) {
	if err := d.f.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	buf := make([]byte, hidReportSize)
	n, err := d.f.Read(buf)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (d *linuxHID) Close() error { return d.f.Close() }
