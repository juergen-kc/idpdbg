package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// CTAP over NFC, or any ISO 7816 transport such as a contactless reader on
// PC/SC (CTAP 2.1 §11.3): the FIDO applet is selected by AID, CTAP2
// commands travel in NFCCTAP_MSG APDUs (with status updates while the key
// works, and command chaining for long requests), and U2F requests are
// plain APDUs.

var fidoAID = []byte{0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01}

const (
	nfcctapMsg         = 0x10
	nfcctapGetResponse = 0x11
	nfcPrefix          = "nfc"
)

// isNFCSelector says whether a device selector names a reader: "nfc", or
// "nfc:<part of the reader's name>".
func isNFCSelector(sel string) bool {
	return sel == nfcPrefix || strings.HasPrefix(sel, nfcPrefix+":")
}

// nfcReaders lists the PC/SC readers that hold a FIDO authenticator, by
// selecting the FIDO applet (which changes nothing on the key).
func nfcReaders() ([]hidInfo, error) {
	if listReaders == nil || connectCard == nil {
		return nil, errors.New("this build has no PC/SC support (built without cgo)")
	}
	readers, err := listReaders()
	if err != nil {
		return nil, err
	}
	var out []hidInfo
	for _, r := range readers {
		conn, _, err := connectCard(r)
		if err != nil {
			continue // no card on this reader
		}
		resp, sw, err := transmit(conn, append(append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(fidoAID))}, fidoAID...), 0x00))
		conn.Close()
		if err == nil && sw == 0x9000 {
			out = append(out, hidInfo{Path: nfcPrefix + ":" + r, Product: r, Manufacturer: "FIDO applet (" + safeText(string(resp)) + ")"})
		}
	}
	return out, nil
}

// openNFC connects to the reader the selector names and selects the FIDO
// applet.
func openNFC(sel string) (*ctapDevice, error) {
	if listReaders == nil || connectCard == nil {
		return nil, errors.New("this build has no PC/SC support (built without cgo), so no NFC")
	}
	want := strings.TrimPrefix(strings.TrimPrefix(sel, nfcPrefix), ":")
	readers, err := listReaders()
	if err != nil {
		return nil, fmt.Errorf("listing readers: %w", err)
	}
	var tried []string
	for _, r := range readers {
		if want != "" && !strings.Contains(strings.ToLower(r), strings.ToLower(want)) {
			continue
		}
		conn, info, err := connectCard(r)
		if err != nil {
			tried = append(tried, r+": "+err.Error())
			continue
		}
		resp, sw, err := transmit(conn, append(append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(fidoAID))}, fidoAID...), 0x00))
		if err != nil || sw != 0x9000 {
			conn.Close()
			if err == nil {
				err = errors.New("no FIDO applet (" + swText(sw) + ")")
			}
			tried = append(tried, r+": "+err.Error())
			continue
		}
		d := &ctapDevice{nfc: conn, info: hidInfo{Path: nfcPrefix + ":" + info.Reader, Product: info.Reader, Manufacturer: "NFC"}, version: string(resp)}
		switch string(resp) {
		case "FIDO_2_0":
			d.caps = 0x04 // CTAP2; whether U2F works too, getInfo says
			if m, err := getInfo(d); err == nil && !contains(strList(m[int64(1)]), "U2F_V2") {
				d.caps |= 0x08
			}
		case "U2F_V2":
		default:
			conn.Close()
			tried = append(tried, r+": the FIDO applet answered "+safeText(string(resp)))
			continue
		}
		return d, nil
	}
	switch {
	case len(tried) > 0:
		return nil, errors.New("no FIDO authenticator on a reader: " + strings.Join(tried, "; "))
	case want != "":
		return nil, fmt.Errorf("no reader matches %q", want)
	}
	return nil, errors.New("no smart-card or NFC readers found")
}

// nfcAPDU sends one command of class cla, chaining data over 255 bytes
// (CLA bit 0x10), and returns the data and status word.
func nfcAPDU(conn cardConn, cla, ins, p1, p2 byte, data []byte) ([]byte, uint16, error) {
	for len(data) > 255 {
		_, sw, err := transmit(conn, append([]byte{cla | 0x10, ins, p1, p2, 255}, data[:255]...))
		if err != nil {
			return nil, 0, err
		}
		if sw != 0x9000 {
			return nil, sw, nil
		}
		data = data[255:]
	}
	cmd := []byte{cla, ins, p1, p2}
	if len(data) > 0 {
		cmd = append(append(cmd, byte(len(data))), data...)
	}
	return transmit(conn, append(cmd, 0x00))
}

// nfcTransact is transact over NFC: a CTAP2 request in NFCCTAP_MSG, or a
// U2F APDU as it is.
func (d *ctapDevice) nfcTransact(cmd byte, data []byte, timeout time.Duration) ([]byte, error) {
	switch cmd {
	case ctaphidCBOR:
		// P1 0x80: this client takes status updates (SW 9100) while the key
		// waits for a touch, and fetches the answer with NFCCTAP_GETRESPONSE.
		resp, sw, err := nfcAPDU(d.nfc, 0x80, nfcctapMsg, 0x80, 0x00, data)
		deadline := time.Now().Add(timeout)
		for err == nil && sw == 0x9100 {
			if d.onKeepalive != nil && len(resp) > 0 {
				d.onKeepalive(resp[0])
			}
			if time.Now().After(deadline) {
				return nil, errTouchTimeout
			}
			time.Sleep(100 * time.Millisecond)
			resp, sw, err = nfcAPDU(d.nfc, 0x80, nfcctapGetResponse, 0x00, 0x00, nil)
		}
		if err != nil {
			return nil, err
		}
		if sw != 0x9000 {
			return nil, fmt.Errorf("NFCCTAP_MSG: %s", swText(sw))
		}
		return resp, nil
	case ctaphidMsg:
		// A U2F request: CTAPHID wraps it in extended-length form; send it
		// short where it fits, as every reader takes that.
		if len(data) < 7 {
			return nil, errors.New("U2F: short APDU")
		}
		n := int(data[5])<<8 | int(data[6])
		var resp []byte
		var sw uint16
		var err error
		if n <= 255 {
			resp, sw, err = nfcAPDU(d.nfc, data[0], data[1], data[2], data[3], data[7:7+n])
		} else {
			resp, sw, err = transmit(d.nfc, data)
		}
		if err != nil {
			return nil, err
		}
		return append(resp, byte(sw>>8), byte(sw)), nil
	}
	return nil, fmt.Errorf("CTAPHID command 0x%02x has no NFC form", cmd)
}
