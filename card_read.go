package main

import (
	"errors"
	"fmt"
	"strings"
)

// Reading a card over PC/SC. Only public data objects are read: no PIN
// is ever sent, so nothing here changes the card's state or retry counters.

type cardConn interface {
	Transmit(cmd []byte) ([]byte, error)
	Close() error
}

type cardInfo struct {
	Reader string
	ATR    []byte
}

// Set by card_pcsc.go when built with cgo; replaced by tests.
var (
	listReaders func() ([]string, error)
	connectCard func(reader string) (cardConn, cardInfo, error)
)

// transmit sends one APDU and follows 61xx (GET RESPONSE) and 6Cxx
// (resend with the right Le), returning the assembled data and final SW.
func transmit(conn cardConn, cmd []byte) ([]byte, uint16, error) {
	var data []byte
	for range 256 {
		r, err := conn.Transmit(cmd)
		if err != nil {
			return nil, 0, err
		}
		if len(r) < 2 {
			return nil, 0, errors.New("card returned no status word")
		}
		data = append(data, r[:len(r)-2]...)
		sw1, sw2 := r[len(r)-2], r[len(r)-1]
		switch {
		case sw1 == 0x61:
			cmd = []byte{0x00, 0xC0, 0x00, 0x00, sw2}
			continue
		case sw1 == 0x6C && len(cmd) >= 5:
			cmd = append(append([]byte(nil), cmd[:len(cmd)-1]...), sw2)
			continue
		}
		if len(data) > 1<<20 {
			return nil, 0, errors.New("card response over 1 MiB")
		}
		return data, uint16(sw1)<<8 | uint16(sw2), nil
	}
	return nil, 0, errors.New("card kept asking for GET RESPONSE")
}

func selectAID(conn cardConn, aid []byte) (uint16, error) {
	_, sw, err := transmit(conn, append(append([]byte{0x00, 0xA4, 0x04, 0x00, byte(len(aid))}, aid...), 0x00))
	return sw, err
}

func swText(sw uint16) string {
	m, _ := swMeaning(byte(sw>>8), byte(sw))
	return fmt.Sprintf("%04X %s", sw, m)
}

// mergeChecks adds an object's checks under a prefix.
func mergeChecks(cs *Checks, prefix string, res M) {
	if sub, ok := res["checks"].(Checks); ok {
		for _, c := range sub {
			c.Name = prefix + ": " + c.Name
			*cs = append(*cs, c)
		}
		delete(res, "checks")
	}
}

var pivReadObjects = []struct{ tag, name, kind string }{
	{"7E", "discovery", "discovery"}, {"5FC102", "chuid", "chuid"},
	{"5FC105", "cert_9a_piv_authentication", "certificate"}, {"5FC10A", "cert_9c_digital_signature", "certificate"},
	{"5FC10B", "cert_9d_key_management", "certificate"}, {"5FC101", "cert_9e_card_authentication", "certificate"},
	{"5FC10C", "key_history", "keyhistory"},
}

func readPIV(conn cardConn, cs *Checks) M {
	out := M{}
	sw, err := selectAID(conn, []byte{0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00})
	if err != nil {
		cs.add("PIV: select", "fail", err.Error(), "SP 800-73-4 Part 2 §3.1.1")
		return nil
	}
	if sw != 0x9000 {
		cs.add("PIV: select", "info", "no PIV applet ("+swText(sw)+")", "SP 800-73-4 Part 2 §3.1.1")
		return nil
	}
	cs.add("PIV: select", "pass", "PIV applet present", "SP 800-73-4 Part 2 §3.1.1")
	for _, o := range pivReadObjects {
		tag := mustHexStr(o.tag)
		cmd := append([]byte{0x00, 0xCB, 0x3F, 0xFF, byte(2 + len(tag)), 0x5C, byte(len(tag))}, tag...)
		data, sw, err := transmit(conn, append(cmd, 0x00))
		switch {
		case err != nil:
			cs.add("PIV: read "+o.name, "fail", err.Error(), "SP 800-73-4 Part 2 §3.1.2")
		case sw == 0x6A82:
			out[o.name] = nil // not present
		case sw != 0x9000:
			cs.add("PIV: read "+o.name, "warn", swText(sw), "SP 800-73-4 Part 2 §3.1.2")
		default:
			res, err := decodePIV(data, o.kind)
			if err != nil {
				cs.add("PIV: decode "+o.name, "fail", err.Error(), "SP 800-73-4 Part 1")
				continue
			}
			mergeChecks(cs, "PIV "+o.name, res)
			out[o.name] = res
		}
	}
	return out
}

func readOpenPGP(conn cardConn, cs *Checks) M {
	sw, err := selectAID(conn, []byte{0xD2, 0x76, 0x00, 0x01, 0x24, 0x01})
	if err != nil {
		cs.add("OpenPGP: select", "fail", err.Error(), "OpenPGP card 3.4 §7.2.1")
		return nil
	}
	if sw != 0x9000 {
		cs.add("OpenPGP: select", "info", "no OpenPGP applet ("+swText(sw)+")", "OpenPGP card 3.4 §7.2.1")
		return nil
	}
	cs.add("OpenPGP: select", "pass", "OpenPGP applet present", "OpenPGP card 3.4 §7.2.1")
	data, sw, err := transmit(conn, []byte{0x00, 0xCA, 0x00, 0x6E, 0x00})
	if err != nil || sw != 0x9000 {
		detail := ""
		if err != nil {
			detail = err.Error()
		} else {
			detail = swText(sw)
		}
		cs.add("OpenPGP: read Application Related Data", "fail", detail, "OpenPGP card 3.4 §7.2.6")
		return nil
	}
	res, err := decodeOpenPGP(data)
	if err != nil {
		cs.add("OpenPGP: decode", "fail", err.Error(), "OpenPGP card 3.4 §4.4")
		return nil
	}
	mergeChecks(cs, "OpenPGP", res)
	if url, sw, err := transmit(conn, []byte{0x00, 0xCA, 0x5F, 0x50, 0x00}); err == nil && sw == 0x9000 && len(url) > 0 {
		res["public_key_url"] = string(url)
	}
	return res
}

// atrText returns the longest printable run in the ATR's historical
// bytes, which often names the token ("YubiKey").
func atrText(atr []byte) string {
	best, cur := "", ""
	for _, b := range atr {
		if b >= 0x20 && b < 0x7F {
			cur += string(rune(b))
			if len(cur) > len(best) {
				best = cur
			}
		} else {
			cur = ""
		}
	}
	if len(best) < 4 {
		return ""
	}
	return best
}

func mustHexStr(s string) []byte {
	b, err := cardBytes(s)
	if err != nil {
		panic(err)
	}
	return b
}

func runCardRead(c *Ctx) (M, error) {
	if listReaders == nil || connectCard == nil {
		return nil, errors.New("this build has no PC/SC support (built without cgo)")
	}
	readers, err := listReaders()
	if err != nil {
		return nil, fmt.Errorf("listing readers: %w", err)
	}
	out := M{"readers": readers}
	if c.Bool("list") {
		return out, nil
	}
	reader := c.Str("reader")
	if reader == "" {
		if len(readers) == 0 {
			return nil, errors.New("no smart-card readers found: plug in the card or token")
		}
		reader = readers[0]
	} else {
		found := ""
		for _, r := range readers {
			if r == reader || strings.Contains(strings.ToLower(r), strings.ToLower(reader)) {
				found = r
				break
			}
		}
		if found == "" {
			return nil, fmt.Errorf("no reader matches %q", reader)
		}
		reader = found
	}
	conn, info, err := connectCard(reader)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", reader, err)
	}
	defer conn.Close()
	out["reader"] = info.Reader
	out["atr"] = strings.ToUpper(fmt.Sprintf("%X", info.ATR))
	if txt := atrText(info.ATR); txt != "" {
		out["atr_text"] = txt
	}
	var cs Checks
	applet := c.Str("applet")
	if applet == "all" || applet == "piv" {
		out["piv"] = readPIV(conn, &cs)
	}
	if applet == "all" || applet == "openpgp" {
		out["openpgp"] = readOpenPGP(conn, &cs)
	}
	out["checks"] = cs
	return out, nil
}

func init() {
	register(&Op{
		Name:    "card.read",
		Summary: "Read a smart card or security key over PC/SC (needs a cgo build): lists readers, selects the PIV and OpenPGP applets and decodes their public objects (CHUID, certificates, discovery, Application Related Data) with the same checks as card.piv and card.openpgp. Never sends a PIN, so retry counters are untouched.",
		Params: []Param{
			{Name: "reader", Type: "string", Desc: "Reader name or a substring of it; default the first reader"},
			{Name: "applet", Type: "string", Enum: []string{"all", "piv", "openpgp"}, Default: "all", Desc: "Which applets to read"},
			{Name: "list", Type: "bool", Desc: "Only list readers"}},
		Run: runCardRead,
	})
}
