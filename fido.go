package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Local FIDO security keys over USB: which are connected, and what each
// says about itself (CTAP2 authenticatorGetInfo).

var getInfoNames = map[int64]string{1: "versions", 2: "extensions", 3: "aaguid", 4: "options", 5: "max_msg_size", 6: "pin_uv_auth_protocols",
	7: "max_credential_count_in_list", 8: "max_credential_id_length", 9: "transports", 10: "algorithms", 11: "max_serialized_large_blob_array",
	12: "force_pin_change", 13: "min_pin_length", 14: "firmware_version", 15: "max_cred_blob_length", 16: "max_rpids_for_set_min_pin_length",
	17: "preferred_platform_uv_attempts", 18: "uv_modality", 19: "certifications", 20: "remaining_discoverable_credentials",
	21: "vendor_prototype_config_commands", 22: "attestation_formats", 23: "uv_count_since_last_pin_entry", 24: "long_touch_for_reset",
	25: "enc_identifier", 26: "transports_for_reset", 27: "pin_complexity_policy", 28: "pin_complexity_policy_url", 29: "max_pin_length"}

var ctapOptionMeaning = map[string][2]string{ // option: {meaning when true, when false}
	"plat":                           {"a platform authenticator, built into the device", "a roaming authenticator (a security key)"},
	"rk":                             {"can store discoverable credentials (passkeys)", "cannot store discoverable credentials"},
	"clientPin":                      {"a PIN is set", "PIN supported but not set"},
	"up":                             {"tests user presence (touch)", "cannot test user presence"},
	"uv":                             {"built-in user verification (e.g. fingerprint) is configured", "built-in user verification supported but not configured"},
	"pinUvAuthToken":                 {"supports PIN/UV auth tokens (CTAP 2.1)", ""},
	"credMgmt":                       {"credential management (list and delete passkeys)", ""},
	"credentialMgmtPreview":          {"credential management (pre-2.1 preview)", ""},
	"bioEnroll":                      {"fingerprints are enrolled", "fingerprint enrollment supported, none enrolled"},
	"largeBlobs":                     {"large blob storage", ""},
	"authnrCfg":                      {"authenticator configuration commands", ""},
	"ep":                             {"enterprise attestation enabled", "enterprise attestation supported, disabled"},
	"alwaysUv":                       {"every operation requires user verification", "user verification only when asked"},
	"makeCredUvNotRqd":               {"non-discoverable credentials can be made without PIN/UV", ""},
	"setMinPINLength":                {"minimum PIN length can be set", ""},
	"noMcGaPermissionsWithClientPin": {"PIN tokens cannot be used for makeCredential/getAssertion", ""},
}

func describeGetInfo(m map[any]any) M {
	out := M{}
	for k, v := range m {
		ki, _ := k.(int64)
		name := getInfoNames[ki]
		if name == "" {
			name = fmt.Sprintf("field_%v", k)
		}
		switch name {
		case "aaguid":
			b, _ := v.([]byte)
			out[name] = uuidString(b)
		case "algorithms":
			var algs []string
			for _, a := range anyList(v) {
				am, _ := a.(map[any]any)
				id, _ := am["alg"].(int64)
				n := coseAlgs[id]
				if n == "" {
					n = fmt.Sprint(id)
				}
				algs = append(algs, n)
			}
			out[name] = algs
		case "options":
			out[name] = cborJSON(v)
		default:
			out[name] = cborJSON(v)
		}
	}
	return out
}

func anyList(v any) []any { l, _ := v.([]any); return l }

func strList(v any) []string {
	var out []string
	for _, x := range anyList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func getInfo(d *ctapDevice) (map[any]any, error) {
	b, err := d.cbor(ctapGetInfo, nil, 5*time.Second)
	if err != nil {
		return nil, err
	}
	m, _, err := cborMapFields(b)
	return m, err
}

func capList(caps byte) []string {
	var out []string
	for bit, n := range map[byte]string{0x01: "wink", 0x04: "cbor (CTAP2)", 0x08: "no msg (no U2F)"} {
		if caps&bit != 0 {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func runFIDODevices(c *Ctx) (M, error) {
	devs, err := fidoDevices()
	if err != nil {
		return nil, err
	}
	var list []M
	for i, info := range devs {
		e := M{"index": i, "transport": "usb", "path": info.Path, "vendor_id": fmt.Sprintf("0x%04x", info.VendorID), "product_id": fmt.Sprintf("0x%04x", info.ProductID),
			"manufacturer": info.Manufacturer, "product": info.Product}
		err := withFIDO(c, info.Path, func(d *ctapDevice) error {
			e["ctaphid_protocol"], e["device_version"], e["capabilities"] = d.protocol, d.version, capList(d.caps)
			if c.Bool("wink") && d.caps&0x01 != 0 {
				if _, err := d.transact(ctaphidWink, nil, 2*time.Second); err == nil {
					e["winked"] = true
				}
			}
			if d.caps&0x04 != 0 {
				if m, err := getInfo(d); err == nil {
					e["versions"] = strList(m[int64(1)])
					if b, ok := m[int64(3)].([]byte); ok {
						e["aaguid"] = uuidString(b)
					}
				}
			}
			return nil
		})
		if err != nil {
			e["error"] = err.Error()
		}
		list = append(list, e)
	}
	out := M{}
	if c.Bool("nfc") {
		// Keys on PC/SC readers (NFC): found by selecting the FIDO applet.
		if nfc, err := nfcReaders(); err != nil {
			out["nfc_error"] = err.Error()
		} else {
			for _, info := range nfc {
				list = append(list, M{"path": info.Path, "transport": "nfc", "reader": info.Product, "applet": strings.TrimSuffix(strings.TrimPrefix(info.Manufacturer, "FIDO applet ("), ")")})
			}
		}
	}
	out["devices"], out["count"] = list, len(list)
	return out, nil
}

func runFIDOInfo(c *Ctx) (M, error) {
	var cs Checks
	out := M{}
	err := withFIDO(c, c.Str("device"), func(d *ctapDevice) error {
		out["device"] = M{"path": d.info.Path, "manufacturer": d.info.Manufacturer, "product": d.info.Product, "device_version": d.version, "capabilities": capList(d.caps), "transport": "usb (CTAPHID)"}
		if d.nfc != nil {
			out["device"] = M{"path": d.info.Path, "reader": d.info.Product, "applet": d.version, "capabilities": capList(d.caps), "transport": "nfc (ISO 7816 over PC/SC)"}
		}
		m, err := getInfo(d)
		if err != nil {
			return err
		}
		info := describeGetInfo(m)
		out["info"] = info
		versions := strList(m[int64(1)])
		has := func(v string) bool {
			for _, x := range versions {
				if x == v {
					return true
				}
			}
			return false
		}
		cs.ok(has("FIDO_2_0") || has("FIDO_2_1") || has("FIDO_2_1_PRE"), "CTAP2 supported", strings.Join(versions, ", "), "CTAP 2.1 §6.4")
		if has("FIDO_2_1") {
			cs.add("CTAP 2.1", "pass", "", "CTAP 2.1 §6.4")
		} else {
			cs.add("CTAP 2.1", "info", "not supported: a CTAP 2.0 key (no credential management, no makeCredUvNotRqd)", "CTAP 2.1 §6.4")
		}
		cs.add("U2F (CTAP1) supported", "info", fmt.Sprint(has("U2F_V2")), "CTAP 2.1 §11.2.9.1.3")
		algs, _ := info["algorithms"].([]string)
		if len(algs) > 0 {
			es := false
			for _, a := range algs {
				es = es || a == "ES256"
			}
			cs.ok(es, "ES256 supported", strings.Join(algs, ", "), "WebAuthn §5.8.5")
		}
		opts, _ := m[int64(4)].(map[any]any)
		var names []string
		for k := range opts {
			names = append(names, fmt.Sprint(k))
		}
		sort.Strings(names)
		var meaning []string
		for _, n := range names {
			v, _ := opts[n].(bool)
			mm := ctapOptionMeaning[n]
			txt := mm[1]
			if v {
				txt = mm[0]
			}
			if txt != "" {
				meaning = append(meaning, n+": "+txt)
			}
		}
		out["options_explained"] = meaning
		pin, pinKnown := opts["clientPin"].(bool)
		uvNotRqd, _ := opts["makeCredUvNotRqd"].(bool)
		alwaysUv, _ := opts["alwaysUv"].(bool)
		switch {
		case alwaysUv:
			cs.add("usable without a PIN (idpdbg)", "info", "alwaysUv is on: every operation needs the PIN (or the key's own verification)", "CTAP 2.1 §7.2")
		case pin && !uvNotRqd:
			cs.add("usable without a PIN (idpdbg)", "info", "a PIN is set and CTAP2 registration needs it (no makeCredUvNotRqd): without the PIN idpdbg registers over U2F, as browsers do", "CTAP 2.1 §6.1.2")
		case pin:
			cs.add("usable without a PIN (idpdbg)", "pass", "a PIN is set, but non-discoverable credentials can be made without it (makeCredUvNotRqd)", "CTAP 2.1 §6.1.2")
		case pinKnown:
			cs.add("usable without a PIN (idpdbg)", "pass", "no PIN is set", "CTAP 2.1 §6.1.2")
		}
		if pinKnown && pin {
			if n, err := pinRetries(d, pinProtocolFor(m)); err == nil {
				info["pin_retries"] = n
				switch {
				case n < pinMinRetries:
					cs.add("PIN attempts left", "warn", fmt.Sprintf("%d: idpdbg will not try a PIN on this key (it blocks at 0)", n), "CTAP 2.1 §6.5.5.2")
				default:
					cs.add("PIN attempts left", "info", fmt.Sprint(n), "CTAP 2.1 §6.5.5.2")
				}
			}
		}
		if rem, ok := info["remaining_discoverable_credentials"]; ok {
			cs.add("discoverable credential slots left", "info", fmt.Sprint(rem), "CTAP 2.1 §6.4")
		}
		if c.Bool("metadata") {
			if b, ok := m[int64(3)].([]byte); ok {
				out["metadata"] = mdsForAttestation(c, &cs, &authData{AAGUID: b}, nil, false)
			}
		}
		if aa, _ := info["aaguid"].(string); aa == "00000000-0000-0000-0000-000000000000" {
			cs.add("AAGUID", "info", "all zeros: the key does not identify its model", "WebAuthn §6.5.1")
		}
		return nil
	})
	out["checks"] = cs
	return out, err
}

func init() {
	register(
		&Op{
			Name:    "fido.devices",
			Summary: "List the FIDO security keys connected over USB: path, vendor and product, CTAPHID version and capabilities (CTAP2, U2F, wink), supported CTAP versions and AAGUID. wink makes each key blink to tell them apart. Keys on NFC readers (PC/SC) are listed too, as nfc:<reader>.",
			Params: []Param{{Name: "wink", Type: "bool", Desc: "Make each key blink (CTAPHID_WINK)"},
				{Name: "nfc", Type: "bool", Default: true, Desc: "Also list keys on smart-card and NFC readers (PC/SC), found by selecting the FIDO applet"}},
			Run: runFIDODevices,
		},
		&Op{
			Name:    "fido.info",
			Summary: "Ask a connected FIDO security key about itself (CTAP2 authenticatorGetInfo): CTAP versions, AAGUID, options explained (PIN set, discoverable credentials, built-in user verification, credential management, enterprise attestation), algorithms, extensions, firmware version, PIN length rules and free passkey slots. Needs no touch.",
			Params: []Param{{Name: "device", Type: "string", Desc: "Which key: index or path from fido.devices (default: the only one on USB); nfc, or nfc:<part of the reader name>, for a key on an NFC reader"},
				{Name: "metadata", Type: "bool", Desc: "Also look the model up in the FIDO Metadata Service (certification, security status)"}},
			Run: runFIDOInfo,
		},
	)
}
