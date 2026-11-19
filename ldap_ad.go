package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Active Directory stores some identity attributes in binary or numeric
// encodings. entryMap keeps the raw values and adds readable forms.

// adBinaryKind names attributes that are always binary, even when their
// bytes happen to be valid UTF-8.
func adBinaryKind(attr string) string {
	switch strings.ToLower(attr) {
	case "objectsid", "securityidentifier", "sidhistory", "tokengroups", "tokengroupsglobalanduniversal", "msds-allowedtoactonbehalfofotheridentity-sid":
		return "sid"
	case "objectguid", "schemaidguid", "attributesecurityguid", "msds-consistencyguid", "ms-ds-consistencyguid", "msexchmailboxguid", "invocationid":
		return "guid"
	}
	return ""
}

// guidString formats a GUID in Windows byte order (MS-DTYP §2.3.4.2).
func guidString(b []byte) (string, bool) {
	if len(b) != 16 {
		return "", false
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]),
		binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:]), true
}

// adBinaryValue renders a binary attribute value, with the SID or GUID
// spelled out when the attribute is a known one.
func adBinaryValue(kind string, b []byte, raw string) M {
	v := M{"base64": raw}
	switch kind {
	case "sid":
		if s, ok := sidString(b); ok {
			v["sid"] = s
		}
	case "guid":
		if s, ok := guidString(b); ok {
			v["guid"] = s
		}
	}
	return v
}

var uacFlags = []struct {
	bit  int64
	name string
}{
	{0x1, "SCRIPT"}, {0x2, "ACCOUNTDISABLE"}, {0x8, "HOMEDIR_REQUIRED"}, {0x10, "LOCKOUT"}, {0x20, "PASSWD_NOTREQD"},
	{0x40, "PASSWD_CANT_CHANGE"}, {0x80, "ENCRYPTED_TEXT_PWD_ALLOWED"}, {0x100, "TEMP_DUPLICATE_ACCOUNT"},
	{0x200, "NORMAL_ACCOUNT"}, {0x800, "INTERDOMAIN_TRUST_ACCOUNT"}, {0x1000, "WORKSTATION_TRUST_ACCOUNT"},
	{0x2000, "SERVER_TRUST_ACCOUNT"}, {0x10000, "DONT_EXPIRE_PASSWORD"}, {0x20000, "MNS_LOGON_ACCOUNT"},
	{0x40000, "SMARTCARD_REQUIRED"}, {0x80000, "TRUSTED_FOR_DELEGATION"}, {0x100000, "NOT_DELEGATED"},
	{0x200000, "USE_DES_KEY_ONLY"}, {0x400000, "DONT_REQ_PREAUTH"}, {0x800000, "PASSWORD_EXPIRED"},
	{0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"}, {0x4000000, "PARTIAL_SECRETS_ACCOUNT"},
}

var encTypeFlags = []struct {
	bit  int64
	name string
}{
	{0x1, "DES-CBC-CRC"}, {0x2, "DES-CBC-MD5"}, {0x4, "RC4-HMAC"}, {0x8, "AES128-CTS-HMAC-SHA1-96"},
	{0x10, "AES256-CTS-HMAC-SHA1-96"}, {0x20, "AES256-CTS-HMAC-SHA1-96-SK"}, {0x10000, "FAST-supported"},
	{0x20000, "Compound-identity-supported"}, {0x40000, "Claims-supported"}, {0x80000, "Resource-SID-compression-disabled"},
}

func flagNames(v int64, table []struct {
	bit  int64
	name string
}) []string {
	names := []string{}
	for _, f := range table {
		if v&f.bit != 0 {
			names = append(names, f.name)
			v &^= f.bit
		}
	}
	if v != 0 {
		names = append(names, fmt.Sprintf("0x%x", v))
	}
	return names
}

// fileTime renders a Windows FILETIME (100 ns since 1601-01-01 UTC).
func fileTime(s string) (string, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return "", false
	}
	switch {
	case n == 0:
		return "never / not set", true
	case n == 1<<63-1:
		return "never", true
	case n < 0:
		return "", false
	}
	const epochDiff = 116444736000000000 // 1601 to 1970 in 100 ns units
	t := time.Unix(0, 0).Add(time.Duration(n-epochDiff) * 100)
	return t.UTC().Format(time.RFC3339), true
}

// adDecoded returns readable forms of numeric AD attributes, keyed by the
// attribute name as the server returned it.
func adDecoded(name string, vals []string) any {
	if len(vals) != 1 {
		return nil
	}
	switch strings.ToLower(name) {
	case "useraccountcontrol", "msds-user-account-control-computed":
		if n, err := strconv.ParseInt(vals[0], 10, 64); err == nil {
			return flagNames(n, uacFlags)
		}
	case "msds-supportedencryptiontypes":
		if n, err := strconv.ParseInt(vals[0], 10, 64); err == nil {
			return flagNames(n, encTypeFlags)
		}
	case "pwdlastset", "lastlogon", "lastlogontimestamp", "badpasswordtime", "accountexpires", "lockouttime", "msds-userpasswordexpirytimecomputed":
		if t, ok := fileTime(vals[0]); ok {
			return t
		}
	}
	return nil
}
