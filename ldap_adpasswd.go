package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// Active Directory does not implement the Password Modify extended operation
// (RFC 3062). It changes passwords through the unicodePwd attribute instead
// (MS-ADTS §3.1.1.3.1.5): the value is the password in double quotes,
// UTF-16LE encoded, and the server accepts it only on an encrypted
// connection.

const (
	oidPasswordModify = "1.3.6.1.4.1.4203.1.11.1"
	oidADCapability   = "1.2.840.113556.1.4.800" // LDAP_CAP_ACTIVE_DIRECTORY_OID
)

type rootDSEInfo struct {
	extensions, capabilities []string
	defaultNC                string
}

func readRootDSE(conn *ldap.Conn) (rootDSEInfo, error) {
	r, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"supportedExtension", "supportedCapabilities", "defaultNamingContext"}, nil))
	if err != nil || len(r.Entries) == 0 {
		return rootDSEInfo{}, err
	}
	e := r.Entries[0]
	return rootDSEInfo{e.GetAttributeValues("supportedExtension"), e.GetAttributeValues("supportedCapabilities"), e.GetAttributeValue("defaultNamingContext")}, nil
}

// adPasswordValue encodes a password for unicodePwd.
func adPasswordValue(pw string) string {
	var b []byte
	for _, u := range utf16.Encode([]rune(`"` + pw + `"`)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return string(b)
}

// adUserDN finds the entry for a bind name that is not a DN: a UPN
// (user@domain) or a down-level name (DOMAIN\user).
func adUserDN(conn *ldap.Conn, base, name string) (string, error) {
	if strings.Contains(name, "=") {
		return name, nil
	}
	filter := "(userPrincipalName=" + ldap.EscapeFilter(name) + ")"
	if _, sam, ok := strings.Cut(name, `\`); ok {
		filter = "(sAMAccountName=" + ldap.EscapeFilter(sam) + ")"
	}
	r, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		"(&(objectClass=user)"+filter+")", []string{"1.1"}, nil))
	if err != nil {
		return "", fmt.Errorf("looking up %s: %w", name, err)
	}
	if len(r.Entries) != 1 {
		return "", fmt.Errorf("looking up %s under %s: %d entries match; pass user_dn", name, base, len(r.Entries))
	}
	return r.Entries[0].DN, nil
}

// adPasswordHints explain the Win32 error at the start of AD's diagnostic
// message.
var adPasswordHints = map[string]string{
	"0000052D": "the new password breaks the domain's password policy: length, complexity, history, or the minimum password age (a user may change their own password only once per minimum age)",
	"00000056": "the current password (old_password) is wrong",
	"0000001F": "Active Directory accepts password changes only over an encrypted connection (ldaps:// or starttls)",
	"00000005": "access denied: setting someone else's password needs the Reset Password right; to change your own, pass old_password",
	"00000775": "the account is locked out",
	"0000203D": "the server does not know this extended operation; Active Directory has no RFC 3062 Password Modify: use method unicodepwd",
}

func adPasswordHint(err error) string {
	var le *ldap.Error
	if !errors.As(err, &le) || le.Err == nil {
		return ""
	}
	msg := le.Err.Error()
	for code, hint := range adPasswordHints {
		if strings.HasPrefix(msg, code) {
			return hint
		}
	}
	return ""
}

// adSetPassword changes (old_password given) or resets the password of dn.
func adSetPassword(conn *ldap.Conn, dn, oldPw, newPw string) (string, error) {
	req := ldap.NewModifyRequest(dn, nil)
	if oldPw != "" {
		// A change by the user: both values in one modify, delete then add.
		req.Delete("unicodePwd", []string{adPasswordValue(oldPw)})
		req.Add("unicodePwd", []string{adPasswordValue(newPw)})
		return "changed (old password verified by the server)", conn.Modify(req)
	}
	req.Replace("unicodePwd", []string{adPasswordValue(newPw)})
	return "reset (administrative set, no old password)", conn.Modify(req)
}
