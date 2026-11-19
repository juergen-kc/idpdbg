# LDAP and passwords on Active Directory

The `ldap` operations work with any LDAPv3 directory. This guide covers what
is different on Active Directory, as tested against Windows Server 2022.

Pass the bind password as `IDPDBG_LDAP_PASSWORD` (or in a profile), not on
the command line.

## Connect securely

AD offers LDAPS on port 636 and StartTLS on 389. Both need a certificate on
the domain controller (AD CS issues one automatically). Give idpdbg the CA
certificate when it isn't in the system trust store:

```bash
idpdbg ldap bind --url ldaps://dc1.idpdbg.test --ca-cert ca.pem --bind-dn alice@idpdbg.test
```

```bash
idpdbg ldap bind --url ldap://dc1.idpdbg.test --starttls --ca-cert ca.pem --bind-dn alice@idpdbg.test
```

Both report the TLS version in **transport is encrypted**, then the bind and
"Who am I?". AD accepts a UPN (`alice@idpdbg.test`) or `DOMAIN\user` as the
bind DN, as well as a full DN.

To see which TLS versions the DC accepts, and what its certificate chain
looks like:

```bash
idpdbg tls probe --host dc1.idpdbg.test --port 636 --ca-cert ca.pem
```

## Read AD attributes

```bash
idpdbg ldap search --url ldaps://dc1.idpdbg.test --ca-cert ca.pem --bind-dn alice@idpdbg.test --base-dn "OU=Lab,DC=idpdbg,DC=test" --filter "(sAMAccountName=bob)" --attributes userAccountControl,objectSid,pwdLastSet
```

Each entry has the raw values and a `decoded` map:

- SIDs and GUIDs as strings;
- `userAccountControl` as flag names, for example `NORMAL_ACCOUNT`,
  `DONT_EXPIRE_PASSWORD`, `NOT_DELEGATED`;
- `msDS-SupportedEncryptionTypes` as encryption type names;
- FILETIME values such as `pwdLastSet` and `lastLogonTimestamp` as dates.

For more than 1000 results, add `--page-size 500`. AD caps a single response.

## Change or reset a password

`ldap passwd` picks the method from the root DSE: the RFC 3062 Password
Modify extended operation where it's offered, and AD's `unicodePwd` attribute
on Active Directory. AD only accepts password writes over an encrypted
connection, so idpdbg refuses to send one over plain LDAP.

**Change** your own password: bind as the user and give the old password.

```bash
export IDPDBG_LDAP_PASSWORD='current' IDPDBG_OLD_PASSWORD='current' IDPDBG_NEW_PASSWORD='new'
```

```bash
idpdbg ldap passwd --url ldaps://dc1.idpdbg.test --ca-cert ca.pem --bind-dn pwtest@idpdbg.test --user-dn "CN=pwtest,OU=Lab,DC=idpdbg,DC=test"
```

```text
pass  transport is encrypted          TLS 1.2
pass  bind                            bound as pwtest@idpdbg.test
pass  password change (unicodePwd)    changed (old password verified by the server)
```

**Reset** someone else's password: bind as an account with the "Reset
password" permission on the user, and leave out the old password.

When AD refuses, idpdbg explains the code in its diagnostic message:

| Code | Cause |
|---|---|
| `0000052D` | The new password breaks the password policy: length, complexity, history, or the minimum password age (users can change their own password only once per minimum age) |
| `00000056` | The old password is wrong |
| `00000005` | Access denied: resetting someone else's password needs the Reset Password right; to change your own, give the old password |
| `00000775` | The account is locked out |
| `0000001F` | The connection isn't encrypted (idpdbg doesn't send it in the first place) |

A wrong old password counts toward the account lockout threshold.

## Other writes

`ldap add`, `modify`, `delete` and `rename` change the directory. Over MCP
they're marked as not read-only. Try them in a test OU first.
