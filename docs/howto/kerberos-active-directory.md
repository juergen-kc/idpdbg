# Kerberos against Active Directory

Everything here was run against a Windows Server 2022 domain controller. The
examples use its names: realm `IDPDBG.TEST`, DC `dc1.idpdbg.test`. Replace
them with yours.

## Before you start

- **Finding the KDC.** You don't need `--kdc` when DNS has the domain's SRV
  records: idpdbg looks up `_kerberos._tcp` (then `_udp`). On macOS it asks the
  system resolver, so a file in `/etc/resolver/` or a VPN's split DNS works,
  and the result says which resolver answered. Pass `--kdc dc1.idpdbg.test`
  (or `--krb5-conf`) to skip discovery.
- **Clock.** Kerberos needs the clocks within five minutes; `krb kinit`
  reports the skew.
- **Secrets.** Pass passwords as `IDPDBG_PASSWORD` (or a profile), not on the
  command line. Keytabs are files: build them with your usual tools (ktpass,
  ktutil) using AD's salt, the realm plus the sAMAccountName.

## Get a TGT

```bash
idpdbg krb kinit --principal alice@IDPDBG.TEST
```

```text
pass  pre-authentication enforced        the KDC demanded pre-authentication
pass  clock skew with the KDC            1s
pass  AS exchange (TGT issued)           krbtgt/IDPDBG.TEST
pass  TGT session key: encryption type   aes256-cts-hmac-sha1-96
info  TGT lifetime                       10h0m0s
```

An account that doesn't require pre-authentication fails the first check:
anyone can request an AS-REP for it and crack it offline (AS-REP roasting).

## Service tickets and the PAC

```bash
idpdbg krb service_ticket --principal alice@IDPDBG.TEST --spn HTTP/web.idpdbg.test --service-keytab web.keytab
```

Without the service keytab you see the ticket's encryption type (RC4 means
the service account can be Kerberoasted). With it, idpdbg decrypts the
ticket, checks the PAC signature with the service key, and decodes the PAC:

- logon info: groups and SIDs;
- the UPN and DNS info, with the sAMAccountName and SID;
- PAC attributes and the requestor SID;
- the services a delegated ticket passed through.

`--spnego-token` also prints a ready `Authorization: Negotiate` header.

To check a website's Windows authentication end to end:

```bash
idpdbg spnego http --url http://dc1.idpdbg.test/ --principal alice@IDPDBG.TEST
```

It reports whether the site offers Negotiate, whether it also offers NTLM (a
warning, because clients without a ticket fall back to it), whether the
ticket was accepted, and whether the server sent a mutual-authentication
token.

## Constrained delegation (S4U)

Run as the delegating service account, impersonating a user:

```bash
idpdbg krb s4u --principal svc-web@IDPDBG.TEST --keytab svc-web.keytab --impersonate alice --target-spn HTTP/app.idpdbg.test --target-keytab app.keytab
```

For resource-based delegation (the target's
`msDS-AllowedToActOnBehalfOfOtherIdentity` lists the service), add `--rbcd`.

When it works, the delegated ticket names alice, decrypts with the target's
keytab, and its PAC records the delegating service as transited. When it
doesn't, idpdbg explains the refusal from what it saw. For an account marked
sensitive:

```text
info  S4U2Self ticket forwardable            not forwardable. Active Directory withholds the flag …
warn  user can be delegated                  the account is marked sensitive and cannot be delegated …
fail  S4U2Proxy (constrained delegation)     (13) KDC_ERR_BADOPTION … the user cannot be delegated …
```

What Active Directory does, as observed on Windows Server 2022:

- S4U2Proxy needs a **forwardable** S4U2Self ticket, for resource-based
  delegation too. AD withholds the forwardable flag when the user can't be
  delegated, and when the service has classic delegation targets
  (`msDS-AllowedToDelegateTo`) but isn't trusted for protocol transition ("use
  any authentication protocol"). A service with no classic delegation
  configured, as is usual for resource-based delegation, gets it.
- Members of **Protected Users** and accounts marked **sensitive** can't be
  delegated. idpdbg reads both from the PAC of its own S4U2Self ticket.

## FAST armoring

```bash
idpdbg krb fast --principal alice@IDPDBG.TEST --keytab alice.keytab --armor-principal svc-web@IDPDBG.TEST --armor-keytab svc-web.keytab --target-spn HTTP/app.idpdbg.test
```

The armor TGT comes from a machine or service account. The run then checks:

- the armored error and the encrypted challenge;
- the KDC's own challenge (which authenticates the KDC);
- the strengthened reply key and the ticket checksums;
- with `--target-spn`, a FAST TGS exchange as well.

The KDC must have "KDC support for claims, compound authentication and
Kerberos armoring" enabled. Active Directory accepts armor at "Supported" but
only advertises FAST at "Always provide claims"; idpdbg reports that as
`info`, not as a failure.

## PKINIT with a certificate

The user needs a certificate with the Client Authentication or Smart Card
Logon purpose. Active Directory also needs a strong mapping: an
`altSecurityIdentities` value such as `X509:<I>issuer<SR>serial`, or the
certificate's SID extension.

```bash
idpdbg krb pkinit --principal alice@IDPDBG.TEST --pkinit-cert alice.crt --pkinit-key alice.key --ca-cert ca.pem --mode dh
```

`--ca-cert` lets idpdbg verify the KDC's certificate chain.

Active Directory works in Diffie-Hellman mode only. With the default
`--mode both`, the public-key encryption attempt fails with
KDC_ERR_ETYPE_NOSUPP, so use `--mode dh`. Expect two warnings:

- the KDC signs its reply with SHA-1;
- the AS-REP returns the PKAuthenticator's nonce instead of the request's.

Both are AD behaviour; Windows clients accept them.

## PKINIT with a YubiKey (PIV)

The key is generated on the card and never leaves it. idpdbg asks for the PIN
and the management key without echoing them. A management key that ykman
stored on the card behind the PIN (`--protect`) is read from there. A PIN is
never retried, and not tried at all with fewer than 2 attempts left.

1. Generate a key in slot 9A and a CSR with the user's UPN:

   ```bash
   idpdbg card piv_generate --slot 9a --common-name alice --upn alice@idpdbg.test
   ```

2. Have the CA issue a certificate from the CSR, then write it to the slot.
   idpdbg first has the card sign a test message to prove the certificate
   matches the key:

   ```bash
   idpdbg card piv_import --slot 9a --cert alice-piv.crt
   ```

3. Map the certificate to the user (strong mapping, as above), then:

   ```bash
   idpdbg krb pkinit --principal alice@IDPDBG.TEST --pkinit-piv-slot 9a --ca-cert ca.pem --mode dh
   ```

The domain controller logs event 4768 with pre-authentication type 16
(PKINIT).

## Samba as a domain controller

idpdbg's CI runs these checks against Samba 4.22 as well. Samba behaves like
Active Directory for the most part, with these differences:

- **Forwardable S4U2Self tickets:** only for services trusted for protocol
  transition. Resource-based delegation therefore needs `samba-tool delegation
  for-any-protocol <service> on` as well.
- **FAST:** advertised by default.
- **Pre-authentication:** demanded even for accounts with `DONT_REQ_PREAUTH`.

With any KDC, idpdbg reads from the PAC whether the user may be delegated
(sensitive, or in Protected Users), and fails "KDC refuses to delegate this
user" if a delegated ticket is issued anyway.

## MIT Kerberos

CI also runs these checks against an MIT krb5 1.21 KDC. Where it differs:

- **Pre-authentication:** principals don't require it unless created with
  `+requires_preauth`, and idpdbg flags the others as AS-REP roastable.
- **PAC:** MIT issues PACs without the Windows logon-info buffer. idpdbg still
  verifies their server signature.
- **S4U2Proxy:** refused with `UNSUPPORTED_S4U2PROXY_REQUEST` by the default
  db2 database, which can't hold delegation rights; it needs the LDAP back
  end. S4U2Self works for principals with `+ok_to_auth_as_delegate`.
- **PKINIT:** both Diffie-Hellman and public-key encryption mode work. MIT
  signs the request's nonce in KDCDHKeyInfo instead of the PKAuthenticator's,
  and encrypts the public-key reply with 3DES. idpdbg reports both as
  warnings.

## Decoding what you captured

- `idpdbg krb decode --message '…'` decodes AS, TGS and AP messages,
  KRB-ERROR (including the salts the KDC offers) and SPNEGO tokens, such as
  the value of an `Authorization: Negotiate` header.
- `idpdbg krb pac --pac '…' --keytab service.keytab` decodes a PAC on its own
  and verifies its signature.
