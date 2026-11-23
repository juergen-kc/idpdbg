# Tested against real systems, and what isn't covered

idpdbg's unit tests run against mock servers. These checks ran against real
ones; the CI jobs repeat most of them on every push. How to run them locally
is in [development.md](development.md#interop-tests).

## Systems

- Active Directory on Windows Server 2022, with AD CS and only TLS 1.2
  enabled: `krb kinit`, `service_ticket` with PAC verification, `s4u`
  (classic and resource-based), `fast`, `pkinit` with a key file and with a
  YubiKey PIV key, KDC discovery through DNS SRV, `ldap` over LDAP, LDAPS and
  StartTLS including password change and reset, and `spnego http` against IIS.
  Behaviour idpdbg recognises and explains there:
  - S4U2Proxy accepts only forwardable S4U2Self evidence, for resource-based
    delegation too; sensitive accounts and Protected Users members are
    refused, which idpdbg reads from the PAC.
  - The KDC advertises FAST only when its policy is "Always provide claims".
  - PKINIT works in Diffie-Hellman mode; public-key encryption mode is
    refused with KDC_ERR_ETYPE_NOSUPP. The AS-REP returns the PKAuthenticator
    nonce, the KDC signs with SHA-1, and certificates need a strong mapping.
- Keycloak 26.8, in CI on every push (`interop_test.go`, realm in
  `testdata/keycloak`). The OIDC side covers:
  - discovery, JWKS, and browser login with PKCE (client secret, or
    private_key_jwt with PAR, signed request objects and DPoP);
  - the client credentials, password, refresh and device grants;
  - token exchange, introspection, UserInfo and revocation;
  - dynamic registration with read and delete, and RP-initiated logout;
  - the RFC 9700 probes and strict mode;
  - a FAPI 2.0 client (Keycloak's FAPI 2.0 DPoP client policy) with `--fapi`
    and its probes.

  The SAML side covers metadata, and SP-initiated login and Single Logout,
  both plain and with signed requests and encrypted assertions. Behaviour
  idpdbg explains there:
  - Introspection reports a token inactive when the asking client isn't in
    its audience.
  - The device grant needs PKCE (`--pkce`) when the client requires it.
- Samba 4.22 as an AD domain controller (functional level 2016), in CI on
  every push (`interop_samba_test.go`, set up by `testdata/samba`). It covers:
  - kinit, keytabs, service tickets with PAC verification, and RC4 tickets
    flagged as Kerberoastable;
  - S4U classic and resource-based, and refusals for sensitive users;
  - FAST;
  - TLS on LDAPS, LDAP over LDAPS and StartTLS: binds, decoded attributes,
    password change, wrong-password and reset, and add, modify, compare,
    rename and delete;
  - CRLs read from the directory: a base and a delta CRL published where
    Active Directory Certificate Services puts them (`CN=CDP,CN=Public Key
    Services` in the configuration partition), found through a host-less
    `ldap:///` location and read as an ordinary user
    (`interop_samba_crl_test.go`).

  Where Samba differs from Active Directory:
  - It makes S4U2Self evidence forwardable only for accounts trusted for
    protocol transition, so resource-based delegation needs that too.
  - It advertises FAST by default.
  - It demands pre-authentication even for accounts with `DONT_REQ_PREAUTH`.
- i2scim 0.10.6, a SCIM 2.0 server, in CI on every push
  (`interop_scim_test.go`). It covers discovery, both lifecycle scenarios,
  filters, wrong credentials and bulk. Where it departs from RFC
  7643/7644, and idpdbg says so:
  - its responses carry no `Content-Type` header;
  - its ServiceProviderConfig has no `etag` member;
  - its error messages give `status` as a number, not a string;
  - it creates a User without `userName`;
  - it advertises bulk as unsupported, yet answers `/Bulk`.
- MIT Kerberos 1.21, in CI on every push (`interop_mit_test.go`, set up by
  `testdata/mitkdc`). It covers:
  - kinit, with a principal lacking pre-authentication flagged as AS-REP
    roastable;
  - service tickets with MIT's PAC;
  - S4U2Self, and S4U2Proxy refused by its db2 database and explained;
  - FAST;
  - PKINIT in both Diffie-Hellman and public-key encryption mode.

  MIT signs the request's nonce in KDCDHKeyInfo, the mirror image of
  Active Directory's AS-REP nonce, and encrypts the public-key reply with
  3DES although AES was offered.
- YubiKey 5 (PIV): key generation on the card, certificate import with a
  PIN-protected management key, and PKINIT.

## Not covered (yet)

The [roadmap](../ROADMAP.md) says which of these are planned, and in which
order.

Compared with the upstream debugger this version leaves out: SAML 1.1 browser
profiles and IdP-initiated logout; WS-Trust renew/cancel, proof-of-possession
keys; OID4VCI authorization-code issuance, mdoc
credentials and the Digital Credentials API; for the software authenticator, attestation formats beyond none and packed self attestation;
on security keys, setting or changing the PIN, credential management, NFC and Bluetooth, and Windows;
on smart cards, OpenPGP card operations that need a PIN, changing PIV PINs,
PUKs or management keys, and secure messaging; FAST with anonymous PKINIT or cross-realm armor, and FAST factors other than encrypted challenge; the SPIRE Server API; XACML AttributeSelector (XPath) and ALFA;
post-quantum certificates; indirect CRLs.
