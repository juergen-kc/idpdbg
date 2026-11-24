# Changelog

What changed in each release of idpdbg. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) (before 1.0, a minor version may
change behaviour).

Versions before 0.24.0, the first public release, were developed in a
private repository; their tags are not part of this one.

Add notes under **Unreleased** as changes land. When tagging, rename that
heading to the version and date: the release workflow publishes that section
as the release notes, and refuses a tag without one.

## [Unreleased]

### Added
- `mdoc decode` verifies device authentication when given the session
  transcript (`--session-transcript`): the device signature with the MSO's
  device key, or the device MAC with the reader's ephemeral key
  (`--reader-key`, derived as EMacKey). Tested with the ISO/IEC 18013-5
  Annex D session.

## [0.27.0] - 2026-11-23

### Added
- `vci issue`: the OID4VCI authorization code flow, for offers with an
  `authorization_code` grant and for wallet-initiated issuance (issuer and
  configuration_id, no offer). It asks the authorization server for the
  credential with authorization_details of type openid_credential (with
  `locations` whenever the issuer lists its authorization servers), the
  configuration's scope, or both (`--request-by`), passes the offer's
  issuer_state, uses PKCE and PAR when wanted, signs the person in through
  the browser, checks state, iss and that the token response names the
  credential, then requests and checks the credential as before.
  Tested against Keycloak's OID4VCI issuer in CI.
- `mdoc decode`: mdoc credentials (ISO/IEC 18013-5: the mDL, the EUDI PID
  in mso_mdoc format) as IssuerSigned, a Document or a DeviceResponse.
  Checks the issuer's COSE_Sign1 signature with the document signer
  certificate, its purpose and its chain to an IACA (`--trust-anchors`),
  the Mobile Security Object (version, docType, digest algorithm,
  validity, device key) and every data element against its digest, and
  shows the elements by namespace. `--at` judges validity at another time.
  Device authentication is decoded, not verified yet. Tested with the
  ISO/IEC 18013-5 Annex D sample.
- `vci issue` checks mso_mdoc credentials the same way, and that the MSO's
  device key is the holder key.

## [0.26.1] - 2026-11-23

### Added
- `scripts/smoke.sh`: a smoke test of what CI cannot reach (public
  services, the binary and its MCP handshake, the interop suites, an Active
  Directory lab, a security key), one line per check.

### Fixed
- `pki crl`: a delta CRL with the same number as its base CRL is applied;
  RFC 5280 §5.2.3 has the CA give both the same number when it issues them
  together, as AD CS does. Only an older delta, a replay, is refused.
- `pki crl`: when the CA publishes delta CRLs but no current one can be
  used (expired, unreachable, for another base), a certificate the base CRL
  clears is undetermined, not good. Windows treats this as revocation
  offline, and an Active Directory KDC then refuses PKINIT with
  KDC_ERR_CLIENT_NOT_TRUSTED; the check says so. Found against AD CS.
- A CRL location in a directory that refuses an anonymous read (Active
  Directory does) says how to read it as a user.
- The "subjectAltName present" check applies only to certificates that
  could serve TLS (serverAuth, or no extended key usage). `card read` no
  longer fails a PIV certificate mapped to its account another way, as an
  Active Directory smart card logon certificate can be.

## [0.26.0] - 2026-11-23

### Security
- URLs a server hands back are held to public addresses: a provider's
  `jwks_uri` and endpoints from discovery or metadata, SSF and OID4VCI
  endpoints, and any other origin the caller did not name. A hostile
  discovery document can no longer point idpdbg at loopback, private or
  link-local addresses (cloud metadata services among them). URLs that
  come inside content the caller passes (a credential offer, a
  presentation request) are held the same way when the caller names no
  server. If the URL the caller passed is itself on such an address (an
  internal IdP, Keycloak on localhost), server-supplied URLs may be too;
  over MCP only an address literal or a localhost name counts.
  `--allow-private-urls` is now available on every operation and lifts the
  rule; local OID4VCI issuers and OID4VP verifiers need it.

### Changed
- Public-only requests (the above, and URLs from certificates) try every
  resolved address, not only the first (an IPv6 address that refused the
  connection made them fail). They never use an HTTP proxy; when one is
  configured and the direct connection fails, the error says so.

### Added
- `krb pkinit --anonymous`: anonymous PKINIT (RFC 8062). A TGT for
  WELLKNOWN/ANONYMOUS with no client certificate; checks the KDC's
  signature and certificate, the anonymous name and ticket flag, and the
  KDC's contribution to the session key (PA_PKINIT_KX).
- `krb fast --armor-anonymous`: armor FAST with a TGT from anonymous
  PKINIT, the usual way to armor without a machine account. Tested
  against MIT krb5 in CI, through the encrypted challenge and a FAST
  service ticket.
- PKINIT in Diffie-Hellman mode also checks PA_PKINIT_KX when the KDC
  sends it, and says so when it does not.
- `saml idp_logout`: IdP-initiated Single Logout. idpdbg runs the local
  SingleLogoutService, receives the IdP's LogoutRequest (Redirect or POST
  binding through the browser, or SOAP), checks its signature (required on
  the front channel), issuer, Destination, timestamps and the NameID and
  SessionIndex it names (decrypting an EncryptedID with `--sp-key`), and
  answers with a LogoutResponse in the same binding: Success, partial, or
  an error, optionally signed. `--start-url` opens the IdP's logout page.
  CI signs in to Keycloak, logs out there, and checks the session is gone.
- SAML IdP metadata: a SingleLogoutService's ResponseLocation is used for
  logout responses.
- `webauthn register`: the software authenticator also attests with a
  certificate: `--attestation-format packed-x5c` (packed with an
  attestation certificate meeting WebAuthn §8.2.1, and idpdbg's AAGUID) or
  `fido-u2f`. `--attestation-ca` names the CA that issues the certificate,
  one the relying party trusts; without it a throwaway CA is used and its
  root shown. Two new tampers test the relying party's checks:
  `broken_attestation_chain` (a certificate from an impostor CA with the
  trusted CA's name; accepting it is a warning, since most relying parties
  rightly ignore attestation) and `bad_attestation_certificate` (a CA
  certificate with the wrong OU).

## [0.25.0] - 2026-11-23

### Added
- [ROADMAP.md](ROADMAP.md): what is planned next of the features not covered
  yet, in which order, and how each will be tested.
- `pki crl` reads CRLs from a directory: `ldap://` and `ldaps://`
  distribution points, including the host-less `ldap:///CN=…,CN=CDP,…`
  locations Active Directory Certificate Services writes by default. Such a
  location goes to `--ldap-url`, or to the domain named by the entry's DN;
  `--bind-dn` and `--ldap-password` read it as a user (only over ldaps:// or
  `--starttls`, and only from the directory in `--ldap-url`: a directory
  the certificate or CRL names is read anonymously). As for http
  locations, the directory must be on a public address unless
  `--allow-private-urls` is given, and its answer is capped like an HTTP
  response. `tls probe --crl` and the
  FIDO metadata signer check fetch these locations too.
- `pki crl` merges delta CRLs: it follows `freshestCRL` from the CRL or the
  certificate (or takes `--delta-crl`), checks the delta's issuer,
  signature, freshness, that it belongs to the base CRL and is newer than
  it, and applies it:
  certificates revoked since the base CRL, and certificates released from
  hold (removeFromCRL).
- CI publishes a base and a delta CRL in Samba AD's configuration partition
  and reads them back through an AD CS-style location.
- `wsfed login`, `wsfed decode` and `wstrust issue` decrypt tokens the STS
  encrypted to the relying party (`--rp-key`): a bare `xenc:EncryptedData`
  as AD FS sends it, or a SAML 2.0 `EncryptedAssertion`, then check the
  token inside as before. The key and data encryption algorithms are
  checked as for SAML (RSA PKCS#1 v1.5 and AES-CBC warn), and when the key
  does not fit, the error names the certificate the STS encrypted to.
- SAML decryption errors also name the certificate the IdP encrypted to,
  when the EncryptedKey says.

### Security
- Over MCP, `sp_key` and the new `rp_key` must be passed in the call, like
  the other keys that sign or decrypt what the caller supplies; they are no
  longer taken from a profile. Otherwise a tool call could decrypt any
  ciphertext encrypted to the person's SP key with `saml decode`, or sign
  SAML requests with it. On the command line nothing changes; MCP clients
  that relied on a profile's `sp_key` now pass the key inline.

## [0.24.0] - 2026-11-19

### Added
- [SECURITY.md](SECURITY.md): how to report vulnerabilities privately,
  what counts, and a note on the test fixtures.
- `.gitleaks.toml` and `.github/secret_scanning.yml` mark the test fixtures
  under `testdata/`, so secret scans come back clean and real findings
  stand out.

### Security
- Endpoints taken from a provider's metadata (token, introspection,
  revocation, PAR, UserInfo, registration, device authorization) now pass
  the stored-secret guard like explicit ones. A hostile or compromised
  discovery document could otherwise have named another host and received
  a client secret stored for the issuer.
- Over MCP, the relying party's answer to a real security key's signed
  response (which can hold a session for the person's account) is withheld
  like the response itself, in the result and in traces. A localhost relying
  party's response may not be sent to a remote host.
- SAML values are read as the signature covers them: an XML comment no longer
  truncates a NameID or other text (the CVE-2017-11427 class), and a NameID
  with a comment is flagged.

### Changed
- The README is a short front door now: what idpdbg is, a four-step
  getting-started path, the protocol map and pointers. Its longer material
  moved unchanged into
  [docs/security.md](docs/security.md) (secrets, profiles, MCP safety),
  [docs/testing.md](docs/testing.md) (real systems tested, what isn't
  covered) and [docs/development.md](docs/development.md) (building, tests,
  releases, layout).
- A test checks that every relative link in the README, the changelog and
  the docs points at a file that exists.

### Fixed
A review of the code added since v0.15.1 found these, all now covered by
tests:

- `oidc bcp_probe`:
  - `dpop_code_binding` failed falsely with a fixed `--dpop-key`: it now
    redeems with a fresh key.
  - The PAR probes counted any answer but 201 as a refusal. Now a request_uri
    means accepted, only a 4xx OAuth error is a refusal, and only when a
    valid pushed request from the client succeeds; anything else is
    inconclusive. Mutual-TLS clients aren't tested for unauthenticated PAR.
  - `pkce_downgrade` passed on any authorization error; only a PKCE error
    counts now.
  - The implicit and `par_required` probes follow through after sign-in
    instead of treating a sign-in page as acceptance.
  - The redirect URI probe waits the full time after sign-in, and tells a
    response at the registered URI from one at the altered one.
  - A `frame-ancestors` with a wildcard no longer counts as framing
    protection.
  - Probes that could not run are warnings, and a FAPI run with any of them
    no longer reports a clean summary.
- `scim scenario`:
  - A refusal probe could delete the scenario's own user when a server
    answered a duplicate with the existing user. Now only a fresh 201 is
    deleted, never the scenario's user, and the outcome is reported.
  - Relative `Location` headers are resolved.
  - Checks with nothing to judge are info, not pass.
  - Every error response is checked for the SCIM error format.
  - Media types compare case-insensitively.
- Kerberos:
  - The PAC fallback for MIT tickets only applies when the logon info alone
    is missing, and still requires the KDC signature and client info.
  - PAC signatures with RFC 8009 (SHA-2) and 3DES checksums verify.
  - "user can be delegated" is info when the PAC has no logon info.
  - PKINIT nonces are compared at full precision.
- `idpdbg docs <dir>` no longer deletes other Markdown files in the
  directory or writes through links; it only replaces pages it generated.
- `--report` writes a new 0600 file (not keeping an old file's mode or
  following a link), and rejects a missing file name instead of swallowing
  the next flag. Its parameter list is an allow list now: booleans, numbers
  and parameters that only say what was run (issuer, client ID, URLs, scope,
  principals). Everything else is hidden, including any parameter added
  later.
- Browser flows:
  - The callback only accepts the run's own `state`.
  - idpdbg refuses to start when another process holds the port on `::1`.
  - Redirect URIs must point at this machine, and one without a port uses
    the scheme's default.
- The interop containers listen on 127.0.0.1 only.

## [0.23.0] - 2026-11-19

### Added
- CI runs idpdbg against an MIT Kerberos 1.21 KDC on every push
  (`scripts/mitkdc.sh`, `interop_mit_test.go`). It covers kinit and AS-REP
  roasting detection, service tickets with MIT's PAC, S4U, FAST, and PKINIT in
  both modes.

### Fixed
- PAC verification failed on tickets from MIT krb5 1.20 and later ("does not
  contain a KerbValidationInfo"). Their PACs have no Windows logon-info
  buffer, and idpdbg now verifies the server signature without it.
- `krb s4u` explains MIT's `UNSUPPORTED_S4U2PROXY_REQUEST`: the db2 database
  can't hold delegation rights.
- `krb pkinit` names a KDCDHKeyInfo nonce that is the request's instead of
  the PKAuthenticator's (MIT does this) as a warning, not an unexplained
  failure, and a mismatch shows both values.

## [0.22.0] - 2026-11-19

### Added
- CI runs idpdbg against a real SCIM 2.0 server, i2scim 0.10.6, on every push
  (`scripts/scim.sh`, `interop_scim_test.go`). It covers discovery, both
  lifecycle scenarios, filters, wrong credentials and bulk.
- `scim scenario user_lifecycle` sends two creates the server must refuse: a
  duplicate `userName` (409, `scimType` "uniqueness") and a user without
  `userName` (400). It deletes anything wrongly created.
- `scim scenario` checks protocol details across all steps:
  - responses use `application/scim+json`;
  - creates return a `Location` header that matches `meta.location`;
  - `ETag` headers match `meta.version`;
  - a 404 is a SCIM error message with `status` as a string.

  Against i2scim these found:
  - no `Content-Type` header on any response;
  - a numeric `status` in error messages;
  - a User created without `userName`.

### Fixed
- Browser flows could cut off the "you can close this tab" page. The loopback
  listener closed while the answer was still being sent, and a browser then
  showed a connection error. It now shuts down gracefully, after the page is
  out. CI's race-detector run caught it.

## [0.21.0] - 2026-11-19

### Added
- `--report out.html` on every command writes a self-contained HTML page of
  the run:
  - what needs attention, then every check grouped by the step it came from;
  - the parameters (secrets and keys left out);
  - the full JSON result, and any `--trace` exchanges.

  It works in light and dark mode and on a phone. It is CLI-only (MCP
  callers can't write files), and readable only by you.

## [0.20.0] - 2026-11-19

### Added
- `--fapi` on every `oidc` operation judges the run against the FAPI 2.0
  Security Profile (and implies `--strict`):
  - discovery: PAR, PKCE S256, private_key_jwt or mutual TLS,
    sender-constrained tokens, the `iss` parameter, permitted signing
    algorithms, TLS;
  - login: PAR used, `iss` returned;
  - PAR: request URI lifetime;
  - tokens: a confidential client, PS256/ES256/EdDSA signatures;
  - refresh: no rotation.

  A "FAPI 2.0 Security Profile" check sums it up.
- `oidc bcp_probe --fapi` adds five probes:
  - a request without PAR refused;
  - PAR without client authentication refused;
  - PAR without `redirect_uri` refused;
  - a DPoP-bound code refused with another key;
  - a code refused after 61 seconds.
- Browser flows take an `https://localhost` redirect URI. idpdbg serves the
  callback with a throwaway self-signed certificate, since FAPI servers
  refuse `http` redirect URIs.
- CI tests a FAPI 2.0 client under Keycloak's FAPI 2.0 DPoP client policy.

### Fixed
- `oidc bcp_probe` keeps cookies while following the authorization server's
  own redirects, as a browser does (Keycloak answered `cookie_not_found`).
- `pkce_downgrade` counts a refusal at the PAR endpoint as PKCE being
  required.

## [0.19.0] - 2026-11-19

### Added
- CI runs idpdbg against a Samba 4.22 Active Directory domain controller on
  every push (`scripts/samba.sh`, `interop_samba_test.go`):
  - Kerberos: kinit, keytabs, service tickets and the PAC, S4U classic and
    resource-based, FAST;
  - LDAP: LDAPS and StartTLS, AD attribute decoding, password change and
    reset, and directory writes.
- `krb s4u` fails a new check, "KDC refuses to delegate this user", when the
  PAC says the user can't be delegated (sensitive, or in Protected Users)
  and the KDC issues the delegated ticket anyway.

### Changed
- The S4U explanations give both Active Directory's and Samba's rule for
  forwardable evidence. Samba makes S4U2Self tickets forwardable only for
  accounts trusted for protocol transition, also for resource-based
  delegation.
- The README and the Kerberos guide describe where Samba differs from Active
  Directory.

## [0.18.0] - 2026-11-19

### Added
- `--strict` on every `oidc` operation judges the run against the OAuth 2.0
  Security BCP (RFC 9700). Every recommendation that isn't met becomes a
  failure, and a summary check counts them, so CI can gate on it.
- New BCP checks, reported as warn or info without `--strict`:
  - discovery: asymmetric client authentication and sender-constrained
    tokens offered;
  - token responses: asymmetric client authentication used, access token
    sender-constrained, access token audience-restricted;
  - login: no access token in the front channel;
  - password grant: used at all;
  - refresh: a public client's refresh token rotated or sender-constrained.
- `oidc bcp_probe` sends requests a compliant server must refuse:
  - redirect URIs with an extra path, an extra query or another host;
  - the implicit grant, and a framable sign-in page;
  - a wrong `code_verifier`, and a PKCE downgrade;
  - a replayed authorization code (and whether its tokens get revoked);
  - a replayed refresh token after rotation.
- Guide: [Check an OAuth server against the Security
  BCP](docs/howto/oauth-security-bcp.md).

## [0.17.0] - 2026-11-19

### Added
- CI runs idpdbg against Keycloak 26.8 on every push (`scripts/keycloak.sh`,
  `interop_test.go`), with a scripted browser:
  - OIDC: discovery, login (also with private_key_jwt, PAR, JAR and DPoP),
    and every grant, token exchange, introspection, UserInfo, revocation,
    dynamic registration and logout;
  - SAML: login and logout, also with signed requests and encrypted
    assertions.
- `oidc device --pkce` and `oidc device_poll --code-verifier`, for servers
  that want PKCE on the device grant (Keycloak does for clients that require
  PKCE). The error that names `code_challenge` now suggests it.

### Changed
- `oidc introspect` explains an inactive JWT: it expired, or its audience
  leaves out the introspecting client (Keycloak 26 reports such tokens
  inactive).
- `saml logout` reports a signed LogoutRequest as a pass, not just an
  unsigned one as a warning.

## [0.16.0] - 2026-11-19

### Added
- `idpdbg docs` writes a Markdown [command reference](docs/reference/README.md)
  from the operation definitions. A test fails when the checked-in reference
  falls behind.
- Six [how-to guides](docs/howto/README.md): OpenID Connect login, SAML
  responses, SCIM servers, Kerberos and LDAP on Active Directory, and MCP
  clients. A test checks every `idpdbg` command in the guides and the README
  against the real operations and parameters.

### Changed
- `--help` lists each group once, with a title.
- The README is reorganised: one line per group linking to the reference,
  a "Tested against real systems" section, and outdated sections corrected.

## [0.15.1] - 2026-11-19

### Fixed
- `tls probe` says "not offered: the server stops at TLS 1.2" when TLS 1.3 is
  missing, instead of an `info` check with no detail.

## [0.15.0] - 2026-11-18

### Added
- `krb pkinit --pkinit-piv-slot`: PKINIT with a key on a smart card or
  YubiKey.
- `card piv_generate`: generates a key pair in a PIV slot (the private key
  never leaves the card), with a CSR the card signs, optionally with a UPN.
- `card piv_import`: writes a certificate into a slot, after a test
  signature proves it matches the key.
- A management key that ykman stored on the card behind the PIN
  (`--protect`) is read from there.
- PINs and management keys come from a no-echo prompt or the environment. A
  PIN is never retried, and not tried at all with fewer than 2 attempts
  left.

## [0.14.0] - 2026-11-18

### Added
- `krb pkinit`: a TGT from a certificate and its key (RFC 4556).
  - It sends the signed AuthPack with an RFC 8070 freshness token, and
    handles Diffie-Hellman (MODP 14 or 2) and public-key encryption replies.
  - It checks the KDC's signature, certificate chain, purpose and name, the
    nonce, and the reply key binding.
  - It explains refusals, including Active Directory's strong certificate
    mapping.
- Verified in Diffie-Hellman mode against Active Directory. Windows Server
  2022 returns the PKAuthenticator nonce, signs with SHA-1, and refuses
  public-key encryption mode.

## [0.13.0] - 2026-11-18

### Added
- Resource-based constrained delegation verified against Active Directory.
  `krb s4u` reads from its own S4U2Self ticket whether the user can be
  delegated (sensitive, Protected Users). It uses that, the forwardable flag
  and the RBCD request flag to explain a refusal.
- The PAC's SAMR user account flags are decoded, with NOT_DELEGATED.

### Fixed
- The hint about non-forwardable evidence: Active Directory refuses it for
  resource-based delegation too.

## [0.12.0] - 2026-11-18

### Added
- `--ca-cert` on every operation: extra CA certificates to trust, such as an
  internal or Active Directory CA. Over MCP a caller can't add one while a
  stored secret is in use.
- `ldap passwd` on Active Directory: `unicodePwd` change and reset, chosen
  from the root DSE. It is refused without TLS, and AD's error codes are
  explained.
- On macOS, KDCs are found through the system resolver, so `/etc/resolver`
  files and VPN split DNS work; the result says which resolver answered.

### Fixed
- StartTLS never set the server name to verify, so every verified StartTLS
  failed.

### Security
- Hostnames from SRV records are validated, and every discovered KDC passes
  the same check as one given by hand.

## [0.11.0] - 2026-11-18

### Added
- Kerberos and LDAP verified against Active Directory (Windows Server 2022).
- PAC decoding names every buffer and decodes the extended UPN/DNS info,
  attributes, requestor SID and the services a delegated ticket transited.
- `krb s4u --target-keytab` verifies the delegated ticket's PAC.
- `ldap search` decodes AD SIDs, GUIDs, userAccountControl, encryption types
  and FILETIME timestamps.

### Fixed
- S4U2Proxy sent a malformed evidence ticket, which Windows dropped without
  an answer. S4U2Proxy now works.
- `krb service_ticket` with `--service-keytab` and `--spnego-token` put the
  decrypted part into the AP-REQ.
- `krb fast`: Active Directory accepts armor without advertising FAST, which
  is now `info` rather than a warning.

## [0.10.0] - 2026-11-18

### Added
- `webauthn login --passkey`: passkey sign-in with a security key. The key
  offers its accounts for the site, and `--account` or a prompt picks one.

### Security
- Passkey requests without user presence are refused, and over MCP the
  accounts are listed by number only. Text from keys and relying parties has
  control characters removed before it is printed.

## [0.9.0] - 2026-11-18

### Added
- `fido metadata`: FIDO Metadata Service (MDS3) lookups by AAGUID, key ID,
  certificate or name. The BLOB is verified against the pinned FIDO roots
  and cached.
- `--metadata` on `fido info`, `webauthn decode` and `webauthn register`
  checks the attestation chain to the model's root.

## [0.8.0] - 2026-11-18

### Added
- User verification on security keys with the PIN (CTAP2 ClientPIN,
  protocols 1 and 2), or the key's fingerprint reader.
- Discoverable credentials (`--resident-key`).
- PINs are never retried, and not tried at all with fewer than 3 attempts
  left.

## [0.7.0] - 2026-11-18

### Added
- Real security keys over USB HID (IOKit on macOS, hidraw on Linux).
  - `fido devices` and `fido info`.
  - `webauthn register` and `webauthn login` with `--authenticator usb`,
    over CTAP2, or U2F where a browser would fall back to it.

### Security
- Over MCP, a security key signs only for the origin the response is sent
  to, with the site's own options. The signed response is withheld from the
  result.

## [0.6.0] - 2026-11-18

### Added
- `krb fast`: FAST armoring (RFC 6113), with the encrypted challenge, the
  KDC's challenge, the strengthened reply key and ticket checksums.

## [0.5.0] - 2026-11-18

### Added
- `krb s4u`: S4U2Self protocol transition and S4U2Proxy constrained
  delegation (MS-SFU).

### Fixed
- WebAuthn custom-API mode loads the site's page first, for its session
  cookie, as a browser does.

## [0.4.0] - 2026-11-17

### Added
- `webauthn register` and `webauthn login`: passkey ceremonies against a
  relying party with a software authenticator. `--tamper` sends broken
  responses that the server must reject.

## [0.3.0] - 2026-11-17

### Added
- `pki crl`, and `--crl` on `tls probe`: revocation status from CRLs, with
  delta CRLs and issuingDistributionPoint scope. For CAs without OCSP.

## [0.2.0] - 2026-11-16

### Added
- `pki ocsp`, and stapled and live OCSP in `tls probe`.

### Security
- URLs taken from certificates may not reach loopback, private or link-local
  addresses unless `--allow-private-urls` is given.

## [0.1.1] - 2026-11-16

### Fixed
- The release workflow attests build provenance only where GitHub supports
  it.

## [0.1.0] - 2026-11-16

### Added
- The first release: an identity protocol debugger that is both a CLI and an
  MCP server, generated from one definition per operation.
- Protocols:
  - OAuth 2.0 and OpenID Connect, with client authentication methods, DPoP,
    PAR, JAR, logout and dynamic registration;
  - JWT, JWKS, JWE and SD-JWT;
  - SAML 2.0, with Single Logout and the Artifact binding;
  - WS-Federation and WS-Trust;
  - SCIM 2.0, with bulk requests;
  - LDAP;
  - Kerberos and SPNEGO;
  - SPIFFE;
  - Shared Signals (CAEP, RISC);
  - GNAP;
  - OID4VCI and OID4VP;
  - XACML 3.0;
  - PKI and a TLS probe;
  - WebAuthn decoding;
  - OATH and Yubico OTP;
  - smart-card decoding over PC/SC.
- Profiles and environment variables for secrets, with stored secrets bound
  to the hosts they belong to. MCP callers can't read local files.

[Unreleased]: https://github.com/juergen-kc/idpdbg/compare/v0.27.0...HEAD
[0.27.0]: https://github.com/juergen-kc/idpdbg/compare/v0.26.1...v0.27.0
[0.26.1]: https://github.com/juergen-kc/idpdbg/compare/v0.26.0...v0.26.1
[0.26.0]: https://github.com/juergen-kc/idpdbg/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/juergen-kc/idpdbg/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/juergen-kc/idpdbg/releases/tag/v0.24.0
