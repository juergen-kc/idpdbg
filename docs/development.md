# Development

Building idpdbg, running its tests, and how a release is made.

## Build

```bash
go build -o idpdbg .
```

`card read` talks to PC/SC through cgo (PCSC.framework on macOS, pcsc-lite on
Linux, WinSCard on Windows). A `CGO_ENABLED=0` build still works; only
`card read` then reports that it is unavailable.

Security keys (`fido`, and `webauthn` with `--authenticator usb`) are reached
over USB HID: IOKit on macOS (cgo), `/dev/hidraw*` on Linux (no cgo; access
comes from the udev rules distributions ship for FIDO devices). Windows is not
supported: it lets only administrators talk to security keys directly.

```bash
go test ./...
```

## Interop tests

Interop tests run idpdbg against a real Keycloak, a Samba AD domain
controller, an MIT Kerberos KDC, a SCIM server and a SPIRE server (in CI on
every push, and locally with Docker):

```bash
scripts/keycloak.sh
```

```bash
scripts/samba.sh
```

```bash
scripts/mitkdc.sh
```

```bash
scripts/scim.sh
```

```bash
scripts/spire.sh
```

```bash
go test -tags interop -v .
```

Each script starts a container (stop it with `stop` as the argument). The
tests are behind the `interop` build tag; `-run Keycloak`, `-run Samba`,
`-run MIT` or `-run SCIM` picks one server.

## Smoke test

`scripts/smoke.sh` checks what CI cannot reach, before a release: public
services (OIDC discovery and JWKS at Google and Microsoft, a site's OCSP
and CRL, the FIDO Metadata Service), the binary itself (the MCP handshake,
an HTML report), the four interop suites, and optionally an Active
Directory lab with AD CS and a security key. It prints one line per check
and a summary:

```bash
scripts/smoke.sh
```

```bash
scripts/smoke.sh adlab
```

The script's header says what the lab section expects. `IDPDBG=path` tests
a release binary instead of one built from the tree.

## Releases

What changed in each release is in [CHANGELOG.md](../CHANGELOG.md). Releases are
made by pushing a `v*` tag, after renaming the changelog's Unreleased section
to that version: the release workflow publishes the section as the release
notes. `scripts/build-release.sh` builds the same archives locally on a Mac.

## Command reference

`idpdbg docs` (or `go run . docs`) writes [the command reference](reference/README.md)
from the operation definitions. A test fails when the checked-in pages fall
behind, so run it after changing an operation.

## Layout

| File | Contents |
|---|---|
| `core.go` | Operation registry, parameter resolution, profiles, checks |
| `httpx.go` | Recording HTTP transport, loopback listener for browser flows |
| `oidc.go`, `jwt.go` | OAuth 2.0 / OpenID Connect, JWT and JWKS |
| `oauthx.go`, `jose.go` | Client assertions, DPoP, PAR, JAR, mTLS, logout, registration management; JWS signing |
| `saml.go`, `saml2.go`, `saml_idplogout.go` | SAML 2.0; Single Logout (SP- and IdP-initiated), Artifact binding, Redirect-binding signatures |
| `scim.go` | SCIM 2.0 |
| `ldapops.go`, `ldap_ad.go`, `ldap_adpasswd.go` | LDAP; Active Directory attribute decoding and password change/reset |
| `jwe.go`, `sdjwt.go`, `webauthn.go`, `tools.go` | JWE and JWT signing; SD-JWT; WebAuthn with CBOR/COSE; encoding and hashing |
| `webauthn_client.go`, `webauthn_hw.go`, `webauthn_attest.go` | Software authenticator (with packed and fido-u2f certificate attestation), security keys (CTAP2 and U2F) and WebAuthn ceremonies against a relying party |
| `webauthn_platform.go`, `webauthn_windows.go` | Security keys through the operating system's WebAuthn API: Windows' webauthn.dll, called without cgo |
| `fido_mds.go`, `fido_mds_roots.go` | FIDO Metadata Service: BLOB verification against the pinned root, cache, lookups, status and attestation trust |
| `fido.go`, `ctaphid.go`, `ctap_pin.go`, `hid_*.go` | FIDO security keys over USB HID: CTAPHID framing, CTAP2 commands, getInfo, ClientPIN (PIN/UV auth protocols 1 and 2); IOKit (macOS) and hidraw (Linux) |
| `ctapnfc.go`, `ctap_credmgmt.go` | CTAP over ISO 7816 (NFC and other PC/SC readers); CTAP 2.1 credential management |
| `gnap.go`, `httpsig.go` | GNAP; HTTP Message Signatures (RFC 9421) and Content-Digest (RFC 9530) |
| `vc.go` | OID4VCI (pre-authorized and authorization code) and OID4VP (SD-JWT VC) |
| `mdoc.go`, `mdoc_present.go` | mdoc (ISO/IEC 18013-5): COSE, MSO and device authentication; presentation over OID4VP |
| `wsstar.go` | WS-Federation, WS-Trust, SAML 1.1 |
| `ssf.go` | Shared Signals, CAEP, RISC |
| `spiffe.go` | SPIFFE (built on go-spiffe) |
| `spire.go` | The SPIRE Server API (gRPC, built on spire-api-sdk) |
| `krb.go`, `krb_srv*.go` | Kerberos and SPNEGO (built on gokrb5); KDC discovery through DNS SRV (the macOS system resolver via dns_sd) |
| `krb_s4u.go`, `krb_fast.go`, `krb_pkinit.go`, `cms.go` | S4U delegation; FAST armoring; PKINIT and the CMS signing and encryption it needs |
| `xacml.go` | XACML 3.0 policy decision point |
| `otp.go` | OATH HOTP/TOTP, Yubico OTP |
| `card.go`, `card_read.go`, `card_pcsc*.go` | BER-TLV, APDUs, PIV and OpenPGP card objects; reading cards over PC/SC (cgo) |
| `card_piv.go` | PIV key generation, certificate import and signing on a card (PIN and management key handling) |
| `card_openpgp.go` | OpenPGP card signing, authentication and decryption, checked against the card's public keys and fingerprints |
| `ocsp.go`, `crl.go` | OCSP requests and response validation; CRL download and validation |
| `crl_ldap.go` | CRLs from ldap(s) distribution points; delta CRLs |
| `pki.go`, `tlsprobe.go`, `mldsa_keys.go` | X.509 decoding, chain verification, a test CA (ML-DSA included); the TLS probe; ML-DSA private keys in every PKCS #8 form |
| `*_test.go` | Tests: mock OpenID providers (one strict about PAR/JAR/DPoP/private_key_jwt), mock SAML IdPs for SLO and artifacts, an in-process LDAP server, a mock SCIM server, an emulated PIV/OpenPGP token, an emulated CTAP2/U2F security key (also behind an emulated NFC reader and an emulated Windows WebAuthn API), an emulated OpenPGP card, an MCP client; OpenSSL-made ML-DSA certificates and keys in `testdata/pq`; `IDPDBG_HW_TEST=1` also runs WebAuthn with a real key (touch needed); `interop_*_test.go` (build tag `interop`) run against Keycloak (with a scripted browser), a Samba AD domain controller, an MIT KDC, i2scim and a SPIRE server; the SPIRE unit tests use an in-process fake SPIRE server |
| `mcp.go` | MCP stdio server |
| `main.go`, `docs.go` | CLI; the generated command reference in `docs/reference` |
