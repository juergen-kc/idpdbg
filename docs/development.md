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
controller, an MIT Kerberos KDC and a SCIM server (in CI on every push, and
locally with Docker):

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
go test -tags interop -v .
```

Each script starts a container (stop it with `stop` as the argument). The
tests are behind the `interop` build tag; `-run Keycloak`, `-run Samba`,
`-run MIT` or `-run SCIM` picks one server.

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
| `saml.go`, `saml2.go` | SAML 2.0; Single Logout, Artifact binding, Redirect-binding signatures |
| `scim.go` | SCIM 2.0 |
| `ldapops.go`, `ldap_ad.go`, `ldap_adpasswd.go` | LDAP; Active Directory attribute decoding and password change/reset |
| `jwe.go`, `sdjwt.go`, `webauthn.go`, `tools.go` | JWE and JWT signing; SD-JWT; WebAuthn with CBOR/COSE; encoding and hashing |
| `webauthn_client.go`, `webauthn_hw.go` | Software authenticator, security keys (CTAP2 and U2F) and WebAuthn ceremonies against a relying party |
| `fido_mds.go`, `fido_mds_roots.go` | FIDO Metadata Service: BLOB verification against the pinned root, cache, lookups, status and attestation trust |
| `fido.go`, `ctaphid.go`, `ctap_pin.go`, `hid_*.go` | FIDO security keys over USB HID: CTAPHID framing, CTAP2 commands, getInfo, ClientPIN (PIN/UV auth protocols 1 and 2); IOKit (macOS) and hidraw (Linux) |
| `gnap.go`, `httpsig.go` | GNAP; HTTP Message Signatures (RFC 9421) and Content-Digest (RFC 9530) |
| `vc.go` | OID4VCI and OID4VP (SD-JWT VC) |
| `wsstar.go` | WS-Federation, WS-Trust, SAML 1.1 |
| `ssf.go` | Shared Signals, CAEP, RISC |
| `spiffe.go` | SPIFFE (built on go-spiffe) |
| `krb.go`, `krb_srv*.go` | Kerberos and SPNEGO (built on gokrb5); KDC discovery through DNS SRV (the macOS system resolver via dns_sd) |
| `krb_s4u.go`, `krb_fast.go`, `krb_pkinit.go`, `cms.go` | S4U delegation; FAST armoring; PKINIT and the CMS signing and encryption it needs |
| `xacml.go` | XACML 3.0 policy decision point |
| `otp.go` | OATH HOTP/TOTP, Yubico OTP |
| `card.go`, `card_read.go`, `card_pcsc*.go` | BER-TLV, APDUs, PIV and OpenPGP card objects; reading cards over PC/SC (cgo) |
| `card_piv.go` | PIV key generation, certificate import and signing on a card (PIN and management key handling) |
| `ocsp.go`, `crl.go` | OCSP requests and response validation; CRL download and validation |
| `pki.go`, `tlsprobe.go` | X.509 decoding, chain verification, a test CA; the TLS probe |
| `*_test.go` | Tests: mock OpenID providers (one strict about PAR/JAR/DPoP/private_key_jwt), mock SAML IdPs for SLO and artifacts, an in-process LDAP server, a mock SCIM server, an emulated PIV/OpenPGP token, an emulated CTAP2/U2F security key, an MCP client; `IDPDBG_HW_TEST=1` also runs WebAuthn with a real key (touch needed); `interop_*_test.go` (build tag `interop`) run against Keycloak (with a scripted browser), a Samba AD domain controller, an MIT KDC and i2scim |
| `mcp.go` | MCP stdio server |
| `main.go`, `docs.go` | CLI; the generated command reference in `docs/reference` |
