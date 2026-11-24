# Roadmap

What idpdbg doesn't cover yet, and in which order it is planned. Items are
ordered by how useful they are when debugging real identity systems, how
much work they are, and whether CI can test them against a real server, as
it does for Keycloak, Samba AD, MIT Kerberos, a SCIM server and SPIRE today.

Every item lands as its own change: with tests, an interop test where a real
server can run in CI, a CHANGELOG entry, and the line removed from
[Not covered (yet)](docs/testing.md#not-covered-yet).

Suggestions and use cases are welcome as issues. A concrete need moves an
item up.

## Phase 1: done

CRL locations over LDAP and delta CRLs, encrypted WS-Trust and
WS-Federation tokens, FAST armored by anonymous PKINIT, IdP-initiated SAML
logout, certificate attestation for the software authenticator, and
server-supplied URLs held to public addresses. The
[CHANGELOG](CHANGELOG.md) has the details.

## Phase 2: done

The OpenID4VCI authorization code flow, mdoc credentials (decoding, device
authentication, and presentation over OpenID4VP), CTAP 2.1 credential
management, the SPIRE Server API, OpenPGP card signing and decryption, and
FIDO security keys on NFC readers. The [CHANGELOG](CHANGELOG.md) has the
details.

There is no phase 3 yet: what comes next depends on what people need.

## On request

Legacy or niche: planned when someone needs them.

- SAML 1.1 browser profiles
- WS-Trust renew and cancel; proof-of-possession keys
- FAST with cross-realm armor, and FAST factors other than encrypted
  challenge (such as SPAKE)
- XACML attribute selectors (XPath) and ALFA
- Indirect CRLs
- SPIRE: banning and deleting agents, CA rotation (prepare, activate,
  taint, revoke), and changing federation relationships and bundles
- Composite (hybrid ML-DSA plus classical) and SLH-DSA certificates, once
  Go's standard library supports them
- The Digital Credentials API: it is a browser API, so idpdbg could at most
  build and check the verifier's side
- Shared Signals as a transmitter, to test receivers (push events to their
  endpoint, serve events for them to poll); and judging a transmitter
  against the CAEP Interoperability Profile, as `--fapi` does for FAPI 2.0
- OpenPGP cards whose PINs are hashed with a KDF (DO F9)
- ML-DSA keys in COSE for the software authenticator (passkeys), once
  relying parties accept them
- More attestation formats for the software authenticator: TPM, Android
  and Apple
- On Windows, the `fido` commands without administrator rights (Windows'
  WebAuthn API has no credential management for security keys)

Waiting on hardware or an account, not on code:

- FIDO over NFC with a real reader (tested against an emulated reader)
- Shared Signals streams and events at the public test transmitter
  ssf.caep.dev, which needs a token from its website

## Not planned

- Setting or changing a security key's PIN, and changing PIV PINs, PUKs or
  management keys. These change a device's state, the vendors' own tools do
  it well, and idpdbg already reports the PIN status.
- Bluetooth security keys, and secure messaging for smart cards: a lot of
  work for very few users.
