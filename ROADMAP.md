# Roadmap

What idpdbg doesn't cover yet, and in which order it is planned. Items are
ordered by how useful they are when debugging real identity systems, how
much work they are, and whether CI can test them against a real server, as
it does for Keycloak, Samba AD, MIT Kerberos and a SCIM server today.

Every item lands as its own change: with tests, an interop test where a real
server can run in CI, a CHANGELOG entry, and the line removed from
[Not covered (yet)](docs/testing.md#not-covered-yet).

Suggestions and use cases are welcome as issues. A concrete need moves an
item up.

## Phase 1: next

| Item | Why | Size | How it is tested |
|---|---|---|---|
| IdP-initiated SAML logout | Receive and answer the IdP's LogoutRequest; logout is a frequent source of bugs | S–M | Keycloak in CI |
| Software authenticator: packed attestation with a certificate chain, and fido-u2f | Tests whether a relying party really verifies attestation, including a negative test with a broken chain | M | Test relying party in the unit tests |
| Internal addresses for metadata URLs | Keep URLs from a provider's metadata (such as `jwks_uri`) off loopback, private and link-local addresses unless the issuer is on one or `--allow-private-urls` is given, as certificate URLs already are | S–M | Unit tests; the CI servers on localhost |

## Phase 2: later

| Item | Why | Size | How it is tested |
|---|---|---|---|
| OID4VCI with the authorization code flow | The other half of OID4VCI issuance, next to the pre-authorized code | M | Issuer container in CI |
| mdoc (ISO/IEC 18013-5) credentials | Decoding and issuer-signature checks first, presentation later | L | Published sample documents, then a container |
| CTAP 2.1 credential management | List the passkeys on a security key; deleting only with explicit confirmation | M | Emulated key in the unit tests; real keys by hand |
| SPIRE Server API | The server's administration API, next to the Workload API | L | SPIRE server container in CI |
| FIDO over NFC | Security keys through an NFC reader, over the existing PC/SC support | S–M | Real keys by hand (needs a reader) |
| OpenPGP card signing and decryption | Card operations that need the PIN; no key generation | M | Emulated card in the unit tests; real cards by hand |

## On request

Legacy or niche: planned when someone needs them.

- SAML 1.1 browser profiles
- WS-Trust renew and cancel; proof-of-possession keys
- FAST with cross-realm armor, and FAST factors other than encrypted
  challenge (such as SPAKE)
- XACML attribute selectors (XPath) and ALFA
- Indirect CRLs
- Post-quantum certificates: decoding first, once Go's standard library
  supports ML-DSA in certificates
- Security keys on Windows, through Windows' own WebAuthn API (Windows lets
  only administrators talk to keys directly)
- The Digital Credentials API: it is a browser API, so idpdbg could at most
  build and check the verifier's side

## Not planned

- Setting or changing a security key's PIN, and changing PIV PINs, PUKs or
  management keys. These change a device's state, the vendors' own tools do
  it well, and idpdbg already reports the PIN status.
- Bluetooth security keys, and secure messaging for smart cards: a lot of
  work for very few users.
