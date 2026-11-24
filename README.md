# idpdbg

An identity protocol debugger for the terminal and for AI assistants. idpdbg
plays the client, relying party, service provider or wallet against a real
identity system, and shows every exchange decoded, with a list of checks
against the specifications.

- **One binary, two interfaces.** Every operation is both a CLI command and an
  MCP tool, generated from the same definition.
- **Built for scripts and CI.** JSON output, a `checks` list with spec
  references, and exit status 2 when a check fails. `--strict` and `--fapi`
  judge a provider against the OAuth Security BCP and the FAPI 2.0 Security
  Profile.
- **Readable when you need it.** `--report out.html` writes a page of the run
  to attach to a ticket.
- **Tested against real servers.** Every push runs idpdbg against Keycloak,
  Samba AD, MIT Kerberos, a SCIM server, SPIRE and a Shared Signals
  transmitter; [details](docs/testing.md).

It covers OAuth 2.0 and OpenID Connect, JWT/JWE/SD-JWT, SAML 2.0, WS-Federation
and WS-Trust, SCIM, LDAP, Kerberos and SPNEGO, PKI and TLS (post-quantum ML-DSA
and ML-KEM included), WebAuthn and FIDO security keys, PIV and OpenPGP smart
cards, SPIFFE and SPIRE, Shared Signals, GNAP, verifiable credentials (SD-JWT VC
and mdoc) and XACML. It is inspired by [idptools.com](https://idptools.com/) /
[id-proto-debugger](https://rcbj.github.io/id-proto-debugger/), as a fresh Go
implementation.

## Getting started

### 1. Install

Download the archive for your platform from the releases page, check it
against `SHA256SUMS`, and put `idpdbg` on your PATH. Releases of the public
repository also carry a signed build provenance attestation, which
`gh attestation verify <archive> --owner juergen-kc` checks. Or build from
source:

```bash
go install github.com/juergen-kc/idpdbg@latest
```

`idpdbg version` confirms it works, and says
whether the build can read smart cards. The macOS and Windows builds can; the
static Linux builds can't (build from source with pcsc-lite for that).

### 2. Check a provider

No account needed: point idpdbg at any OpenID Connect issuer.

```bash
idpdbg oidc discover --issuer https://accounts.google.com --report google.html
```

The JSON on stdout lists each check with `pass`, `fail`, `warn` or `info`, and
the specification it comes from. `google.html` shows the same as a page, with
what needs attention first. Add `--strict` to judge the provider against the
OAuth 2.0 Security BCP.

### 3. Sign in to your own provider

Register a client with the redirect URI `http://localhost:8765/callback`, keep
its secret out of your shell history, and run the login:

```bash
export IDPDBG_CLIENT_SECRET='…'
```

```bash
idpdbg oidc login --issuer https://idp.example.com --client-id my-client
```

Your browser opens. After you sign in, idpdbg checks the whole flow:

- the authorization response;
- the token exchange;
- the ID token's signature, issuer, audience and nonce;
- UserInfo.

For SAML, register idpdbg as a service provider (`idpdbg saml sp_metadata`)
and run `idpdbg saml login`.

### 4. Use it from Claude

```bash
claude mcp add idpdbg -- /absolute/path/to/idpdbg mcp
```

Then ask, for example, "discover https://idp.example.com and tell me what's
misconfigured". Keep secrets in a profile or the server's environment, not in
the conversation: see [the MCP guide](docs/howto/mcp-clients.md).

### Next steps

| To | Read |
|---|---|
| Debug a failing OpenID Connect login, or tokens an API rejects | [OIDC login guide](docs/howto/oidc-login.md) |
| Check a provider against the OAuth Security BCP or FAPI 2.0 | [Security BCP guide](docs/howto/oauth-security-bcp.md) |
| See what a SAML IdP sends, and why an SP rejects it | [SAML guide](docs/howto/saml-response.md) |
| Test a SCIM server | [SCIM guide](docs/howto/scim-provisioning.md) |
| Debug Kerberos, delegation, FAST or PKINIT on Active Directory | [Kerberos guide](docs/howto/kerberos-active-directory.md) |
| Work with LDAP and passwords on Active Directory | [LDAP guide](docs/howto/ldap-active-directory.md) |
| Look up every operation and parameter | [Command reference](docs/reference/README.md) |

## Using idpdbg

```
idpdbg <group> <operation> [--param value ...]
idpdbg <group> <operation> --help
```

- **Output:** JSON on stdout; progress and prompts on stderr.
- **Exit status:** 0, 1 on an error, 2 when a check failed.
- **On every operation:**
  - `--trace` adds the raw HTTP exchanges, with credentials in requests
    redacted;
  - `--report out.html` writes the run as a page;
  - `--ca-cert` trusts an internal or Active Directory CA.
- **Secrets** (client secrets, passwords, tokens, PINs) fall back to
  `IDPDBG_<PARAMETER>` environment variables. A profile in
  `~/.config/idpdbg/config.json` supplies defaults. Stored secrets are only
  sent to the hosts they belong to: see
  [Secrets, profiles and the MCP safety model](docs/security.md).

What each group covers:

| Group | Covers |
|---|---|
| [`oidc`](docs/reference/oidc.md) | Discovery, login with auth code + PKCE (also implicit and hybrid), PAR, JAR, DPoP, private_key_jwt and mutual TLS client auth, client credentials, password, refresh, device flow, token exchange, introspection, revocation, UserInfo, dynamic registration, logout; `--strict` judges against the OAuth Security BCP (RFC 9700) and `--fapi` against the FAPI 2.0 Security Profile, and `bcp_probe` tests what a server enforces of them |
| [`jwt`](docs/reference/jwt.md), [`jwks`](docs/reference/jwks.md) | Decode, verify (RS/PS/ES/EdDSA/HS, and post-quantum ML-DSA; keys from the issuer, a JWKS, PEM or a secret) and sign JWTs; fetch a JWKS |
| [`jwe`](docs/reference/jwe.md) | Decrypt and encrypt: RSA-OAEP, RSA1_5, ECDH-ES, AES and AES-GCM key wrap, PBES2, dir |
| [`sdjwt`](docs/reference/sdjwt.md) | SD-JWT and SD-JWT VC: disclosures, reconstructed claims, issuer signature, key binding |
| [`mdoc`](docs/reference/mdoc.md) | mdoc (ISO/IEC 18013-5, mDL and EUDI PID): issuer signature, document signer chain, MSO validity and element digests; device authentication (signature or MAC) against the session transcript |
| [`saml`](docs/reference/saml.md) | IdP and SP metadata, AuthnRequests, login with a local ACS (POST or Artifact), response decoding with signature checks and decryption, Single Logout (SP- and IdP-initiated) |
| [`wsfed`](docs/reference/wsfed.md), [`wstrust`](docs/reference/wstrust.md) | WS-Federation passive sign-in and wresult decoding; WS-Trust issue (AD FS usernamemixed) and validate; encrypted tokens decrypted with the relying party's key |
| [`scim`](docs/reference/scim.md) | Discovery, single requests, user and group lifecycle scenarios, bulk |
| [`ldap`](docs/reference/ldap.md) | Root DSE, bind, paged search with Active Directory attributes decoded, writes, compare, password change and reset (RFC 3062, or `unicodePwd` on AD) |
| [`krb`](docs/reference/krb.md) | kinit, service tickets with PAC verification, keytabs, message decoding, S4U constrained delegation (classic and resource-based), FAST (armored by a TGT or by anonymous PKINIT), PKINIT with a key file or a PIV smart card, anonymous PKINIT; KDCs found through DNS SRV |
| [`spnego`](docs/reference/spnego.md) | Negotiate sign-on to a web resource: offered schemes, NTLM fallback, mutual authentication |
| [`pki`](docs/reference/pki.md) | Certificate, chain, CSR and CRL decoding, chain verification, a throwaway test CA, leaf issuance, OCSP and CRL revocation checks (CRLs over HTTP or LDAP, delta CRLs included); post-quantum ML-DSA keys and signatures |
| [`tls`](docs/reference/tls.md) | Versions, cipher, key exchange (post-quantum or not), ALPN, chain trust, OCSP stapling, client certificates, mutual TLS, LDAP and SMTP StartTLS |
| [`webauthn`](docs/reference/webauthn.md) | Decode ceremonies; register and sign in against a relying party with a software authenticator (attestation none, packed or fido-u2f) or a real security key (on Windows through the Windows WebAuthn API, no administrator rights needed); `--tamper` negative tests |
| [`fido`](docs/reference/fido.md) | Security keys over USB or an NFC reader, CTAP2 authenticatorGetInfo, the passkeys a key stores (list and delete, CTAP 2.1 credential management), FIDO Metadata Service (MDS3) lookups |
| [`card`](docs/reference/card.md) | Read cards and YubiKeys over PC/SC; decode APDUs, PIV and OpenPGP objects; generate a PIV key on the card and import its certificate; sign, authenticate and decrypt with an OpenPGP card, checked against its public key and fingerprint |
| [`oath`](docs/reference/oath.md), [`yubico`](docs/reference/yubico.md) | HOTP and TOTP codes; Yubico OTP decoding and checks |
| [`spiffe`](docs/reference/spiffe.md) | SPIFFE IDs, X509- and JWT-SVIDs, trust bundles, the Workload API |
| [`spire`](docs/reference/spire.md) | The SPIRE Server API over the admin socket or mTLS: server, CA and bundle state, entries, agents, federation; minting checked SVIDs; creating and deleting entries and join tokens |
| [`ssf`](docs/reference/ssf.md) | Shared Signals: discovery, streams, poll and push delivery (a local HTTPS receiver), Security Event Token checks for CAEP and RISC |
| [`gnap`](docs/reference/gnap.md) | Grants with HTTP message signatures, interaction, continuation, rotation, revocation |
| [`vci`](docs/reference/vci.md), [`vp`](docs/reference/vp.md) | OID4VCI issuance as a wallet (pre-authorized code, or the authorization code flow); OID4VP requests and presentations of SD-JWT VCs (selective disclosure) and mdocs (only the requested elements, device-signed) |
| [`xacml`](docs/reference/xacml.md) | XACML 3.0 decisions with a trace, and policy lint |
| [`tools`](docs/reference/tools.md) | Encode, decode (recognises JWT, JWE, SD-JWT, SAML and PEM inside URL, base64, hex and DEFLATE layers) and hash |

## More

- [Tested against real systems, and what isn't covered](docs/testing.md), and
  the [roadmap](ROADMAP.md) for what comes next
- [Development](docs/development.md): building, tests, interop tests, releases
  and the source layout
- [CHANGELOG.md](CHANGELOG.md): what changed in each release
- [SECURITY.md](SECURITY.md): how to report a vulnerability privately
- License: Apache 2.0 ([LICENSE](LICENSE))
