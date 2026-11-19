# Check an OAuth server against the Security BCP (RFC 9700)

[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), the OAuth 2.0 Security
Best Current Practice, says how authorization servers and clients should
use OAuth today: PKCE everywhere, no implicit or password grant, exact
redirect URI matching, sender-constrained tokens and more. idpdbg checks it
in two ways:

- **Strict mode** (`--strict` on any `oidc` command) judges what a normal
  run observes. Every BCP recommendation that isn't met becomes a failure.
- **Probes** (`oidc bcp_probe`) send requests a compliant server must refuse,
  and report what the server actually enforces.

## Strict mode

Without `--strict`, idpdbg reports BCP findings as warnings or info. With
it, every unmet recommendation fails, and a summary check counts them:

```bash
idpdbg oidc discover --issuer https://idp.example.com --strict
```

```text
fail  implicit grant not offered                     strict: grant_types_supported includes implicit
fail  resource owner password grant not offered      strict: grant_types_supported includes password, which must not be used
pass  sender-constrained access tokens offered       DPoP, mTLS-bound tokens
fail  strict mode (RFC 9700)                         2 recommendation(s) of the OAuth 2.0 Security BCP not met
```

The exit status is 2 when anything fails, so a CI job can gate on it:

```bash
idpdbg oidc discover --issuer https://idp.example.com --strict > discovery.json
```

What strict mode looks at:

| Where | Check | RFC 9700 |
|---|---|---|
| Discovery | PKCE S256 advertised, plain not offered | §2.1.1 |
| Discovery | No implicit grant and no response type that returns tokens in the front channel | §2.1.2 |
| Discovery | No resource owner password grant | §2.4 |
| Discovery | Asymmetric client authentication (private_key_jwt, mutual TLS) offered | §2.5 |
| Discovery | Sender-constrained tokens (DPoP, mTLS-bound) offered | §2.2.1 |
| Login | PKCE used; no access token in the front channel | §2.1.1, §2.1.2 |
| Token responses | The client authenticated asymmetrically | §2.5 |
| Token responses | The access token is sender-constrained | §2.2.1 |
| Token responses | The access token is audience-restricted (JWT `aud`) | §2.3 |
| Password grant | The grant was used at all | §2.4 |
| Refresh | A public client's refresh token is rotated or sender-constrained | §2.2.2 |

Strict mode also judges your client setup. A login with a client secret
and bearer tokens fails strict mode, even against a perfect server. To show
that a server supports the BCP, log in the way the BCP wants:

```bash
idpdbg oidc login --issuer https://idp.example.com --client-id my-client --client-auth private_key_jwt --client-key client.key --par --dpop --strict
```

## Probes

`oidc bcp_probe` uses the same client and loopback redirect URI as `oidc
login`. It sends requests that the server must refuse, so run it against a
test client, not a production one.

```bash
idpdbg oidc bcp_probe --issuer https://idp.example.com --client-id my-client
```

| Probe | What it sends | A compliant server |
|---|---|---|
| `redirect_uri` | The registered redirect URI with an extra path segment, an extra query parameter, or another host | Refuses with an error page and never redirects there |
| `implicit` | `response_type=token` | Refuses it for this client |
| `clickjacking` | A normal request, to read the sign-in page's headers | Sends `X-Frame-Options` or CSP `frame-ancestors` |
| `pkce` | A token request with the wrong `code_verifier` | Refuses it |
| `pkce_downgrade` | A request without `code_challenge`, then a token request with a `code_verifier` | Refuses the request, or the token request |
| `code_replay` | The same authorization code twice | Refuses the second use, and should revoke what the first produced |
| `refresh_replay` | A refresh token again after it was rotated | Refuses it, for public clients at least |

The first three need no sign-in. The others need one each, and the
provider's session usually completes all but the first by itself. Choose
probes with `--probes`, for example `--probes redirect_uri,implicit,clickjacking`
to stay away from the browser.

Some results are `info` rather than pass or fail, when idpdbg can't see the
outcome:

- **A sign-in page for a tampered redirect URI.** The server may compare
  the redirect URI only after sign-in. For tampered URIs that still point at
  idpdbg's listener, the probe goes through the browser and fails if a code
  arrives. For another host it can't tell.
- **A confidential client's old refresh tokens still work.** That's
  allowed. The BCP only requires rotation or binding for public clients.

## FAPI 2.0

The [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
builds on the BCP for high-value APIs: open banking, open data, health.
`--fapi` on any `oidc` command adds its requirements as checks, ends with a
"FAPI 2.0 Security Profile" summary check, and implies `--strict`.

| Where | Requirement |
|---|---|
| Discovery | PAR, PKCE S256, private_key_jwt or mutual TLS, DPoP or mTLS-bound tokens, the `iss` response parameter, `response_type=code`, PS256/ES256/EdDSA offered and `none` refused, TLS on every endpoint |
| Login | PAR used (only `client_id` and `request_uri` in the browser), PKCE S256, `iss` returned, an https redirect URI |
| PAR | `request_uri` expires in under 600 seconds |
| Token responses | A confidential client with private_key_jwt or mutual TLS, sender-constrained tokens, ID and access tokens signed with PS256, ES256 or EdDSA |
| Refresh | Not rotated (FAPI asks servers not to, except in extraordinary circumstances) |

A FAPI login looks like this:

```bash
idpdbg oidc login --issuer https://idp.example.com --client-id my-fapi-client --client-auth private_key_jwt --client-key client.key --par --dpop --redirect-uri https://localhost:8765/callback --fapi
```

FAPI servers refuse `http` redirect URIs. With an `https://localhost` redirect
URI, idpdbg serves the callback over TLS with a throwaway self-signed
certificate. Your browser warns about it once; accept it to let the response
through. idpdbg prints the certificate's fingerprint so you can compare.

`oidc bcp_probe --fapi` adds five probes:

| Probe | What it sends | A FAPI server |
|---|---|---|
| `par_required` | An authorization request with its parameters in the browser | Refuses it |
| `par_client_auth` | A pushed request without client authentication | Refuses it |
| `par_redirect_uri` | A pushed request without `redirect_uri` | Refuses it |
| `dpop_code_binding` | A code requested with `dpop_jkt`, redeemed with another DPoP key | Refuses it (needs `--dpop`) |
| `code_lifetime` | A code redeemed after 61 seconds | Refuses it (codes live at most 60 seconds) |

`code_lifetime` makes the run take a minute longer.

The network layer (TLS 1.2 or later, the BCP 195 cipher suites) isn't
covered by `--fapi`. Check it with `tls probe`.

## What Keycloak does

Keycloak 26.8, as tested in CI with its default settings:

- **Strict discovery fails.** Keycloak advertises the password and implicit
  grants and plain PKCE (they can be turned off per client).
- **All probes pass.** It refuses altered redirect URIs and the implicit
  grant before sign-in, protects the sign-in page against framing, enforces
  PKCE and refuses the downgrade (for a client set to require S256), and
  refuses a replayed code. On a replayed code, it also revokes the session
  that the code started.
- **Strict mode passes** for a login with private_key_jwt, PAR and DPoP.
- **FAPI 2.0:** the CI realm has a client under Keycloak's
  `fapi-2-dpop-security-profile` client policy, with PAR required and an
  audience mapper. It passes `--fapi` for discovery, login and every probe,
  including DPoP-bound codes and the 60-second code lifetime. Keycloak
  refuses its `http://localhost` redirect URI, so the client uses
  `https://localhost`.
