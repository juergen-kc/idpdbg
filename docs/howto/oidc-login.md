# Debug a failing OpenID Connect login

idpdbg plays the relying party: it runs the whole Authorization Code flow
with PKCE against your provider and checks each step, from discovery to the
ID token and UserInfo.

## 1. Check the provider's metadata

```bash
idpdbg oidc discover --issuer https://idp.example.com
```

Look for:

- **issuer matches the URL used for discovery exactly.** A trailing slash
  or a different host here is the most common reason a library rejects every
  ID token from the provider later.
- **required metadata** entries, and **jwks_uri is reachable**.
- Warnings about PKCE `plain` or front-channel response types. They don't
  stop the login, but they're worth raising with the provider.

## 2. Register idpdbg as a client

At the provider, create (or reuse) a client with the redirect URI
`http://localhost:8765/callback`. Use `--redirect-port`, `--redirect-path` or
`--redirect-uri` if you need a different one. A provider that only accepts
https redirect URIs, as FAPI 2.0 servers do, takes
`https://localhost:8765/callback`: idpdbg then serves the callback with a
throwaway self-signed certificate, which your browser asks you to accept once.
Keep the client secret out of your shell history:

```bash
export IDPDBG_CLIENT_SECRET='…'
```

Or put the issuer, client ID and secret in a [profile](../security.md#secrets-and-profiles)
and add `--profile name` to the commands below.

## 3. Run the login

This opens your browser and waits up to 180 seconds for you to sign in:

```bash
idpdbg oidc login --issuer https://idp.example.com --client-id my-client --scope "openid profile email"
```

idpdbg checks, among others:

- **state matches the request** and **iss response parameter matches the
  issuer**, which defend against CSRF and mix-up attacks;
- **id_token: signature**, **id_token: iss matches the issuer**,
  **id_token: nonce matches the request**, and **azp** when there are several
  audiences;
- **userinfo: sub matches the ID token**;
- granted scopes that had no effect: `offline_access` without a refresh token,
  or `profile`/`email` without any of their claims.

Add `--trace` to see every request and response. Add `--strict` to fail
everything the OAuth Security BCP recommends that this login didn't do (see
[the BCP guide](oauth-security-bcp.md)).

## 4. Narrow it down

- **The browser shows an error before you're asked to sign in.** It's
  usually the redirect URI or a scope. Build the request without sending it
  and compare it with the client's registration:

  ```bash
  idpdbg oidc auth_url --issuer https://idp.example.com --client-id my-client --redirect-uri http://localhost:8765/callback
  ```

  The result has the `authorization_url` plus the `state`, `nonce` and PKCE
  `code_verifier` it used.
- **You can't receive the redirect on this machine** (a remote host, or an MCP
  client). Open the `authorization_url` yourself, copy the `code` from the
  address bar after sign-in, and exchange it:

  ```bash
  idpdbg oidc exchange_code --issuer https://idp.example.com --client-id my-client --redirect-uri http://localhost:8765/callback --code '…' --code-verifier '…' --nonce '…'
  ```
- **The token request fails.** Check the client authentication method. The
  provider may expect `--client-auth post`, `private_key_jwt`
  (with `--client-key`) or mutual TLS (`--mtls-cert`, `--mtls-key`).
  `oidc discover` lists what it supports.
- **The provider wants PAR, signed request objects or DPoP.** Add `--par`,
  `--jar` or `--dpop`.
- **The device flow fails with a missing `code_challenge`.** The provider
  wants PKCE on the device grant (Keycloak does when the client requires
  PKCE): add `--pkce` to `oidc device`.

## 5. When an API rejects the token

Verify the access token the way the API should, against the issuer's keys
and the audience the API expects:

```bash
pbpaste | idpdbg jwt verify --token - --issuer https://idp.example.com --audience https://api.example.com
```

If the token is opaque (not a JWT), ask the provider about it instead:

```bash
idpdbg oidc introspect --issuer https://idp.example.com --client-id my-api --token '…'
```

An inactive result isn't always a revoked token. idpdbg says when the token
has expired, or when its audience leaves out the client that asked. Keycloak
26, for example, reports such tokens inactive to that client; add an audience
mapper for it.

Not sure what a string is? `idpdbg tools decode --input '…'` recognises JWTs,
JWEs, SD-JWTs, SAML messages and PEM, even inside URL encoding or base64.
