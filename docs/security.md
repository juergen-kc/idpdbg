# Secrets, profiles and the MCP safety model

How idpdbg keeps credentials out of shell history and conversations, binds
stored secrets to where they belong, and limits what an MCP caller can do.
For setting up an MCP client, see [Use idpdbg from Claude and other MCP
clients](howto/mcp-clients.md).

## Secrets and profiles

Secret parameters (client secrets, passwords, tokens, PINs, management keys)
fall back to the environment variable `IDPDBG_` plus the parameter name in
capitals, such as `IDPDBG_CLIENT_SECRET` or `IDPDBG_LDAP_PASSWORD`, so they
stay out of shell history and out of an MCP client's tool arguments. The
[reference](reference/README.md#secrets) lists them all.

A profile supplies defaults for any parameter. Put them in
`~/.config/idpdbg/config.json` (or the file named by `IDPDBG_CONFIG`) and select
one with `--profile name` or `IDPDBG_PROFILE`:

```json
{
  "profiles": {
    "dev": {
      "issuer": "https://idp.example.com",
      "client_id": "my-client",
      "client_secret": "…",
      "base_url": "https://example.com/scim/v2",
      "scim_token": "…"
    }
  }
}
```

Precedence: explicit parameter, then profile, then environment, then default.

Stored secrets are bound to where they belong. A secret taken from a profile
is only used with the exact origins (scheme, host and port) that appear in that
profile or in the comma-separated `IDPDBG_ALLOWED_HOSTS`. Pointing `--base-url`,
`--issuer` or an endpoint override anywhere else while relying on the stored
secret is refused, including the same host over plain http or on another port.
An `IDPDBG_ALLOWED_HOSTS` entry is either a full origin (`https://host:8443`)
or a bare host, which means its https and ldaps default ports only. Over MCP
the same applies to secrets from environment variables, and neither `insecure`
nor a caller's `ca_cert` is accepted while a stored secret is in use, so set `IDPDBG_ALLOWED_HOSTS`
(or use a profile) when configuring the server that way. A secret passed
explicitly is always used as given.
`idpdbg profiles` lists the profiles and their keys (never the values).

## What an MCP caller can and can't do

- `oidc_login` and `saml_login` open the browser on the machine running the
  server and block until sign-in completes (default 180 s). For a fully manual
  flow use `oidc_auth_url` + `oidc_exchange_code`, or `saml_authn_request` +
  `saml_decode`.
- Tools that change data (at the remote system, or on a smart card) are
  annotated as not read-only; the reference
  [lists them](reference/README.md#operations-that-change-data).
- With a real security key, `webauthn_register` and `webauthn_login` sign only
  for the origin the response is sent to (or offline for localhost), so a
  steered call cannot relay a real sign-in elsewhere.
- PINs (security keys, PIV) are asked for without echo on a terminal or taken
  from the environment, never retried, and not tried at all when too few
  attempts are left.
- An MCP caller cannot make the server read or write local files: the CLI's
  `@file` / `-` shorthand and `saml_sp_metadata`'s `out` are CLI-only, and the
  key material and metadata parameters (`sp_key`, `sp_cert`, `idp_cert`, `pem`,
  `jwks`, `idp_metadata`) accept a file path only from the CLI or from a
  profile. Over MCP, pass that content inline or put the path in a profile.
- `--report` is a command-line flag, not a tool parameter, so an MCP caller
  can't write an HTML report to disk. The CLI writes it to a new file readable
  only by you (replacing a link rather than writing through it), since it can
  hold tokens from the responses. Its parameter list only shows what says what
  was run (issuer, client ID, URLs, scope, principals, flags); every other
  parameter, including any added later, is left out.
- The loopback listener for browser flows only accepts the response that
  carries the run's own `state`. Another local process or a web page posting
  to localhost can neither end a run nor plant a result. If another process
  already holds the port on `::1` (where browsers try `localhost` first),
  idpdbg refuses to start rather than let it receive the redirect.
- `--trace` redacts credentials in requests (secrets, tokens, codes and
  credential-bearing headers). Responses are shown as received, so a trace of a
  token request still contains the issued tokens.
