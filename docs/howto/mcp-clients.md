# Use idpdbg from Claude and other MCP clients

`idpdbg mcp` serves every operation as an MCP tool over stdio, with the same
parameters as the command line. An assistant can then discover a provider,
decode a token or run a SCIM scenario for you, and explain the checks.

## Add the server

For Claude Code:

```bash
claude mcp add idpdbg -- /absolute/path/to/idpdbg mcp
```

For other clients, add it to the MCP configuration:

```json
{
  "mcpServers": {
    "idpdbg": {
      "command": "/absolute/path/to/idpdbg",
      "args": ["mcp"],
      "env": { "IDPDBG_PROFILE": "dev" }
    }
  }
}
```

## Keep secrets out of the conversation

Anything you pass as a tool argument ends up in the conversation. Put client
secrets, tokens and passwords in a [profile](../security.md#secrets-and-profiles),
or in the server's environment (`IDPDBG_CLIENT_SECRET`, `IDPDBG_SCIM_TOKEN`,
…), and select the profile with `IDPDBG_PROFILE` or the `profile` argument.

idpdbg binds stored secrets to where they belong, so a steered tool call
can't send them elsewhere:

- A secret from a profile is used only with the origins that appear in that
  profile or in `IDPDBG_ALLOWED_HOSTS`.
- Over MCP, the same goes for secrets from the environment. Set
  `IDPDBG_ALLOWED_HOSTS` (for example `https://idp.example.com`) when you
  configure the server that way.
- While a stored secret is in use, the caller can't turn off certificate
  checks (`insecure`) or add its own CA (`ca_cert`).

## What an MCP caller can't do

- **Read or write local files.** Key material and metadata (`sp_cert`,
  `pem`, `jwks`, `idp_metadata`, keytabs, …) can't be file paths in a tool
  call: pass the content inline, or put the path in a profile.
- **Sign or decrypt what it supplies with a stored key.** Keys that sign or
  decrypt content from the caller (`sp_key`, `rp_key`, JWT and JWE keys, a
  CA's key, …) must be passed in the call, never taken from a profile or the
  environment. Keys that authenticate idpdbg to a server (`client_key`,
  `mtls_key`, `dpop_key`, keytabs) may come from a profile, but only go to
  the profile's origins.
- **Relay a security-key sign-in.** With a real key, `webauthn_register` and
  `webauthn_login` sign only for the origin the response is sent to (or
  offline for localhost).

## Tools that need you

- **Browser sign-in.** `oidc_login`, `saml_login`, `wsfed_login`,
  `oidc_logout`, `saml_logout` and `gnap_grant` open the browser on the
  machine running the server, and wait for you to finish. Without a browser
  there, use `oidc_auth_url` with `oidc_exchange_code`, or
  `saml_authn_request` with `saml_decode`.
- **Security keys and smart cards.** These wait for a touch, or ask for a PIN
  on the server's terminal. With no terminal, they take the PIN from the
  environment (`IDPDBG_PIN`, `IDPDBG_PIV_PIN`).
- **Writes.** Tools that change data at the remote system or on a card are
  annotated as not read-only, so the client can ask before running them. See
  the [list](../reference/README.md#operations-that-change-data).

## Things to ask

- "Discover https://idp.example.com and tell me what's misconfigured."
- "Decode this SAML response and check it against SP entity ID
  https://sp.example.com."
- "Run the SCIM user lifecycle against the staging profile and summarise the
  failures."
- "Get a service ticket for HTTP/web.example.com and show me the groups in the
  PAC."

Add `trace` to see the raw HTTP exchanges. Requests are redacted, but
responses are shown as received, so a trace of a token request contains the
issued tokens.
