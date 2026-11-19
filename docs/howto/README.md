# How-to guides

Task-based walkthroughs. For every parameter of every operation, see the
[command reference](../reference/README.md).

| Guide | When you need it |
|---|---|
| [Debug a failing OpenID Connect login](oidc-login.md) | A sign-in with an OIDC provider fails, or an API rejects the tokens it issued |
| [Check a SAML response](saml-response.md) | A SAML service provider rejects sign-ins, or you need to see what an IdP actually sends |
| [Check an OAuth server against the Security BCP](oauth-security-bcp.md) | You want to know whether a provider (and your client setup) follows RFC 9700 or the FAPI 2.0 Security Profile, or gate CI on it |
| [Test a SCIM server](scim-provisioning.md) | You build or integrate a SCIM 2.0 endpoint and want to know it behaves |
| [Kerberos against Active Directory](kerberos-active-directory.md) | TGTs, service tickets and PACs, constrained and resource-based delegation, FAST, PKINIT with a certificate or a YubiKey |
| [LDAP and passwords on Active Directory](ldap-active-directory.md) | LDAPS and StartTLS, reading AD attributes, changing and resetting passwords |
| [Use idpdbg from Claude and other MCP clients](mcp-clients.md) | Let an assistant run the same checks, with secrets kept out of the conversation |

## Reading the results

Every command prints one JSON object on stdout. Most carry a `checks` list,
each entry with `check` (what was tested), `status`, an optional `detail` and
an optional `ref` (the specification section).

| Status | Meaning |
|---|---|
| `pass` | The behaviour matches the specification |
| `fail` | It does not; the exit status becomes 2 |
| `warn` | Allowed, but risky or likely to break some clients |
| `info` | Worth knowing, no judgement |

Exit status is 0 when nothing failed, 1 on an error (the exchange could not
be completed; the message is on stderr) and 2 when a check failed, so scripts
and CI jobs can use it directly.

To see only what needs attention:

```bash
idpdbg oidc discover --issuer https://accounts.google.com | jq -r '.checks[] | select(.status != "pass") | "\(.status)\t\(.check)\t\(.detail // "")"'
```

`--trace` adds every HTTP request and response to the result (credentials in
requests are redacted; responses are shown as received).

`--report out.html` writes the same result as a readable page: what needs
attention first, then every check by step. Attach it to a ticket, or send it
to whoever runs the identity provider. It can contain tokens, like the JSON,
so check before sharing it.
