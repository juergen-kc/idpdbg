# Security policy

idpdbg handles credentials, talks to identity systems on your behalf and,
as an MCP server, takes instructions from AI assistants. Security reports
are welcome.

## Reporting a vulnerability

Please report privately, not in a public issue: use **Report a
vulnerability** on the repository's Security tab (GitHub private
vulnerability reporting). Include what you found, how to reproduce it, and
the idpdbg version (`idpdbg version`).

You can expect an answer within a week. Fixes are released as soon as they
are ready, and the CHANGELOG credits the reporter unless they prefer
otherwise.

## What counts

Anything that breaks idpdbg's own promises, for example:

- a stored secret (profile or environment) sent to a host it doesn't belong
  to;
- an MCP caller reading or writing local files, using a stored signing key,
  or relaying a security-key sign-in;
- a check that reports `pass` for something insecure, such as a forged
  signature or token accepted as valid;
- credentials appearing in traces, reports or logs where idpdbg says they
  are redacted;
- the loopback listener for browser flows accepting responses it should
  turn away.

[docs/security.md](docs/security.md) describes these protections.

Findings about identity providers or other software that idpdbg detects
belong with that software's vendor, not here.

## Supported versions

Only the latest release gets fixes. idpdbg is a single binary; upgrading
means downloading the new release.

## Test fixtures

The private keys and passwords under `testdata/` and in `scripts/` belong to
throwaway servers the interop tests start locally. They are not secrets.
