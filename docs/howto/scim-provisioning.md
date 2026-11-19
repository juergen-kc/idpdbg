# Test a SCIM server

idpdbg acts as the provisioning client, as an identity provider would, and
checks that a SCIM 2.0 service provider answers as RFC 7643 and 7644 require.

Keep the bearer token out of your shell history:

```bash
export IDPDBG_SCIM_TOKEN='…'
```

If the service wants a different authentication header, pass it as a JSON
object with `--headers`.

## 1. See what the server says it supports

```bash
idpdbg scim discover --base-url https://example.com/scim/v2
```

This reads ServiceProviderConfig, ResourceTypes and Schemas and summarises
PATCH, bulk, filter, sort, ETag and authentication support. Many integration
problems are a client relying on something the server doesn't advertise.

## 2. Run a lifecycle scenario

The scenarios create real objects, so run them against a test tenant. The
objects get clearly marked `idpdbg-…` names and are deleted at the end, unless
you add `--keep`.

```bash
idpdbg scim scenario --base-url https://example.com/scim/v2 --scenario user_lifecycle
```

`user_lifecycle` creates a user, reads it back, finds it with a filter,
changes it with PATCH and with PUT, deactivates it, deletes it, and confirms
the server then answers 404. On the way it sends two creates the server must
refuse: a duplicate `userName` (409 with `scimType` "uniqueness") and a user
without `userName` (400). Anything the server wrongly creates is deleted
again.

```bash
idpdbg scim scenario --base-url https://example.com/scim/v2 --scenario group_lifecycle
```

`group_lifecycle` creates a user and a group, adds and removes the
membership, and deletes both.

Every step records the status code and checks the response body. Across all
steps, the scenario also checks:

- responses use `application/scim+json`;
- creates return a `Location` header that matches `meta.location`;
- `ETag` headers match `meta.version`;
- a 404 is a proper SCIM error message.

Use
`--user-name` or `--email-domain` when the server only accepts certain
userNames (for example, addresses in a verified domain).

## 3. Reproduce a single request

When one step fails, send that request on its own and change it until it
works:

```bash
idpdbg scim request --base-url https://example.com/scim/v2 --method PATCH --path /Users/2819c223 --body @patch.json --trace
```

## 4. Bulk

If the server supports bulk operations:

```bash
idpdbg scim bulk --base-url https://example.com/scim/v2 --operations @bulk.json
```

`bulk.json` is a JSON array of operations; `bulkId` references between them
are checked in the response. `--fail-on-errors` asks the server to stop after
that many failed operations (`failOnErrors`).

All of these except `scim discover` change data at the service. Over MCP they
are marked as not read-only.
