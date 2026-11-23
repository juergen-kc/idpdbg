# Check a SAML response

Two ways in. Either let idpdbg be the service provider and run the sign-in,
or decode a response you captured from a real service provider's sign-in.

## Run SP-initiated sign-in

1. Generate idpdbg's SP metadata and register it with the IdP. That's the
   entity ID `idpdbg` and the ACS `http://localhost:8766/saml/acs`:

   ```bash
   idpdbg saml sp_metadata --out sp-metadata.xml
   ```

2. Check the IdP's metadata:

   ```bash
   idpdbg saml metadata --idp-metadata https://idp.example.com/saml/metadata
   ```

   It should have an **entityID**, a **SingleSignOnService** and a **signing
   certificate**.

3. Sign in. This opens your browser and waits for the response on the local
   ACS:

   ```bash
   idpdbg saml login --idp-metadata https://idp.example.com/saml/metadata
   ```

   Add `--sign --sp-key sp.key --sp-cert sp.crt` if the IdP wants signed
   AuthnRequests, or `--response-binding artifact` to test the Artifact
   binding.

## Test logout started at the IdP

When a person signs out at the IdP, it sends each service provider a
LogoutRequest. idpdbg can play that service provider: it listens on the
same local SingleLogoutService (`http://localhost:8766/saml/slo`, in the
SP metadata above), checks the request and answers with a LogoutResponse.
Sign in first with `saml login` in the same browser, then:

```bash
idpdbg saml idp_logout --idp-metadata https://idp.example.com/saml/metadata --name-id alice@example.com
```

and sign out at the IdP, or add `--start-url` with the IdP's logout page to
open it. The request must be signed on the front channel (an unsigned one
lets any web page log people out), name this SingleLogoutService as its
Destination, and name the session you expect. `--status partial` or
`--status responder` answers with something other than plain Success, to
see how the IdP reports it.

## Decode a captured response

Copy the `SAMLResponse` form value from the browser's developer tools, or
from a SAML tracer extension, into a file. Then check it against what the
real service provider expects:

```bash
idpdbg saml decode --message @response.b64 --idp-metadata idp.xml --sp-entity-id https://sp.example.com --acs-url https://sp.example.com/saml/acs
```

`--message` takes the value in any encoding: raw XML, base64, DEFLATE plus
base64, or a whole HTTP-Redirect URL. For a Redirect URL, the detached
signature is checked too.

## What the checks tell you

| Check | When it fails |
|---|---|
| **response: status is Success** | The IdP refused; the status code and message say why (for example, the user isn't assigned to the application) |
| **every assertion is covered by a trusted signature** | Only the Response is signed while the SP wants the assertion signed (or the other way round), or the signing certificate isn't the one in the metadata you gave |
| **response: Issuer is the IdP entity ID** | The IdP's entity ID differs from the one the SP has configured |
| Audience and recipient | The SP's entity ID or ACS URL is configured differently at the IdP |
| **assertion: Conditions NotBefore reached** / **not expired** | Clocks are out of sync, or the response is old; `--leeway` sets the tolerated skew in seconds (default 120) |
| **EncryptedAssertion** | The assertion is encrypted: pass the SP's key with `--sp-key` to decrypt it. Weak algorithms (RSA 1.5, AES-CBC) are flagged |

## Not sure what you have?

`idpdbg tools decode --input '…'` works out what a string is (URL-encoded,
base64, DEFLATE) and names the command to use next.

For logout, `saml logout` sends an SP-initiated LogoutRequest and checks the
LogoutResponse on `http://localhost:8766/saml/slo`.
