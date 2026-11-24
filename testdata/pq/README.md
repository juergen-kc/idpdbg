# Post-quantum test fixtures

Made with OpenSSL 4.1, so the tests check idpdbg against another
implementation. All keys are throwaway test keys.

- `root.pem`, `leaf.pem`, `leaf.csr`: an ML-DSA-65 root, an ML-DSA-44 leaf
  for `pq.example` it signed, and the leaf's CSR.
- `key-both.pem`, `key-seed.pem`, `key-expanded.pem`: one ML-DSA-44 private
  key in the three PKCS #8 forms of RFC 9881 §6 (seed and expanded key, the
  OpenSSL default; seed only; expanded key only), and `key-pub.pem`, its
  public key.

To make them again:

```sh
openssl genpkey -algorithm ML-DSA-44 -out key-both.pem
openssl pkey -in key-both.pem -provparam ml-dsa.output_formats=seed-only -out key-seed.pem
openssl pkey -in key-both.pem -provparam ml-dsa.output_formats=priv-only -out key-expanded.pem
openssl pkey -in key-both.pem -pubout -out key-pub.pem
```
