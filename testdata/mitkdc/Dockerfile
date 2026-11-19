# MIT Kerberos KDC for idpdbg's interop tests (see scripts/mitkdc.sh).
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      krb5-kdc krb5-admin-server krb5-pkinit openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY setup.sh /setup.sh
CMD ["/bin/sh", "/setup.sh"]
