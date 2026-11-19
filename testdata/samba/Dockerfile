# Samba AD domain controller for idpdbg's interop tests (see scripts/samba.sh).
# The domain is provisioned when the container starts, because provisioning
# sets ACL extended attributes, which needs a privileged container.
FROM debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba samba-ad-dc samba-ad-provision samba-dsdb-modules python3-samba \
      samba-common-bin winbind ldb-tools openssl ca-certificates netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*
COPY setup.sh /setup.sh
CMD ["/bin/sh", "/setup.sh"]
