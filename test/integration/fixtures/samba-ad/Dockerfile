FROM debian:trixie-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        samba \
        samba-ad-dc \
        samba-common-bin \
        samba-ad-provision \
        samba-dsdb-modules \
        samba-vfs-modules \
        python3-samba \
        winbind \
        attr \
        acl \
        ldb-tools \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 88/tcp 88/udp 389/tcp 636/tcp 464/tcp 464/udp

# Wait for the framework to finish provisioning, then run samba.
# The framework signals readiness by touching /var/run/samba-ready.
CMD ["sh", "-c", "until [ -f /var/run/samba-ready ]; do sleep 0.1; done; exec samba -i --no-process-group"]
