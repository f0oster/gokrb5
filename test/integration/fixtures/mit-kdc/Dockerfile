FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        krb5-kdc \
        krb5-admin-server \
        krb5-user \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 88/tcp 88/udp

# Wait for the framework to finish provisioning, then run krb5kdc.
# The framework signals readiness by touching /var/run/kdc-ready.
CMD ["sh", "-c", "until [ -f /var/run/kdc-ready ]; do sleep 0.1; done; exec /usr/sbin/krb5kdc -n"]
