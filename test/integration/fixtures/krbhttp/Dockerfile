FROM debian:bookworm-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        apache2 \
        libapache2-mod-auth-gssapi \
        krb5-user \
    && rm -rf /var/lib/apt/lists/*

# The apache2 package declares /var/run/apache2 and /var/lock/apache2
# via /usr/lib/tmpfiles.d/apache2.conf, expecting systemd-tmpfiles to
# create them at boot. Without systemd in the container, materialise
# them at build time with the same ownership and mode the tmpfiles.d
# entry specifies.
RUN install -d -o root -g www-data -m 0750 \
        /var/run/apache2 /var/lock/apache2

# Redirect apache's error and access logs to the container's stdio so
# they surface via `docker logs` and the framework's log dumper.
RUN ln -sf /dev/stderr /var/log/apache2/error.log && \
    ln -sf /dev/stdout /var/log/apache2/access.log

RUN a2enmod auth_gssapi && a2dissite 000-default

COPY krbhttp.conf /etc/apache2/sites-available/krbhttp.conf
COPY index.html /var/www/html/spnego/index.html
RUN a2ensite krbhttp

EXPOSE 80/tcp

CMD ["sh", "-c", "until [ -f /var/run/krbhttp-ready ]; do sleep 0.1; done; \
                  . /etc/apache2/envvars && exec /usr/sbin/apache2 -DFOREGROUND"]
