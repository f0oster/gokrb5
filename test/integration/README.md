# Integration tests

The gokrb5 client exercised against real KDCs running in containers.

## What's tested

The gokrb5 client against:

- An MIT KDC with two realms joined by a one-way trust.
- A Samba AD-DC.
- A third-party SPNEGO HTTP acceptor keyed to either KDC.

Coverage:

- AS exchange (password and keytab), preauth required and not, invalid password, unknown principal.
- TGS exchange, including ticket caching, unknown SPN, and cross-realm referrals.
- Network fallthrough and no-reachable-KDC error paths.
- Encryption-type matrix across AES-SHA1 and AES-SHA2.
- Concurrent `Login` on a shared client.
- SASL/GSSAPI bind over plain LDAP (none, integrity, confidentiality layers).
- SASL/GSSAPI bind over LDAPS with RFC 5929 channel bindings (matching and tampered).
- SPNEGO HTTP authentication.

## Requirements

- Docker daemon reachable from the test host.
- Go matching the version declared in `go.mod`.

## Running

```sh
cd test/integration
INTEGRATION=1 go test ./...
```

Without `INTEGRATION=1` or without Docker, tests skip cleanly.

Per-test status with `-v`. Framework log lines are prefixed `[fixture]`:

```sh
INTEGRATION=1 go test -v ./...
```

testcontainers-go's progress output is silenced by default. Set `TC_VERBOSE=1` to opt back in.

## Adding a test

Pick the file matching the backend you target:

| Backend | File |
|---|---|
| MIT | `client_mit_test.go` |
| Samba AD | `client_samba_ad_test.go` |
| SASL/LDAP against Samba AD | `sasl_ldap_samba_ad_test.go` |

Use the matching require helper to obtain the fixture:

| Helper | Returns |
|---|---|
| `requireMIT(t)` | `*framework.MITKDC` |
| `requireAD(t)` | `framework.ActiveDirectory` |
| `requireMITHTTPAcceptor(t)` | `framework.HTTPAcceptor` |
| `requireADHTTPAcceptor(t)` | `framework.HTTPAcceptor` |

Provisioned principals available to tests:

- MIT (`HOME.GOKRB5`): `preauth_user`, `nopreauth_user`, `HTTP/host.home.gokrb5`.
- MIT (`TRUSTED.GOKRB5`): `HTTP/host.trusted.gokrb5`.
- Samba AD (`AD.GOKRB5`): `testuser1`, `testuser2`, `HTTP/web.ad.gokrb5`.
