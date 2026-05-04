# gokrb5

A pure Go Kerberos 5 library for client authentication and service-side authentication/authorization. Implements GSS-API and SPNEGO for both initiator/client and acceptor/service roles. Fork of [jcmturner/gokrb5](https://github.com/jcmturner/gokrb5), licensed under Apache 2.0.

> [!IMPORTANT]
> This fork is *not* API-compatible with the original gokrb5 and contains *major* [breaking changes](BREAKING_CHANGES.md). The library has been redesigned around separate `Initiator` and `Acceptor` types, one for each of the two roles in GSS-API.

New capabilities beyond upstream include SASL/GSSAPI security-layer negotiation, TLS channel bindings (`tls-server-end-point`), and a streaming session helper for non-HTTP protocols.

> [!WARNING]
> Work in progress, expect breaking changes. Not recommended for production use.

Requires Go 1.25 or later.

## Documentation

- [USAGE.md](USAGE.md) - API / Usage reference
- [BREAKING_CHANGES.md](BREAKING_CHANGES.md) — changes from [jcmturner/gokrb5](https://github.com/jcmturner/gokrb5).
- [`examples/`](examples/)

## Features

- GSS-API per-message tokens (Wrap and MIC), integrity-only and confidential. RFC 4121.
- GSS-API context establishment, both initiator and acceptor sides. RFC 4121.
- SPNEGO context establishment, both initiator and acceptor sides. RFC 4178.
- AP-REP mutual-authentication verification. RFC 4120.
- Channel-bindings verification on the acceptor side. RFC 4121 §4.1.1.1.
- SASL/GSSAPI security-layer negotiation. RFC 4752.
- TLS channel bindings (`tls-server-end-point`). RFC 5929.
- Authenticator subkey generation for GSS per-message tokens. RFC 4121.
- Credential delegation through the GSS authenticator checksum. RFC 4121.

Tested against Microsoft Active Directory (WS2022, 2016 FFL/DFL), Samba AD (samba=2:4.22.8+dfsg-0+deb13u1, samba-ad-dc=2:4.22.8+dfsg-0+deb13u1) and MIT Kerberos (krb5-kdc=1.20.1-2+deb12u4)

## Implemented encryption and checksum types

| Implementation | Encryption ID | Checksum ID | RFC |
|-------|-------------|------------|------|
| des3-cbc-sha1-kd | 16 | 12 | 3961 |
| aes128-cts-hmac-sha1-96 | 17 | 15 | 3962 |
| aes256-cts-hmac-sha1-96 | 18 | 16 | 3962 |
| aes128-cts-hmac-sha256-128 | 19 | 19 | 8009 |
| aes256-cts-hmac-sha384-192 | 20 | 20 | 8009 |
| rc4-hmac | 23 | -138 | 4757 |

RC4-HMAC is disabled by default. Set `allow_rc4 = true` in `[libdefaults]` to opt back in.

## Testing

`test/integration/` runs the fork against MIT KDC and Samba AD-DC containers via testcontainers-go. Requires Docker.

```sh
cd test/integration
INTEGRATION=1 go test ./...
```

## Standards

- [RFC 2743](https://tools.ietf.org/html/rfc2743) — GSS-API v2, Update 1
- [RFC 2744](https://tools.ietf.org/html/rfc2744) — GSS-API v2 C-bindings
- [RFC 3244](https://tools.ietf.org/html/rfc3244) — Microsoft Windows 2000 Kerberos Change Password and Set Password Protocols
- [RFC 3961](https://tools.ietf.org/html/rfc3961) — Encryption and Checksum Specifications for Kerberos 5
- [RFC 3962](https://tools.ietf.org/html/rfc3962) — AES Encryption for Kerberos 5
- [RFC 4120](https://tools.ietf.org/html/rfc4120) — The Kerberos Network Authentication Service (V5)
- [RFC 4121](https://tools.ietf.org/html/rfc4121) — The Kerberos Version 5 GSS-API Mechanism
- [RFC 4178](https://tools.ietf.org/html/rfc4178) — SPNEGO
- [RFC 4422](https://tools.ietf.org/html/rfc4422) — Simple Authentication and Security Layer (SASL)
- [RFC 4559](https://tools.ietf.org/html/rfc4559) — SPNEGO-based Kerberos and NTLM HTTP Authentication in Microsoft Windows
- [RFC 4752](https://tools.ietf.org/html/rfc4752) — The Kerberos V5 ("GSSAPI") SASL Mechanism
- [RFC 4757](https://tools.ietf.org/html/rfc4757) — RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows
- [RFC 5929](https://tools.ietf.org/html/rfc5929) — Channel Bindings for TLS
- [RFC 6113](https://tools.ietf.org/html/rfc6113) — A Generalized Framework for Kerberos Pre-Authentication
- [RFC 6806](https://tools.ietf.org/html/rfc6806) — Kerberos Principal Name Canonicalization and Cross-Realm Referrals
- [RFC 8009](https://tools.ietf.org/html/rfc8009) — AES Encryption with HMAC-SHA2 for Kerberos 5
- [\[MS-KILE\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9) — Kerberos Protocol Extensions. Particularly §3.1.1.2 (Cryptographic Material), §3.2.1 (Abstract Data Model), and §3.4.5.4.1 (Kerberos Binding of GSS_WrapEx).
- [\[MS-PAC\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962) — Privilege Attribute Certificate Data Structure. Particularly §2.5 (KerbValidationInfo) and §2.7 (PAC_CLIENT_INFO).
- [IANA Kerberos parameters](http://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml)

## Known issues inherited from the Go standard library

| Issue | Worked around? | References |
|-------|-------------|------------|
| `encoding/asn1` cannot unmarshal into a slice of `asn1.RawValue` | Yes | https://github.com/golang/go/issues/17321 |
| `encoding/asn1` cannot marshal a `GeneralString` | Yes — using [`jcmturner/gofork/encoding/asn1`](https://github.com/jcmturner/gofork/tree/master/encoding/asn1) | https://github.com/golang/go/issues/18832 |
| `encoding/asn1` cannot marshal a slice of strings and pass `stringtype` parameter tags to members | Yes — using [`jcmturner/gofork/encoding/asn1`](https://github.com/jcmturner/gofork/tree/master/encoding/asn1) | https://github.com/golang/go/issues/18834 |
| `encoding/asn1` cannot marshal with application tags | Yes | |
| `x/crypto/pbkdf2.Key` uses `int` for iteration count, so the 2³² count specified in [RFC 3962 §4](https://tools.ietf.org/html/rfc3962#section-4) cannot be met on 32-bit systems | Yes — using [`jcmturner/gofork/x/crypto/pbkdf2`](https://github.com/jcmturner/gofork/tree/master/x/crypto/pbkdf2) | https://go-review.googlesource.com/c/crypto/+/85535 |

## License

Apache 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for attribution.
