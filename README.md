# gokrb5

Personal fork derived from [jcmturner/gokrb5](https://github.com/jcmturner/gokrb5), licensed under Apache 2.0. This fork has branched from upstream and does not aim to maintain compatibility. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for attribution and license terms.

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

Tested against Active Directory (Windows Server 2022) and FreeIPA (MIT KDC).

## Breaking changes:

### PA-FX-FAST removal

`client.DisablePAFXFAST` is removed. `PA-REQ-ENC-PA-REP` is sent on every AS-REQ, and the echo is verified per RFC 6806 §11 when the `enc-pa-rep` flag is set. `PA-FX-FAST` (RFC 6113) is not required in the encrypted PA-data, so KDCs that do not advertise FAST (including default Active Directory) interoperate.

### service package and SPNEGO hybrid type removed

The server-side AP-REQ verifier has moved out of the `service` package and into `gssapi`. Build a server-side acceptor with `gssapi.NewAcceptor(kt, opts...)` and call `Accept(mechToken)`; replay-cache lookup, host-address check, and PAC processing run automatically. What were `service.<Option>` settings are now `gssapi.AcceptorOption` values; `service.GetReplayCache` is now `gssapi.GetReplayCache`.

The HTTP-side helpers (`KRB5BasicAuthenticator`, `SessionMgr`) have moved into the `spnego` package. The `service` package no longer exists.

The hybrid `*spnego.SPNEGO` type is gone. Client-side callers replace `spnego.SPNEGOClient(cl, spn)` with `gssapi.NewInitiator(cl, spn, opts...)` (or `spnego.NewInitiator` for SPNEGO-framed transports). Server-side callers replace `spnego.SPNEGOService(kt, ...)` with `spnego.NewAcceptor(kt, opts...)`. `spnego.NewKRB5TokenAPREQ` is removed; produce an AP-REQ mech token by calling `Step(nil)` on a `gssapi.NewInitiator` (or `gssapi.NewInitiatorFromTicket` when the ticket is already in hand). `KRB5Token.Verify` for AP-REQ tokens is absorbed into `gssapi.Acceptor.Accept`. `SPNEGOToken.Context()` is removed; the verified credentials are exposed as a field on the `*spnego.Acceptance` value returned from `spnego.Acceptor.Accept`.

`spnego.SPNEGOKRB5Authenticate` takes a pre-built `*spnego.Acceptor` plus `spnego.HTTPOption` values (`WithSessionManager`, `WithHTTPLogger`). GSS-level policy (keytab, permitted enctypes, max clock skew) goes on the Acceptor; HTTP-level concerns go on the middleware.

### service package and SPNEGO hybrid type removed

The server-side AP-REQ verifier has moved out of `service` and into `gssapi`. Build a server-side acceptor with `gssapi.NewAcceptor(kt, opts...)` and call `Accept(mechToken)`; replay-cache lookup, host-address check, and PAC processing run automatically. What were `service.<Option>` settings are now `gssapi.AcceptorOption` values.

The HTTP-side helpers (`KRB5BasicAuthenticator`, `SessionMgr`) have moved into the `spnego` package. The `service` package no longer exists.

The hybrid `*spnego.SPNEGO` type is gone. Client-side callers now build `gssapi.NewInitiator(cl, spn, opts...)` for raw GSS or `spnego.NewInitiator(cl, spn, opts...)` for SPNEGO-framed transports; these replace `SPNEGOClient` and `SPNEGOClientWithBindings`. Server-side callers use `gssapi.NewAcceptor` or `spnego.NewAcceptor`; these replace `SPNEGOService`. To produce an AP-REQ mech token directly, call `Step(nil)` on an Initiator (or use `gssapi.NewInitiatorFromTicket` when the ticket is already in hand); this replaces `NewKRB5TokenAPREQ` and `NewKRB5TokenAPREQWithBindings`. To verify a mutual-auth AP-REP, call `Step(replyBytes)` on the same Initiator; this replaces `KRB5Token.Verify` plus `SetAPRepVerification`. The `SPNEGOToken` accessor methods (`SecurityContext`, `Credentials`, `ResponseToken`) are removed; the same data is on the `*spnego.Acceptance` value returned from `spnego.Acceptor.Accept`.

`spnego.SPNEGOKRB5Authenticate` takes a pre-built `*spnego.Acceptor` plus `spnego.HTTPOption` values (`WithSessionManager`, `WithHTTPLogger`). GSS-level policy (keytab, permitted enctypes, max clock skew) goes on the Acceptor; HTTP-level concerns go on the middleware.

## Implemented encryption and checksum types

| Implementation | Encryption ID | Checksum ID | RFC |
|-------|-------------|------------|------|
| des3-cbc-sha1-kd | 16 | 12 | 3961 |
| aes128-cts-hmac-sha1-96 | 17 | 15 | 3962 |
| aes256-cts-hmac-sha1-96 | 18 | 16 | 3962 |
| aes128-cts-hmac-sha256-128 | 19 | 19 | 8009 |
| aes256-cts-hmac-sha384-192 | 20 | 20 | 8009 |
| rc4-hmac | 23 | -138 | 4757 |

## Testing

`test/integration/` runs gokrb5 against MIT KDC and Samba AD-DC containers via testcontainers-go. Requires Docker; set `INTEGRATION=1` to run.

```sh
cd test/integration
INTEGRATION=1 go test ./...
```

## Standards / RFCs

* [RFC 2743](https://tools.ietf.org/html/rfc2743) - GSS-API v2, Update 1
* [RFC 2744](https://tools.ietf.org/html/rfc2744) - GSS-API v2 C-bindings
* [RFC 3244](https://tools.ietf.org/html/rfc3244) - Microsoft Windows 2000 Kerberos Change Password and Set Password Protocols
* [RFC 3961](https://tools.ietf.org/html/rfc3961) - Encryption and Checksum Specifications for Kerberos 5
* [RFC 3962](https://tools.ietf.org/html/rfc3962) - AES Encryption for Kerberos 5
* [RFC 4120](https://tools.ietf.org/html/rfc4120) - The Kerberos Network Authentication Service (V5)
* [RFC 4121](https://tools.ietf.org/html/rfc4121) - The Kerberos Version 5 GSS-API Mechanism
* [RFC 4178](https://tools.ietf.org/html/rfc4178.html) - SPNEGO
* [RFC 4422](https://tools.ietf.org/html/rfc4422) - Simple Authentication and Security Layer (SASL)
* [RFC 4559](https://tools.ietf.org/html/rfc4559.html) - SPNEGO-based Kerberos and NTLM HTTP Authentication in Microsoft Windows
* [RFC 4752](https://tools.ietf.org/html/rfc4752) - The Kerberos V5 ("GSSAPI") SASL Mechanism
* [RFC 4757](https://tools.ietf.org/html/rfc4757) - The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows
* [RFC 5929](https://tools.ietf.org/html/rfc5929) - Channel Bindings for TLS
* [RFC 6113](https://tools.ietf.org/html/rfc6113.html) - A Generalized Framework for Kerberos Pre-Authentication
* [RFC 6806](https://tools.ietf.org/html/rfc6806.html) - Kerberos Principal Name Canonicalization and Cross-Realm Referrals
* [RFC 8009](https://tools.ietf.org/html/rfc8009) - AES Encryption with HMAC-SHA2 for Kerberos 5
* [\[MS-KILE\] Kerberos Protocol Extensions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9). Particularly §3.1.1.2 (Cryptographic Material), §3.2.1 (Abstract Data Model), and §3.4.5.4.1 (Kerberos Binding of GSS_WrapEx).
* [\[MS-PAC\] Privilege Attribute Certificate Data Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962). Particularly §2.5 (KerbValidationInfo) and §2.7 (PAC_CLIENT_INFO).
* [IANA Assigned Kerberos Numbers](http://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml)

## Known issues

| Issue | Worked around? | References |
|-------|-------------|------------|
| The Go standard library's encoding/asn1 package cannot unmarshal into slice of asn1.RawValue | Yes | https://github.com/golang/go/issues/17321 |
| The Go standard library's encoding/asn1 package cannot marshal into a GeneralString | Yes - using https://github.com/jcmturner/gofork/tree/master/encoding/asn1 | https://github.com/golang/go/issues/18832 |
| The Go standard library's encoding/asn1 package cannot marshal into slice of strings and pass stringtype parameter tags to members | Yes - using https://github.com/jcmturner/gofork/tree/master/encoding/asn1 | https://github.com/golang/go/issues/18834 |
| The Go standard library's encoding/asn1 package cannot marshal with application tags | Yes | |
| The Go standard library's x/crypto/pbkdf2.Key function uses the int type for iteration count limiting, meaning the 4294967296 count specified in [RFC 3962 §4](https://tools.ietf.org/html/rfc3962#section-4) cannot be met on 32-bit systems | Yes - using https://github.com/jcmturner/gofork/tree/master/x/crypto/pbkdf2 | https://go-review.googlesource.com/c/crypto/+/85535 |
