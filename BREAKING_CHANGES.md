# Breaking changes from `github.com/jcmturner/gokrb5/v8`

This document enumerates breaking changes in `github.com/f0oster/gokrb5` relative to upstream `github.com/jcmturner/gokrb5/v8` at commit `855dbc7`.

---

## 1. Module identity and toolchain

### 1.1 Module path

```diff
- github.com/jcmturner/gokrb5/v8
+ github.com/f0oster/gokrb5
```

All import paths in user code must be updated. The `/v8` major-version segment is removed; the fork lives at the module root.

### 1.2 Minimum Go version

```diff
- go 1.16
+ go 1.25
```

Set in `go.mod`. Build environments that cannot install Go 1.25 cannot consume the fork.

---

## 2. Removed packages

### 2.1 `service` package

The `service` package is removed. Its responsibilities are split:

- AP-REQ verification moved to `gssapi.Acceptor`.
- HTTP middleware (`KRB5BasicAuthenticator`, `SessionMgr`) moved to `spnego`.
- Replay-cache types and helpers moved to `gssapi.ReplayCache` / `gssapi.GetReplayCache` / `gssapi.NewReplayCache`.
- `service.Settings` and its option setters are replaced by `gssapi.AcceptorOption` values.
- `service.VerifyAPREQ` is replaced by `(*gssapi.Acceptor).Accept`.

Mapping table:

| Removed (`service.<X>`) | Replacement |
|---|---|
| `Settings` (struct) and `NewSettings` | `gssapi.Acceptor` constructed via `gssapi.NewAcceptor(kt, opts...)` |
| `RequireHostAddr(bool)` | `gssapi.RequireHostAddress()` |
| `DecodePAC(bool)` | `gssapi.DisablePACDecoding()` (PAC decoding is on by default) |
| `ClientAddress(types.HostAddress)` | `gssapi.WithRemoteAddress(h)` as a per-call `AcceptOption` |
| `Logger(*log.Logger)` | `gssapi.WithAcceptorLogger(l)` |
| `KeytabPrincipal(string)` | `gssapi.WithKeytabPrincipal(name)` |
| `MaxClockSkew(time.Duration)` | `gssapi.WithMaxClockSkew(d)` |
| `SName(string)` | No replacement; the principal is derived from the AP-REQ |
| `SessionManager(SessionMgr)` | `spnego.WithSessionManager(sm)` (HTTP-layer option) |
| `Settings` getters (`RequireHostAddr()`, `DecodePAC()`, etc.) | No replacement; `Acceptor` does not expose its option state |
| `VerifyAPREQ(*messages.APReq, *Settings)` | `(*gssapi.Acceptor).Accept(mechToken)` |
| `Cache` (replay cache) and `NewCache` | `gssapi.ReplayCache` and `gssapi.NewReplayCache(d)` |
| `GetReplayCache(d)` | `gssapi.GetReplayCache(d)` |
| `Cache.IsReplay(sname, a)` | `(*gssapi.ReplayCache).IsReplay(sname, a, ciphertext)` — see §3.5 |
| `Cache.AddEntry`, `Cache.ClearOldEntries` | Same names on `*gssapi.ReplayCache` |
| `KRB5BasicAuthenticator` and `NewKRB5BasicAuthenticator` | `spnego.KRB5BasicAuthenticator` and `spnego.NewKRB5BasicAuthenticator` — signature also changed (§3.14) |
| `SessionMgr` (interface) | `spnego.SessionMgr` (same shape) |

---

## 3. Changed and removed exported identifiers

### 3.1 `client.DisablePAFXFAST`

```diff
- func DisablePAFXFAST(b bool) func(*Settings)
- func (s *Settings) DisablePAFXFAST() bool
```

Removed. `PA-REQ-ENC-PA-REP` is sent on every AS-REQ, and the echo is verified per RFC 6806 §11 when the `enc-pa-rep` flag is present in the AS-REP.

### 3.2 `config.GetKDCs` and `config.GetKpasswdServers`

```diff
- func (c *Config) GetKDCs(realm string, tcp bool) (int, map[int]string, error)
+ func (c *Config) GetKDCs(realm string, tcp bool) ([]string, error)

- func (c *Config) GetKpasswdServers(realm string, tcp bool) (int, map[int]string, error)
+ func (c *Config) GetKpasswdServers(realm string, tcp bool) ([]string, error)
```

The count and preference-keyed map collapse into a single ordered slice. Use `len(slice)` for the count; iterate the slice directly in preference order.

### 3.3 `messages.APReq.Verify`

```diff
- func (a *APReq) Verify(kt *keytab.Keytab, d time.Duration, cAddr types.HostAddress, snameOverride *types.PrincipalName) (bool, error)
+ func (a *APReq) Verify(kt *keytab.Keytab, d time.Duration, cAddr types.HostAddress, snameOverride *types.PrincipalName, permitted []int32) (bool, error)
```

Added `permitted []int32` listing accepted etype IDs for ticket and authenticator decryption. Pass `nil` to accept any etype.

### 3.4 `crypto/rfc4757.StringToKey`

```diff
- func StringToKey(secret string) ([]byte, error)
+ func StringToKey(secret string) []byte
```

The error return is removed. The fork uses `utf16.Encode([]rune(secret))` for the password encoding, which correctly handles characters outside the Basic Multilingual Plane.

### 3.5 `gssapi.ReplayCache.IsReplay`

```diff
- func (c *Cache) IsReplay(sname types.PrincipalName, a types.Authenticator) bool
+ func (c *ReplayCache) IsReplay(sname types.PrincipalName, a types.Authenticator, ciphertext []byte) bool
```

Added `ciphertext []byte`. The cache key now includes the authenticator ciphertext bytes, so callers must supply them.

### 3.6 `gssapi.NewInitiatorWrapToken` and `gssapi.NewInitiatorMICToken`

```diff
- func NewInitiatorWrapToken(payload []byte, key types.EncryptionKey) (*WrapToken, error)
- func NewInitiatorMICToken(payload []byte, key types.EncryptionKey) (*MICToken, error)
```

Removed. To produce per-message tokens, establish a `*gssapi.SecurityContext` and call `Wrap(plaintext)` or `MakeSignature(msg)`. The `WrapToken` and `MICToken` types remain with their `Marshal`, `Unmarshal`, `SetCheckSum`/`SetChecksum`, and `Verify` methods unchanged.

### 3.7 SPNEGO type and entry points

```diff
- type SPNEGO struct { ... }
- func SPNEGOClient(cl *client.Client, spn string) *SPNEGO
- func SPNEGOService(kt *keytab.Keytab, options ...func(*service.Settings)) *SPNEGO
- func (s *SPNEGO) AcquireCred() error
- func (s *SPNEGO) InitSecContext() (gssapi.ContextToken, error)
- func (s *SPNEGO) AcceptSecContext(ct gssapi.ContextToken) (bool, context.Context, gssapi.Status)
- func (s *SPNEGO) OID() asn1.ObjectIdentifier
- func (s *SPNEGO) Log(format string, v ...interface{})
```

Removed. Use `spnego.NewInitiator(cl, spn, opts...)` for the client side and `spnego.NewAcceptor(kt, opts...)` for the server side. Both wrap their `gssapi` counterparts.

Initiator usage:

```go
init, err := spnego.NewInitiator(cl, spn, gssapi.WithMutualAuth())
sptBytes, err := init.Step(nil)
// send sptBytes, receive respBytes
_, err = init.Step(respBytes)
ctx, _ := init.SecurityContext()
```

Acceptor usage:

```go
acc := spnego.NewAcceptor(kt, opts...)
acceptance, err := acc.Accept(spnegoBytes)
// acceptance.ResponseToken, acceptance.Context, acceptance.Credentials
```

### 3.8 `KRB5Token`

```diff
- type KRB5Token struct { ... }
- func NewKRB5TokenAPREQ(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, GSSAPIFlags []int, APOptions []int) (KRB5Token, error)
- func (m *KRB5Token) Marshal() ([]byte, error)
- func (m *KRB5Token) Unmarshal(b []byte) error
- func (m *KRB5Token) Verify() (bool, gssapi.Status)
- func (m *KRB5Token) IsAPReq() bool
- func (m *KRB5Token) IsAPRep() bool
- func (m *KRB5Token) IsKRBError() bool
- func (m *KRB5Token) Context() context.Context
```

Removed. Replacements:

- Produce an AP-REQ mech token: `gssapi.NewInitiator(cl, spn).Step(nil)` (or `gssapi.NewInitiatorFromTicket(cl, tkt, sessionKey).Step(nil)` if the ticket is already in hand).
- Marshal or unmarshal the RFC 2743 §3.1 mech-token framing directly: `gssapi.MarshalMechToken(tokID, body)` and `gssapi.UnmarshalMechToken(b)`.
- Verify an AP-REQ mech token: `(*gssapi.Acceptor).Accept(mechToken)`.
- Discriminate token type: compare `UnmarshalMechToken`'s second return value (`tokID`) against the string constants `gssapi.TokIDAPReq`, `gssapi.TokIDAPRep`, `gssapi.TokIDKRBErr`.

### 3.9 `SPNEGOToken.Verify` and `SPNEGOToken.Context`

```diff
- func (s *SPNEGOToken) Verify() (bool, gssapi.Status)
- func (s *SPNEGOToken) Context() context.Context
```

Removed. `SPNEGOToken` is now a container type with `Marshal` and `Unmarshal` only. Verification and context establishment flow through `(*spnego.Acceptor).Accept`, which returns `*spnego.Acceptance` containing the verified credentials and an established `*gssapi.SecurityContext`.

### 3.10 `NegTokenInit` and `NegTokenResp` lose `Verify` and `Context`

```diff
- func (n *NegTokenInit) Verify() (bool, gssapi.Status)
- func (n *NegTokenInit) Context() context.Context
- func (n *NegTokenResp) Verify() (bool, gssapi.Status)
- func (n *NegTokenResp) Context() context.Context
```

Removed. The structs themselves remain with `Marshal` and `Unmarshal`. Verification is performed by `spnego.Acceptor`.

### 3.11 `spnego.NewNegTokenInitKRB5`

```diff
- func NewNegTokenInitKRB5(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey) (NegTokenInit, error)
```

Removed. Use `spnego.NewInitiatorFromTicket(cl, tkt, sessionKey).Step(nil)`, which returns the marshaled `NegTokenInit` as `[]byte`.

### 3.12 `spnego.NegTokenTarg`

```diff
- type NegTokenTarg NegTokenResp
```

Removed. Use `NegTokenResp` directly.

### 3.13 `spnego.SPNEGOKRB5Authenticate`

```diff
- func SPNEGOKRB5Authenticate(inner http.Handler, kt *keytab.Keytab, settings ...func(*service.Settings)) http.Handler
+ func SPNEGOKRB5Authenticate(inner http.Handler, acc *Acceptor, opts ...HTTPOption) http.Handler
```

Construct a `*spnego.Acceptor` first, passing GSS-layer options such as `gssapi.WithKeytabPrincipal`. Pass it plus HTTP-layer options (`spnego.WithSessionManager`, `spnego.WithHTTPLogger`) to `SPNEGOKRB5Authenticate`.

```go
acc := spnego.NewAcceptor(kt, gssapi.WithKeytabPrincipal("HTTP/host.example"))
http.Handle("/", spnego.SPNEGOKRB5Authenticate(handler, acc, spnego.WithHTTPLogger(l)))
```

### 3.14 `spnego.NewKRB5BasicAuthenticator`

```diff
- func NewKRB5BasicAuthenticator(headerVal string, krb5conf *config.Config, serviceSettings *service.Settings, clientSettings *client.Settings) KRB5BasicAuthenticator
+ func NewKRB5BasicAuthenticator(headerVal string, krb5Conf *config.Config, clientSettings *client.Settings, kt *keytab.Keytab, spn string, opts ...BasicAuthOption) KRB5BasicAuthenticator
```

The third parameter changed from `*service.Settings` to `*client.Settings`. The keytab and SPN moved to explicit positional parameters. Acceptor-side configuration flows through the new `BasicAuthOption` type (`spnego.WithBasicAuthKeytabPrincipal`, `spnego.WithBasicAuthLogger`).

### 3.15 `spnego.UnmarshalNegToken`

```diff
- func UnmarshalNegToken(b []byte) (bool, interface{}, error)
+ func UnmarshalNegToken(b []byte) (bool, any, error)
```

Source-compatible since Go 1.18 because `any` is an alias for `interface{}`. Listed for completeness; tooling that compares signatures textually may flag it.

---

## 4. Behavioural changes

These changes do not alter API shape. Code that compiles unchanged may behave differently at runtime.

### 4.1 RC4-HMAC disabled by default

`LibDefaults` has a new `AllowRC4 bool` field, parsed from the `allow_rc4` directive in `[libdefaults]`. Default is `false`. A krb5.conf with `default_tkt_enctypes = rc4-hmac` that previously loaded RC4 will silently drop it from the resulting etype ID list.

To restore the previous behaviour, set `allow_rc4 = true` in `[libdefaults]` or assign `cfg.LibDefaults.AllowRC4 = true` programmatically.

### 4.2 Default enctypes realigned with MIT 1.21

`LibDefaults.DefaultTktEnctypes`, `DefaultTGSEnctypes`, and `PermittedEnctypes` default to:

```go
[]string{
    "aes256-cts-hmac-sha1-96",
    "aes128-cts-hmac-sha1-96",
    "aes256-cts-hmac-sha384-192",
    "aes128-cts-hmac-sha256-128",
    "des3-cbc-sha1",
    "arcfour-hmac",
    "camellia128-cts-cmac",
    "camellia256-cts-cmac",
}
```

Single-DES variants are no longer in the defaults; AES SHA-2 (RFC 8009) variants are added. Environments that relied on des-cbc defaults must set `default_tkt_enctypes` explicitly.

### 4.3 `permitted_enctypes` enforced on AS-REP and TGS-REP session keys

An AS-REP or TGS-REP whose session-key etype is not in `LibDefaults.PermittedEnctypeIDs` is rejected. AS-REQ and TGS-REQ etype offerings are also intersected with `permitted_enctypes` before being sent.

### 4.4 Pre-authentication etype filtered by `permitted_enctypes`

Cached and fallback pre-auth etype selection is validated against `permitted_enctypes`. Pre-auth etypes outside the permitted list are not honoured.

### 4.5 PAC `KerbValidationInfo` and `ClientInfo` are optional

PAC verification requires `ServerChecksum` and `KDCChecksum`; `KerbValidationInfo` (MS-PAC §2.5) and `ClientInfo` (MS-PAC §2.7) are optional. Code that called `creds.GetADCredentials()` and assumed the result was always populated should handle the empty case.

### 4.6 Username containing `@` becomes `KRB_NT_ENTERPRISE`

`credentials.New(username, realm)` inspects `username` for `@`. If present, the principal name type is set to `KRB_NT_ENTERPRISE` (RFC 6806 §6) and the full `user@REALM` string is used as the principal name. If absent, the type remains `KRB_NT_PRINCIPAL`. Code that inspects `cl.Credentials.CName().NameType` will observe the change.

### 4.7 Replay cache distinguishes by ciphertext

The replay cache key is `(sname, ctime, cusec, cname, ciphertext)`. The previous key was `(sname, ctime, cusec, cname)`. Entries that the previous implementation considered identical may now be considered distinct.

### 4.8 Authenticator CRealm validated against ticket CRealm

The Acceptor rejects an AP-REQ where the authenticator's `CRealm` does not match the ticket's `CRealm`.

### 4.9 KDC TCP response capped

`client.Settings.MaxKDCResponseBytes` (default 1 MiB, exposed via `client.MaxKDCResponseBytes(n)` and the `client.DefaultMaxKDCResponseBytes` constant) bounds the size of TCP responses from a KDC. Larger responses cause the exchange to fail.

### 4.10 RFC 6806 §11 AS-REP verification

When `enc-pa-rep` is set in the AS-REP, the `PA-REQ-ENC-PA-REP` echo is verified per RFC 6806 §11.

### 4.11 `KDC_ERR_WRONG_REALM` referrals followed in AS exchange

The client follows `KDC_ERR_WRONG_REALM` referrals during AS-REQ to discover the home realm, rather than surfacing the error to the caller.

### 4.12 `KDCTimeSync` parsed but not applied

The `LibDefaults.KDCTimeSync` field is parsed from `[libdefaults]` but is not applied to client-side timestamping.

### 4.13 SPNEGO session-store key changed

The internal session-store key for marshaled credentials changed from `github.com/jcmturner/gokrb5/v8/sessionCredentials` to `github.com/f0oster/gokrb5/sessionCredentials`. Existing sessions written by the previous package path will not be readable; users will need to re-authenticate after a deployment that carries this change.

### 4.14 `BuildSASLClientToken` mutates `SecurityContext.Confidential`

`gssapi.BuildSASLClientToken(ctx, resp)` sets `ctx.Confidential = (resp.ChosenLayer == SASLSecurityConfidential)`. Subsequent `Wrap` calls on the same context use the newly-set confidentiality regime.

### 4.15 Replay cache singleton skew window is set on first call

`gssapi.GetReplayCache(d)` returns a process-wide singleton. The first call's `d` argument fixes the singleton's `MaxClockSkew`; later calls with a different `d` return the same singleton with the original window. Pass `gssapi.WithReplayCache(gssapi.NewReplayCache(d))` on `Acceptor` construction for an isolated cache.

### 4.16 `spnego.Acceptance.ResponseToken` is always non-nil

`(*spnego.Acceptor).Accept` returns an `Acceptance` whose `ResponseToken` always carries a marshaled `NegTokenResp(accept-completed)`, regardless of whether mutual auth was requested. The corresponding `*gssapi.Acceptance.ResponseToken` is `nil` unless mutual auth was requested. The two types share the field name but have different invariants.

---

## 5. Test infrastructure

The fork's test layout differs from upstream. The integration suite under `test/integration/` runs against MIT KDC and Samba AD-DC containers via testcontainers-go and is gated by `INTEGRATION=1`. Vendoring tools that referenced upstream's `test/` paths will not find matching files.

The `test/testdata` package and its constants (`testdata.KEYTAB_TESTUSER1_USER_GOKRB5`, `testdata.KRB5_CONF`, etc.) remain available at `github.com/f0oster/gokrb5/test/testdata`.
