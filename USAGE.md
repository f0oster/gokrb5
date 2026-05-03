## Version 8 Usage

### Configuration
The gokrb5 libraries use the same krb5.conf configuration file format as MIT Kerberos,
described [here](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).
Config instances can be created from a file path or from a string,
io.Reader, or bufio.Scanner:
```go
import "github.com/f0oster/gokrb5/config"
cfg, err := config.Load("/path/to/config/file")
cfg, err := config.NewFromString(krb5Str) // string must include newlines
cfg, err := config.NewFromReader(reader)
cfg, err := config.NewFromScanner(scanner)
```

### Keytab files
Keytabs can be read from a file or from a slice of bytes:
```go
import "github.com/f0oster/gokrb5/keytab"
kt, err := keytab.Load("/path/to/file.keytab")
kt, err := keytab.Parse(b)
```

---

### Kerberos Client
**Create** a client instance with either a password or a keytab. A
configuration must also be passed. Optional settings come from the
functions defined in `client/settings.go`:
```go
import "github.com/f0oster/gokrb5/client"
cl := client.NewWithPassword("username", "REALM.COM", "password", cfg)
cl := client.NewWithKeytab("username", "REALM.COM", kt, cfg)
```

**Login**:
```go
err := cl.Login()
```
Kerberos Ticket Granting Tickets (TGT) are automatically renewed
unless the client was created from a CCache.

A client can be **destroyed**:
```go
cl.Destroy()
```

#### Authenticate to a service

##### HTTP SPNEGO
Build the HTTP request, then create a SPNEGO client and use it to
issue the request via the same methods as on an `http.Client`. Passing
nil for the HTTP client uses `http.DefaultClient`. Passing an empty
SPN derives the SPN from the request URL.
```go
import "github.com/f0oster/gokrb5/spnego"
r, _ := http.NewRequest("GET", "http://host.test.gokrb5/index.html", nil)
spnegoCl := spnego.NewClient(cl, nil, "")
resp, err := spnegoCl.Do(r)
```

##### Programmatic GSS-API context (RFC 2743)
For non-HTTP application protocols, `gssapi.Initiator` drives the full
client-side handshake: it acquires the service ticket, builds the
AP-REQ, optionally verifies the mutual-auth AP-REP, and produces a
`SecurityContext` for per-message Wrap, Unwrap, and MIC operations.
```go
import "github.com/f0oster/gokrb5/gssapi"

init, err := gssapi.NewInitiator(cl, "ldap/dc.example.com",
    gssapi.WithMutualAuth(),
    gssapi.WithConfidentiality(),
)
if err != nil {
    return err
}

apReq, err := init.Step(nil)               // first call: AP-REQ wire bytes
if err != nil {
    return err
}
// send apReq, receive reply...

if _, err := init.Step(reply); err != nil { // verify AP-REP (mutual auth)
    return err
}

ctx, err := init.SecurityContext()
if err != nil {
    return err
}

sealed, err := ctx.Wrap([]byte("hello"))
plaintext, err := ctx.Unwrap(serverToken)
```
Initiator-only flows omit `WithMutualAuth`; the context is established
after the first `Step`. `SecurityContext` is safe for concurrent send
and receive (RFC 2743 §1.1.3). Other options:
`WithChannelBindings(cb)`, `WithDelegation(krbCredDER)`,
`WithStrictSequence`.

##### TLS channel bindings (RFC 5929)
`tls-server-end-point` channel bindings hash the leaf certificate into
the authenticator checksum.
```go
cb, err := gssapi.NewTLSChannelBindingsFromState(&tlsState)
if err != nil {
    return err
}
init, err := gssapi.NewInitiator(cl, spn,
    gssapi.WithMutualAuth(),
    gssapi.WithChannelBindings(cb),
)
```

##### SASL/GSSAPI security layer (RFC 4752)
After the GSS handshake, SASL/GSSAPI mechanisms exchange a wrapped
4-byte security-layer token. `gssapi.ParseSASLServerToken` and
`gssapi.BuildSASLClientToken` round-trip this exchange against the
established `SecurityContext`.
```go
offer, err := gssapi.ParseSASLServerToken(ctx, serverToken)
if err != nil {
    return err
}
if !offer.SupportsLayer(gssapi.SASLSecurityNone) {
    return fmt.Errorf("server does not offer no-layer auth")
}

clientToken, err := gssapi.BuildSASLClientToken(ctx, gssapi.SASLClientResponse{
    ChosenLayer: gssapi.SASLSecurityNone,
    AuthzID:     "",
})
```
`SASLSecurityIntegrity` and `SASLSecurityConfidential` set the
corresponding flag on `ctx`; subsequent `Wrap`/`Unwrap` calls then
enforce the chosen layer.

##### Low-level AP-REQ construction
`gssapi.NewInitiatorFromTicket` builds the AP-REQ from a ticket the
caller has already obtained without driving another KDC exchange:
```go
import (
    "github.com/f0oster/gokrb5/gssapi"
    "github.com/f0oster/gokrb5/messages"
)

tkt, sessionKey, err := cl.GetServiceTicket("HTTP/host.test.gokrb5")
if err != nil {
    return err
}
init, err := gssapi.NewInitiatorFromTicket(cl, tkt, sessionKey, gssapi.WithMutualAuth())
if err != nil {
    return err
}
mechBytes, err := init.Step(nil) // RFC 2743 §3.1 framed AP-REQ
```
`gssapi.MarshalMechToken(tokID, body)` and
`gssapi.UnmarshalMechToken(b)` expose the RFC 2743 §3.1 framing
([APPLICATION 0] OID + tokID + body) for callers that need to manipulate
mech tokens directly.

#### Changing a client password
Implements the Microsoft Kerberos Password Change protocol (RFC 3244),
supported by Active Directory and by MIT krb5kdc 1.7+. The kpasswd
server typically listens on port 464.
```go
cfg, err := config.Load("/path/to/config/file")
if err != nil {
    panic(err.Error())
}
kt, err := keytab.Load("/path/to/file.keytab")
if err != nil {
    panic(err.Error())
}
cl := client.NewWithKeytab("username", "REALM.COM", kt, cfg)

ok, err := cl.ChangePasswd("newpassword")
if err != nil {
    panic(err.Error())
}
if !ok {
    panic("failed to change password")
}
```
The client krb5.conf must define either `kpasswd_server` or
`admin_server` in the relevant `[realms]` section:
```
REALM.COM = {
  kdc = 127.0.0.1:88
  kpasswd_server = 127.0.0.1:464
  default_domain = realm.com
}
```
See https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html#realms for more information.

#### Client diagnostics
The client's `Diagnostics` method checks that the enctypes required by
the client's krb5 config are available in its keytab and that KDCs can
be resolved for the client's realm. The error returned describes any
failed checks; the configuration details are written to the supplied
`io.Writer`.

---

### Kerberised service

#### SPNEGO/Kerberos HTTP service
Construct a `*spnego.Acceptor` with the service keytab and any
GSS-level options, then pass it to `spnego.SPNEGOKRB5Authenticate`
along with HTTP-level options:
```go
acc := spnego.NewAcceptor(kt,
    gssapi.WithKeytabPrincipal("HTTP/host.example"),
    gssapi.WithPermittedEnctypes([]int32{etypeID.AES256_CTS_HMAC_SHA1_96}),
)

l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
h := http.HandlerFunc(apphandler)
http.Handle("/", spnego.SPNEGOKRB5Authenticate(h, acc, spnego.WithHTTPLogger(l)))
```

##### Session management
Most authenticated web applications maintain a session rather than
re-authenticating on every request. Pass a session manager into the
middleware:
```go
type SessionMgr interface {
    New(w http.ResponseWriter, r *http.Request, k string, v []byte) error
    Get(r *http.Request, k string) ([]byte, error)
}
```
- `New` stores a key/value pair in the session.
- `Get` returns the value held under the key in an existing session,
  or nil bytes / an error if there is no session.

```go
http.Handle("/", spnego.SPNEGOKRB5Authenticate(h, acc,
    spnego.WithHTTPLogger(l),
    spnego.WithSessionManager(sm),
))
```
The `httpServer.go` source file in the examples directory shows usage
with the gorilla web toolkit.

##### Validating users and accessing user details
On successful authentication the request's context carries a
credentials object implementing the `goidentity.Identity` interface
from `github.com/jcmturner/goidentity/v6`. When the KDC is Active
Directory, the credentials' attribute map carries an `ADCredentials`
struct (group SIDs, primary group, logon times, etc.) under
`credentials.AttributeKeyADCredentials`:
```go
import (
    "github.com/jcmturner/goidentity/v6"
    "github.com/f0oster/gokrb5/credentials"
)

creds := goidentity.FromHTTPRequestContext(r)
if creds == nil || !creds.Authenticated() {
    w.WriteHeader(http.StatusUnauthorized)
    fmt.Fprint(w, "Authentication failed")
    return
}
if ad, ok := creds.Attributes()[credentials.AttributeKeyADCredentials].(credentials.ADCredentials); ok {
    // ad.GroupMembershipSIDs, ad.EffectiveName, ad.PrimaryGroupID, ...
}
```
Code holding `*credentials.Credentials` directly (e.g., from a
non-HTTP acceptor) can call `creds.GetADCredentials()` to obtain the
struct without the attribute-map lookup.

#### SPNEGO/Kerberos acceptor (non-HTTP)
For application protocols that frame their own GSS handshake (LDAP,
IMAP, custom TCP), drive the SPNEGO acceptor directly. `Accept`
verifies the AP-REQ against the keytab; the `Acceptance` carries the
marshaled NegTokenResp, the verified credentials, and a
`SecurityContext` for per-message Wrap/Unwrap.
```go
acc := spnego.NewAcceptor(kt)

acceptance, err := acc.Accept(spnegoBytes)
if err != nil {
    return err
}
// send acceptance.ResponseToken back to the initiator
ctx := acceptance.Context
creds := acceptance.Credentials
```
For raw GSS callers (no SPNEGO framing on the wire), use
`gssapi.NewAcceptor` directly:
```go
acc := gssapi.NewAcceptor(kt)
acceptance, err := acc.Accept(mechToken)
// acceptance.ResponseToken is non-nil only when mutual auth was requested.
```

##### Streaming convenience: Session over a frame codec
For framed TCP-style services that wrap every post-auth message,
`AcceptOn` drives the handshake on a stream and returns a `*Session`
ready for `ReadMsg` / `WriteMsg` against the established
`SecurityContext`:
```go
acc := spnego.NewAcceptor(kt)

sess, err := acc.AcceptOn(conn, gssapi.LengthPrefix4)
if err != nil {
    return err
}
msg, err := sess.ReadMsg()       // reads a framed Wrap'd message
if err != nil {
    return err
}
err = sess.WriteMsg(reply)       // wraps and writes a reply frame
```
`gssapi.LengthPrefix4` frames messages with a 4-byte big-endian length
and a 16 MiB cap. Implement `gssapi.FrameCodec` for other framings.

##### Channel-binding verification on the acceptor side
`gssapi.WithExpectedChannelBindings` makes `Accept` verify the
initiator's hashed bindings against `MD5(cb.Marshal())`; mismatch
returns `gssapi.ErrChannelBindingMismatch`.
```go
cb, _ := gssapi.NewTLSChannelBindingsFromCert(leafCert)

acc := gssapi.NewAcceptor(kt)
acceptance, err := acc.Accept(mechToken,
    gssapi.WithExpectedChannelBindings(cb),
)
if errors.Is(err, gssapi.ErrChannelBindingMismatch) {
    // initiator's bindings did not match
}
```
Without this option the acceptor ignores whatever bindings the
initiator hashed in.

#### Permitted enctypes (operator policy)
`gssapi.WithPermittedEnctypes` constrains which etypes the acceptor
will accept on inbound tickets and authenticators. An AP-REQ
presenting an etype outside the list is rejected before decryption.
```go
import (
    "github.com/f0oster/gokrb5/iana/etypeID"
    "github.com/f0oster/gokrb5/gssapi"
)

acc := gssapi.NewAcceptor(kt,
    gssapi.WithPermittedEnctypes([]int32{
        etypeID.AES256_CTS_HMAC_SHA1_96,
        etypeID.AES128_CTS_HMAC_SHA1_96,
    }),
)
```
An empty list (the default) imposes no restriction.

#### HTTP Basic auth via Kerberos
`spnego.KRB5BasicAuthenticator` authenticates an HTTP Basic header by
running an AS-REQ + TGS-REQ for the supplied credentials and decrypting
the resulting service ticket against the local keytab.
```go
auth := spnego.NewKRB5BasicAuthenticator(headerVal, krb5Conf, clientSettings, kt, "HTTP/host.example")
id, ok, err := auth.Authenticate()
```
