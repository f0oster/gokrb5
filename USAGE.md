# Usage

## Configuration
The gokrb5 libraries use the same krb5.conf configuration file format as MIT Kerberos,
described [here](https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html).
Config instances can be created by loading from a file path or by passing a string, io.Reader or bufio.Scanner to the
relevant method:
```go
import "github.com/f0oster/gokrb5/config"
cfg, err := config.Load("/path/to/config/file")
cfg, err := config.NewFromString(krb5Str) //String must have appropriate newline separations
cfg, err := config.NewFromReader(reader)
cfg, err := config.NewFromScanner(scanner)
```

## Keytab files
Standard keytab files can be read from a file or from a slice of bytes:
```go
import "github.com/f0oster/gokrb5/keytab"
ktFromFile, err := keytab.Load("/path/to/file.keytab")

kt := keytab.New()
err = kt.Unmarshal(b)
```

---

## Initiator and acceptor

GSS-API splits authentication into two roles. An **initiator** runs on the client side: it
acquires a Kerberos service ticket, builds an AP-REQ containing that ticket and an
authenticator proving possession of the ticket session key, and yields a `SecurityContext`
for per-message protection on the established channel. An **acceptor** runs on the service
side: it uses its keytab to decrypt the service ticket inside an inbound AP-REQ, verifies
the authenticator, produces an AP-REP back when mutual auth was requested, and yields both
a `SecurityContext` and the verified client `Credentials`.

After the handshake, both sides hold matching `SecurityContext`s that can `Wrap` / `Unwrap`
per-message payloads with integrity or confidentiality.

---

## Kerberos Client
**Create** a client instance with either a password or a keytab.
A configuration must also be passed. Optional additional settings can also be provided.
```go
import "github.com/f0oster/gokrb5/client"
cl := client.NewWithPassword("username", "REALM.COM", "password", cfg)
cl := client.NewWithKeytab("username", "REALM.COM", kt, cfg)
```
Optional settings are provided using the functions defined in `client/settings.go`.

**Login**:
```go
err := cl.Login()
```
Successful login spawns a background goroutine that automatically renews the TGT before it
expires. Clients constructed from a CCache do not auto-renew, since they hold no password or
keytab to perform a fresh AS exchange.

A client can be **destroyed** with the following method, which stops the auto-renewal
goroutine and clears all sessions and cached tickets:
```go
cl.Destroy()
```

### Changing a Client Password
This feature uses the Microsoft Kerberos Password Change protocol (RFC 3244).
This is implemented in Microsoft Active Directory and in MIT krb5kdc as of version 1.7.
Typically the kpasswd server listens on port 464.

Below is example code for how to use this feature:
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

The client kerberos config (krb5.conf) will need to have either the kpasswd_server or admin_server defined in the
relevant [realms] section. For example:
```
REALM.COM = {
  kdc = 127.0.0.1:88
  kpasswd_server = 127.0.0.1:464
  default_domain = realm.com
 }
```
See https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html#realms for more information.

### Client Diagnostics
In the event of issues the configuration of a client can be investigated with its `Diagnostics` method.
This will check that the required enctypes defined in the client's krb5 config are available in its keytab.
It will also check that KDCs can be resolved for the client's REALM.
The error returned will contain details of any failed checks.
The configuration details of the client will be written to the `io.Writer` provided.

---

## Authenticate to a Service

### HTTP SPNEGO
Create the HTTP request object and then create an SPNEGO client and use it to process the request with methods that
are the same as on a HTTP client.
If nil is passed as the HTTP client when creating the SPNEGO client the http.DefaultClient is used.
When creating the SPNEGO client pass the Service Principal Name (SPN) or auto generate the SPN from the request
object by passing a null string "".
```go
import "github.com/f0oster/gokrb5/spnego"
r, _ := http.NewRequest("GET", "http://host.test.gokrb5/index.html", nil)
spnegoCl := spnego.NewClient(cl, nil, "")
resp, err := spnegoCl.Do(r)
```

### Non-HTTP Services
For non-HTTP application protocols, the fork offers two initiator types depending on whether the
service expects SPNEGO-wrapped tokens or raw Kerberos AP-REQ mech tokens:

- `gssapi.NewInitiator` produces a raw Kerberos AP-REQ mech token: the ASN.1 envelope carrying the
  Kerberos OID `1.2.840.113554.1.2.2` and the AP-REQ body, with no SPNEGO around it. SASL/GSSAPI bind
  (RFC 4752, used by LDAP) and Kerberos-only services speak this.
- `spnego.NewInitiator` wraps the same AP-REQ in a SPNEGO `NegTokenInit`, advertising the Kerberos OID
  in the negotiated mech list and attaching the AP-REQ as the optimistic mech token. HTTP "Negotiate"
  (RFC 4559), SMB/CIFS, and most Microsoft-flavoured services speak this.

Both run the same Kerberos exchange under the hood (acquire service ticket, build authenticator,
optionally verify the AP-REP) and accept the same options:

- `WithMutualAuth()` requests an AP-REP from the service, letting the client verify the service
  possesses the long-term key the KDC encrypted the ticket with.
- `WithConfidentiality()` enables encryption on `Wrap` output. Without it, `Wrap` produces
  integrity-only tokens.
- `WithChannelBindings(cb)` binds the authenticator to channel data so a man-in-the-middle on a
  different channel cannot relay the AP-REQ. For TLS, build `cb` with
  `gssapi.NewTLSChannelBindingsFromCert` (RFC 5929 `tls-server-end-point`).
- `WithDelegation(krbCredDER)` attaches a forwarded TGT in the authenticator checksum so the service
  can act on the client's behalf to a downstream service.
- `WithStrictSequence()` rejects per-message tokens whose sequence numbers arrive out of order; the
  default is to accept reordered messages within the receive window.

#### Raw GSS-API initiator
`gssapi.NewInitiator` is the entry point for protocols that put a bare Kerberos mech token on the
wire without SPNEGO around it. SASL/GSSAPI bind (RFC 4752, used by LDAP) is one such protocol:
the SASL layer carries the mech name "GSSAPI" out-of-band, and the bytes inside the SASL
`BindRequest` are the AP-REQ itself.

`Step(nil)` returns the marshaled mech token bytes; the caller transports them. `Step(reply)`
consumes the AP-REP when mutual auth was requested. After the handshake, `SecurityContext()`
returns the established context, which is safe to share between send and receive goroutines:
```go
import "github.com/f0oster/gokrb5/gssapi"

// Build the initiator. NewInitiator eagerly acquires the service ticket
// (issuing a TGS-REQ to the KDC if not cached). WithMutualAuth asks the
// service to return an AP-REP the client can verify against the ticket
// session key.
init, err := gssapi.NewInitiator(cl, spn, gssapi.WithMutualAuth())

// Build the AP-REQ from the cached service ticket and return the marshaled
// mech token bytes for the wire.
mechBytes, err := init.Step(nil)
// send mechBytes, receive reply...

// Verify the AP-REP. Without WithMutualAuth, skip this step; the service
// sends nothing back and the context is already established.
if _, err := init.Step(reply); err != nil {
    // verify AP-REP failed
}

// SecurityContext yields a context safe to share between send and receive
// goroutines. Wrap encrypts when WithConfidentiality was set; otherwise it
// produces an integrity-only token. MakeSignature / VerifySignature are
// also available for integrity-only MIC tokens.
ctx, _ := init.SecurityContext()
sealed, _ := ctx.Wrap([]byte("hello"))
```

Integration notes:
- Without `WithMutualAuth`, the service does not send an AP-REP back; the caller proceeds
  directly to the post-auth `Wrap` exchange after the first `Step`.
- Channel bindings are passed to `NewInitiator` via `WithChannelBindings(cb)` and folded into
  the AP-REQ on the first `Step`. Build `cb` with `gssapi.NewTLSChannelBindingsFromCert` only
  after the transport's TLS handshake has completed and the leaf certificate is available.
- Service tickets are cached on the underlying `*client.Client`. Re-using a client across many
  initiators avoids a fresh TGS-REQ per call.

#### SPNEGO initiator
`spnego.NewInitiator` is the entry point for protocols that run SPNEGO on the wire. HTTP
"Negotiate" (RFC 4559) and the Microsoft service stack (SMB/CIFS, RPC, SQL Server, etc.) speak
this.

`Step(nil)` returns a marshaled `NegTokenInit` advertising the supported Kerberos OIDs and
embedding the AP-REQ. `Step(reply)` parses the `NegTokenResp`, requires the negotiation state
to be `accept-completed`, confirms the acceptor selected one of the offered Kerberos OIDs, and
verifies the embedded AP-REP when mutual auth was requested:
```go
import "github.com/f0oster/gokrb5/spnego"

// Build the SPNEGO initiator. NewInitiator eagerly acquires the service
// ticket (issuing a TGS-REQ to the KDC if not cached). WithMutualAuth
// asks the service to embed an AP-REP in the NegTokenResp that the
// client can verify against the ticket session key.
init, err := spnego.NewInitiator(cl, spn, gssapi.WithMutualAuth())

// Build the AP-REQ and wrap it in a NegTokenInit advertising the
// Kerberos OID(s).
spnegoInit, err := init.Step(nil)
// send spnegoInit (NegTokenInit), receive NegTokenResp...

// Parse the NegTokenResp: require accept-completed with a Kerberos mech,
// and verify the embedded AP-REP when mutual auth was requested.
if _, err := init.Step(spnegoResp); err != nil {
    // SPNEGO or AP-REP verification failed
}

// SecurityContext yields a Kerberos context for per-message Wrap/Unwrap.
// MakeSignature / VerifySignature are available for MIC tokens.
ctx, _ := init.SecurityContext()
```

Integration notes:
- The initiator advertises both the canonical Kerberos OID (`1.2.840.113554.1.2.2`) and the
  legacy MS-KRB5 OID (`1.2.840.48018.1.2.2`).
- The `mechListMIC` field is parsed but not verified end-to-end. Downgrade detection on the
  offered mech list is a known gap.
- The acceptor's `SupportedMech` field is checked (when present) against the offered Kerberos
  OIDs. Per RFC 4178 §4.2.2 the field is optional in subsequent `NegTokenResp` messages, so an
  absent field is accepted.

---

## Kerberised Service

### SPNEGO/Kerberos HTTP Service
A HTTP handler wrapper can be used to implement Kerberos SPNEGO authentication for web services.
First construct a `*spnego.Acceptor` with the service keytab and any GSS-level options (keytab principal,
permitted enctypes, etc.); then pass the Acceptor and any HTTP-level options to `SPNEGOKRB5Authenticate`.
```go
acc := spnego.NewAcceptor(kt)

l := log.New(os.Stderr, "GOKRB5 Service: ", log.Ldate|log.Ltime|log.Lshortfile)
h := http.HandlerFunc(apphandler)
http.Handle("/", spnego.SPNEGOKRB5Authenticate(h, acc, spnego.WithHTTPLogger(l)))
```
Active Directory often maps the SPN to a user account whose keytab uses that account's
sAMAccountName rather than the SPN; pass it explicitly to the Acceptor:
```go
acc := spnego.NewAcceptor(kt, gssapi.WithKeytabPrincipal("sysHTTP"))
```

#### Session Management
For efficiency reasons it is not desirable to authenticate on every call to a web service.
Therefore most authenticated web applications implement some form of session with the user.
Such sessions can be supported by passing a "session manager" into the `SPNEGOKRB5Authenticate` wrapper handler.
In order to not demand a specific session manager solution, the session manager must implement a simple interface:
```go
type SessionMgr interface {
    New(w http.ResponseWriter, r *http.Request, k string, v []byte) error
    Get(r *http.Request, k string) ([]byte, error)
}
```
- New - creates a new session for the request and adds a piece of data (key/value pair) to the session
- Get - extract from an existing session the value held within it under the key provided.
This should return nil bytes or an error if there is no existing session.

The session manager (sm) that implements this interface should then be passed to the `SPNEGOKRB5Authenticate`
wrapper handler as below:
```go
http.Handle("/", spnego.SPNEGOKRB5Authenticate(h, acc, spnego.WithSessionManager(sm)))
```

The `httpServer.go` source file in the examples directory shows how this can be used with the gorilla web toolkit.

#### Validating Users and Accessing Users' Details
If authentication succeeds then the request's context will have a credentials object added to it.
This object implements the `goidentity.Identity` interface from `github.com/jcmturner/goidentity/v6`.
If Microsoft Active Directory is used as the KDC then additional `ADCredentials` are available in the
`credentials.Attributes` map under the key `credentials.AttributeKeyADCredentials`.
For example the SIDs of the user's group memberships are available there for application authorization.

Checking and accessing the credentials within your application:
```go
// Get a goidentity credentials object from the request's context
creds := goidentity.FromHTTPRequestContext(r)
if creds == nil || !creds.Authenticated() {
    w.WriteHeader(http.StatusUnauthorized)
    fmt.Fprint(w, "Authentication failed")
    return
}
// Check for Active Directory attributes
if ad, ok := creds.Attributes()[credentials.AttributeKeyADCredentials].(credentials.ADCredentials); ok {
    // ad.GroupMembershipSIDs, ad.EffectiveName, ad.PrimaryGroupID, ...
}
```

### Non-HTTP Services
For application protocols that handle their own framing, the fork offers two acceptor types
depending on what the client sends on the wire:

- `spnego.NewAcceptor` accepts SPNEGO-wrapped tokens (`NegTokenInit` / `NegTokenResp`).
  HTTP "Negotiate" (RFC 4559), SMB/CIFS, and most Microsoft-flavoured protocols speak this.
- `gssapi.NewAcceptor` accepts raw Kerberos AP-REQ mech tokens (no SPNEGO envelope).
  SASL/GSSAPI bind (RFC 4752, used by LDAP) and Kerberos-only protocols speak this.

Both run the same Kerberos verification under the hood (decrypt the service ticket against the
keytab, validate ticket times and client address, decrypt and verify the authenticator
including its clock skew against the service clock, check the replay cache, then cross-check
the PAC ClientInfo against the ticket CName when a PAC is present) and expose the same
two-tier API:

- `Accept(tokenBytes, opts...)` takes a pre-extracted mech token and returns an `Acceptance`
  carrying the response token, the verified `Credentials`, and an established `SecurityContext`.
  The caller handles wire framing.
- `AcceptOn(rw, codec, opts...)` drives the handshake on a `net.Conn`-like reader/writer using
  the supplied `FrameCodec` (`gssapi.LengthPrefix4` is the 4-byte big-endian length codec) and
  returns a `Session` whose `ReadMsg` / `WriteMsg` methods frame post-auth payloads.

Construction options apply to every `Accept` call on the resulting acceptor:

- `WithKeytabPrincipal(name)` overrides the principal looked up in the keytab. Required when
  the keytab is keyed by sAMAccountName rather than the SPN clients address the ticket to (a
  common Active Directory layout).
- `WithMaxClockSkew(d)` sets the maximum acceptable skew between the service clock and the
  authenticator's `ctime`. Default 5 minutes.
- `RequireHostAddress()` rejects tickets that do not carry at least one client address (RFC 4120
  §5.3). Off by default.
- `WithPermittedEnctypes(ids)` restricts which ticket and authenticator etypes the acceptor will
  attempt to decrypt. Empty (default) imposes no restriction.
- `DisablePACDecoding()` skips PAC parsing on accepted tickets. Useful for services that do not
  consume Kerberos authorization data.
- `WithReplayCache(rc)` substitutes a custom replay cache for the process-wide singleton.
  Mainly for tests that need isolated replay state.
- `WithAcceptorLogger(l)` enables diagnostic logging during PAC decoding.

Per-call options narrow a single `Accept` invocation:

- `WithRemoteAddress(h)` passes the initiator's transport address into the AP-REQ check;
  relevant when `RequireHostAddress` was set on the acceptor and the ticket carries `caddr`.
- `WithExpectedChannelBindings(cb)` verifies the channel bindings the initiator hashed into its
  authenticator checksum against the supplied bindings. Mismatch returns
  `gssapi.ErrChannelBindingMismatch`. Use `gssapi.NewTLSChannelBindingsFromCert` (or
  `NewTLSChannelBindingsFromState`) to build `cb` from the server's TLS leaf certificate
  (RFC 5929 `tls-server-end-point`).

For a TLS-fronted service that wants to verify clients hashed the same `tls-server-end-point`
bindings, build `cb` from the server's leaf certificate once and pass it on every `Accept`:
```go
cb, err := gssapi.NewTLSChannelBindingsFromCert(serverCert)
if err != nil {
    return err
}
acceptance, err := acc.Accept(spnegoBytes, gssapi.WithExpectedChannelBindings(cb))
if errors.Is(err, gssapi.ErrChannelBindingMismatch) {
    // client hashed bindings derived from a different cert; reject
}
```
The same option works against `gssapi.NewAcceptor` for non-SPNEGO transports.

#### SPNEGO acceptor
`spnego.NewAcceptor` is the entry point for services that receive SPNEGO-wrapped tokens. The
acceptor unwraps the `NegTokenInit`, verifies the inner Kerberos AP-REQ, and produces a
`NegTokenResp(accept-completed)` carrying the AP-REP when mutual auth was requested.

`Accept` takes the inbound SPNEGO bytes (extracted from whatever framing your transport uses)
and returns the marshaled response token plus the established context and credentials:
```go
// Build the acceptor with the service's keytab.
acc := spnego.NewAcceptor(kt)

// Verify the NegTokenInit and the inner AP-REQ. The Acceptance carries the
// marshaled NegTokenResp(accept-completed), the established Kerberos
// SecurityContext, and the verified client credentials.
acceptance, err := acc.Accept(spnegoBytes)
// send acceptance.ResponseToken back to the initiator

ctx := acceptance.Context        // for per-message Wrap/Unwrap
creds := acceptance.Credentials  // verified principal + PAC if present
```
For length-prefixed wire formats, `AcceptOn` drives the same handshake on a connection and
returns a `Session` ready for `ReadMsg` / `WriteMsg`:
```go
// AcceptOn reads one length-prefixed SPNEGO frame, calls Accept, writes
// the response frame, and returns a Session over the same codec.
sess, err := acc.AcceptOn(conn, gssapi.LengthPrefix4)

// ReadMsg reads the next inbound frame and Unwraps it to plaintext.
msg, _ := sess.ReadMsg()

// WriteMsg Wraps the payload and writes a length-prefixed frame.
sess.WriteMsg(reply)
```

Integration notes:
- `acceptance.ResponseToken` is always non-nil. SPNEGO requires the acceptor to confirm
  completion even when mutual auth was not requested.
- The acceptor accepts a `NegTokenInit` whose first listed mech is the canonical Kerberos OID
  (`1.2.840.113554.1.2.2`) or the legacy MS-KRB5 OID (`1.2.840.48018.1.2.2`). Any other first
  mech is rejected; the acceptor does not walk the rest of the offered list.
- The `mechListMIC` field is parsed but not verified end-to-end. Downgrade detection on the
  offered mech list is a known gap.

#### Raw GSS-API acceptor
`gssapi.NewAcceptor` is the entry point for services that receive a bare Kerberos AP-REQ on the
wire. The acceptor decrypts the ticket against the keytab, verifies the authenticator, runs the
replay-cache and PAC ClientInfo checks, and produces an AP-REP only when the initiator
requested mutual auth.
```go
// Build the acceptor with the service's keytab.
acc := gssapi.NewAcceptor(kt)

// Decrypt the AP-REQ ticket against the keytab, verify the authenticator,
// run replay-cache and PAC ClientInfo checks, and build credentials.
// ResponseToken holds the AP-REP when the initiator requested mutual auth.
acceptance, err := acc.Accept(mechToken)
if acceptance.ResponseToken != nil {
    // send acceptance.ResponseToken back as AP-REP
}

ctx := acceptance.Context        // for per-message Wrap/Unwrap
creds := acceptance.Credentials  // verified principal + PAC if present
```
`AcceptOn` enforces the same nil-or-non-nil rule on a length-prefixed connection: it writes a
response frame only when there is an AP-REP to send, so initiator-only flows do not see a stray
empty frame on the wire:
```go
// AcceptOn reads one length-prefixed AP-REQ frame, calls Accept, writes
// the AP-REP frame only when there is one, and returns a Session over
// the same codec.
sess, err := acc.AcceptOn(conn, gssapi.LengthPrefix4)

// ReadMsg reads the next inbound frame and Unwraps it to plaintext.
msg, _ := sess.ReadMsg()

// WriteMsg Wraps the payload and writes a length-prefixed frame.
sess.WriteMsg(reply)
```

Integration notes:
- `acceptance.ResponseToken` is nil when the initiator did not request mutual auth.
- AP-REQ verification errors that map to a Kerberos error code carry a `messages.KRBError`.
  Services that need to surface a KRB-ERROR mech token to the initiator can recover it via
  `errors.As(err, &kerr)` where `kerr` is `messages.KRBError`.
- `acceptance.Credentials.GetADCredentials()` is populated only when the ticket carries a PAC
  with `KerbValidationInfo` (group SIDs, primary group ID, effective name, etc.). AD-issued
  tickets typically carry this buffer; tickets without a PAC yield empty `ADCredentials`.
- The default replay cache is a process-wide singleton sized by `WithMaxClockSkew`.
- The PAC server signature is verified against the service key when a PAC is present. The KDC
  signature is parsed but not verified, since the service does not hold the krbtgt key.
