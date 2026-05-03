## Version 8 Usage

### Configuration
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

### Keytab files
Standard keytab files can be read from a file or from a slice of bytes:
```go
import "github.com/f0oster/gokrb5/keytab"
ktFromFile, err := keytab.Load("/path/to/file.keytab")
ktFromBytes, err := keytab.Parse(b)
```

---

### Kerberos Client
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
Kerberos Ticket Granting Tickets (TGT) will be automatically renewed unless the client was created from a CCache.

A client can be **destroyed** with the following method:
```go
cl.Destroy()
```

#### Authenticate to a Service

##### HTTP SPNEGO
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

##### Generic Kerberos Client
For non-HTTP application protocols, `gssapi.NewInitiator` drives the client side: it acquires the service ticket,
builds the AP-REQ, optionally verifies a mutual-auth AP-REP, and yields a SecurityContext for per-message
Wrap/Unwrap.
```go
import "github.com/f0oster/gokrb5/gssapi"
init, err := gssapi.NewInitiator(cl, spn, gssapi.WithMutualAuth())
mechBytes, err := init.Step(nil)
// send mechBytes, receive reply...
if _, err := init.Step(reply); err != nil {
    // verify AP-REP failed
}
ctx, _ := init.SecurityContext()
sealed, _ := ctx.Wrap([]byte("hello"))
```
Initiator-only flows omit `WithMutualAuth`; the context is established after the first `Step`. Other options:
`WithChannelBindings(cb)`, `WithDelegation(krbCredDER)`, `WithConfidentiality()`, `WithStrictSequence()`.

For SPNEGO-framed transports (NegTokenInit / NegTokenResp on the wire), `spnego.NewInitiator` wraps `gssapi.NewInitiator`
with the same options and produces / consumes the SPNEGO framing.

The `examples/go-ldapv3/` directory has a complete working LDAP+TLS+CBT+SASL/GSSAPI client.

#### Changing a Client Password
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

#### Client Diagnostics
In the event of issues the configuration of a client can be investigated with its `Diagnostics` method.
This will check that the required enctypes defined in the client's krb5 config are available in its keytab.
It will also check that KDCs can be resolved for the client's REALM.
The error returned will contain details of any failed checks.
The configuration details of the client will be written to the `io.Writer` provided.

---

### Kerberised Service

#### SPNEGO/Kerberos HTTP Service
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

##### Session Management
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

##### Validating Users and Accessing Users' Details
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

#### SPNEGO/Kerberos Service (non-HTTP)
For application protocols that frame their own GSS handshake, drive the SPNEGO acceptor directly.
`Accept` verifies the inbound NegTokenInit; the returned `Acceptance` carries the marshaled NegTokenResp,
the verified credentials, and a SecurityContext for per-message Wrap/Unwrap.
```go
acc := spnego.NewAcceptor(kt)
acceptance, err := acc.Accept(spnegoBytes)
// send acceptance.ResponseToken back to the initiator
ctx := acceptance.Context
creds := acceptance.Credentials
```
For services that frame every post-auth message with a length prefix, `AcceptOn` drives the handshake
on a connection and returns a `Session` ready for `ReadMsg` / `WriteMsg`:
```go
sess, err := acc.AcceptOn(conn, gssapi.LengthPrefix4)
msg, _ := sess.ReadMsg()
sess.WriteMsg(reply)
```
For raw GSS callers (no SPNEGO framing on the wire), use `gssapi.NewAcceptor` instead.

#### Generic Kerberised Service - Validating Client Details
For services that handle their own AP-REQ wire framing, validate an inner mech token directly:
```go
import "github.com/f0oster/gokrb5/gssapi"
acc := gssapi.NewAcceptor(kt) // optional gssapi.AcceptorOption values can also be provided
acceptance, err := acc.Accept(mechToken)
// acceptance.Credentials carries the verified client identity
// acceptance.ResponseToken carries the AP-REP (non-nil only when the initiator requested mutual auth)
```
