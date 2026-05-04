# Examples

[`httpClient.go`](httpClient.go) builds a keytab-backed `*client.Client`, wraps it in `spnego.NewClient`, and issues a GET against an SPN. The SPNEGO Authorization round-trip is hidden behind the wrapper, so the caller code looks like an ordinary `http.Client.Do`.

[`httpServer.go`](httpServer.go) wraps an application handler in `spnego.SPNEGOKRB5Authenticate` with a gorilla cookie-backed `SessionMgr`. The first request runs the full SPNEGO handshake; subsequent requests in the same session reuse the cached identity without re-handshaking.

[`longRunningClient.go`](longRunningClient.go) keeps a keytab-backed `*client.Client` alive across TGT lifetime boundaries. The client renews its TGT automatically, so a long-lived process does not need to re-`Login` on every call.

[`example.go`](example.go) wires the SPNEGO client and acceptor together against an `httptest.Server` running in-process. The test keytabs and `krb5.conf` are bundled, so it runs without an external KDC.

[`example-AD.go`](example-AD.go) is the same shape with an AD-style realm and SPN, and issues the request twice to exercise session reuse via the cookie-backed manager.

[`go-ldapv3/`](go-ldapv3/) authenticates to LDAP via `github.com/go-ldap/ldap/v3` using `gssapi.NewInitiator` with `WithChannelBindings` derived from the server's TLS leaf certificate, exercising `tls-server-end-point` channel bindings (RFC 5929) end to end.

[`sasl/`](sasl/) drives a raw-TCP LDAP SASL bind through `gssapi.NewInitiator` directly, then negotiates a SASL/GSSAPI security layer (none, integrity, or confidentiality per RFC 4752) and exchanges per-message-protected payloads over the bound socket.
