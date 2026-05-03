package gssapi

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/iana/flags"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/types"
)

const defaultMaxClockSkew = 5 * time.Minute

// Acceptor verifies inbound AP-REQ mech tokens against a keytab.
// Long-lived; safe for concurrent use across goroutines. Construct
// once per service and share across all connection handlers.
//
// Acceptor is symmetric to Initiator: where Initiator drives the
// client side of the GSS handshake, Acceptor drives the server side.
// SPNEGO callers should use spnego.Acceptor, which wraps this with
// SPNEGO framing on both directions.
type Acceptor struct {
	keytab            *keytab.Keytab
	keytabPrincipal   *types.PrincipalName
	maxClockSkew      time.Duration
	requireHostAddr   bool
	decodePAC         bool
	permittedEnctypes []int32
	logger            *log.Logger
	replayCache       *ReplayCache
}

// AcceptorOption configures an Acceptor at construction time.
type AcceptorOption func(*Acceptor)

// WithKeytabPrincipal overrides the principal name used to look up the
// service key in the keytab. Useful when an Active Directory account's
// keytab uses the user's sAMAccountName rather than the SPN.
func WithKeytabPrincipal(name string) AcceptorOption {
	return func(a *Acceptor) {
		pn, _ := types.ParseSPNString(name)
		a.keytabPrincipal = &pn
	}
}

// WithMaxClockSkew sets the maximum acceptable clock skew between the
// service and the issue time of inbound tickets. Default 5 minutes.
func WithMaxClockSkew(d time.Duration) AcceptorOption {
	return func(a *Acceptor) { a.maxClockSkew = d }
}

// RequireHostAddress requires inbound tickets to carry a non-empty
// HostAddress list (RFC 4120 §5.3 caddr). Off by default.
func RequireHostAddress() AcceptorOption {
	return func(a *Acceptor) { a.requireHostAddr = true }
}

// WithPermittedEnctypes restricts the etypes the Acceptor will accept
// on inbound ticket and authenticator decryption. An AP-REQ outside
// this list is rejected before decryption. Empty (default) imposes no
// restriction.
func WithPermittedEnctypes(ids []int32) AcceptorOption {
	return func(a *Acceptor) { a.permittedEnctypes = ids }
}

// DisablePACDecoding disables PAC processing on accepted tickets.
// PAC decoding is on by default; this is the off switch for services
// that do not consume Kerberos authorization data.
func DisablePACDecoding() AcceptorOption {
	return func(a *Acceptor) { a.decodePAC = false }
}

// WithReplayCache overrides the process-wide singleton replay cache
// with a caller-supplied instance. Useful for tests requiring isolated
// replay state, or for services that want a per-Acceptor cache.
func WithReplayCache(rc *ReplayCache) AcceptorOption {
	return func(a *Acceptor) { a.replayCache = rc }
}

// WithAcceptorLogger sets the logger used during PAC decoding for
// diagnostic output. Nil (default) is silent.
func WithAcceptorLogger(l *log.Logger) AcceptorOption {
	return func(a *Acceptor) { a.logger = l }
}

// NewAcceptor constructs an Acceptor for the given service keytab.
// The replay cache defaults to the process-wide singleton; pass
// WithReplayCache to override.
func NewAcceptor(kt *keytab.Keytab, opts ...AcceptorOption) *Acceptor {
	a := &Acceptor{
		keytab:       kt,
		decodePAC:    true,
		maxClockSkew: defaultMaxClockSkew,
	}
	for _, o := range opts {
		o(a)
	}
	if a.replayCache == nil {
		a.replayCache = GetReplayCache(a.maxClockSkew)
	}
	return a
}

// acceptCall holds per-Accept-call state populated by AcceptOptions.
type acceptCall struct {
	remoteAddr types.HostAddress
	expectedCB *ChannelBindings
}

// AcceptOption configures a single Accept call.
type AcceptOption func(*acceptCall)

// WithRemoteAddress passes the initiator's transport address into the
// AP-REQ verification. Required when RequireHostAddress was set on the
// Acceptor and the initiator's ticket carries CAddr; otherwise has no
// effect.
func WithRemoteAddress(h types.HostAddress) AcceptOption {
	return func(c *acceptCall) { c.remoteAddr = h }
}

// WithExpectedChannelBindings makes Accept verify the initiator's
// hashed channel bindings against MD5(cb.Marshal()). Mismatch returns
// ErrChannelBindingMismatch.
func WithExpectedChannelBindings(cb *ChannelBindings) AcceptOption {
	return func(c *acceptCall) { c.expectedCB = cb }
}

// Acceptance carries the result of a successful Accept.
type Acceptance struct {
	// ResponseToken is the AP-REP mech token to send back to the
	// initiator when mutual auth was requested. nil otherwise.
	ResponseToken []byte
	// Context is the established bidirectional SecurityContext for
	// per-message Wrap/Unwrap/MIC operations.
	Context *SecurityContext
	// Credentials carries the verified client identity. Populated
	// ADCredentials are present only when the ticket carried a PAC
	// with KerbValidationInfo.
	Credentials *credentials.Credentials
}

// Accept verifies the inner GSS-API mech token (the RFC 2743 §3.1
// framed AP-REQ; not SPNEGO-wrapped). On success, Acceptance carries
// the AP-REP response token (non-nil iff the initiator requested
// mutual auth), the established SecurityContext, and the verified
// client credentials.
//
// On verification failure the returned error is typically a
// *messages.KRBError; callers serializing a KRB-ERROR mech token to
// the initiator can recover it via errors.As().
func (a *Acceptor) Accept(mechToken []byte, opts ...AcceptOption) (*Acceptance, error) {
	oid, tokID, inner, err := UnmarshalMechToken(mechToken)
	if err != nil {
		return nil, fmt.Errorf("unmarshal mech token: %w", err)
	}
	if !oid.Equal(OIDKRB5.OID()) {
		return nil, fmt.Errorf("mech token OID is %s, want %s", oid.String(), OIDKRB5.OID().String())
	}
	if tokID != TokIDAPReq {
		return nil, fmt.Errorf("unexpected mech token ID %s, want %s", tokID, TokIDAPReq)
	}

	var apReq messages.APReq
	if err := apReq.Unmarshal(inner); err != nil {
		return nil, fmt.Errorf("unmarshal AP-REQ: %w", err)
	}

	call := &acceptCall{}
	for _, o := range opts {
		o(call)
	}

	creds, err := verifyAPREQ(&apReq, a, call)
	if err != nil {
		return nil, err
	}

	if call.expectedCB != nil {
		if err := verifyChannelBindings(&apReq, call.expectedCB); err != nil {
			return nil, err
		}
	}

	mutualAuth := types.IsFlagSet(&apReq.APOptions, flags.APOptionMutualRequired)

	var responseToken []byte
	var apRepSubkey types.EncryptionKey
	var apRepSeq uint64
	if mutualAuth {
		rep, enc, err := messages.NewAPRep(apReq.Ticket.DecryptedEncPart.Key, apReq.Authenticator)
		if err != nil {
			return nil, fmt.Errorf("build AP-REP: %w", err)
		}
		repBytes, err := rep.Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshal AP-REP: %w", err)
		}
		responseToken, err = MarshalMechToken(TokIDAPRep, repBytes)
		if err != nil {
			return nil, fmt.Errorf("marshal AP-REP mech token: %w", err)
		}
		apRepSubkey = enc.Subkey
		apRepSeq = uint64(enc.SequenceNumber)
	}

	ctx := NewAcceptorContext(
		apReq.Ticket.DecryptedEncPart.Key,
		apReq.Authenticator.SubKey,
		apRepSubkey,
		apRepSeq,
		uint64(apReq.Authenticator.SeqNumber),
	)

	return &Acceptance{
		ResponseToken: responseToken,
		Context:       ctx,
		Credentials:   creds,
	}, nil
}

// ErrAcceptorKeytabRequired is returned by NewAcceptor's caller path
// if a nil keytab is observed at Accept time. Constructing an Acceptor
// with a nil keytab is a programmer error.
var ErrAcceptorKeytabRequired = errors.New("gssapi: Acceptor keytab is nil")
