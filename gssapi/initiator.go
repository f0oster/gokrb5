package gssapi

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/asn1tools"
	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/crypto"
	"github.com/f0oster/gokrb5/iana/flags"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/types"
)

// Hex-encoded GSS-API KRB5 mech token IDs (RFC 4121 §4.1).
const (
	TokIDAPReq  = "0100"
	TokIDAPRep  = "0200"
	TokIDKRBErr = "0300"
)

type initiatorState int

const (
	stateReady initiatorState = iota
	stateAwaitingReply
	stateDone
)

// Initiator drives client-side Kerberos GSS context establishment per
// RFC 2743 §2.2.1. It acquires a service ticket, builds an AP-REQ
// with the RFC 4121 §4.1.1 GSS authenticator checksum, optionally
// verifies a mutual-authentication AP-REP, and produces an
// established SecurityContext for per-message Wrap/Unwrap/MIC
// operations.
//
// Usage:
//
//	init, err := gssapi.NewInitiator(cl, "ldap/dc.example.com",
//	    gssapi.WithMutualAuth(),
//	    gssapi.WithChannelBindings(cb),
//	)
//	apReq, err := init.Step(nil)
//	// send apReq, receive reply
//	_, err = init.Step(reply)
//	ctx, err := init.SecurityContext()
type Initiator struct {
	cl  *client.Client
	cfg initiatorConfig
	spn string

	tkt        messages.Ticket
	sessionKey types.EncryptionKey
	sentAuth   types.Authenticator

	ctx   *SecurityContext
	state initiatorState
}

type initiatorConfig struct {
	mutualAuth    bool
	confidential  bool
	strictSeq     bool
	bindings      *ChannelBindings
	delegationDER []byte
}

// InitiatorOption configures an Initiator.
type InitiatorOption func(*initiatorConfig)

// WithMutualAuth requests mutual authentication. Step will expect an
// AP-REP from the peer and verify it per RFC 4120 §3.2.4 before the
// context is established.
func WithMutualAuth() InitiatorOption {
	return func(c *initiatorConfig) { c.mutualAuth = true }
}

// WithChannelBindings binds the context to a transport channel. The
// bindings are MD5-hashed into the AP-REQ authenticator checksum per
// RFC 4121 §4.1.1.
func WithChannelBindings(cb *ChannelBindings) InitiatorOption {
	return func(c *initiatorConfig) { c.bindings = cb }
}

// WithDelegation forwards the provided KRB_CRED (DER-encoded) to
// the peer via the authenticator checksum delegation field per
// RFC 4121 §4.1.1.1.
func WithDelegation(krbCredDER []byte) InitiatorOption {
	return func(c *initiatorConfig) { c.delegationDER = krbCredDER }
}

// WithConfidentiality sets the Confidential flag on the resulting
// SecurityContext so that Wrap produces sealed (encrypted) tokens.
func WithConfidentiality() InitiatorOption {
	return func(c *initiatorConfig) { c.confidential = true }
}

// WithStrictSequence enables StrictSequence on the resulting
// SecurityContext, promoting non-OK supplementary statuses to errors.
func WithStrictSequence() InitiatorOption {
	return func(c *initiatorConfig) { c.strictSeq = true }
}

// NewInitiator prepares a GSS context against the given SPN. The
// service ticket is acquired eagerly from the client's TGT session.
// Returns an error if no valid TGT is available for the target realm.
func NewInitiator(cl *client.Client, spn string, opts ...InitiatorOption) (*Initiator, error) {
	var cfg initiatorConfig
	for _, o := range opts {
		o(&cfg)
	}
	tkt, sessionKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("acquire service ticket for %s: %w", spn, err)
	}
	return &Initiator{
		cl:         cl,
		cfg:        cfg,
		spn:        spn,
		tkt:        tkt,
		sessionKey: sessionKey,
		state:      stateReady,
	}, nil
}

// NewInitiatorFromTicket prepares a GSS context using a caller-supplied
// service ticket and session key, skipping the KDC exchange.
func NewInitiatorFromTicket(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, opts ...InitiatorOption) (*Initiator, error) {
	var cfg initiatorConfig
	for _, o := range opts {
		o(&cfg)
	}
	return &Initiator{
		cl:         cl,
		cfg:        cfg,
		tkt:        tkt,
		sessionKey: sessionKey,
		state:      stateReady,
	}, nil
}

// Step advances the context. On the first call input must be nil; the
// returned bytes are the RFC 2743 §3.1 framed AP-REQ mech token. On
// the second call (mutual auth only) input is the peer's response
// token containing an AP-REP or KRB-ERROR.
//
// Returns (nil, nil) when the context is established and no further
// output token is needed.
func (i *Initiator) Step(input []byte) ([]byte, error) {
	switch i.state {
	case stateReady:
		return i.stepInitial()
	case stateAwaitingReply:
		return i.stepReply(input)
	case stateDone:
		return nil, errors.New("context already established")
	default:
		return nil, errors.New("invalid initiator state")
	}
}

// Done reports whether the security context is established.
func (i *Initiator) Done() bool { return i.state == stateDone }

// SPN returns the service principal name this Initiator targets.
func (i *Initiator) SPN() string { return i.spn }

// SessionKeyEtype returns the enctype of the session key from the
// service ticket. Available immediately after NewInitiator.
func (i *Initiator) SessionKeyEtype() int32 { return i.sessionKey.KeyType }

// SecurityContext returns the established per-message context.
func (i *Initiator) SecurityContext() (*SecurityContext, error) {
	if i.state != stateDone {
		return nil, errors.New("security context not yet established")
	}
	return i.ctx, nil
}

func (i *Initiator) stepInitial() ([]byte, error) {
	gssFlags := []int{ContextFlagInteg}
	if i.cfg.mutualAuth {
		gssFlags = append(gssFlags, ContextFlagMutual)
	}
	if i.cfg.confidential {
		gssFlags = append(gssFlags, ContextFlagConf)
	}
	if i.cfg.delegationDER != nil {
		gssFlags = append(gssFlags, ContextFlagDeleg)
	}

	auth, err := NewGSSAuthenticator(i.cl.Credentials, gssFlags, i.cfg.bindings, i.cfg.delegationDER)
	if err != nil {
		return nil, fmt.Errorf("build GSS authenticator: %w", err)
	}

	encType, err := crypto.GetEtype(i.sessionKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("get etype for authenticator subkey: %w", err)
	}
	if err := auth.GenerateSeqNumberAndSubKey(i.sessionKey.KeyType, encType.GetKeyByteSize()); err != nil {
		return nil, fmt.Errorf("generate authenticator subkey: %w", err)
	}

	apReq, err := messages.NewAPReq(i.tkt, i.sessionKey, auth)
	if err != nil {
		return nil, fmt.Errorf("build AP-REQ: %w", err)
	}
	if i.cfg.mutualAuth {
		types.SetFlag(&apReq.APOptions, flags.APOptionMutualRequired)
	}

	i.sentAuth = auth

	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal AP-REQ: %w", err)
	}
	wireToken, err := MarshalMechToken(TokIDAPReq, apReqBytes)
	if err != nil {
		return nil, err
	}

	if !i.cfg.mutualAuth {
		i.ctx = i.buildContext(types.EncryptionKey{}, 0)
		i.state = stateDone
	} else {
		i.state = stateAwaitingReply
	}

	return wireToken, nil
}

func (i *Initiator) stepReply(input []byte) ([]byte, error) {
	if input == nil {
		return nil, errors.New("mutual auth requires a reply token")
	}

	oid, tokID, innerBytes, err := UnmarshalMechToken(input)
	if err != nil {
		return nil, fmt.Errorf("unmarshal reply token: %w", err)
	}
	if !oid.Equal(OIDKRB5.OID()) {
		return nil, fmt.Errorf("reply mech token OID is %s, want %s", oid.String(), OIDKRB5.OID().String())
	}

	switch tokID {
	case TokIDAPRep:
		var apRep messages.APRep
		if err := apRep.Unmarshal(innerBytes); err != nil {
			return nil, fmt.Errorf("unmarshal AP-REP: %w", err)
		}
		encPart, err := VerifyAPRep(apRep, i.sessionKey, i.sentAuth)
		if err != nil {
			return nil, fmt.Errorf("verify AP-REP: %w", err)
		}
		i.ctx = i.buildContext(encPart.Subkey, uint64(encPart.SequenceNumber))
		i.state = stateDone
		return nil, nil

	case TokIDKRBErr:
		var krbErr messages.KRBError
		if err := krbErr.Unmarshal(innerBytes); err != nil {
			return nil, fmt.Errorf("unmarshal KRB-ERROR: %w", err)
		}
		return nil, fmt.Errorf("server returned KRB-ERROR %d: %s", krbErr.ErrorCode, krbErr.EText)

	default:
		return nil, fmt.Errorf("unexpected reply token ID %s", tokID)
	}
}

func (i *Initiator) buildContext(apRepSubkey types.EncryptionKey, apRepSeq uint64) *SecurityContext {
	ctx := NewInitiatorContext(
		i.sessionKey,
		i.sentAuth.SubKey,
		apRepSubkey,
		uint64(i.sentAuth.SeqNumber),
		apRepSeq,
	)
	ctx.Confidential = i.cfg.confidential
	ctx.StrictSequence = i.cfg.strictSeq
	return ctx
}

// MarshalMechToken produces an RFC 2743 §3.1 KRB5 mech token:
// [APPLICATION 0] { KRB5 OID, tokID, body }. tokID is hex-encoded
// (TokIDAPReq, TokIDAPRep, TokIDKRBErr).
func MarshalMechToken(tokID string, body []byte) ([]byte, error) {
	oidBytes, err := asn1.Marshal(OIDKRB5.OID())
	if err != nil {
		return nil, fmt.Errorf("marshal KRB5 OID: %w", err)
	}
	tb, err := hex.DecodeString(tokID)
	if err != nil {
		return nil, fmt.Errorf("decode token ID: %w", err)
	}
	b := make([]byte, 0, len(oidBytes)+len(tb)+len(body))
	b = append(b, oidBytes...)
	b = append(b, tb...)
	b = append(b, body...)
	return asn1tools.AddASNAppTag(b, 0), nil
}

// UnmarshalMechToken strips RFC 2743 §3.1 framing and returns the OID
// identifying the mech, the hex-encoded tokID, and the inner message
// body.
func UnmarshalMechToken(b []byte) (asn1.ObjectIdentifier, string, []byte, error) {
	var oid asn1.ObjectIdentifier
	r, err := asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
	if err != nil {
		return nil, "", nil, fmt.Errorf("unmarshal mech token OID: %w", err)
	}
	if len(r) < 2 {
		return nil, "", nil, errors.New("mech token too short after OID")
	}
	tokID := hex.EncodeToString(r[0:2])
	return oid, tokID, r[2:], nil
}
