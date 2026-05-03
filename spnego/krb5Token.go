package spnego

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/asn1tools"
	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/crypto"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/iana/msgtype"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/service"
	"github.com/f0oster/gokrb5/types"
)

// GSSAPI KRB5 MechToken IDs.
const (
	TOK_ID_KRB_AP_REQ = "0100"
	TOK_ID_KRB_AP_REP = "0200"
	TOK_ID_KRB_ERROR  = "0300"
)

// KRB5Token context token implementation for GSSAPI.
type KRB5Token struct {
	OID      asn1.ObjectIdentifier
	tokID    []byte
	APReq    messages.APReq
	APRep    messages.APRep
	KRBError messages.KRBError
	// EncAPRepPart is the decrypted AP-REP populated by Verify; it carries
	// the optional Subkey and SequenceNumber for seeding a
	// gssapi.SecurityContext.
	EncAPRepPart *messages.EncAPRepPart
	// Authenticator is the plaintext Authenticator generated when the
	// token is built via NewKRB5TokenAPREQ or NewKRB5TokenAPREQWithBindings.
	// Unset for tokens parsed from the wire.
	Authenticator types.Authenticator
	// AcceptorSubkey is the subkey placed in EncAPRepPart of an AP-REP
	// produced by Verify when the initiator requested mutual auth. It is
	// the per-message keying material for the established context per
	// RFC 4121 §4.2.5; MS-KILE §3.1.1.2 mandates it for AES.
	AcceptorSubkey types.EncryptionKey
	// AcceptorSeqNumber is the sequence number placed in EncAPRepPart of
	// the AP-REP produced by Verify; the initiator uses it to seed
	// seq_recv per RFC 4121 §4.2.1.
	AcceptorSeqNumber int64
	settings *service.Settings
	// sentAuth and sessionKey are set by SetAPRepVerification before
	// Verify is called on an AP-REP token. Without them Verify cannot
	// perform the RFC 4120 3.2.4 ctime/cusec check.
	sentAuth      types.Authenticator
	sessionKey    types.EncryptionKey
	responseToken []byte
	context       context.Context
	// rawMechToken preserves the application-tagged input bytes from
	// Unmarshal so the AP-REQ branch of Verify can pass them directly
	// to gssapi.Acceptor.Accept without re-marshaling.
	rawMechToken []byte
}

// ResponseToken returns the GSS MechToken bytes for the AP-REP that
// Verify produced when the initiator requested mutual authentication.
// Returns nil for AP-REQ tokens without mutual auth or for any other
// token type.
func (m *KRB5Token) ResponseToken() []byte {
	return m.responseToken
}

// SetAPRepVerification provides the inputs required to verify an AP-REP
// KRB5Token per RFC 4120 3.2.4. Callers doing client-side mutual
// authentication must call this before invoking Verify on a token that
// contains an AP-REP. sentAuth is the Authenticator the client placed
// in its AP-REQ (its ctime and cusec are the mutual-auth proof);
// sessionKey is the session key from the service ticket.
func (m *KRB5Token) SetAPRepVerification(sentAuth types.Authenticator, sessionKey types.EncryptionKey) {
	m.sentAuth = sentAuth
	m.sessionKey = sessionKey
}

// Marshal a KRB5Token into a slice of bytes.
func (m *KRB5Token) Marshal() ([]byte, error) {
	// Create the header
	b, _ := asn1.Marshal(m.OID)
	b = append(b, m.tokID...)
	var tb []byte
	var err error
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		tb, err = m.APReq.Marshal()
		if err != nil {
			return []byte{}, fmt.Errorf("error marshalling AP_REQ for MechToken: %v", err)
		}
	case TOK_ID_KRB_AP_REP:
		tb, err = m.APRep.Marshal()
		if err != nil {
			return []byte{}, fmt.Errorf("error marshalling AP_REP for MechToken: %v", err)
		}
	case TOK_ID_KRB_ERROR:
		return []byte{}, errors.New("marshal of KRB_ERROR GSSAPI MechToken not supported by gokrb5")
	}
	if err != nil {
		return []byte{}, fmt.Errorf("error mashalling kerberos message within mech token: %v", err)
	}
	b = append(b, tb...)
	return asn1tools.AddASNAppTag(b, 0), nil
}

// Unmarshal a KRB5Token.
func (m *KRB5Token) Unmarshal(b []byte) error {
	m.rawMechToken = b
	var oid asn1.ObjectIdentifier
	r, err := asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
	if err != nil {
		return fmt.Errorf("error unmarshalling KRB5Token OID: %v", err)
	}
	if !oid.Equal(gssapi.OIDKRB5.OID()) {
		return fmt.Errorf("error unmarshalling KRB5Token, OID is %s not %s", oid.String(), gssapi.OIDKRB5.OID().String())
	}
	m.OID = oid
	if len(r) < 2 {
		return fmt.Errorf("krb5token too short")
	}
	m.tokID = r[0:2]
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		var a messages.APReq
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REQ: %v", err)
		}
		m.APReq = a
	case TOK_ID_KRB_AP_REP:
		var a messages.APRep
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token AP_REP: %v", err)
		}
		m.APRep = a
	case TOK_ID_KRB_ERROR:
		var a messages.KRBError
		err = a.Unmarshal(r[2:])
		if err != nil {
			return fmt.Errorf("error unmarshalling KRB5Token KRBError: %v", err)
		}
		m.KRBError = a
	}
	return nil
}

// Verify a KRB5Token.
func (m *KRB5Token) Verify() (bool, gssapi.Status) {
	switch hex.EncodeToString(m.tokID) {
	case TOK_ID_KRB_AP_REQ:
		acceptor := newAcceptorFromSettings(m.settings)
		acceptance, err := acceptor.Accept(m.rawMechToken,
			gssapi.WithRemoteAddress(m.settings.ClientAddress()),
		)
		if err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: err.Error()}
		}
		m.responseToken = acceptance.ResponseToken
		if acceptance.Context != nil {
			m.AcceptorSubkey = acceptance.Context.APRepSubkey
			m.AcceptorSeqNumber = int64(acceptance.Context.SendSeq())
		}
		m.context = context.Background()
		m.context = context.WithValue(m.context, ctxCredentials, acceptance.Credentials)
		return true, gssapi.Status{Code: gssapi.StatusComplete}
	case TOK_ID_KRB_AP_REP:
		// Client side: verify the AP-REP per RFC 4120 3.2.4. The caller
		// must have provided the sent Authenticator and session key via
		// SetAPRepVerification before reaching here.
		if len(m.sessionKey.KeyValue) == 0 {
			return false, gssapi.Status{Code: gssapi.StatusFailure, Message: "AP-REP verification inputs not set; call SetAPRepVerification before Verify"}
		}
		encPart, err := gssapi.VerifyAPRep(m.APRep, m.sessionKey, m.sentAuth)
		if err != nil {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveCredential, Message: err.Error()}
		}
		m.EncAPRepPart = encPart
		return true, gssapi.Status{Code: gssapi.StatusComplete}
	case TOK_ID_KRB_ERROR:
		if m.KRBError.MsgType != msgtype.KRB_ERROR {
			return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "KRB5_Error token not valid"}
		}
		return true, gssapi.Status{Code: gssapi.StatusUnavailable}
	}
	return false, gssapi.Status{Code: gssapi.StatusDefectiveToken, Message: "unknown TOK_ID in KRB5 token"}
}

// IsAPReq tests if the MechToken contains an AP_REQ.
func (m *KRB5Token) IsAPReq() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REQ {
		return true
	}
	return false
}

// IsAPRep tests if the MechToken contains an AP_REP.
func (m *KRB5Token) IsAPRep() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_AP_REP {
		return true
	}
	return false
}

// IsKRBError tests if the MechToken contains an KRB_ERROR.
func (m *KRB5Token) IsKRBError() bool {
	if hex.EncodeToString(m.tokID) == TOK_ID_KRB_ERROR {
		return true
	}
	return false
}

// Context returns the KRB5 token's context which will contain any verify user identity information.
func (m *KRB5Token) Context() context.Context {
	return m.context
}

// SecurityContext returns an acceptor SecurityContext built from the
// keys and seq numbers established by Verify on a mutual-auth AP-REQ.
// Returns nil for AP-REQ tokens without mutual auth (no AcceptorSubkey),
// for AP-REP tokens, or for KRBError tokens.
func (m *KRB5Token) SecurityContext() *gssapi.SecurityContext {
	if !m.IsAPReq() || m.AcceptorSubkey.KeyValue == nil {
		return nil
	}
	return gssapi.NewAcceptorContext(
		m.APReq.Ticket.DecryptedEncPart.Key,
		m.APReq.Authenticator.SubKey,
		m.AcceptorSubkey,
		uint64(m.AcceptorSeqNumber),
		uint64(m.APReq.Authenticator.SeqNumber),
	)
}

// newAcceptorFromSettings builds a gssapi.Acceptor from a service.Settings.
// Used by the AP-REQ branch of KRB5Token.Verify during the migration to
// spnego.Acceptor; retired alongside the *spnego.SPNEGO hybrid type once
// the SPNEGO HTTP middleware moves to spnego.NewAcceptor directly.
func newAcceptorFromSettings(s *service.Settings) *gssapi.Acceptor {
	var opts []gssapi.AcceptorOption
	if pn := s.KeytabPrincipal(); pn != nil {
		opts = append(opts, gssapi.WithKeytabPrincipal(pn.PrincipalNameString()))
	}
	if d := s.MaxClockSkew(); d != 0 {
		opts = append(opts, gssapi.WithMaxClockSkew(d))
	}
	if s.RequireHostAddr() {
		opts = append(opts, gssapi.RequireHostAddress())
	}
	if !s.DecodePAC() {
		opts = append(opts, gssapi.DisablePACDecoding())
	}
	if pe := s.PermittedEnctypes(); len(pe) > 0 {
		opts = append(opts, gssapi.WithPermittedEnctypes(pe))
	}
	if l := s.Logger(); l != nil {
		opts = append(opts, gssapi.WithAcceptorLogger(l))
	}
	return gssapi.NewAcceptor(s.Keytab, opts...)
}

// buildAPRep constructs the AP-REP for an already-verified AP-REQ that
// requested mutual authentication. It populates m.APRep, m.AcceptorSubkey,
// m.AcceptorSeqNumber, and m.responseToken (the GSS MechToken bytes).
func (m *KRB5Token) buildAPRep() error {
	rep, enc, err := messages.NewAPRep(m.APReq.Ticket.DecryptedEncPart.Key, m.APReq.Authenticator)
	if err != nil {
		return fmt.Errorf("could not build AP-REP: %w", err)
	}
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REP)
	out := KRB5Token{
		OID:   gssapi.OIDKRB5.OID(),
		tokID: tb,
		APRep: rep,
	}
	mtb, err := out.Marshal()
	if err != nil {
		return fmt.Errorf("could not marshal AP-REP MechToken: %w", err)
	}
	m.APRep = rep
	m.AcceptorSubkey = enc.Subkey
	m.AcceptorSeqNumber = enc.SequenceNumber
	m.responseToken = mtb
	return nil
}

// NewKRB5TokenAPREQ creates a new KRB5 AP-REQ token without channel
// bindings or credential delegation. Use NewKRB5TokenAPREQWithBindings
// for either.
func NewKRB5TokenAPREQ(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, GSSAPIFlags []int, APOptions []int) (KRB5Token, error) {
	return NewKRB5TokenAPREQWithBindings(cl, tkt, sessionKey, GSSAPIFlags, APOptions, nil, nil)
}

// NewKRB5TokenAPREQWithBindings creates a new KRB5 AP-REQ token with
// optional channel bindings and credential delegation. When bindings is
// non-nil its MD5 hash is placed in the authenticator checksum Bnd field
// per RFC 4121 §4.1.1. When delegationCredDER is non-nil, the DER-encoded
// KRB_CRED bytes are placed in the Deleg field and ContextFlagDeleg is
// set per RFC 4121 §4.1.1.1; callers typically reuse a KRB_CRED they
// already received from the KDC.
//
// A random Authenticator subkey matching the session key's enctype is
// generated unconditionally (strict CFX acceptors require it). The
// plaintext Authenticator including the subkey is stored on
// KRB5Token.Authenticator so callers can pass its SeqNumber and SubKey
// into gssapi.NewInitiatorContext.
func NewKRB5TokenAPREQWithBindings(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, GSSAPIFlags []int, APOptions []int, bindings *gssapi.ChannelBindings, delegationCredDER []byte) (KRB5Token, error) {
	// TODO consider providing the SPN rather than the specific tkt and key and get these from the krb client.
	var m KRB5Token
	m.OID = gssapi.OIDKRB5.OID()
	tb, _ := hex.DecodeString(TOK_ID_KRB_AP_REQ)
	m.tokID = tb

	auth, err := gssapi.NewGSSAuthenticator(cl.Credentials, GSSAPIFlags, bindings, delegationCredDER)
	if err != nil {
		return m, err
	}
	// Generate a random Authenticator subkey matching the session key's
	// enctype. Strict CFX acceptors require a GSS-specific subkey.
	encType, err := crypto.GetEtype(sessionKey.KeyType)
	if err != nil {
		return m, fmt.Errorf("get etype for authenticator subkey: %w", err)
	}
	if err := auth.GenerateSeqNumberAndSubKey(sessionKey.KeyType, encType.GetKeyByteSize()); err != nil {
		return m, fmt.Errorf("generate authenticator subkey: %w", err)
	}
	APReq, err := messages.NewAPReq(
		tkt,
		sessionKey,
		auth,
	)
	if err != nil {
		return m, err
	}
	for _, o := range APOptions {
		types.SetFlag(&APReq.APOptions, o)
	}
	m.APReq = APReq
	m.Authenticator = auth
	return m, nil
}

