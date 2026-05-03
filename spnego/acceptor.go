package spnego

import (
	"errors"
	"fmt"
	"io"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/keytab"
)

// Acceptor verifies inbound SPNEGO/Kerberos NegTokenInit bytes. It
// wraps gssapi.Acceptor with SPNEGO framing on both directions.
type Acceptor struct {
	gss *gssapi.Acceptor
}

// NewAcceptor constructs a SPNEGO Acceptor backed by gssapi.Acceptor.
// The supplied gssapi.AcceptorOption values configure the underlying
// GSS-layer acceptor.
func NewAcceptor(kt *keytab.Keytab, opts ...gssapi.AcceptorOption) *Acceptor {
	return &Acceptor{gss: gssapi.NewAcceptor(kt, opts...)}
}

// Acceptance carries the result of a successful Accept.
type Acceptance struct {
	// ResponseToken is the marshaled NegTokenResp(accept-completed) to
	// send back to the initiator. Always non-nil on success: SPNEGO
	// requires the acceptor to confirm completion, with the AP-REP
	// MechToken embedded when mutual auth was requested.
	ResponseToken []byte
	Context       *gssapi.SecurityContext
	Credentials   *credentials.Credentials
}

// Accept verifies a SPNEGO NegTokenInit and returns the marshaled
// NegTokenResp plus the established context and verified credentials.
func (a *Acceptor) Accept(spnegoBytes []byte, opts ...gssapi.AcceptOption) (*Acceptance, error) {
	var spt SPNEGOToken
	if err := spt.Unmarshal(spnegoBytes); err != nil {
		return nil, fmt.Errorf("unmarshal SPNEGO init: %w", err)
	}
	if !spt.Init {
		return nil, errors.New("SPNEGO token is not a NegTokenInit")
	}
	if len(spt.NegTokenInit.MechTypes) == 0 {
		return nil, errors.New("NegTokenInit carries no MechTypes")
	}
	oid := spt.NegTokenInit.MechTypes[0]
	if !(oid.Equal(gssapi.OIDKRB5.OID()) || oid.Equal(gssapi.OIDMSLegacyKRB5.OID())) {
		return nil, fmt.Errorf("SPNEGO mech OID %s is not Kerberos", oid.String())
	}

	gssAcceptance, err := a.gss.Accept(spt.NegTokenInit.MechTokenBytes, opts...)
	if err != nil {
		return nil, err
	}

	resp := NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptCompleted),
		SupportedMech: gssapi.OIDKRB5.OID(),
		ResponseToken: gssAcceptance.ResponseToken,
	}
	respBytes, err := resp.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal NegTokenResp: %w", err)
	}

	return &Acceptance{
		ResponseToken: respBytes,
		Context:       gssAcceptance.Context,
		Credentials:   gssAcceptance.Credentials,
	}, nil
}

// AcceptOn drives the SPNEGO handshake on rw. It reads one framed
// NegTokenInit, calls Accept, and writes the framed
// NegTokenResp(accept-completed) back. Returns a gssapi.Session ready
// for ReadMsg/WriteMsg over the same codec.
//
// Unlike gssapi.Acceptor.AcceptOn, this method always writes a
// response frame: SPNEGO requires the initiator to receive
// accept-completed even when mutual auth was not requested.
func (a *Acceptor) AcceptOn(rw io.ReadWriter, codec gssapi.FrameCodec, opts ...gssapi.AcceptOption) (*gssapi.Session, error) {
	frame, err := codec.ReadFrame(rw)
	if err != nil {
		return nil, fmt.Errorf("read SPNEGO frame: %w", err)
	}
	acceptance, err := a.Accept(frame, opts...)
	if err != nil {
		return nil, err
	}
	if err := codec.WriteFrame(rw, acceptance.ResponseToken); err != nil {
		return nil, fmt.Errorf("write SPNEGO response frame: %w", err)
	}
	return gssapi.NewSession(rw, codec, acceptance.Context, acceptance.Credentials), nil
}
