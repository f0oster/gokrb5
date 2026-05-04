package spnego

import (
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/types"
)

// Initiator drives the client side of a SPNEGO/Kerberos handshake.
// Step(nil) returns a marshaled NegTokenInit; Step(<NegTokenResp bytes>)
// verifies any embedded AP-REP under mutual auth.
type Initiator struct {
	gss *gssapi.Initiator
}

// NewInitiator prepares a SPNEGO/Kerberos initiator against the given
// SPN. The service ticket is acquired eagerly from the client's TGT
// session.
func NewInitiator(cl *client.Client, spn string, opts ...gssapi.InitiatorOption) (*Initiator, error) {
	g, err := gssapi.NewInitiator(cl, spn, opts...)
	if err != nil {
		return nil, err
	}
	return &Initiator{gss: g}, nil
}

// NewInitiatorFromTicket prepares a SPNEGO/Kerberos initiator using a
// caller-supplied service ticket and session key, skipping the KDC
// exchange.
func NewInitiatorFromTicket(cl *client.Client, tkt messages.Ticket, sessionKey types.EncryptionKey, opts ...gssapi.InitiatorOption) (*Initiator, error) {
	g, err := gssapi.NewInitiatorFromTicket(cl, tkt, sessionKey, opts...)
	if err != nil {
		return nil, err
	}
	return &Initiator{gss: g}, nil
}

// Step advances the SPNEGO handshake. The first call must pass nil and
// returns a marshaled NegTokenInit. The second call passes the
// marshaled NegTokenResp; under mutual auth the embedded AP-REP is
// verified, otherwise the NegState is checked for accept-completed.
// Step returns (nil, nil) when the context is established.
func (i *Initiator) Step(input []byte) ([]byte, error) {
	if input == nil {
		mechBytes, err := i.gss.Step(nil)
		if err != nil {
			return nil, err
		}
		spt := &SPNEGOToken{
			Init: true,
			NegTokenInit: NegTokenInit{
				MechTypes: []asn1.ObjectIdentifier{
					gssapi.OIDKRB5.OID(),
					gssapi.OIDMSLegacyKRB5.OID(),
				},
				MechTokenBytes: mechBytes,
			},
		}
		return spt.Marshal()
	}
	var resp NegTokenResp
	if err := resp.Unmarshal(input); err != nil {
		return nil, fmt.Errorf("unmarshal NegTokenResp: %w", err)
	}
	if resp.NegState != asn1.Enumerated(NegStateAcceptCompleted) {
		return nil, fmt.Errorf("SPNEGO NegState = %v, want accept-completed", resp.NegState)
	}
	// Confirm the acceptor selected one of the Kerberos OIDs we offered.
	// RFC 4178 §4.2.2 makes supportedMech optional on subsequent
	// NegTokenResp messages, so an absent field is accepted.
	if len(resp.SupportedMech) > 0 &&
		!resp.SupportedMech.Equal(gssapi.OIDKRB5.OID()) &&
		!resp.SupportedMech.Equal(gssapi.OIDMSLegacyKRB5.OID()) {
		return nil, fmt.Errorf("SPNEGO acceptor selected mech %s, initiator only supports Kerberos mechs", resp.SupportedMech.String())
	}
	if i.gss.Done() {
		return nil, nil
	}
	if len(resp.ResponseToken) == 0 {
		return nil, errors.New("NegTokenResp carries no AP-REP under mutual auth")
	}
	if _, err := i.gss.Step(resp.ResponseToken); err != nil {
		return nil, err
	}
	return nil, nil
}

// Done reports whether the security context is established.
func (i *Initiator) Done() bool { return i.gss.Done() }

// SecurityContext returns the established per-message context.
func (i *Initiator) SecurityContext() (*gssapi.SecurityContext, error) {
	return i.gss.SecurityContext()
}
