// Package spnego implements the Simple and Protected GSSAPI Negotiation Mechanism for Kerberos authentication.
package spnego

import (
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/asn1tools"
	"github.com/f0oster/gokrb5/gssapi"
)

// SPNEGOToken carries an RFC 4178 NegotiationToken on the wire. After
// Unmarshal, Init is true and NegTokenInit is populated for an inbound
// initiator request; Resp is true and NegTokenResp is populated for an
// inbound acceptor response.
type SPNEGOToken struct {
	Init         bool
	Resp         bool
	NegTokenInit NegTokenInit
	NegTokenResp NegTokenResp
}

// Marshal an SPNEGO context token.
func (s *SPNEGOToken) Marshal() ([]byte, error) {
	if s.Init {
		hb, _ := asn1.Marshal(gssapi.OIDSPNEGO.OID())
		tb, err := s.NegTokenInit.Marshal()
		if err != nil {
			return nil, fmt.Errorf("could not marshal NegTokenInit: %v", err)
		}
		return asn1tools.AddASNAppTag(append(hb, tb...), 0), nil
	}
	if s.Resp {
		b, err := s.NegTokenResp.Marshal()
		if err != nil {
			return nil, fmt.Errorf("could not marshal NegTokenResp: %v", err)
		}
		return b, nil
	}
	return nil, errors.New("SPNEGOToken contains neither a NegTokenInit nor a NegTokenResp")
}

// Unmarshal an SPNEGO context token.
func (s *SPNEGOToken) Unmarshal(b []byte) error {
	if len(b) < 1 {
		return fmt.Errorf("provided byte array is empty")
	}
	var r []byte
	if b[0] != byte(161) {
		// Not a NegTokenResp; expect the OID-tagged Init form.
		var oid asn1.ObjectIdentifier
		var err error
		r, err = asn1.UnmarshalWithParams(b, &oid, fmt.Sprintf("application,explicit,tag:%v", 0))
		if err != nil {
			return fmt.Errorf("not a valid SPNEGO token: %v", err)
		}
		if !oid.Equal(gssapi.OIDSPNEGO.OID()) {
			return fmt.Errorf("OID %s does not match SPNEGO OID %s", oid.String(), gssapi.OIDSPNEGO.OID().String())
		}
	} else {
		r = b
	}

	_, nt, err := UnmarshalNegToken(r)
	if err != nil {
		return err
	}
	switch v := nt.(type) {
	case NegTokenInit:
		s.Init = true
		s.NegTokenInit = v
	case NegTokenResp:
		s.Resp = true
		s.NegTokenResp = v
	default:
		return errors.New("unknown choice type for NegotiationToken")
	}
	return nil
}
