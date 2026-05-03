package spnego

import (
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
)

// https://msdn.microsoft.com/en-us/library/ms995330.aspx

// Negotiation state values.
const (
	NegStateAcceptCompleted  NegState = 0
	NegStateAcceptIncomplete NegState = 1
	NegStateReject           NegState = 2
	NegStateRequestMIC       NegState = 3
)

// NegState is a type to indicate the SPNEGO negotiation state.
type NegState int

// NegTokenInit implements the SPNEGO NegotiationToken of type Init
// (RFC 4178 §4.2.1).
type NegTokenInit struct {
	MechTypes      []asn1.ObjectIdentifier
	ReqFlags       asn1.BitString
	MechTokenBytes []byte
	MechListMIC    []byte
}

type marshalNegTokenInit struct {
	MechTypes      []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags       asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechTokenBytes []byte                  `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC    []byte                  `asn1:"explicit,optional,omitempty,tag:3"`
}

// NegTokenResp implements the SPNEGO NegotiationToken of type Resp
// (RFC 4178 §4.2.2).
type NegTokenResp struct {
	NegState      asn1.Enumerated
	SupportedMech asn1.ObjectIdentifier
	ResponseToken []byte
	MechListMIC   []byte
}

type marshalNegTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"explicit,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,omitempty,tag:3"`
}

// Marshal an Init negotiation token.
func (n *NegTokenInit) Marshal() ([]byte, error) {
	m := marshalNegTokenInit{
		MechTypes:      n.MechTypes,
		ReqFlags:       n.ReqFlags,
		MechTokenBytes: n.MechTokenBytes,
		MechListMIC:    n.MechListMIC,
	}
	b, err := asn1.Marshal(m)
	if err != nil {
		return nil, err
	}
	nt := asn1.RawValue{
		Tag:        0,
		Class:      2,
		IsCompound: true,
		Bytes:      b,
	}
	return asn1.Marshal(nt)
}

// Unmarshal an Init negotiation token.
func (n *NegTokenInit) Unmarshal(b []byte) error {
	init, nt, err := UnmarshalNegToken(b)
	if err != nil {
		return err
	}
	if !init {
		return errors.New("bytes were not that of a NegTokenInit")
	}
	nInit := nt.(NegTokenInit)
	n.MechTokenBytes = nInit.MechTokenBytes
	n.MechListMIC = nInit.MechListMIC
	n.MechTypes = nInit.MechTypes
	n.ReqFlags = nInit.ReqFlags
	return nil
}

// Marshal a Resp/Targ negotiation token.
func (n *NegTokenResp) Marshal() ([]byte, error) {
	m := marshalNegTokenResp{
		NegState:      n.NegState,
		SupportedMech: n.SupportedMech,
		ResponseToken: n.ResponseToken,
		MechListMIC:   n.MechListMIC,
	}
	b, err := asn1.Marshal(m)
	if err != nil {
		return nil, err
	}
	nt := asn1.RawValue{
		Tag:        1,
		Class:      2,
		IsCompound: true,
		Bytes:      b,
	}
	return asn1.Marshal(nt)
}

// Unmarshal a Resp/Targ negotiation token.
func (n *NegTokenResp) Unmarshal(b []byte) error {
	init, nt, err := UnmarshalNegToken(b)
	if err != nil {
		return err
	}
	if init {
		return errors.New("bytes were not that of a NegTokenResp")
	}
	nResp := nt.(NegTokenResp)
	n.MechListMIC = nResp.MechListMIC
	n.NegState = nResp.NegState
	n.ResponseToken = nResp.ResponseToken
	n.SupportedMech = nResp.SupportedMech
	return nil
}

// State returns the negotiation state.
func (n *NegTokenResp) State() NegState {
	return NegState(n.NegState)
}

// UnmarshalNegToken unmarshals SPNEGO bytes as either a NegTokenInit or
// a NegTokenResp. The bool reports whether the result is a NegTokenInit.
func UnmarshalNegToken(b []byte) (bool, any, error) {
	var a asn1.RawValue
	_, err := asn1.Unmarshal(b, &a)
	if err != nil {
		return false, nil, fmt.Errorf("error unmarshalling NegotiationToken: %v", err)
	}
	switch a.Tag {
	case 0:
		var n marshalNegTokenInit
		if _, err := asn1.Unmarshal(a.Bytes, &n); err != nil {
			return false, nil, fmt.Errorf("error unmarshalling NegotiationToken type %d (Init): %v", a.Tag, err)
		}
		return true, NegTokenInit{
			MechTypes:      n.MechTypes,
			ReqFlags:       n.ReqFlags,
			MechTokenBytes: n.MechTokenBytes,
			MechListMIC:    n.MechListMIC,
		}, nil
	case 1:
		var n marshalNegTokenResp
		if _, err := asn1.Unmarshal(a.Bytes, &n); err != nil {
			return false, nil, fmt.Errorf("error unmarshalling NegotiationToken type %d (Resp/Targ): %v", a.Tag, err)
		}
		return false, NegTokenResp{
			NegState:      n.NegState,
			SupportedMech: n.SupportedMech,
			ResponseToken: n.ResponseToken,
			MechListMIC:   n.MechListMIC,
		}, nil
	default:
		return false, nil, errors.New("unknown choice type for NegotiationToken")
	}
}
