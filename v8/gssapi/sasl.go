package gssapi

import (
	"fmt"
)

// SASL/GSSAPI security layer flags per RFC 4752 §3.1.
// These are used in the first byte of the SASL negotiation payload.
const (
	// SASLSecurityNone indicates no security layer (authentication only).
	// Post-authentication messages are sent in the clear.
	SASLSecurityNone byte = 0x01

	// SASLSecurityIntegrity indicates integrity protection only.
	// Post-authentication messages are wrapped with GSS_Wrap (conf_flag=FALSE).
	SASLSecurityIntegrity byte = 0x02

	// SASLSecurityConfidential indicates confidentiality protection.
	// Post-authentication messages are wrapped with GSS_Wrap (conf_flag=TRUE).
	SASLSecurityConfidential byte = 0x04
)

// saslMaxBufferSize is the RFC 4752 §3.1 upper bound on the max-buffer-size
// field: the field is encoded as three octets in network byte order, so
// values must fit in 24 bits.
const saslMaxBufferSize = 1 << 24

// SASLServerOffer represents the server's security layer offering
// sent during SASL/GSSAPI negotiation (RFC 4752 §3.1).
type SASLServerOffer struct {
	// SupportedLayers is a bitmask of security layers the server supports.
	// Check against SASLSecurityNone, SASLSecurityIntegrity, SASLSecurityConfidential.
	SupportedLayers byte

	// MaxBufferSize is the maximum buffer size the server can receive.
	// This is a 24-bit value (0-16777215).
	MaxBufferSize uint32
}

// SASLClientResponse represents the client's security layer choice
// sent in response to the server's offer (RFC 4752 §3.1).
type SASLClientResponse struct {
	// ChosenLayer is the single security layer the client selects.
	// Must be exactly one of SASLSecurityNone, SASLSecurityIntegrity,
	// or SASLSecurityConfidential.
	ChosenLayer byte

	// MaxBufferSize is the maximum buffer size the client can receive.
	// This is a 24-bit value (0-16777215). When ChosenLayer is
	// SASLSecurityNone this MUST be 0 per RFC 4752 §3.1.
	MaxBufferSize uint32

	// AuthzID is the authorization identity (optional).
	// If empty, the authentication identity is used.
	AuthzID string
}

// ParseSASLServerToken unwraps and validates the server's SASL/GSSAPI
// negotiation token through the established SecurityContext. The token
// is a GSS-API WrapToken whose payload is the 4-byte SASL header
// (security-layer bitmask byte followed by a 3-octet max-buffer-size in
// network byte order).
//
// Sequence-number tracking, replay detection, and subkey selection all
// flow through ctx; the caller gets back the parsed server offer or an
// error.
func ParseSASLServerToken(ctx *SecurityContext, token []byte) (*SASLServerOffer, error) {
	payload, err := ctx.Unwrap(token)
	if err != nil {
		return nil, fmt.Errorf("unwrap SASL server token: %w", err)
	}
	if len(payload) < 4 {
		return nil, fmt.Errorf("SASL payload too short: %d bytes", len(payload))
	}
	return &SASLServerOffer{
		SupportedLayers: payload[0],
		MaxBufferSize:   uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3]),
	}, nil
}

// BuildSASLClientToken constructs the client's SASL/GSSAPI response and
// wraps it through the established SecurityContext. The wrapped token's
// payload is the 4-byte SASL header followed by an optional UTF-8
// authorization identity.
//
// The ChosenLayer and MaxBufferSize fields are validated against
// RFC 4752 §3.1 before wrapping: MaxBufferSize must fit in 24 bits, and
// when ChosenLayer is SASLSecurityNone the buffer size MUST be 0.
func BuildSASLClientToken(ctx *SecurityContext, resp SASLClientResponse) ([]byte, error) {
	if err := validateSASLClientResponse(resp); err != nil {
		return nil, err
	}
	payload := make([]byte, 4+len(resp.AuthzID))
	payload[0] = resp.ChosenLayer
	payload[1] = byte(resp.MaxBufferSize >> 16)
	payload[2] = byte(resp.MaxBufferSize >> 8)
	payload[3] = byte(resp.MaxBufferSize)
	copy(payload[4:], resp.AuthzID)
	return ctx.Wrap(payload)
}

func validateSASLClientResponse(resp SASLClientResponse) error {
	switch resp.ChosenLayer {
	case SASLSecurityNone, SASLSecurityIntegrity, SASLSecurityConfidential:
	default:
		return fmt.Errorf("SASL ChosenLayer %#x is not exactly one of None/Integrity/Confidential", resp.ChosenLayer)
	}
	if resp.MaxBufferSize >= saslMaxBufferSize {
		return fmt.Errorf("SASL MaxBufferSize %d exceeds RFC 4752 3-octet limit", resp.MaxBufferSize)
	}
	// RFC 4752 §3.1: "If the client does not support any security layer,
	// it MUST NOT set any flag in the security layer bit-mask, and it
	// MUST set the buffer size to 0."
	if resp.ChosenLayer == SASLSecurityNone && resp.MaxBufferSize != 0 {
		return fmt.Errorf("SASL layer None requires MaxBufferSize=0 per RFC 4752 3.1")
	}
	return nil
}

// SupportsLayer checks if the server offer includes the specified security layer.
func (o *SASLServerOffer) SupportsLayer(layer byte) bool {
	return (o.SupportedLayers & layer) != 0
}
