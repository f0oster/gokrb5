package gssapi

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// TLSServerEndPointPrefix is the channel binding prefix per RFC 5929 §4.1.
const TLSServerEndPointPrefix = "tls-server-end-point:"

// MakeTLSChannelBindingData builds the tls-server-end-point channel binding
// data per RFC 5929 §4.1: the prefix followed by a hash of the server
// certificate. SHA-384 and SHA-512 keep their native hash, MD5 and
// SHA-1 are upgraded to SHA-256 per §4.1, and SHA-256 is used as-is.
// Algorithms that §4.1 leaves undefined (Ed25519, MD2, anything outside
// the named family) return an error.
func MakeTLSChannelBindingData(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate cannot be nil")
	}

	var hash []byte

	switch cert.SignatureAlgorithm {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		h := sha512.Sum384(cert.Raw)
		hash = h[:]
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		h := sha512.Sum512(cert.Raw)
		hash = h[:]
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS,
		x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		h := sha256.Sum256(cert.Raw)
		hash = h[:]
	case x509.PureEd25519:
		return nil, fmt.Errorf("tls-server-end-point undefined for Ed25519 per RFC 5929 §4.1")
	case x509.UnknownSignatureAlgorithm:
		return nil, fmt.Errorf("tls-server-end-point: certificate signature algorithm is unknown to crypto/x509")
	default:
		return nil, fmt.Errorf("tls-server-end-point undefined for signature algorithm %v per RFC 5929 §4.1", cert.SignatureAlgorithm)
	}

	// Construct: prefix + hash
	result := make([]byte, len(TLSServerEndPointPrefix)+len(hash))
	copy(result, TLSServerEndPointPrefix)
	copy(result[len(TLSServerEndPointPrefix):], hash)

	return result, nil
}

// NewTLSChannelBindingsFromState returns tls-server-end-point
// ChannelBindings derived from the peer leaf certificate in state. Only
// ApplicationData is populated; address fields are unspecified per
// standard TLS channel binding practice.
func NewTLSChannelBindingsFromState(state *tls.ConnectionState) (*ChannelBindings, error) {
	if state == nil {
		return nil, fmt.Errorf("TLS connection state cannot be nil")
	}

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates in TLS connection state")
	}

	// Use the leaf certificate (first in the chain)
	leafCert := state.PeerCertificates[0]

	appData, err := MakeTLSChannelBindingData(leafCert)
	if err != nil {
		return nil, fmt.Errorf("failed to create channel binding data: %w", err)
	}

	return &ChannelBindings{
		InitiatorAddrType: AddressTypeUnspecified,
		AcceptorAddrType:  AddressTypeUnspecified,
		ApplicationData:   appData,
	}, nil
}

// NewTLSChannelBindingsFromCert returns tls-server-end-point
// ChannelBindings derived directly from a certificate.
func NewTLSChannelBindingsFromCert(cert *x509.Certificate) (*ChannelBindings, error) {
	appData, err := MakeTLSChannelBindingData(cert)
	if err != nil {
		return nil, err
	}

	return &ChannelBindings{
		InitiatorAddrType: AddressTypeUnspecified,
		AcceptorAddrType:  AddressTypeUnspecified,
		ApplicationData:   appData,
	}, nil
}
