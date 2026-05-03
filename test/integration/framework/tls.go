package framework

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/spnego"
)

// SelfSignedTLSCert returns a fresh ECDSA-P256 self-signed certificate
// valid for 127.0.0.1, suitable for tests that wrap a localhost
// listener in TLS.
func SelfSignedTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}
}

// StartTLSGSSAcceptor binds a TLS-wrapped localhost listener and runs
// the GSS handshake with WithExpectedChannelBindings derived from the
// certificate's leaf (RFC 5929 tls-server-end-point).
func StartTLSGSSAcceptor(kt *keytab.Keytab, reply ReplyFunc, cert tls.Certificate) (*GSSAcceptor, error) {
	if cert.Leaf == nil {
		return nil, errors.New("tls.Certificate.Leaf must be populated")
	}
	cb, err := gssapi.NewTLSChannelBindingsFromCert(cert.Leaf)
	if err != nil {
		return nil, fmt.Errorf("build channel bindings: %w", err)
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	listener := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}})
	if reply == nil {
		reply = DefaultReply
	}
	a := &GSSAcceptor{
		listener:   listener,
		acceptor:   spnego.NewAcceptor(kt),
		reply:      reply,
		acceptOpts: []gssapi.AcceptOption{gssapi.WithExpectedChannelBindings(cb)},
		errs:       make(chan error, 16),
	}
	a.wg.Go(a.serve)
	return a, nil
}
