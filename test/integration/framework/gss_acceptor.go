package framework

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/spnego"
)

// GSSAcceptor is a tiny in-process TCP server that performs an SPNEGO/Kerberos
// GSS handshake using kt and the SPN it was provisioned for, then exchanges
// one Wrap message in each direction. On a successful handshake the acceptor
// sends back a Wrap'd reply produced by ReplyFunc.
//
// Wire format on each connection (length is 4-byte big-endian):
//
//  1. [len][AP-REQ SPNEGO NegTokenInit]
//  2. [len][AP-REP SPNEGO NegTokenResp]
//  3. [len][Wrap'd client message]
//  4. [len][Wrap'd reply payload]
//
// Per-connection failures are pushed to Errors() and the connection is
// closed.
type GSSAcceptor struct {
	listener net.Listener
	spnego   *spnego.SPNEGO
	reply    ReplyFunc
	errs     chan error

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// ReplyFunc produces the cleartext payload the acceptor wraps and sends
// back to the initiator after a successful handshake. It receives the
// verified client credentials so authorization-aware servers can branch
// on group membership, principal name, etc.
type ReplyFunc func(creds *credentials.Credentials) []byte

// AuthenticatedReply is the default ReplyFunc payload returned for any
// successful handshake.
const AuthenticatedReply = "authenticated"

// DefaultReply returns AuthenticatedReply for any successful handshake.
func DefaultReply(*credentials.Credentials) []byte {
	return []byte(AuthenticatedReply)
}

// StartGSSAcceptor binds a localhost TCP listener and spawns an accept
// loop that handles each connection by performing the GSS handshake.
// reply produces the per-message payload sent after a successful
// handshake; pass DefaultReply for the standard "authenticated"
// response.
func StartGSSAcceptor(kt *keytab.Keytab, reply ReplyFunc) (*GSSAcceptor, error) {
	if reply == nil {
		reply = DefaultReply
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	a := &GSSAcceptor{
		listener: listener,
		spnego:   spnego.SPNEGOService(kt),
		reply:    reply,
		errs:     make(chan error, 16),
	}
	a.wg.Go(a.serve)
	return a, nil
}

// Addr returns the listener's "host:port".
func (a *GSSAcceptor) Addr() string { return a.listener.Addr().String() }

// Errors returns a channel surfacing per-connection failures from the
// handler goroutines. Drain after the test exchange to detect server-side
// problems that didn't surface on the client side.
func (a *GSSAcceptor) Errors() <-chan error { return a.errs }

// Close stops accepting new connections and waits for in-flight handlers
// to finish.
func (a *GSSAcceptor) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()
	err := a.listener.Close()
	a.wg.Wait()
	return err
}

func (a *GSSAcceptor) serve() {
	for {
		conn, err := a.listener.Accept()
		if err != nil {
			a.mu.Lock()
			closed := a.closed
			a.mu.Unlock()
			if closed {
				return
			}
			a.pushErr(fmt.Errorf("accept: %w", err))
			return
		}
		a.wg.Go(func() { a.handle(conn) })
	}
}

func (a *GSSAcceptor) handle(conn net.Conn) {
	defer conn.Close()

	apreqBytes, err := ReadFramed(conn)
	if err != nil {
		a.pushErr(fmt.Errorf("read AP-REQ: %w", err))
		return
	}

	var spt spnego.SPNEGOToken
	if err := spt.Unmarshal(apreqBytes); err != nil {
		a.pushErr(fmt.Errorf("unmarshal SPNEGO init: %w", err))
		return
	}

	authed, _, status := a.spnego.AcceptSecContext(&spt)
	if !authed || status.Code != gssapi.StatusComplete {
		a.pushErr(fmt.Errorf("AcceptSecContext: code=%v message=%q", status.Code, status.Message))
		return
	}

	sc := spt.SecurityContext()
	if sc == nil {
		a.pushErr(errors.New("SecurityContext nil after successful AcceptSecContext"))
		return
	}

	resp := spnego.NegTokenResp{
		NegState:      asn1.Enumerated(spnego.NegStateAcceptCompleted),
		SupportedMech: gssapi.OIDKRB5.OID(),
		ResponseToken: spt.ResponseToken(),
	}
	respBytes, err := resp.Marshal()
	if err != nil {
		a.pushErr(fmt.Errorf("marshal NegTokenResp: %w", err))
		return
	}
	if err := WriteFramed(conn, respBytes); err != nil {
		a.pushErr(fmt.Errorf("send AP-REP: %w", err))
		return
	}

	clientMsg, err := ReadFramed(conn)
	if err != nil {
		a.pushErr(fmt.Errorf("read client Wrap: %w", err))
		return
	}
	if _, err := sc.Unwrap(clientMsg); err != nil {
		a.pushErr(fmt.Errorf("unwrap client message: %w", err))
		return
	}

	replyPayload := a.reply(spt.Credentials())
	reply, err := sc.Wrap(replyPayload)
	if err != nil {
		a.pushErr(fmt.Errorf("wrap reply: %w", err))
		return
	}
	if err := WriteFramed(conn, reply); err != nil {
		a.pushErr(fmt.Errorf("send Wrap reply: %w", err))
		return
	}
}

func (a *GSSAcceptor) pushErr(err error) {
	select {
	case a.errs <- err:
	default:
	}
}

// ReadFramed reads a 4-byte big-endian length prefix followed by that
// many bytes of payload. Returns the payload.
func ReadFramed(conn io.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	const maxFrame = 16 * 1024 * 1024
	if size > maxFrame {
		return nil, fmt.Errorf("framed message size %d exceeds max %d", size, maxFrame)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// WriteFramed writes a 4-byte big-endian length prefix followed by b.
func WriteFramed(conn io.Writer, b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(b)
	return err
}
