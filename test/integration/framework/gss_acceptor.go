package framework

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/spnego"
)

// GSSAcceptor is an in-process TCP server that performs a
// SPNEGO/Kerberos GSS handshake on each connection and then exchanges
// one Wrap message in each direction, with the reply payload produced
// by ReplyFunc. Wire framing is gssapi.LengthPrefix4. Per-connection
// failures are pushed to Errors() and the connection is closed.
type GSSAcceptor struct {
	listener net.Listener
	acceptor *spnego.Acceptor
	reply    ReplyFunc
	errs     chan error

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// ReplyFunc returns the cleartext payload the acceptor wraps and sends
// back to the initiator. The verified client credentials let
// authorization-aware servers vary the reply by principal or group.
type ReplyFunc func(creds *credentials.Credentials) []byte

// AuthenticatedReply is the default ReplyFunc payload returned for any
// successful handshake.
const AuthenticatedReply = "authenticated"

// DefaultReply returns AuthenticatedReply for any successful handshake.
func DefaultReply(*credentials.Credentials) []byte {
	return []byte(AuthenticatedReply)
}

// StartGSSAcceptor binds a localhost TCP listener and spawns an accept
// loop. reply produces the per-message payload sent after a successful
// handshake; passing nil uses DefaultReply.
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
		acceptor: spnego.NewAcceptor(kt),
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
	sess, err := a.acceptor.AcceptOn(conn, gssapi.LengthPrefix4)
	if err != nil {
		a.pushErr(fmt.Errorf("accept: %w", err))
		return
	}
	if _, err := sess.ReadMsg(); err != nil {
		a.pushErr(fmt.Errorf("read client wrap: %w", err))
		return
	}
	if err := sess.WriteMsg(a.reply(sess.Credentials)); err != nil {
		a.pushErr(fmt.Errorf("write reply: %w", err))
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
