package gssapi

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/f0oster/gokrb5/credentials"
)

// FrameCodec reads and writes length-delimited frames on a stream.
type FrameCodec interface {
	ReadFrame(io.Reader) ([]byte, error)
	WriteFrame(io.Writer, []byte) error
}

// LengthPrefix4 is a FrameCodec using a 4-byte big-endian length
// prefix and a 16 MiB cap on frame size.
var LengthPrefix4 FrameCodec = lengthPrefix4{}

type lengthPrefix4 struct{}

func (lengthPrefix4) ReadFrame(r io.Reader) ([]byte, error) {
	var size uint32
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	const maxFrame = 16 * 1024 * 1024
	if size > maxFrame {
		return nil, fmt.Errorf("framed message size %d exceeds max %d", size, maxFrame)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (lengthPrefix4) WriteFrame(w io.Writer, b []byte) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// Session is an authenticated framed conversation produced by AcceptOn.
type Session struct {
	Context     *SecurityContext
	Credentials *credentials.Credentials

	rw    io.ReadWriter
	codec FrameCodec
}

// NewSession wraps an established SecurityContext and credentials with
// a stream and codec for ReadMsg/WriteMsg use. Acceptors that drive
// the handshake themselves (for example, spnego.Acceptor) call this
// after producing the context.
func NewSession(rw io.ReadWriter, codec FrameCodec, ctx *SecurityContext, creds *credentials.Credentials) *Session {
	return &Session{
		Context:     ctx,
		Credentials: creds,
		rw:          rw,
		codec:       codec,
	}
}

// ReadMsg reads one framed token from the underlying stream and
// unwraps it through the SecurityContext.
func (s *Session) ReadMsg() ([]byte, error) {
	frame, err := s.codec.ReadFrame(s.rw)
	if err != nil {
		return nil, err
	}
	return s.Context.Unwrap(frame)
}

// WriteMsg wraps msg through the SecurityContext and writes it framed.
func (s *Session) WriteMsg(msg []byte) error {
	wrapped, err := s.Context.Wrap(msg)
	if err != nil {
		return err
	}
	return s.codec.WriteFrame(s.rw, wrapped)
}

// AcceptOn drives the GSS handshake on rw. It reads one framed AP-REQ
// token, calls Accept, writes the AP-REP frame back when mutual auth
// was requested, and returns a Session ready for ReadMsg/WriteMsg.
//
// AcceptOn does not write a response frame when mutual auth was not
// requested: the initiator is not reading one and a stray empty frame
// would desync the stream. SPNEGO callers want spnego.Acceptor.AcceptOn,
// which always writes a NegTokenResp(accept-completed).
//
// Deadlines are the caller's responsibility; set them on rw if needed.
func (a *Acceptor) AcceptOn(rw io.ReadWriter, codec FrameCodec, opts ...AcceptOption) (*Session, error) {
	apReqFrame, err := codec.ReadFrame(rw)
	if err != nil {
		return nil, fmt.Errorf("read AP-REQ frame: %w", err)
	}
	acceptance, err := a.Accept(apReqFrame, opts...)
	if err != nil {
		return nil, err
	}
	if acceptance.ResponseToken != nil {
		if err := codec.WriteFrame(rw, acceptance.ResponseToken); err != nil {
			return nil, fmt.Errorf("write AP-REP frame: %w", err)
		}
	}
	return NewSession(rw, codec, acceptance.Context, acceptance.Credentials), nil
}
