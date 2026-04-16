// Minimal LDAP transport for the SASL examples. The BER encoding and
// parsing here handles only the exact message shapes these examples
// produce and receive (SASL bind, rootDSE search). It is not a
// supposed to serve as a good example of an LDAP client,
// it is intended to show how to implement message wrapping.
package main

import (
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/jcmturner/gokrb5/v8/gssapi"
)

type LDAPConn struct {
	Conn  net.Conn
	MsgID int
}

const (
	LDAPResultSuccess          = 0
	LDAPResultSaslBindProgress = 14
)

func (l *LDAPConn) SASLBind(mechanism string, credentials []byte) (int, []byte, error) {
	req := buildSASLBindRequest(l.MsgID, mechanism, credentials)
	l.MsgID++
	if _, err := l.Conn.Write(req); err != nil {
		return -1, nil, err
	}
	resp, err := l.readLDAPMessage()
	if err != nil {
		return -1, nil, err
	}
	resultCode, err := extractResultCode(resp)
	if err != nil {
		return -1, nil, err
	}
	creds, err := extractSASLCredentials(resp)
	if err != nil {
		return resultCode, nil, err
	}
	return resultCode, creds, nil
}

func (l *LDAPConn) SendRaw(data []byte) error {
	length := uint32(len(data))
	buf := make([]byte, 4+len(data))
	buf[0] = byte(length >> 24)
	buf[1] = byte(length >> 16)
	buf[2] = byte(length >> 8)
	buf[3] = byte(length)
	copy(buf[4:], data)
	_, err := l.Conn.Write(buf)
	return err
}

func (l *LDAPConn) RecvRaw() ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(l.Conn, lenBuf); err != nil {
		return nil, err
	}
	length := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
	const maxLen = 10 * 1024 * 1024
	if length > maxLen || length < 0 {
		return nil, fmt.Errorf("message length %d exceeds maximum %d", length, maxLen)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(l.Conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (l *LDAPConn) readLDAPMessage() ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(l.Conn, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[1])
	if hdr[1]&0x80 != 0 {
		numBytes := int(hdr[1] & 0x7f)
		if numBytes > 4 {
			return nil, fmt.Errorf("BER length field too large: %d bytes", numBytes)
		}
		lenBytes := make([]byte, numBytes)
		if _, err := io.ReadFull(l.Conn, lenBytes); err != nil {
			return nil, err
		}
		length = 0
		for _, b := range lenBytes {
			length = length<<8 | int(b)
		}
		hdr = append(hdr, lenBytes...)
	}
	const maxLen = 10 * 1024 * 1024
	if length > maxLen || length < 0 {
		return nil, fmt.Errorf("message length %d exceeds maximum %d", length, maxLen)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(l.Conn, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// SendLDAP sends a raw BER-encoded LDAP message (no SASL framing).
func (l *LDAPConn) SendLDAP(msg []byte) error {
	_, err := l.Conn.Write(msg)
	return err
}

// RecvLDAP reads a single BER-encoded LDAP message (no SASL framing).
func (l *LDAPConn) RecvLDAP() ([]byte, error) {
	return l.readLDAPMessage()
}

func buildSASLBindRequest(msgID int, mechanism string, credentials []byte) []byte {
	saslContents := marshalOctetString(mechanism)
	if len(credentials) > 0 {
		saslContents = append(saslContents, marshalOctetStringBytes(credentials)...)
	}
	saslChoice := encodeContextTag(3, true, saslContents)
	bindReqBytes := concat(marshalInteger(3), marshalOctetString(""), saslChoice)
	bindReq := encodeAppTag(0, bindReqBytes)
	msgBytes := concat(marshalInteger(msgID), bindReq)
	return encodeSequence(msgBytes)
}

func BuildRootDSESearchRequest(msgID int, attrs []string) []byte {
	filterBytes := asn1.RawValue{Class: 2, Tag: 7, Bytes: []byte("objectClass")}
	var attrsBytes []byte
	for _, a := range attrs {
		attrsBytes = append(attrsBytes, marshalOctetString(a)...)
	}
	attrsSeq := asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: attrsBytes}
	searchReq := asn1.RawValue{
		Class: 1, Tag: 3, IsCompound: true,
		Bytes: concat(
			marshalOctetString(""), marshalEnum(0), marshalEnum(0),
			marshalInteger(0), marshalInteger(0), marshalBoolean(false),
			mustMarshal(filterBytes), mustMarshal(attrsSeq),
		),
	}
	msg := asn1.RawValue{
		Class: 0, Tag: 16, IsCompound: true,
		Bytes: append(marshalInteger(msgID), mustMarshal(searchReq)...),
	}
	return mustMarshal(msg)
}

func extractSASLCredentials(msg []byte) ([]byte, error) {
	offset := 0
	if len(msg) < 2 {
		return nil, fmt.Errorf("message too short")
	}
	_, lenSize := berLength(msg[1:])
	offset = 1 + lenSize
	if offset >= len(msg) {
		return nil, fmt.Errorf("missing messageID")
	}
	_, elemLen, lenSize := berElement(msg[offset:])
	offset += 1 + lenSize + elemLen
	if offset >= len(msg) || (msg[offset]&0x1f) != 1 {
		return nil, fmt.Errorf("expected BindResponse")
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen
	if offset >= len(msg) {
		return nil, nil
	}
	tag := msg[offset]
	if (tag & 0x1f) == 7 {
		contentLen, lenSize := berLength(msg[offset+1:])
		start := offset + 1 + lenSize
		return msg[start : start+contentLen], nil
	}
	return nil, nil
}

func extractResultCode(msg []byte) (int, error) {
	offset := 0
	if len(msg) < 2 {
		return -1, fmt.Errorf("message too short")
	}
	_, lenSize := berLength(msg[1:])
	offset = 1 + lenSize
	_, elemLen, lenSize := berElement(msg[offset:])
	offset += 1 + lenSize + elemLen
	if offset >= len(msg) || (msg[offset]&0x1f) != 1 {
		return -1, fmt.Errorf("expected BindResponse")
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize
	if offset >= len(msg) || msg[offset] != 0x0a {
		return -1, fmt.Errorf("expected resultCode")
	}
	contentLen, lenSize := berLength(msg[offset+1:])
	start := offset + 1 + lenSize
	code := 0
	for i := range contentLen {
		code = code<<8 | int(msg[start+i])
	}
	return code, nil
}

func ParseSearchResult(msg []byte) string {
	offset := 0
	if len(msg) < 2 {
		return "(too short)"
	}
	_, lenSize := berLength(msg[1:])
	offset = 1 + lenSize
	_, elemLen, lenSize := berElement(msg[offset:])
	offset += 1 + lenSize + elemLen
	if offset >= len(msg) {
		return "(no entry)"
	}
	tag := msg[offset]
	if (tag & 0x1f) != 4 {
		return fmt.Sprintf("(unexpected tag 0x%02x)", tag)
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen
	if offset >= len(msg) || msg[offset] != 0x30 {
		return "(no attributes)"
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize
	if offset >= len(msg) || msg[offset] != 0x30 {
		return "(no attribute)"
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen
	if offset >= len(msg) || msg[offset] != 0x31 {
		return "(no values)"
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize
	if offset >= len(msg) || msg[offset] != 0x04 {
		return "(no value)"
	}
	contentLen, lenSize := berLength(msg[offset+1:])
	start := offset + 1 + lenSize
	if start+contentLen > len(msg) {
		return "(truncated)"
	}
	return string(msg[start : start+contentLen])
}

func berLength(data []byte) (int, int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 128 {
		return int(data[0]), 1
	}
	n := int(data[0] & 0x7f)
	if len(data) < 1+n {
		return 0, 0
	}
	length := 0
	for i := range n {
		length = length<<8 | int(data[1+i])
	}
	return length, 1 + n
}

func berElement(data []byte) (byte, int, int) {
	if len(data) < 2 {
		return 0, 0, 0
	}
	cl, ls := berLength(data[1:])
	return data[0], cl, ls
}

func encodeSequence(c []byte) []byte      { return encodeTLV(0x30, c) }
func encodeAppTag(t int, c []byte) []byte { return encodeTLV(byte(0x60|t), c) }
func encodeContextTag(t int, constructed bool, c []byte) []byte {
	tb := byte(0x80 | t)
	if constructed {
		tb |= 0x20
	}
	return encodeTLV(tb, c)
}
func encodeTLV(tag byte, content []byte) []byte {
	lb := encodeLength(len(content))
	r := make([]byte, 1+len(lb)+len(content))
	r[0] = tag
	copy(r[1:], lb)
	copy(r[1+len(lb):], content)
	return r
}
func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	var lb []byte
	for length > 0 {
		lb = append([]byte{byte(length & 0xff)}, lb...)
		length >>= 8
	}
	return append([]byte{byte(0x80 | len(lb))}, lb...)
}

func marshalInteger(v int) []byte { b, _ := asn1.Marshal(v); return b }
func marshalEnum(v int) []byte    { return []byte{0x0a, 0x01, byte(v)} }
func marshalBoolean(v bool) []byte {
	if v {
		return []byte{0x01, 0x01, 0xff}
	}
	return []byte{0x01, 0x01, 0x00}
}
func marshalOctetString(s string) []byte { return marshalOctetStringBytes([]byte(s)) }
func marshalOctetStringBytes(b []byte) []byte {
	if len(b) < 128 {
		return append([]byte{0x04, byte(len(b))}, b...)
	}
	lb := encodeLength(len(b))
	return append(append([]byte{0x04}, lb...), b...)
}
func mustMarshal(v any) []byte { b, _ := asn1.Marshal(v); return b }
func concat(s ...[]byte) []byte {
	var r []byte
	for _, x := range s {
		r = append(r, x...)
	}
	return r
}

func DescribeWrapHeader(tok []byte) string {
	if len(tok) < 16 {
		return "(short token)"
	}
	f := tok[2]
	ec := binary.BigEndian.Uint16(tok[4:6])
	rrc := binary.BigEndian.Uint16(tok[6:8])
	seq := binary.BigEndian.Uint64(tok[8:16])
	var names []string
	if f&gssapi.SentByAcceptorFlag != 0 {
		names = append(names, "SentByAcceptor")
	}
	if f&gssapi.SealedFlag != 0 {
		names = append(names, "Sealed")
	}
	if f&gssapi.AcceptorSubkeyFlag != 0 {
		names = append(names, "AcceptorSubkey")
	}
	flagDesc := "none"
	if len(names) > 0 {
		flagDesc = strings.Join(names, "|")
	}
	return fmt.Sprintf("flags=0x%02x (%s)  EC=%d  RRC=%d  SND_SEQ=%d", f, flagDesc, ec, rrc, seq)
}

func ReadWrapSndSeq(tok []byte) uint64 {
	if len(tok) < 16 {
		return 0
	}
	return binary.BigEndian.Uint64(tok[8:16])
}

func Header(s string) string {
	return fmt.Sprintf("=== %s ===", s)
}
