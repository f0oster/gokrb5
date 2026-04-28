package framework

import (
	"encoding/asn1"
	"fmt"
	"io"
	"net"

	"github.com/f0oster/gokrb5/gssapi"
)

// Minimal LDAP transport for SASL/GSSAPI tests. The BER encoding
// here covers only the message shapes our tests produce: SASL bind
// and rootDSE search. Not a general-purpose LDAP client.

const (
	ldapResultSuccess          = 0
	ldapResultSaslBindProgress = 14
)

type saslLDAPConn struct {
	conn  net.Conn
	msgID int
}

// saslBind sends one SASL bind round-trip and returns the result code
// plus any server SASL credentials.
func (l *saslLDAPConn) saslBind(mechanism string, credentials []byte) (int, []byte, error) {
	l.msgID++
	req := buildSASLBindRequest(l.msgID, mechanism, credentials)
	if _, err := l.conn.Write(req); err != nil {
		return -1, nil, err
	}
	resp, err := l.readLDAPMessage()
	if err != nil {
		return -1, nil, err
	}
	code, err := extractResultCode(resp)
	if err != nil {
		return -1, nil, err
	}
	creds, err := extractSASLCredentials(resp)
	if err != nil {
		return code, nil, err
	}
	return code, creds, nil
}

// sendRaw writes a length-prefixed payload, used for wrapped LDAP.
func (l *saslLDAPConn) sendRaw(data []byte) error {
	length := uint32(len(data))
	buf := make([]byte, 4+len(data))
	buf[0] = byte(length >> 24)
	buf[1] = byte(length >> 16)
	buf[2] = byte(length >> 8)
	buf[3] = byte(length)
	copy(buf[4:], data)
	_, err := l.conn.Write(buf)
	return err
}

// recvRaw reads a length-prefixed payload.
func (l *saslLDAPConn) recvRaw() ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(l.conn, lenBuf); err != nil {
		return nil, err
	}
	length := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
	const maxLen = 10 * 1024 * 1024
	if length > maxLen || length < 0 {
		return nil, fmt.Errorf("message length %d exceeds maximum %d", length, maxLen)
	}
	data := make([]byte, length)
	if _, err := io.ReadFull(l.conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (l *saslLDAPConn) readLDAPMessage() ([]byte, error) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(l.conn, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[1])
	if hdr[1]&0x80 != 0 {
		numBytes := int(hdr[1] & 0x7f)
		if numBytes > 4 {
			return nil, fmt.Errorf("BER length field too large: %d bytes", numBytes)
		}
		lenBytes := make([]byte, numBytes)
		if _, err := io.ReadFull(l.conn, lenBytes); err != nil {
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
	if _, err := io.ReadFull(l.conn, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// SASLBindGSSAPI runs a SASL/GSSAPI bind on conn and returns the
// established SecurityContext. init must be pre-configured (mutual
// auth, channel bindings, confidentiality). chosenLayer must be one
// of gssapi.SASLSecurityNone/Integrity/Confidential.
func SASLBindGSSAPI(conn net.Conn, init *gssapi.Initiator, chosenLayer byte) (*gssapi.SecurityContext, error) {
	ldap := &saslLDAPConn{conn: conn}

	apReq, err := init.Step(nil)
	if err != nil {
		return nil, fmt.Errorf("initiator first step: %w", err)
	}

	var ctx *gssapi.SecurityContext
	token := apReq

	// RFC 4752 normal flow completes in 3-4 round-trips; cap at 8 so
	// a misbehaving server (or a state-machine bug) surfaces as a
	// clear error instead of a test-timeout hang.
	const maxRounds = 8
	for range maxRounds {
		code, serverCreds, err := ldap.saslBind("GSSAPI", token)
		if err != nil {
			return nil, fmt.Errorf("SASL bind transport: %w", err)
		}
		if code == ldapResultSuccess {
			return ctx, nil
		}
		if code != ldapResultSaslBindProgress {
			return nil, fmt.Errorf("BindResponse resultCode=%d (expected saslBindInProgress=14)", code)
		}

		if len(serverCreds) == 0 {
			token = nil
			continue
		}

		if !init.Done() {
			if _, err := init.Step(serverCreds); err != nil {
				return nil, fmt.Errorf("initiator step (AP-REP): %w", err)
			}
			ctx, err = init.SecurityContext()
			if err != nil {
				return nil, fmt.Errorf("get SecurityContext: %w", err)
			}
			token = nil
			continue
		}

		if ctx == nil {
			return nil, fmt.Errorf("server sent SASL offer before AP-REP")
		}
		offer, err := gssapi.ParseSASLServerToken(ctx, serverCreds)
		if err != nil {
			return nil, fmt.Errorf("parse SASL server offer: %w", err)
		}
		if !offer.SupportsLayer(chosenLayer) {
			return nil, fmt.Errorf("server does not advertise SASL layer 0x%02x (offer=0x%02x)",
				chosenLayer, offer.SupportedLayers)
		}
		var maxBuf uint32
		if chosenLayer != gssapi.SASLSecurityNone {
			maxBuf = 65536
		}
		token, err = gssapi.BuildSASLClientToken(ctx, gssapi.SASLClientResponse{
			ChosenLayer:   chosenLayer,
			MaxBufferSize: maxBuf,
		})
		if err != nil {
			return nil, fmt.Errorf("build SASL client response: %w", err)
		}
	}
	return nil, fmt.Errorf("SASL bind did not complete within %d rounds", maxRounds)
}

// WrappedRootDSESearch sends a wrapped rootDSE search and returns
// the unwrapped first attribute value. Exercises per-message
// protection after an integrity/confidentiality SASL bind.
func WrappedRootDSESearch(conn net.Conn, ctx *gssapi.SecurityContext, attribute string) (string, error) {
	ldap := &saslLDAPConn{conn: conn, msgID: 1}

	searchReq := buildRootDSESearchRequest(ldap.msgID, []string{attribute})
	wrappedReq, err := ctx.Wrap(searchReq)
	if err != nil {
		return "", fmt.Errorf("wrap search: %w", err)
	}
	if err := ldap.sendRaw(wrappedReq); err != nil {
		return "", fmt.Errorf("send wrapped search: %w", err)
	}
	wrappedResp, err := ldap.recvRaw()
	if err != nil {
		return "", fmt.Errorf("recv wrapped response: %w", err)
	}
	unwrapped, err := ctx.Unwrap(wrappedResp)
	if err != nil {
		return "", fmt.Errorf("unwrap response: %w", err)
	}
	return parseSearchResult(unwrapped), nil
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

func buildRootDSESearchRequest(msgID int, attrs []string) []byte {
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

// parseSearchResult extracts the first attribute value from a
// SearchResultEntry, or a "(...)" placeholder if the shape is
// unexpected.
func parseSearchResult(msg []byte) string {
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

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func concat(s ...[]byte) []byte {
	var r []byte
	for _, x := range s {
		r = append(r, x...)
	}
	return r
}
