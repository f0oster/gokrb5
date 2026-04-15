//go:build ignore

/*
sasl_negotiation.go: example of a SASL/GSSAPI LDAP bind against
Active Directory with a post-bind Integrity or Confidentiality
layer. Select the layer with -layer.

Usage:

	go run sasl_negotiation.go -server dc.example.com -realm EXAMPLE.COM \
	    -user testuser -password secret -layer integrity
	go run sasl_negotiation.go -server dc.example.com -realm EXAMPLE.COM \
	    -user testuser -password secret -layer confidentiality
*/
package main

import (
	"encoding/asn1"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

func main() {
	server := flag.String("server", "", "LDAP server FQDN (required)")
	realm := flag.String("realm", "", "Kerberos realm (required)")
	user := flag.String("user", "", "Username without realm (required)")
	password := flag.String("password", "", "Password (required)")
	layer := flag.String("layer", "integrity", "SASL security layer to negotiate: integrity or confidentiality")
	timeout := flag.Duration("timeout", 30*time.Second, "TCP dial timeout")
	flag.Parse()

	if *server == "" || *realm == "" || *user == "" || *password == "" {
		flag.Usage()
		log.Fatal("Missing required flags")
	}

	var chosenLayer byte
	var chosenLayerName string
	switch strings.ToLower(*layer) {
	case "integrity", "integ", "i":
		chosenLayer = gssapi.SASLSecurityIntegrity
		chosenLayerName = "integrity"
	case "confidentiality", "conf", "c":
		chosenLayer = gssapi.SASLSecurityConfidential
		chosenLayerName = "confidentiality"
	default:
		log.Fatalf("ERROR: -layer must be integrity or confidentiality, got %q", *layer)
	}

	// =========================================================================
	// Kerberos (RFC 4120)
	//
	// NewWithPassword + Login drives AS-REQ/AS-REP. GetServiceTicket then
	// drives TGS-REQ/TGS-REP for ldap/<server>. The returned tkt and
	// sessionKey are what we'll feed into the AP-REQ during the SASL bind.
	// =========================================================================
	fmt.Println("\n" + header("Kerberos (RFC 4120)"))

	krb5Conf, err := config.NewFromString(fmt.Sprintf(`
[libdefaults]
  default_realm = %s
  udp_preference_limit = 1
[realms]
  %s = {
    kdc = %s
  }
`, *realm, *realm, *server))
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}

	krb5Client := client.NewWithPassword(*user, *realm, *password, krb5Conf)
	if err := krb5Client.Login(); err != nil {
		log.Fatalf("ERROR: AS-REQ failed: %v", err)
	}
	defer krb5Client.Destroy()
	fmt.Printf("[+] AS-REP: TGT for %s@%s\n", *user, *realm)

	spn := "ldap/" + *server
	tkt, sessionKey, err := krb5Client.GetServiceTicket(spn)
	if err != nil {
		log.Fatalf("ERROR: TGS-REQ failed: %v", err)
	}
	fmt.Printf("[+] TGS-REP: ticket for %s (etype %d)\n", spn, sessionKey.KeyType)

	// =========================================================================
	// SASL/GSSAPI bind (RFC 4752, RFC 4121)
	//
	// Run the SASL bind and negotiate the requested security layer.
	// =========================================================================
	fmt.Println("\n" + header("SASL/GSSAPI bind (RFC 4752, RFC 4121)"))

	conn, err := net.DialTimeout("tcp", *server+":389", *timeout)
	if err != nil {
		log.Fatalf("ERROR: dial: %v", err)
	}
	defer conn.Close()
	fmt.Printf("[+] TCP %s:389\n", *server)

	ldap := &LDAPConn{conn: conn, msgID: 1}

	// Build the initial AP-REQ. Request Integ, Conf, and Mutual so AD
	// offers all three SASL layers; the -layer flag picks which one
	// this run selects.
	apReqToken, err := spnego.NewKRB5TokenAPREQWithBindings(
		krb5Client, tkt, sessionKey,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual},
		[]int{flags.APOptionMutualRequired},
		nil, nil,
	)
	if err != nil {
		log.Fatalf("ERROR: build AP-REQ: %v", err)
	}
	sentAuth := apReqToken.Authenticator
	token, _ := apReqToken.Marshal()

	// ctx is nil until the AP-REP comes back and we verify mutual auth.
	// After that, every per-message Wrap/Unwrap flows through it.
	var ctx *gssapi.SecurityContext

	firstStep := true
	for {
		label := "GSS token"
		switch {
		case firstStep:
			label = "GSSAPI initial context token"
		case token == nil:
			label = "empty GSS token (security-layer negotiation)"
		case ctx != nil:
			label = "wrapped client response"
		}
		fmt.Printf("[>] BindRequest: %s (%d bytes)\n", label, len(token))
		firstStep = false

		resultCode, serverCreds, err := ldap.SASLBind("GSSAPI", token)
		if err != nil {
			log.Fatalf("ERROR: SASL bind transport: %v", err)
		}

		if resultCode == ldapResultSuccess {
			fmt.Println("[<] success: bind complete")
			break
		}
		if resultCode != ldapResultSaslBindProgress {
			log.Fatalf("ERROR: BindResponse resultCode=%d (expected saslBindInProgress=14)", resultCode)
		}

		// Empty server creds: send another empty token to keep the bind
		// progressing.
		if len(serverCreds) == 0 {
			fmt.Println("[<] saslBindInProgress: no server token")
			token = nil
			continue
		}

		var krb5Token spnego.KRB5Token
		if err := krb5Token.Unmarshal(serverCreds); err == nil && krb5Token.IsAPRep() {
			// AP-REP: verify mutual auth and build SecurityContext.
			fmt.Printf("[<] saslBindInProgress: AP-REP (%d bytes)\n", len(serverCreds))
			krb5Token.SetAPRepVerification(sentAuth, sessionKey)
			ok, status := krb5Token.Verify()
			if !ok {
				log.Fatalf("ERROR: AP-REP verify: %s", status.Message)
			}
			fmt.Println("    mutual auth verified (RFC 4120 §3.2.4)")

			// Seed the SecurityContext from the AP-REP subkey and
			// sequence number (both optional; see NewInitiatorContext).
			var apRepSubkey types.EncryptionKey
			var apRepSeq uint64
			if krb5Token.EncAPRepPart != nil {
				if krb5Token.EncAPRepPart.Subkey.KeyValue != nil {
					apRepSubkey = krb5Token.EncAPRepPart.Subkey
					fmt.Printf("    AP-REP subkey: etype %d, %d bytes  [acceptor subkey in use]\n",
						apRepSubkey.KeyType, len(apRepSubkey.KeyValue))
				}
				apRepSeq = uint64(krb5Token.EncAPRepPart.SequenceNumber)
			}
			ctx = gssapi.NewInitiatorContext(
				sessionKey,
				sentAuth.SubKey,
				apRepSubkey,
				uint64(sentAuth.SeqNumber),
				apRepSeq,
			)
			token = nil
			continue
		}

		// SASL offer: server has wrapped its layer/buffer offer.
		if ctx == nil {
			log.Fatalf("ERROR: server sent a SASL offer before the AP-REP")
		}
		fmt.Printf("[<] saslBindInProgress: wrapped server offer (%d bytes)\n", len(serverCreds))
		offer, err := gssapi.ParseSASLServerToken(ctx, serverCreds)
		if err != nil {
			log.Fatalf("ERROR: parse SASL server offer: %v", err)
		}
		fmt.Printf("    server offers: %s, max-buffer %d\n",
			describeSASLLayers(offer.SupportedLayers), offer.MaxBufferSize)

		if !offer.SupportsLayer(chosenLayer) {
			log.Fatalf("ERROR: server does not advertise SASL %s (offer=0x%02x)",
				chosenLayerName, offer.SupportedLayers)
		}
		token, err = gssapi.BuildSASLClientToken(ctx, gssapi.SASLClientResponse{
			ChosenLayer:   chosenLayer,
			MaxBufferSize: 65536,
		})
		if err != nil {
			log.Fatalf("ERROR: build SASL client response: %v", err)
		}
		fmt.Printf("    client selects: %s, max-buffer 65536\n", chosenLayerName)
	}

	// The SASL negotiation response token itself is always integrity-only
	// per RFC 4752 §3.1, so ctx.Confidential is flipped only after the
	// bind loop exits.
	if chosenLayer == gssapi.SASLSecurityConfidential {
		ctx.Confidential = true
	}

	// =========================================================================
	// Per-message protection (RFC 4121 §4.2)
	//
	// Run a rootDSE search through the negotiated layer. Each direction's
	// WrapToken header is decoded inline so the flags/EC/RRC/SND_SEQ are
	// visible in the output.
	// =========================================================================
	fmt.Println("\n" + header("Per-message protection (RFC 4121 §4.2)"))

	if ctx == nil {
		log.Fatal("ERROR: SASL bind finished without establishing a SecurityContext (bug)")
	}

	searchReq := buildRootDSESearchRequest(ldap.msgID, []string{"defaultNamingContext"})
	fmt.Println("[>] SearchRequest rootDSE defaultNamingContext")

	preWrapSend := ctx.SendSeq()
	wrappedReq, err := ctx.Wrap(searchReq)
	if err != nil {
		log.Fatalf("ERROR: ctx.Wrap: %v", err)
	}
	fmt.Printf("    plaintext %d B -> wrapped %d B   sendSeq %d -> %d\n",
		len(searchReq), len(wrappedReq), preWrapSend, ctx.SendSeq())
	fmt.Printf("    %s\n", describeWrapHeader(wrappedReq))

	if err := ldap.SendRaw(wrappedReq); err != nil {
		log.Fatalf("ERROR: send: %v", err)
	}

	wrappedResp, err := ldap.RecvRaw()
	if err != nil {
		log.Fatalf("ERROR: recv: %v", err)
	}

	unwrapped, err := ctx.Unwrap(wrappedResp)
	if err != nil {
		log.Fatalf("ERROR: ctx.Unwrap: %v", err)
	}
	recvSeq := readWrapSndSeq(wrappedResp)
	status := ctx.LastRecvStatus()
	fmt.Printf("[<] wrapped %d B -> plaintext %d B   recvSeq=%d  status=%v\n",
		len(wrappedResp), len(unwrapped), recvSeq, status)
	if status == gssapi.SeqStatusDuplicate || status == gssapi.SeqStatusOld {
		fmt.Println("    (AD emits every server wrap with SND_SEQ=0; StrictSequence=false accepts)")
	}

	result := parseSearchResult(unwrapped)
	fmt.Printf("[+] defaultNamingContext = %s\n", result)
}

// describeSASLLayers renders an RFC 4752 §3.1 security-layer bitmask
// into a human-readable "none|integrity|confidentiality" string.
func describeSASLLayers(mask byte) string {
	var parts []string
	if mask&gssapi.SASLSecurityNone != 0 {
		parts = append(parts, "none")
	}
	if mask&gssapi.SASLSecurityIntegrity != 0 {
		parts = append(parts, "integrity")
	}
	if mask&gssapi.SASLSecurityConfidential != 0 {
		parts = append(parts, "confidentiality")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%02x", mask)
	}
	return strings.Join(parts, "|")
}

// describeWrapHeader decodes the 16-byte RFC 4121 §4.2.2 WrapToken
// header at the start of tok into a one-line summary: flags (with
// named bits), EC, RRC, and SND_SEQ.
func describeWrapHeader(tok []byte) string {
	if len(tok) < 16 {
		return "(short token)"
	}
	flags := tok[2]
	ec := binary.BigEndian.Uint16(tok[4:6])
	rrc := binary.BigEndian.Uint16(tok[6:8])
	seq := binary.BigEndian.Uint64(tok[8:16])
	var names []string
	if flags&gssapi.SentByAcceptorFlag != 0 {
		names = append(names, "SentByAcceptor")
	}
	if flags&gssapi.SealedFlag != 0 {
		names = append(names, "Sealed")
	}
	if flags&gssapi.AcceptorSubkeyFlag != 0 {
		names = append(names, "AcceptorSubkey")
	}
	flagDesc := "none"
	if len(names) > 0 {
		flagDesc = strings.Join(names, "|")
	}
	return fmt.Sprintf("flags=0x%02x (%s)  EC=%d  RRC=%d  SND_SEQ=%d",
		flags, flagDesc, ec, rrc, seq)
}

// readWrapSndSeq returns the SND_SEQ field from a WrapToken header,
// or 0 if the token is too short. Used to report the server's chosen
// sequence number after Unwrap.
func readWrapSndSeq(tok []byte) uint64 {
	if len(tok) < 16 {
		return 0
	}
	return binary.BigEndian.Uint64(tok[8:16])
}

// =============================================================================
// LDAP wire framing
// =============================================================================

// LDAPConn is a minimal LDAP connection handler.
type LDAPConn struct {
	conn  net.Conn
	msgID int
}

// LDAP result codes
const (
	ldapResultSuccess          = 0
	ldapResultSaslBindProgress = 14
)

// SASLBind sends a SASL bind request and returns (resultCode, serverCredentials, error).
func (l *LDAPConn) SASLBind(mechanism string, credentials []byte) (int, []byte, error) {
	req := buildSASLBindRequest(l.msgID, mechanism, credentials)
	l.msgID++

	if _, err := l.conn.Write(req); err != nil {
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

// SendRaw sends raw bytes (for wrapped messages).
func (l *LDAPConn) SendRaw(data []byte) error {
	// SASL-wrapped messages are sent with 4-byte length prefix
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

// RecvRaw receives raw bytes (for wrapped messages).
func (l *LDAPConn) RecvRaw() ([]byte, error) {
	// Read 4-byte length prefix
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(l.conn, lenBuf); err != nil {
		return nil, err
	}
	length := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])

	// Cap length to prevent memory exhaustion
	const maxLen = 10 * 1024 * 1024 // 10MB
	if length > maxLen || length < 0 {
		return nil, fmt.Errorf("message length %d exceeds maximum %d", length, maxLen)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(l.conn, data); err != nil {
		return nil, err
	}
	return data, nil
}

func (l *LDAPConn) readLDAPMessage() ([]byte, error) {
	// Read BER tag and length
	header := make([]byte, 2)
	if _, err := io.ReadFull(l.conn, header); err != nil {
		return nil, err
	}

	length := int(header[1])
	if header[1]&0x80 != 0 {
		numBytes := int(header[1] & 0x7f)
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
		header = append(header, lenBytes...)
	}

	// Cap length to prevent memory exhaustion
	const maxLen = 10 * 1024 * 1024 // 10MB
	if length > maxLen || length < 0 {
		return nil, fmt.Errorf("message length %d exceeds maximum %d", length, maxLen)
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(l.conn, body); err != nil {
		return nil, err
	}

	return append(header, body...), nil
}

// =============================================================================
// LDAP message builders (BER encode)
// =============================================================================

func buildSASLBindRequest(msgID int, mechanism string, credentials []byte) []byte {
	// Build: SEQUENCE { messageID, bindRequest { version, name, [3] SaslCredentials } }
	// SaslCredentials ::= SEQUENCE { mechanism LDAPString, credentials OCTET STRING OPTIONAL }
	//
	// RFC 4511 uses IMPLICIT TAGS, so [3] SaslCredentials means the context tag
	// REPLACES the SEQUENCE tag (not wraps it). The constructed [3] tag directly
	// contains the mechanism and optional credentials.

	// SASL credentials contents (no inner SEQUENCE - implicit tagging)
	saslContents := marshalOctetString(mechanism)
	if len(credentials) > 0 {
		saslContents = append(saslContents, marshalOctetStringBytes(credentials)...)
	}

	// Context tag 3 for SASL choice (constructed, implicit replacement for SEQUENCE)
	saslChoice := encodeContextTag(3, true, saslContents)

	// BindRequest: version (INTEGER 3) + name (OCTET STRING "") + auth choice
	bindReqBytes := concat(
		marshalInteger(3),
		marshalOctetString(""),
		saslChoice,
	)

	// Application tag 0 for BindRequest (constructed)
	bindReq := encodeAppTag(0, bindReqBytes)

	// SEQUENCE wrapper
	msgBytes := concat(marshalInteger(msgID), bindReq)
	return encodeSequence(msgBytes)
}

func encodeSequence(content []byte) []byte {
	return encodeTLV(0x30, content)
}

func encodeContextTag(tag int, constructed bool, content []byte) []byte {
	tagByte := byte(0x80 | tag) // Context-specific
	if constructed {
		tagByte |= 0x20
	}
	return encodeTLV(tagByte, content)
}

func encodeAppTag(tag int, content []byte) []byte {
	tagByte := byte(0x40 | 0x20 | tag) // Application, constructed
	return encodeTLV(tagByte, content)
}

func encodeTLV(tag byte, content []byte) []byte {
	lenBytes := encodeLength(len(content))
	result := make([]byte, 1+len(lenBytes)+len(content))
	result[0] = tag
	copy(result[1:], lenBytes)
	copy(result[1+len(lenBytes):], content)
	return result
}

// buildRootDSESearchRequest builds a baseObject-scoped LDAP search of
// the empty DN (rootDSE) using a hard-coded "(objectClass=*)" present
// filter. attrs lists the attributes to return. This helper is
// intentionally not parameterised on filter or scope: it only does
// what this example needs. A general LDAP client would use a real
// LDAP library.
func buildRootDSESearchRequest(msgID int, attrs []string) []byte {
	// SearchRequest ::= [APPLICATION 3] SEQUENCE {
	//   baseObject, scope, derefAliases, sizeLimit, timeLimit, typesOnly,
	//   filter, attributes
	// }
	// Filter "objectClass=*" encodes as a present filter (tag [7]).
	filterBytes := asn1.RawValue{Class: 2, Tag: 7, Bytes: []byte("objectClass")}

	var attrsBytes []byte
	for _, a := range attrs {
		attrsBytes = append(attrsBytes, marshalOctetString(a)...)
	}
	attrsSeq := asn1.RawValue{Class: 0, Tag: 16, IsCompound: true, Bytes: attrsBytes}

	searchReq := asn1.RawValue{
		Class:      1,
		Tag:        3, // SearchRequest, [APPLICATION 3]
		IsCompound: true,
		Bytes: concat(
			marshalOctetString(""),   // baseObject = "" (rootDSE)
			marshalEnum(0),           // scope: baseObject
			marshalEnum(0),           // derefAliases: neverDerefAliases
			marshalInteger(0),        // sizeLimit
			marshalInteger(0),        // timeLimit
			marshalBoolean(false),    // typesOnly
			mustMarshal(filterBytes), // filter: present(objectClass)
			mustMarshal(attrsSeq),    // attributes
		),
	}

	msg := asn1.RawValue{
		Class:      0,
		Tag:        16,
		IsCompound: true,
		Bytes:      append(marshalInteger(msgID), mustMarshal(searchReq)...),
	}
	return mustMarshal(msg)
}

// =============================================================================
// LDAP message parsers (BER decode)
//
// Hand-rolled because AD uses non-minimal length encoding that some
// stricter parsers reject, and because we need to dig into specific
// context tags (serverSaslCreds [7]) that the stdlib asn1 package
// doesn't expose ergonomically.
// =============================================================================

func extractSASLCredentials(msg []byte) ([]byte, error) {
	// Structure: SEQUENCE { messageID, BindResponse { resultCode, matchedDN, diagnosticMsg, [7] serverSaslCreds } }

	offset := 0

	// Skip outer SEQUENCE tag and length
	if len(msg) < 2 {
		return nil, fmt.Errorf("message too short")
	}
	_, lenSize := berLength(msg[1:])
	offset = 1 + lenSize

	// Skip messageID (INTEGER)
	if offset >= len(msg) {
		return nil, fmt.Errorf("missing messageID")
	}
	_, elemLen, lenSize := berElement(msg[offset:])
	offset += 1 + lenSize + elemLen

	// BindResponse (APPLICATION 1)
	if offset >= len(msg) || (msg[offset]&0x1f) != 1 {
		return nil, fmt.Errorf("expected BindResponse")
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize

	// Skip resultCode (ENUMERATED)
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen

	// Skip matchedDN (OCTET STRING)
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen

	// Skip diagnosticMessage (OCTET STRING)
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen

	// Look for serverSaslCreds [7] (context tag 7 = 0x87 or 0xa7)
	if offset >= len(msg) {
		return nil, nil // No SASL creds
	}

	tag := msg[offset]
	if (tag & 0x1f) == 7 { // Context tag 7
		contentLen, lenSize := berLength(msg[offset+1:])
		start := offset + 1 + lenSize
		return msg[start : start+contentLen], nil
	}

	return nil, nil
}

func berLength(data []byte) (length int, bytesConsumed int) {
	if len(data) == 0 {
		return 0, 0
	}
	if data[0] < 128 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7f)
	if len(data) < 1+numBytes {
		return 0, 0
	}
	length = 0
	for i := range numBytes {
		length = length<<8 | int(data[1+i])
	}
	return length, 1 + numBytes
}

func berElement(data []byte) (tag byte, contentLen int, lenBytesConsumed int) {
	if len(data) < 2 {
		return 0, 0, 0
	}
	tag = data[0]
	contentLen, lenBytesConsumed = berLength(data[1:])
	return
}

func extractResultCode(msg []byte) (int, error) {
	// Manual BER parsing for result code
	offset := 0

	// Skip outer SEQUENCE
	if len(msg) < 2 {
		return -1, fmt.Errorf("message too short")
	}
	_, lenSize := berLength(msg[1:])
	offset = 1 + lenSize

	// Skip messageID
	_, elemLen, lenSize := berElement(msg[offset:])
	offset += 1 + lenSize + elemLen

	// BindResponse
	if offset >= len(msg) || (msg[offset]&0x1f) != 1 {
		return -1, fmt.Errorf("expected BindResponse")
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize

	// ResultCode (ENUMERATED - tag 0x0a)
	if offset >= len(msg) || msg[offset] != 0x0a {
		return -1, fmt.Errorf("expected resultCode")
	}
	contentLen, lenSize := berLength(msg[offset+1:])
	start := offset + 1 + lenSize

	// Parse the integer value
	code := 0
	for i := range contentLen {
		code = code<<8 | int(msg[start+i])
	}
	return code, nil
}

func parseSearchResult(msg []byte) string {
	// Manual BER parsing for search result
	// SearchResultEntry ::= [APPLICATION 4] SEQUENCE { objectName, attributes }
	// We just want to find any attribute value to prove the search worked

	offset := 0

	// Skip outer SEQUENCE
	if len(msg) < 2 {
		return "(too short)"
	}
	_, lenSize := berLength(msg[1:])
	offset = 1 + lenSize

	// Skip messageID
	_, elemLen, lenSize := berElement(msg[offset:])
	offset += 1 + lenSize + elemLen

	// Check for SearchResultEntry (APPLICATION 4 = 0x64)
	if offset >= len(msg) {
		return "(no entry)"
	}
	tag := msg[offset]
	if (tag & 0x1f) != 4 {
		return fmt.Sprintf("(unexpected tag 0x%02x)", tag)
	}

	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize

	// Skip objectName (OCTET STRING)
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen

	// Attributes SEQUENCE
	if offset >= len(msg) || msg[offset] != 0x30 {
		return "(no attributes)"
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize

	// First attribute SEQUENCE
	if offset >= len(msg) || msg[offset] != 0x30 {
		return "(no attribute)"
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize

	// Skip attribute type (OCTET STRING)
	_, elemLen, lenSize = berElement(msg[offset:])
	offset += 1 + lenSize + elemLen

	// Values SET (0x31)
	if offset >= len(msg) || msg[offset] != 0x31 {
		return "(no values)"
	}
	_, lenSize = berLength(msg[offset+1:])
	offset += 1 + lenSize

	// First value (OCTET STRING)
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

// =============================================================================
// BER primitive helpers
// =============================================================================

func marshalInteger(v int) []byte {
	b, _ := asn1.Marshal(v)
	return b
}

func marshalEnum(v int) []byte {
	return []byte{0x0a, 0x01, byte(v)}
}

func marshalBoolean(v bool) []byte {
	if v {
		return []byte{0x01, 0x01, 0xff}
	}
	return []byte{0x01, 0x01, 0x00}
}

func marshalOctetString(s string) []byte {
	// LDAP requires OCTET STRING (tag 0x04), not UTF8String
	return marshalOctetStringBytes([]byte(s))
}

func marshalOctetStringBytes(b []byte) []byte {
	// Manual OCTET STRING encoding (tag 0x04)
	if len(b) < 128 {
		return append([]byte{0x04, byte(len(b))}, b...)
	}
	// Long form length encoding
	lenBytes := encodeLength(len(b))
	return append(append([]byte{0x04}, lenBytes...), b...)
}

func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	var lenBytes []byte
	for length > 0 {
		lenBytes = append([]byte{byte(length & 0xff)}, lenBytes...)
		length >>= 8
	}
	return append([]byte{byte(0x80 | len(lenBytes))}, lenBytes...)
}

func mustMarshal(v any) []byte {
	b, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func concat(slices ...[]byte) []byte {
	var result []byte
	for _, s := range slices {
		result = append(result, s...)
	}
	return result
}

func header(s string) string {
	return fmt.Sprintf("=== %s ===", s)
}

// Note: this example assumes Go 1.21+ for the built-in min function.
