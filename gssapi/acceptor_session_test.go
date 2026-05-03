package gssapi

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/iana/flags"
	"github.com/f0oster/gokrb5/iana/nametype"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/test/testdata"
	"github.com/f0oster/gokrb5/types"
)

func TestAcceptOn_RoundTrip(t *testing.T) {
	t.Parallel()
	cl := getTestClient()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	st := time.Now().UTC()
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		types.NewKrbFlags(),
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("NewTicket: %v", err)
	}
	auth := newTestAuthenticator(*cl.Credentials)
	apReq, err := messages.NewAPReq(tkt, sessionKey, auth)
	if err != nil {
		t.Fatalf("NewAPReq: %v", err)
	}
	types.SetFlag(&apReq.APOptions, flags.APOptionMutualRequired)

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var acceptErr error
	var sess *Session
	go func() {
		defer wg.Done()
		acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
		s, err := acc.AcceptOn(serverConn, LengthPrefix4)
		if err != nil {
			acceptErr = err
			return
		}
		sess = s
		msg, err := sess.ReadMsg()
		if err != nil {
			acceptErr = err
			return
		}
		acceptErr = sess.WriteMsg(append([]byte("echo:"), msg...))
	}()

	mech := mechTokenFromAPReq(t, apReq)
	if err := LengthPrefix4.WriteFrame(clientConn, mech); err != nil {
		t.Fatalf("write AP-REQ frame: %v", err)
	}
	apRepFrame, err := LengthPrefix4.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("read AP-REP frame: %v", err)
	}
	encPart, err := verifyAPRepFromMechToken(apRepFrame, sessionKey, auth)
	if err != nil {
		t.Fatalf("verify AP-REP: %v", err)
	}

	clientCtx := NewInitiatorContext(
		sessionKey,
		auth.SubKey,
		encPart.Subkey,
		uint64(auth.SeqNumber),
		uint64(encPart.SequenceNumber),
	)

	greeting, err := clientCtx.Wrap([]byte("hello"))
	if err != nil {
		t.Fatalf("client Wrap: %v", err)
	}
	if err := LengthPrefix4.WriteFrame(clientConn, greeting); err != nil {
		t.Fatalf("write greeting frame: %v", err)
	}
	replyFrame, err := LengthPrefix4.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("read reply frame: %v", err)
	}
	reply, err := clientCtx.Unwrap(replyFrame)
	if err != nil {
		t.Fatalf("client Unwrap: %v", err)
	}
	if string(reply) != "echo:hello" {
		t.Fatalf("reply = %q, want %q", reply, "echo:hello")
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("server side: %v", acceptErr)
	}
}

func TestAcceptOn_NoMutualAuthSkipsResponse(t *testing.T) {
	t.Parallel()
	cl := getTestClient()
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	kt.Unmarshal(b)
	tkt, sessionKey := newTestTicket(t, kt, cl)
	apReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(*cl.Credentials))
	if err != nil {
		t.Fatalf("NewAPReq: %v", err)
	}
	// No APOptionMutualRequired set on apReq.

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	go func() {
		defer wg.Done()
		acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
		_, serverErr = acc.AcceptOn(serverConn, LengthPrefix4)
	}()

	mech := mechTokenFromAPReq(t, apReq)
	if err := LengthPrefix4.WriteFrame(clientConn, mech); err != nil {
		t.Fatalf("write AP-REQ frame: %v", err)
	}

	// No response frame is written when mutual auth was not requested.
	if err := clientConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := LengthPrefix4.ReadFrame(clientConn); err == nil {
		t.Fatal("expected ReadFrame to time out; AcceptOn should not write a response without mutual auth")
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatalf("server side: %v", serverErr)
	}
}

// verifyAPRepFromMechToken strips the mech-token framing and verifies
// an AP-REP against the initiator's session key and authenticator.
func verifyAPRepFromMechToken(mechToken []byte, sessionKey types.EncryptionKey, sentAuth types.Authenticator) (*messages.EncAPRepPart, error) {
	oid, tokID, inner, err := UnmarshalMechToken(mechToken)
	if err != nil {
		return nil, err
	}
	if !oid.Equal(OIDKRB5.OID()) {
		return nil, fmt.Errorf("mech token OID is %s, want %s", oid.String(), OIDKRB5.OID().String())
	}
	if tokID != TokIDAPRep {
		return nil, &mechTokenIDError{got: tokID, want: TokIDAPRep}
	}
	var apRep messages.APRep
	if err := apRep.Unmarshal(inner); err != nil {
		return nil, err
	}
	return VerifyAPRep(apRep, sessionKey, sentAuth)
}

type mechTokenIDError struct{ got, want string }

func (e *mechTokenIDError) Error() string {
	return "unexpected mech token ID " + e.got + ", want " + e.want
}
