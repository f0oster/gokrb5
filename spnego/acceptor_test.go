package spnego

import (
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/config"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/iana/nametype"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/test/testdata"
	"github.com/f0oster/gokrb5/types"
)

func acceptorTestClient(t *testing.T) *client.Client {
	t.Helper()
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatalf("client keytab: %v", err)
	}
	c, err := config.NewFromString(testdata.KRB5_CONF)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
}

func acceptorTestKeytab(t *testing.T) *keytab.Keytab {
	t.Helper()
	b, _ := hex.DecodeString(testdata.HTTP_KEYTAB)
	kt := keytab.New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatalf("service keytab: %v", err)
	}
	return kt
}

func newServiceTicket(t *testing.T, kt *keytab.Keytab, cl *client.Client) (messages.Ticket, types.EncryptionKey) {
	t.Helper()
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"HTTP", "host.test.gokrb5"},
	}
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
	return tkt, sessionKey
}

func TestAcceptor_Accept(t *testing.T) {
	t.Parallel()
	cl := acceptorTestClient(t)
	kt := acceptorTestKeytab(t)
	tkt, sessionKey := newServiceTicket(t, kt, cl)

	init, err := NewInitiatorFromTicket(cl, tkt, sessionKey, gssapi.WithMutualAuth())
	if err != nil {
		t.Fatalf("NewInitiatorFromTicket: %v", err)
	}
	sptBytes, err := init.Step(nil)
	if err != nil {
		t.Fatalf("build SPNEGO init: %v", err)
	}

	acc := NewAcceptor(kt, gssapi.WithReplayCache(gssapi.NewReplayCache(time.Minute)))
	a, err := acc.Accept(sptBytes)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if len(a.ResponseToken) == 0 {
		t.Fatalf("ResponseToken should be non-nil on success")
	}
	if a.Context == nil {
		t.Fatalf("Acceptance carries no SecurityContext")
	}
	if a.Credentials == nil || !a.Credentials.Authenticated() {
		t.Fatalf("Acceptance does not carry authenticated credentials")
	}

	// The marshaled NegTokenResp round-trips back into a valid SPNEGO
	// response with accept-completed plus an embedded AP-REP MechToken.
	var resp NegTokenResp
	if err := resp.Unmarshal(a.ResponseToken); err != nil {
		t.Fatalf("unmarshal NegTokenResp: %v", err)
	}
	if resp.NegState != asn1.Enumerated(NegStateAcceptCompleted) {
		t.Fatalf("NegState = %v, want accept-completed", resp.NegState)
	}
	if len(resp.ResponseToken) == 0 {
		t.Fatalf("NegTokenResp carries no AP-REP MechToken despite mutual auth")
	}
}

func TestAcceptor_AcceptOn_RoundTrip(t *testing.T) {
	t.Parallel()
	cl := acceptorTestClient(t)
	kt := acceptorTestKeytab(t)
	tkt, sessionKey := newServiceTicket(t, kt, cl)

	init, err := NewInitiatorFromTicket(cl, tkt, sessionKey, gssapi.WithMutualAuth())
	if err != nil {
		t.Fatalf("NewInitiatorFromTicket: %v", err)
	}
	sptBytes, err := init.Step(nil)
	if err != nil {
		t.Fatalf("build SPNEGO init: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	go func() {
		defer wg.Done()
		acc := NewAcceptor(kt, gssapi.WithReplayCache(gssapi.NewReplayCache(time.Minute)))
		sess, err := acc.AcceptOn(serverConn, gssapi.LengthPrefix4)
		if err != nil {
			serverErr = err
			return
		}
		msg, err := sess.ReadMsg()
		if err != nil {
			serverErr = err
			return
		}
		serverErr = sess.WriteMsg(append([]byte("echo:"), msg...))
	}()

	if err := gssapi.LengthPrefix4.WriteFrame(clientConn, sptBytes); err != nil {
		t.Fatalf("write SPNEGO init frame: %v", err)
	}

	respFrame, err := gssapi.LengthPrefix4.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("read SPNEGO response frame: %v", err)
	}
	if _, err := init.Step(respFrame); err != nil {
		t.Fatalf("SPNEGO response verify: %v", err)
	}
	clientCtx, err := init.SecurityContext()
	if err != nil {
		t.Fatalf("SecurityContext: %v", err)
	}

	greeting, err := clientCtx.Wrap([]byte("hello"))
	if err != nil {
		t.Fatalf("client Wrap: %v", err)
	}
	if err := gssapi.LengthPrefix4.WriteFrame(clientConn, greeting); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	replyFrame, err := gssapi.LengthPrefix4.ReadFrame(clientConn)
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
	if serverErr != nil {
		t.Fatalf("server side: %v", serverErr)
	}
}
