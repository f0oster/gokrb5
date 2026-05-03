package suites

import (
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/gssapi"
	"github.com/f0oster/gokrb5/iana/flags"
	"github.com/f0oster/gokrb5/spnego"
	"github.com/f0oster/gokrb5/test/integration/framework"
)

// TestAcceptorRoundTrip_MIT runs an end-to-end GSS handshake where both
// sides are gokrb5: the acceptor uses the MIT-issued HTTP service keytab,
// the initiator logs in as preauth_user against the same MIT KDC. The
// test exchanges Wrap'd messages in both directions and asserts the
// acceptor's "authenticated" reply round-trips. The PAC is logged to
// the test output; for MIT it should be empty (no KerbValidationInfo).
func TestAcceptorRoundTrip_MIT(t *testing.T) {
	kdc := requireMIT(t)
	runAcceptorRoundTrip(t, kdc, "preauth_user", framework.MITUserPassword, kdc.HTTPSPN(),
		loggingReply(t, framework.DefaultReply), framework.AuthenticatedReply)
}

// TestAcceptorRoundTrip_AD is the Samba AD counterpart. The PAC is
// logged; for AD it should carry KerbValidationInfo with one or more
// group SIDs.
func TestAcceptorRoundTrip_AD(t *testing.T) {
	kdc := requireAD(t)
	runAcceptorRoundTrip(t, kdc, "testuser1", framework.SambaUserPassword, kdc.HTTPSPN(),
		loggingReply(t, framework.DefaultReply), framework.AuthenticatedReply)
}

// TestAcceptorPrivilegedUser_AD authenticates a user that belongs to the
// PrivilegedUserGroup security group provisioned by the Samba fixture and
// asserts the acceptor returns the privileged reply. The acceptor's
// ReplyFunc inspects ADCredentials.GroupMembershipSIDs for the group's SID,
// which exercises the full PAC → KerbValidationInfo → ADCredentials path
// against real AD-issued group data.
func TestAcceptorPrivilegedUser_AD(t *testing.T) {
	kdc := requireAD(t)
	groupSID, err := kdc.GroupSID(framework.PrivilegedUserGroupName)
	if err != nil {
		t.Fatalf("look up group SID: %v", err)
	}
	t.Logf("PrivilegedUserGroup SID: %s", groupSID)
	runAcceptorRoundTrip(t, kdc, "privileged_user", framework.SambaUserPassword, kdc.HTTPSPN(),
		loggingReply(t, privilegedReply(t, groupSID)), privilegedReplyText)
}

// TestAcceptorNonPrivilegedUser_AD is the negative counterpart: a user
// outside the PrivilegedUserGroup logs in with the same group-SID-aware
// reply function, and gets the regular "authenticated" reply because
// they're not a member.
func TestAcceptorNonPrivilegedUser_AD(t *testing.T) {
	kdc := requireAD(t)
	groupSID, err := kdc.GroupSID(framework.PrivilegedUserGroupName)
	if err != nil {
		t.Fatalf("look up group SID: %v", err)
	}
	t.Logf("PrivilegedUserGroup SID: %s", groupSID)
	runAcceptorRoundTrip(t, kdc, "testuser1", framework.SambaUserPassword, kdc.HTTPSPN(),
		loggingReply(t, privilegedReply(t, groupSID)), framework.AuthenticatedReply)
}

const privilegedReplyText = "privileged"

// privilegedReply returns a ReplyFunc that emits privilegedReplyText when
// the authenticated user has groupSID in their PAC group memberships,
// otherwise framework.AuthenticatedReply.
func privilegedReply(t *testing.T, groupSID string) framework.ReplyFunc {
	t.Helper()
	return func(creds *credentials.Credentials) []byte {
		if creds == nil {
			return []byte(framework.AuthenticatedReply)
		}
		if slices.Contains(creds.GetADCredentials().GroupMembershipSIDs, groupSID) {
			return []byte(privilegedReplyText)
		}
		return []byte(framework.AuthenticatedReply)
	}
}

// loggingReply wraps inner with diagnostics that print the authenticated
// principal and the PAC-derived authorization info to the test output.
// Diagnostics fire before inner so the log appears even when inner's
// payload determines a non-default reply.
func loggingReply(t *testing.T, inner framework.ReplyFunc) framework.ReplyFunc {
	t.Helper()
	return func(creds *credentials.Credentials) []byte {
		logAcceptedClient(t, creds)
		return inner(creds)
	}
}

// logAcceptedClient prints the authenticated principal and any
// PAC-derived ADCredentials to the test log. Empty ADCredentials is
// itself meaningful (the KDC issued no KerbValidationInfo) and is
// reported explicitly.
func logAcceptedClient(t *testing.T, creds *credentials.Credentials) {
	t.Helper()
	if creds == nil {
		t.Log("acceptor: no credentials in security context")
		return
	}
	t.Logf("acceptor: authenticated %s@%s", creds.UserName(), creds.Domain())
	ad := creds.GetADCredentials()
	if len(ad.GroupMembershipSIDs) == 0 && ad.EffectiveName == "" {
		t.Log("acceptor: PAC carried no KerbValidationInfo (no AD authorization data)")
		return
	}
	t.Logf("acceptor: AD effective name %q, user ID %d, primary group ID %d, %d group SID(s)",
		ad.EffectiveName, ad.UserID, ad.PrimaryGroupID, len(ad.GroupMembershipSIDs))
	for _, sid := range ad.GroupMembershipSIDs {
		t.Logf("acceptor:   group SID %s", sid)
	}
}

// runAcceptorRoundTrip is the shared body of the per-fixture tests.
// Drives the full SPNEGO/Kerberos handshake over an in-process TCP
// connection: build AP-REQ → acceptor verifies and emits AP-REP →
// initiator verifies AP-REP → both sides build SecurityContexts →
// exchange Wrap'd messages, expect expectedReply back.
func runAcceptorRoundTrip(t *testing.T, kdc framework.KDC, username, password, spn string, reply framework.ReplyFunc, expectedReply string) {
	t.Helper()

	serviceKeytab, err := kdc.Keytab(spn)
	if err != nil {
		t.Fatalf("get service keytab for %s: %v", spn, err)
	}

	acceptor, err := framework.StartGSSAcceptor(serviceKeytab, reply)
	if err != nil {
		t.Fatalf("start acceptor: %v", err)
	}
	t.Cleanup(func() { _ = acceptor.Close() })

	// fatalWithAcceptor surfaces any acceptor-side error alongside the
	// client-side error so the test failure message names the actual
	// cause when the acceptor closed the connection early.
	fatalWithAcceptor := func(format string, args ...any) {
		t.Helper()
		// Give the acceptor goroutine a beat to push its error.
		select {
		case aerr := <-acceptor.Errors():
			t.Fatalf("%s [acceptor error: %v]", fmt.Sprintf(format, args...), aerr)
		case <-time.After(200 * time.Millisecond):
			t.Fatalf(format, args...)
		}
	}

	cl, err := kdc.NewClient(username, password)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer cl.Destroy()
	if err := cl.Login(); err != nil {
		t.Fatalf("login as %s: %v", username, err)
	}

	tkt, sessionKey, err := cl.GetServiceTicket(spn)
	if err != nil {
		t.Fatalf("get service ticket for %s: %v", spn, err)
	}

	mt, err := spnego.NewKRB5TokenAPREQWithBindings(cl, tkt, sessionKey,
		[]int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual},
		[]int{flags.APOptionMutualRequired},
		nil, nil)
	if err != nil {
		t.Fatalf("build AP-REQ KRB5Token: %v", err)
	}
	mtBytes, err := mt.Marshal()
	if err != nil {
		t.Fatalf("marshal AP-REQ MechToken: %v", err)
	}
	spt := &spnego.SPNEGOToken{
		Init: true,
		NegTokenInit: spnego.NegTokenInit{
			MechTypes:      []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()},
			MechTokenBytes: mtBytes,
		},
	}
	sptBytes, err := spt.Marshal()
	if err != nil {
		t.Fatalf("marshal SPNEGOToken: %v", err)
	}

	conn, err := net.Dial("tcp", acceptor.Addr())
	if err != nil {
		t.Fatalf("dial acceptor: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}

	if err := framework.WriteFramed(conn, sptBytes); err != nil {
		fatalWithAcceptor("send AP-REQ: %v", err)
	}

	respBytes, err := framework.ReadFramed(conn)
	if err != nil {
		fatalWithAcceptor("receive AP-REP: %v", err)
	}
	var negResp spnego.NegTokenResp
	if err := negResp.Unmarshal(respBytes); err != nil {
		t.Fatalf("unmarshal NegTokenResp: %v", err)
	}
	if negResp.ResponseToken == nil {
		t.Fatalf("acceptor's NegTokenResp lacked ResponseToken (mutual auth not honoured)")
	}

	var apRepTok spnego.KRB5Token
	if err := apRepTok.Unmarshal(negResp.ResponseToken); err != nil {
		t.Fatalf("unmarshal AP-REP MechToken: %v", err)
	}
	apRepTok.SetAPRepVerification(mt.Authenticator, sessionKey)
	ok, status := apRepTok.Verify()
	if !ok {
		t.Fatalf("verify AP-REP: code=%v message=%q", status.Code, status.Message)
	}
	if apRepTok.EncAPRepPart == nil {
		t.Fatalf("verified AP-REP did not populate EncAPRepPart")
	}

	initCtx := gssapi.NewInitiatorContext(
		sessionKey,
		mt.Authenticator.SubKey,
		apRepTok.EncAPRepPart.Subkey,
		uint64(mt.Authenticator.SeqNumber),
		uint64(apRepTok.EncAPRepPart.SequenceNumber),
	)

	pingTok, err := initCtx.Wrap([]byte("ping"))
	if err != nil {
		t.Fatalf("wrap client message: %v", err)
	}
	if err := framework.WriteFramed(conn, pingTok); err != nil {
		fatalWithAcceptor("send Wrap: %v", err)
	}

	replyBytes, err := framework.ReadFramed(conn)
	if err != nil {
		fatalWithAcceptor("receive Wrap reply: %v", err)
	}
	msg, err := initCtx.Unwrap(replyBytes)
	if err != nil {
		t.Fatalf("unwrap reply: %v", err)
	}
	t.Logf("initiator received reply: %q", msg)
	if string(msg) != expectedReply {
		t.Fatalf("unexpected reply payload: got %q want %q", msg, expectedReply)
	}

	// Drain any acceptor-side errors that may have been recorded.
	select {
	case err := <-acceptor.Errors():
		t.Fatalf("acceptor error: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}
