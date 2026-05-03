package gssapi

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/client"
	"github.com/f0oster/gokrb5/config"
	"github.com/f0oster/gokrb5/credentials"
	"github.com/f0oster/gokrb5/iana/errorcode"
	"github.com/f0oster/gokrb5/iana/flags"
	"github.com/f0oster/gokrb5/iana/nametype"
	"github.com/f0oster/gokrb5/keytab"
	"github.com/f0oster/gokrb5/messages"
	"github.com/f0oster/gokrb5/test/testdata"
	"github.com/f0oster/gokrb5/types"
	"github.com/stretchr/testify/assert"
)

func newTestAuthenticator(creds credentials.Credentials) types.Authenticator {
	auth, _ := types.NewAuthenticator(creds.Domain(), creds.CName())
	auth.GenerateSeqNumberAndSubKey(18, 32)
	return auth
}

func getTestClient() *client.Client {
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	c, _ := config.NewFromString(testdata.KRB5_CONF)
	cl := client.NewWithKeytab("testuser1", "TEST.GOKRB5", kt, c)
	return cl
}

// mechTokenFromAPReq wraps an AP-REQ in the RFC 2743 §3.1 application
// framing the Acceptor expects.
func mechTokenFromAPReq(t *testing.T, apReq messages.APReq) []byte {
	t.Helper()
	apReqBytes, err := apReq.Marshal()
	if err != nil {
		t.Fatalf("marshal AP-REQ: %v", err)
	}
	tok, err := marshalMechToken(tokIDAPReq, apReqBytes)
	if err != nil {
		t.Fatalf("marshal mech token: %v", err)
	}
	return tok
}

// freshReplayCache returns a ReplayCache isolated from the process-wide
// singleton so tests cannot collide on shared state.
func freshReplayCache(t *testing.T) *ReplayCache {
	t.Helper()
	return &ReplayCache{entries: make(map[clientKey]clientEntries)}
}

func TestAcceptor_Accept(t *testing.T) {
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
		t.Fatalf("Error getting test ticket: %v", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(*cl.Credentials))
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
	a, err := acc.Accept(mechTokenFromAPReq(t, apReq), WithRemoteAddress(h))
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	if a.Credentials == nil || !a.Credentials.Authenticated() {
		t.Fatalf("Acceptance does not carry authenticated credentials")
	}
	if a.Context == nil {
		t.Fatalf("Acceptance does not carry a SecurityContext")
	}
	if a.ResponseToken != nil {
		t.Fatalf("ResponseToken should be nil when mutual auth was not requested")
	}
}

func TestAcceptor_Accept_MutualAuthProducesAPRep(t *testing.T) {
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
		t.Fatalf("Error getting test ticket: %v", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(*cl.Credentials))
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	types.SetFlag(&apReq.APOptions, flags.APOptionMutualRequired)

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
	a, err := acc.Accept(mechTokenFromAPReq(t, apReq), WithRemoteAddress(h))
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	if len(a.ResponseToken) == 0 {
		t.Fatalf("ResponseToken should be non-nil when mutual auth was requested")
	}
	if a.Context == nil || len(a.Context.APRepSubkey.KeyValue) == 0 {
		t.Fatalf("Context should carry the AP-REP subkey when mutual auth was requested")
	}
}

func TestAcceptor_Accept_KeytabPrincipalOverride(t *testing.T) {
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
		t.Fatalf("Error getting test ticket: %v", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(*cl.Credentials))
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt,
		WithKeytabPrincipal("foo"),
		WithReplayCache(freshReplayCache(t)),
	)
	_, err = acc.Accept(mechTokenFromAPReq(t, apReq), WithRemoteAddress(h))
	if err == nil {
		t.Fatalf("Accept should have failed with keytab principal override")
	}
	if !strings.Contains(err.Error(), "Looking for \"foo\" realm") {
		t.Fatalf("Looking for wrong entity: %s", err.Error())
	}
}

func TestAcceptor_Accept_BADMATCH_CName(t *testing.T) {
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
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	a.CName = types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"BADMATCH"},
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, a)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
	_, err = acc.Accept(mechTokenFromAPReq(t, apReq), WithRemoteAddress(h))
	if err == nil {
		t.Fatal("Accept passed when authenticator CName differed from ticket CName")
	}
	if kerr, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_BADMATCH, kerr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestAcceptor_Accept_BADMATCH_CRealm(t *testing.T) {
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
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	a.CRealm = "OTHER.GOKRB5"
	apReq, err := messages.NewAPReq(tkt, sessionKey, a)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
	_, err = acc.Accept(mechTokenFromAPReq(t, apReq), WithRemoteAddress(h))
	if err == nil {
		t.Fatal("Accept passed when authenticator CRealm differed from ticket CRealm")
	}
	if kerr, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_BADMATCH, kerr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestAcceptor_Accept_LargeClockSkew(t *testing.T) {
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
		t.Fatalf("Error getting test ticket: %v", err)
	}
	a := newTestAuthenticator(*cl.Credentials)
	a.CTime = a.CTime.Add(time.Duration(-10) * time.Minute)
	apReq, err := messages.NewAPReq(tkt, sessionKey, a)
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
	_, err = acc.Accept(mechTokenFromAPReq(t, apReq), WithRemoteAddress(h))
	if err == nil {
		t.Fatal("Accept passed despite a 10-minute clock skew")
	}
	if kerr, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_SKEW, kerr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestAcceptor_Accept_Replay(t *testing.T) {
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
		t.Fatalf("Error getting test ticket: %v", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(*cl.Credentials))
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}

	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
	mechToken := mechTokenFromAPReq(t, apReq)

	if _, err := acc.Accept(mechToken, WithRemoteAddress(h)); err != nil {
		t.Fatalf("first Accept failed: %v", err)
	}
	_, err = acc.Accept(mechToken, WithRemoteAddress(h))
	if err == nil {
		t.Fatal("second Accept (replay) passed when it should not have")
	}
	assert.IsType(t, messages.KRBError{}, err, "Error is not a KRBError")
	assert.Equal(t, errorcode.KRB_AP_ERR_REPEAT, err.(messages.KRBError).ErrorCode, "Error code not as expected")
}

func TestAcceptor_Accept_FutureTicket(t *testing.T) {
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
		st.Add(time.Duration(60)*time.Minute),
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(*cl.Credentials))
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
	_, err = acc.Accept(mechTokenFromAPReq(t, apReq), WithRemoteAddress(h))
	if err == nil {
		t.Fatal("Accept passed for a not-yet-valid ticket")
	}
	if kerr, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, kerr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestAcceptor_Accept_InvalidTicket(t *testing.T) {
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
	f := types.NewKrbFlags()
	types.SetFlag(&f, flags.Invalid)
	tkt, sessionKey, err := messages.NewTicket(cl.Credentials.CName(), cl.Credentials.Domain(),
		sname, "TEST.GOKRB5",
		f,
		kt,
		18,
		1,
		st,
		st,
		st.Add(time.Duration(24)*time.Hour),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(*cl.Credentials))
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
	_, err = acc.Accept(mechTokenFromAPReq(t, apReq), WithRemoteAddress(h))
	if err == nil {
		t.Fatal("Accept passed for a ticket with the Invalid flag set")
	}
	if kerr, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_NYV, kerr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}

func TestAcceptor_Accept_ExpiredTicket(t *testing.T) {
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
		st.Add(time.Duration(-30)*time.Minute),
		st.Add(time.Duration(48)*time.Hour),
	)
	if err != nil {
		t.Fatalf("Error getting test ticket: %v", err)
	}
	apReq, err := messages.NewAPReq(tkt, sessionKey, newTestAuthenticator(*cl.Credentials))
	if err != nil {
		t.Fatalf("Error getting test AP_REQ: %v", err)
	}
	h, _ := types.GetHostAddress("127.0.0.1:1234")
	acc := NewAcceptor(kt, WithReplayCache(freshReplayCache(t)))
	_, err = acc.Accept(mechTokenFromAPReq(t, apReq), WithRemoteAddress(h))
	if err == nil {
		t.Fatal("Accept passed for an expired ticket")
	}
	if kerr, ok := err.(messages.KRBError); ok {
		assert.Equal(t, errorcode.KRB_AP_ERR_TKT_EXPIRED, kerr.ErrorCode, "Error code not as expected")
	} else {
		t.Fatalf("Error is not a KRBError: %v", err)
	}
}
