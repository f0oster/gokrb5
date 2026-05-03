package gssapi

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarshalUnmarshalMechToken_RoundTrip(t *testing.T) {
	t.Parallel()
	inner := []byte("test AP-REQ payload")
	wire, err := MarshalMechToken(TokIDAPReq, inner)
	assert.NoError(t, err)
	assert.NotEmpty(t, wire)

	oid, tokID, gotInner, err := UnmarshalMechToken(wire)
	assert.NoError(t, err)
	assert.True(t, oid.Equal(OIDKRB5.OID()))
	assert.Equal(t, TokIDAPReq, tokID)
	assert.Equal(t, inner, gotInner)
}

func TestMarshalUnmarshalMechToken_APRep(t *testing.T) {
	t.Parallel()
	inner := []byte("test AP-REP payload")
	wire, err := MarshalMechToken(TokIDAPRep, inner)
	assert.NoError(t, err)

	oid, tokID, gotInner, err := UnmarshalMechToken(wire)
	assert.NoError(t, err)
	assert.True(t, oid.Equal(OIDKRB5.OID()))
	assert.Equal(t, TokIDAPRep, tokID)
	assert.Equal(t, inner, gotInner)
}

func TestUnmarshalMechToken_Truncated(t *testing.T) {
	t.Parallel()
	wire, err := MarshalMechToken(TokIDAPReq, []byte("data"))
	assert.NoError(t, err)
	_, _, _, err = UnmarshalMechToken(wire[:5])
	assert.Error(t, err)
}

func TestUnmarshalMechToken_TooShort(t *testing.T) {
	t.Parallel()
	_, _, _, err := UnmarshalMechToken([]byte{0x60, 0x03, 0x06, 0x01, 0x00})
	assert.Error(t, err)
}

func TestInitiator_StepBeforeReady(t *testing.T) {
	t.Parallel()
	i := &Initiator{state: stateDone}
	_, err := i.Step(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already established")
}

func TestInitiator_SecurityContextBeforeDone(t *testing.T) {
	t.Parallel()
	i := &Initiator{state: stateReady}
	_, err := i.SecurityContext()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not yet established")
}

func TestInitiator_DoneReflectsState(t *testing.T) {
	t.Parallel()
	i := &Initiator{state: stateReady}
	assert.False(t, i.Done())
	i.state = stateAwaitingReply
	assert.False(t, i.Done())
	i.state = stateDone
	assert.True(t, i.Done())
}

func TestInitiator_StepReplyWithNilInput(t *testing.T) {
	t.Parallel()
	i := &Initiator{state: stateAwaitingReply}
	_, err := i.Step(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires a reply token")
}
