package gssapi

import "testing"

func TestSeqState_NeitherFlagSet_AlwaysOK(t *testing.T) {
	t.Parallel()
	s := newSeqState(100, false, false)
	// Arbitrary seqs in any order all accepted without updating state.
	for _, seq := range []uint64{100, 42, 9999, 0, 100} {
		if got := s.check(seq); got != SeqStatusOK {
			t.Errorf("check(%d) = %v, want SeqStatusOK", seq, got)
		}
	}
}

func TestSeqState_StrictInOrder(t *testing.T) {
	t.Parallel()
	s := newSeqState(0, true, true)
	for i := uint64(0); i < 5; i++ {
		if got := s.check(i); got != SeqStatusOK {
			t.Errorf("check(%d) = %v, want SeqStatusOK", i, got)
		}
	}
}

func TestSeqState_ForwardGapWithSequenceDetect(t *testing.T) {
	t.Parallel()
	s := newSeqState(0, true, true)
	if got := s.check(0); got != SeqStatusOK {
		t.Fatalf("check(0) = %v, want SeqStatusOK", got)
	}
	if got := s.check(5); got != SeqStatusGap {
		t.Errorf("check(5) after 0 = %v, want SeqStatusGap", got)
	}
	// After the gap, next = 6; seq 6 is in-order from here.
	if got := s.check(6); got != SeqStatusOK {
		t.Errorf("check(6) after gap = %v, want SeqStatusOK", got)
	}
}

func TestSeqState_ForwardGapWithoutSequenceDetect(t *testing.T) {
	t.Parallel()
	// Replay-only mode: gaps are not reported as such.
	s := newSeqState(0, true, false)
	_ = s.check(0)
	if got := s.check(5); got != SeqStatusOK {
		t.Errorf("check(5) in replay-only = %v, want SeqStatusOK", got)
	}
}

func TestSeqState_OutOfOrderWithinWindow(t *testing.T) {
	t.Parallel()
	s := newSeqState(0, true, true)
	// Accept 0, 5 (gap), then 3 (in-window, past).
	_ = s.check(0)
	_ = s.check(5)
	if got := s.check(3); got != SeqStatusUnsequenced {
		t.Errorf("check(3) after 5 = %v, want SeqStatusUnsequenced", got)
	}
}

func TestSeqState_DuplicateDetected(t *testing.T) {
	t.Parallel()
	s := newSeqState(0, true, true)
	_ = s.check(0)
	_ = s.check(5)
	// 5 again: duplicate.
	if got := s.check(5); got != SeqStatusDuplicate {
		t.Errorf("check(5) twice = %v, want SeqStatusDuplicate", got)
	}
	// 0 again: also duplicate (in window).
	if got := s.check(0); got != SeqStatusDuplicate {
		t.Errorf("check(0) after 5 = %v, want SeqStatusDuplicate", got)
	}
}

func TestSeqState_OldBeyondWindow(t *testing.T) {
	t.Parallel()
	s := newSeqState(0, true, true)
	// Jump to 100, then try 10 which is 90 slots in the past (> 64).
	_ = s.check(100)
	if got := s.check(10); got != SeqStatusUnsequenced {
		// With sequence-detect, anything older than the window is
		// flagged as Unsequenced (not Old), matching MIT.
		t.Errorf("check(10) far-past with SEQUENCE = %v, want SeqStatusUnsequenced", got)
	}
}

func TestSeqState_OldBeyondWindow_ReplayOnly(t *testing.T) {
	t.Parallel()
	// Without sequence-detect, far-past tokens report as Old instead.
	s := newSeqState(0, true, false)
	_ = s.check(100)
	if got := s.check(10); got != SeqStatusOld {
		t.Errorf("check(10) far-past in replay-only = %v, want SeqStatusOld", got)
	}
}

func TestSeqState_ADStyleRepeatedZero(t *testing.T) {
	t.Parallel()
	// Active Directory emits every server→client WrapToken with
	// SND_SEQ=0 regardless of context state. With a sliding window,
	// the first is accepted and subsequent ones are flagged as
	// duplicates — but callers that ignore duplicate-status (most LDAP
	// clients) still get the payload.
	s := newSeqState(0, true, true)
	if got := s.check(0); got != SeqStatusOK {
		t.Fatalf("first AD token at 0: %v, want SeqStatusOK", got)
	}
	if got := s.check(0); got != SeqStatusDuplicate {
		t.Errorf("second AD token at 0: %v, want SeqStatusDuplicate", got)
	}
	if got := s.check(0); got != SeqStatusDuplicate {
		t.Errorf("third AD token at 0: %v, want SeqStatusDuplicate", got)
	}
}

func TestSeqState_NonZeroBaseFromEncAPRepPart(t *testing.T) {
	t.Parallel()
	// Simulate an MIT acceptor that put a real seq-number in
	// EncAPRepPart. recvSeq starts at that value; the first incoming
	// token must match.
	s := newSeqState(1000, true, true)
	if got := s.check(1000); got != SeqStatusOK {
		t.Errorf("check(1000) at base 1000 = %v, want SeqStatusOK", got)
	}
	if got := s.check(1001); got != SeqStatusOK {
		t.Errorf("check(1001) = %v, want SeqStatusOK", got)
	}
}

func TestSeqState_LargeForwardJumpClearsBitmap(t *testing.T) {
	t.Parallel()
	// Jump forward by more than the window size; the recvmap should
	// be cleared (prior in-window entries retired) and the new slot
	// marked.
	s := newSeqState(0, true, true)
	_ = s.check(0)
	_ = s.check(1)
	_ = s.check(2)
	// Large jump: offset+1 > 64.
	if got := s.check(200); got != SeqStatusGap {
		t.Errorf("check(200) = %v, want SeqStatusGap", got)
	}
	// 199 is now 1 slot in the past from next=201 → offset=2.
	if got := s.check(199); got != SeqStatusUnsequenced {
		t.Errorf("check(199) = %v, want SeqStatusUnsequenced", got)
	}
}

func TestSeqState_NextExpected(t *testing.T) {
	t.Parallel()
	s := newSeqState(50, true, true)
	if got := s.nextExpected(); got != 50 {
		t.Errorf("initial nextExpected = %d, want 50", got)
	}
	_ = s.check(50)
	if got := s.nextExpected(); got != 51 {
		t.Errorf("after check(50), nextExpected = %d, want 51", got)
	}
	_ = s.check(51)
	if got := s.nextExpected(); got != 52 {
		t.Errorf("after check(51), nextExpected = %d, want 52", got)
	}
}
