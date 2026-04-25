package gssapi

import "fmt"

// seqState is a 64-slot sliding-window tracker for RFC 4121 per-message
// sequence numbers. Out-of-order, gapped, and duplicate tokens are reported
// via SeqStatus; per RFC 2743 these supplementary statuses are non-fatal,
// so only a replay under replay-detection mode is a hard reject.
type seqState struct {
	base       uint64 // initial expected sequence number (from EncAPRepPart)
	next       uint64 // next expected rel_seqnum (relative to base)
	recvmap    uint64 // bitmap of seen seqnums within the window
	doReplay   bool
	doSequence bool
}

// SeqStatus reports the result of a sliding-window sequence check and
// corresponds to RFC 2743 GSS supplementary status codes.
type SeqStatus int

const (
	// SeqStatusOK indicates the token arrived in the expected slot or was
	// accepted under the configured replay/sequence policy.
	SeqStatusOK SeqStatus = iota

	// SeqStatusGap indicates the token arrived ahead of the expected seq
	// number; earlier tokens were skipped. Matches GSS_S_GAP_TOKEN.
	SeqStatusGap

	// SeqStatusUnsequenced indicates the token arrived out of order but
	// within the window. Matches GSS_S_UNSEQ_TOKEN.
	SeqStatusUnsequenced

	// SeqStatusOld indicates the token is older than the window can track.
	// Matches GSS_S_OLD_TOKEN.
	SeqStatusOld

	// SeqStatusDuplicate indicates the token's seq number has already been
	// seen within the window. Matches GSS_S_DUPLICATE_TOKEN. RFC 2743
	// §1.2.3 classifies this as supplementary (non-fatal); see
	// SecurityContext for how the AD-interop default surfaces it.
	SeqStatusDuplicate
)

// String returns the GSS supplementary status name for s.
func (s SeqStatus) String() string {
	switch s {
	case SeqStatusOK:
		return "OK"
	case SeqStatusGap:
		return "Gap"
	case SeqStatusUnsequenced:
		return "Unsequenced"
	case SeqStatusOld:
		return "Old"
	case SeqStatusDuplicate:
		return "Duplicate"
	default:
		return fmt.Sprintf("SeqStatus(%d)", int(s))
	}
}

// seqWindowSize is the number of past-slot bits tracked by recvmap.
const seqWindowSize = 64

// newSeqState returns a tracker anchored at base. replayDetect and
// sequenceDetect correspond to GSS_C_REPLAY_FLAG and GSS_C_SEQUENCE_FLAG
// per RFC 2743; when both are false, check always returns SeqStatusOK
// without updating state.
func newSeqState(base uint64, replayDetect, sequenceDetect bool) *seqState {
	return &seqState{
		base:       base,
		doReplay:   replayDetect,
		doSequence: sequenceDetect,
	}
}

// check validates seqnum against the sliding window and updates state.
// Callers that want strict in-order enforcement should reject anything
// other than SeqStatusOK. Callers that want AD-interoperable behaviour
// should accept any status except SeqStatusDuplicate.
func (s *seqState) check(seqnum uint64) SeqStatus {
	// No replay or sequence checking requested: accept everything without
	// updating state.
	if !s.doReplay && !s.doSequence {
		return SeqStatusOK
	}

	// uint64 modular arithmetic implements MIT's (seqnum - base) & seqmask.
	rel := seqnum - s.base

	if rel >= s.next {
		// Token is at or ahead of the expected position.
		offset := rel - s.next
		// Left-shift the bitmap by (offset + 1) to "retire" the slots
		// between the old next and the new one. Go's shift is defined
		// for any count: shifts >= 64 produce zero, so we don't need a
		// separate branch for the large-offset case.
		if offset+1 >= seqWindowSize {
			s.recvmap = 0
		} else {
			s.recvmap <<= offset + 1
		}
		s.recvmap |= 1
		s.next = rel + 1
		if offset > 0 && s.doSequence {
			return SeqStatusGap
		}
		return SeqStatusOK
	}

	// Token is in the past relative to next.
	offset := s.next - rel
	if offset > seqWindowSize {
		if s.doSequence {
			return SeqStatusUnsequenced
		}
		return SeqStatusOld
	}

	bit := uint64(1) << (offset - 1)
	if s.doReplay && s.recvmap&bit != 0 {
		return SeqStatusDuplicate
	}
	s.recvmap |= bit
	if s.doSequence {
		return SeqStatusUnsequenced
	}
	return SeqStatusOK
}

// nextExpected returns the absolute sequence number the tracker expects
// next. Exposed for tests and diagnostics.
func (s *seqState) nextExpected() uint64 {
	return s.base + s.next
}
