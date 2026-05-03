package gssapi

import (
	"encoding/binary"
	"strings"
	"testing"
)

func gssChecksumNoDeleg(bnd [16]byte, flags uint32) []byte {
	out := make([]byte, 24)
	binary.LittleEndian.PutUint32(out[0:4], 16)
	copy(out[4:20], bnd[:])
	binary.LittleEndian.PutUint32(out[20:24], flags)
	return out
}

func gssChecksumWithDeleg(bnd [16]byte, flags uint32, dlgOpt uint16, deleg []byte) []byte {
	out := make([]byte, 28+len(deleg))
	binary.LittleEndian.PutUint32(out[0:4], 16)
	copy(out[4:20], bnd[:])
	binary.LittleEndian.PutUint32(out[20:24], flags)
	binary.LittleEndian.PutUint16(out[24:26], dlgOpt)
	binary.LittleEndian.PutUint16(out[26:28], uint16(len(deleg)))
	copy(out[28:], deleg)
	return out
}

func TestParseGSSChecksum_NoDelegation(t *testing.T) {
	t.Parallel()
	var bnd [16]byte
	for i := range bnd {
		bnd[i] = byte(i)
	}
	cs, err := ParseGSSChecksum(gssChecksumNoDeleg(bnd, 0x36))
	if err != nil {
		t.Fatalf("ParseGSSChecksum: %v", err)
	}
	if cs.Bnd != bnd {
		t.Fatalf("Bnd = %x, want %x", cs.Bnd, bnd)
	}
	if cs.Flags != 0x36 {
		t.Fatalf("Flags = %#x, want 0x36", cs.Flags)
	}
	if cs.DlgOpt != 0 || cs.Deleg != nil {
		t.Fatalf("delegation fields set on a no-delegation checksum: DlgOpt=%d Deleg=%x", cs.DlgOpt, cs.Deleg)
	}
}

func TestParseGSSChecksum_WithDelegation(t *testing.T) {
	t.Parallel()
	var bnd [16]byte
	deleg := []byte("forwarded-tgt-bytes")
	cs, err := ParseGSSChecksum(gssChecksumWithDeleg(bnd, 0, 1, deleg))
	if err != nil {
		t.Fatalf("ParseGSSChecksum: %v", err)
	}
	if cs.DlgOpt != 1 {
		t.Fatalf("DlgOpt = %d, want 1", cs.DlgOpt)
	}
	if string(cs.Deleg) != string(deleg) {
		t.Fatalf("Deleg = %q, want %q", cs.Deleg, deleg)
	}
}

func TestParseGSSChecksum_TooShort(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 23} {
		_, err := ParseGSSChecksum(make([]byte, n))
		if err == nil {
			t.Fatalf("expected error on %d-byte input", n)
		}
		if !strings.Contains(err.Error(), "too short") {
			t.Fatalf("error on %d-byte input does not mention 'too short': %v", n, err)
		}
	}
}

func TestParseGSSChecksum_WrongLgth(t *testing.T) {
	t.Parallel()
	bad := make([]byte, 24)
	binary.LittleEndian.PutUint32(bad[0:4], 17) // RFC says 16
	_, err := ParseGSSChecksum(bad)
	if err == nil || !strings.Contains(err.Error(), "Lgth") {
		t.Fatalf("expected Lgth error, got %v", err)
	}
}

func TestParseGSSChecksum_TruncatedDelegationHeader(t *testing.T) {
	t.Parallel()
	// 26 bytes: full prefix + 2 bytes of DlgOpt but missing Dlgth.
	bad := make([]byte, 26)
	binary.LittleEndian.PutUint32(bad[0:4], 16)
	_, err := ParseGSSChecksum(bad)
	if err == nil || !strings.Contains(err.Error(), "delegation header truncated") {
		t.Fatalf("expected truncated-header error, got %v", err)
	}
}

func TestParseGSSChecksum_DelegationOverflow(t *testing.T) {
	t.Parallel()
	// 28 bytes: full delegation header but Dlgth claims 100 bytes that
	// don't exist.
	bad := make([]byte, 28)
	binary.LittleEndian.PutUint32(bad[0:4], 16)
	binary.LittleEndian.PutUint16(bad[26:28], 100)
	_, err := ParseGSSChecksum(bad)
	if err == nil || !strings.Contains(err.Error(), "exceeds remaining") {
		t.Fatalf("expected Dlgth-overflow error, got %v", err)
	}
}
