package gssapi

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/f0oster/gokrb5/iana/nametype"
	"github.com/f0oster/gokrb5/types"
)

func makeAuth(realm, cname string, ct time.Time, cusec int) types.Authenticator {
	return types.Authenticator{
		CRealm: realm,
		CName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{cname},
		},
		CTime: ct,
		Cusec: cusec,
	}
}

func makeSName() types.PrincipalName {
	return types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"HTTP", "host.test"},
	}
}

func TestReplayCache_IsReplay_DifferentRealms(t *testing.T) {
	t.Parallel()
	c := &ReplayCache{entries: make(map[clientKey]clientEntries)}
	now := time.Now().UTC().Truncate(time.Second)
	sname := makeSName()
	a1 := makeAuth("REALM-A", "alice", now, 100)
	a2 := makeAuth("REALM-B", "alice", now, 100)
	if c.IsReplay(sname, a1, []byte("ciphertext-A")) {
		t.Fatalf("first IsReplay returned true")
	}
	if c.IsReplay(sname, a2, []byte("ciphertext-B")) {
		t.Fatalf("same cname in different realm flagged as replay")
	}
}

func TestReplayCache_IsReplay_DetectsReplay(t *testing.T) {
	t.Parallel()
	c := &ReplayCache{entries: make(map[clientKey]clientEntries)}
	now := time.Now().UTC().Truncate(time.Second)
	sname := makeSName()
	a := makeAuth("REALM-A", "alice", now, 100)
	if c.IsReplay(sname, a, []byte("ciphertext-A")) {
		t.Fatalf("first IsReplay returned true")
	}
	if !c.IsReplay(sname, a, []byte("ciphertext-A")) {
		t.Fatalf("second IsReplay should have flagged a replay")
	}
}

func TestReplayCache_IsReplay_DistinctContent(t *testing.T) {
	t.Parallel()
	c := &ReplayCache{entries: make(map[clientKey]clientEntries)}
	now := time.Now().UTC().Truncate(time.Second)
	sname := makeSName()
	a := makeAuth("REALM-A", "alice", now, 100)
	if c.IsReplay(sname, a, []byte("ciphertext-A")) {
		t.Fatalf("first IsReplay returned true")
	}
	if c.IsReplay(sname, a, []byte("ciphertext-B")) {
		t.Fatalf("matching identity+timestamp but distinct ciphertext flagged as replay")
	}
	if !c.IsReplay(sname, a, []byte("ciphertext-A")) {
		t.Fatalf("repeat of same ciphertext should have flagged a replay")
	}
}

func TestReplayCache_IsReplay_TOCTOU(t *testing.T) {
	t.Parallel()
	c := &ReplayCache{entries: make(map[clientKey]clientEntries)}
	now := time.Now().UTC().Truncate(time.Second)
	sname := makeSName()
	a := makeAuth("REALM-A", "alice", now, 100)
	ciphertext := []byte("ciphertext-A")
	const goroutines = 32
	var nonReplay int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if !c.IsReplay(sname, a, ciphertext) {
				atomic.AddInt32(&nonReplay, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if got := atomic.LoadInt32(&nonReplay); got != 1 {
		t.Fatalf("non-replay count = %d, want 1 (TOCTOU race admits multiple)", got)
	}
}
