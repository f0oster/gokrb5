package gssapi

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/f0oster/gokrb5/types"
)

// ReplayCache implements the RFC 4120 §3.2.3 server-side replay
// detection cache. Entries are keyed by client principal + realm,
// authenticator timestamp, and a SHA-256 hash of the encrypted
// authenticator ciphertext.
type ReplayCache struct {
	entries map[clientKey]clientEntries
	mux     sync.Mutex
}

// clientKey identifies a client uniquely within the replay cache.
// Including the realm prevents same-name principals in different realms
// from colliding.
type clientKey struct {
	cname  string
	crealm string
}

// clientEntries holds entries of client details sent to the service.
type clientEntries struct {
	replayMap map[entryKey]replayCacheEntry
}

// entryKey identifies a single authenticator within a client's entries.
// The contentHash distinguishes two distinct authenticators that share
// a (cname, crealm, ctime+cusec) tuple by including a hash of the
// encrypted authenticator bytes.
type entryKey struct {
	ct          time.Time
	contentHash [sha256.Size]byte
}

// replayCacheEntry tracks the timestamps recorded for a stored authenticator.
type replayCacheEntry struct {
	presentedTime time.Time
	sName         types.PrincipalName
	cTime         time.Time // This combines the ticket's CTime and Cusec
}

// Process-wide singleton shared by Acceptors that don't override via
// WithReplayCache.
var (
	replayCache *ReplayCache
	once        sync.Once
)

// NewReplayCache creates a ReplayCache and starts a background goroutine
// that periodically purges entries older than d.
func NewReplayCache(d time.Duration) *ReplayCache {
	c := &ReplayCache{entries: make(map[clientKey]clientEntries)}
	go func() {
		for {
			time.Sleep(d)
			c.ClearOldEntries(d)
		}
	}()
	return c
}

// GetReplayCache returns the process-wide ReplayCache singleton, lazily
// initialized on first call with TTL d. Subsequent calls reuse the
// singleton; their d is ignored.
func GetReplayCache(d time.Duration) *ReplayCache {
	once.Do(func() {
		replayCache = NewReplayCache(d)
	})
	return replayCache
}

// keyOf returns the realm-aware map key for an authenticator.
func keyOf(a types.Authenticator) clientKey {
	return clientKey{cname: a.CName.PrincipalNameString(), crealm: a.CRealm}
}

// ClearOldEntries removes entries from the cache that are older than d.
func (c *ReplayCache) ClearOldEntries(d time.Duration) {
	c.mux.Lock()
	defer c.mux.Unlock()
	for ke, ce := range c.entries {
		for k, e := range ce.replayMap {
			if time.Now().UTC().Sub(e.presentedTime) > d {
				delete(ce.replayMap, k)
			}
		}
		if len(ce.replayMap) == 0 {
			delete(c.entries, ke)
		}
	}
}

// IsReplay tests whether the authenticator has been seen before. The
// match keys on client identity, server name, ticket timestamp, and a
// SHA-256 hash of the encrypted authenticator bytes; two distinct
// authenticators with matching timestamps differ on the ciphertext
// hash and so do not collide. The check and the add happen under a
// single lock so concurrent callers presenting the same authenticator
// see exactly one non-replay outcome.
func (c *ReplayCache) IsReplay(sname types.PrincipalName, a types.Authenticator, ciphertext []byte) bool {
	hash := sha256.Sum256(ciphertext)
	c.mux.Lock()
	defer c.mux.Unlock()
	ct := a.CTime.Add(time.Duration(a.Cusec) * time.Microsecond)
	k := keyOf(a)
	ek := entryKey{ct: ct, contentHash: hash}
	if ce, ok := c.entries[k]; ok {
		if e, ok := ce.replayMap[ek]; ok && e.sName.Equal(sname) {
			return true
		}
	}
	entry := replayCacheEntry{
		presentedTime: time.Now().UTC(),
		sName:         sname,
		cTime:         ct,
	}
	if ce, ok := c.entries[k]; ok {
		ce.replayMap[ek] = entry
		return false
	}
	c.entries[k] = clientEntries{
		replayMap: map[entryKey]replayCacheEntry{ek: entry},
	}
	return false
}
