package spnego

import "net/http"

// SessionMgr stores and retrieves marshaled credentials keyed by a
// caller-chosen string for the request's associated session.
type SessionMgr interface {
	New(w http.ResponseWriter, r *http.Request, k string, v []byte) error
	Get(r *http.Request, k string) ([]byte, error)
}
