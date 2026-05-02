package messages

import (
	"encoding/hex"
	"testing"

	"github.com/f0oster/gokrb5/test/testdata"
)

func FuzzAPReqUnmarshal(f *testing.F) {
	if seed, err := hex.DecodeString(testdata.MarshaledKRB5ap_req); err == nil {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var a APReq
		_ = a.Unmarshal(data)
	})
}
