package messages

import (
	"encoding/hex"
	"testing"

	"github.com/f0oster/gokrb5/test/testdata"
)

func FuzzASRepUnmarshal(f *testing.F) {
	if seed, err := hex.DecodeString(testdata.MarshaledKRB5as_rep); err == nil {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var a ASRep
		_ = a.Unmarshal(data)
	})
}

func FuzzTGSRepUnmarshal(f *testing.F) {
	if seed, err := hex.DecodeString(testdata.MarshaledKRB5tgs_rep); err == nil {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var a TGSRep
		_ = a.Unmarshal(data)
	})
}
