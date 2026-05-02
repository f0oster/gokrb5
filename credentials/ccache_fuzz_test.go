package credentials

import (
	"testing"
)

func FuzzCCacheUnmarshal(f *testing.F) {
	f.Add([]byte{0x05, 0x04})
	f.Fuzz(func(t *testing.T, data []byte) {
		var c CCache
		_ = c.Unmarshal(data)
	})
}
