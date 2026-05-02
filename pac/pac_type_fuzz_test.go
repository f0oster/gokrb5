package pac

import (
	"log"
	"os"
	"testing"

	"github.com/f0oster/gokrb5/types"
)

func FuzzPACTypeUnmarshal(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var p PACType
		_ = p.Unmarshal(data)
	})
}

func FuzzProcessPACInfoBuffers(f *testing.F) {
	logger := log.New(os.Stderr, "", 0)
	f.Fuzz(func(t *testing.T, data []byte) {
		var p PACType
		if err := p.Unmarshal(data); err != nil {
			return
		}
		_ = p.ProcessPACInfoBuffers(types.EncryptionKey{}, logger)
	})
}
