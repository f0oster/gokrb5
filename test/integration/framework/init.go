package framework

import (
	"io"
	"log"
	"os"
	"strings"

	tclog "github.com/testcontainers/testcontainers-go/log"
)

// init relaxes Go's x509 negative-serial check process-wide. Samba's
// auto-generated LDAPS cert uses a negative serial; Go 1.23+ rejects
// these at parse time, so the GODEBUG flag is the only way in.
func init() {
	if v := os.Getenv("GODEBUG"); v == "" {
		_ = os.Setenv("GODEBUG", "x509negativeserial=1")
	} else if !strings.Contains(v, "x509negativeserial") {
		_ = os.Setenv("GODEBUG", v+",x509negativeserial=1")
	}
}

// init silences testcontainers' default progress logger. Under
// `go test -v`, testcontainers' own init() routes its logger to
// stderr with build/start/stop chatter; this overrides that. Set
// TC_VERBOSE=1 to keep it.
func init() {
	if os.Getenv("TC_VERBOSE") != "1" {
		tclog.SetDefault(log.New(io.Discard, "", 0))
	}
}
