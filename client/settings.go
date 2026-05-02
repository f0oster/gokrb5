package client

import (
	"encoding/json"
	"fmt"
	"log"
	"sync/atomic"
)

// Settings holds optional client settings.
type Settings struct {
	assumePreAuthentication atomic.Bool
	preAuthEType            atomic.Int32
	logger                  *log.Logger
	maxKDCResponseBytes     int
}

// jsonSettings is used when marshaling the Settings details to JSON format.
type jsonSettings struct {
	AssumePreAuthentication bool
	MaxKDCResponseBytes     int
}

// DefaultMaxKDCResponseBytes is the default cap for a KDC TCP response.
const DefaultMaxKDCResponseBytes = 1 << 20 // 1 MiB

// NewSettings creates a new client settings struct.
func NewSettings(settings ...func(*Settings)) *Settings {
	s := &Settings{maxKDCResponseBytes: DefaultMaxKDCResponseBytes}
	for _, set := range settings {
		set(s)
	}
	return s
}

// AssumePreAuthentication used to configure the client to assume pre-authentication is required.
//
// s := NewSettings(AssumePreAuthentication(true))
func AssumePreAuthentication(b bool) func(*Settings) {
	return func(s *Settings) {
		s.assumePreAuthentication.Store(b)
	}
}

// AssumePreAuthentication indicates if the client should proactively assume using pre-authentication.
func (s *Settings) AssumePreAuthentication() bool {
	return s.assumePreAuthentication.Load()
}

// Logger used to configure client with a logger.
//
// s := NewSettings(kt, Logger(l))
func Logger(l *log.Logger) func(*Settings) {
	return func(s *Settings) {
		s.logger = l
	}
}

// Logger returns the client logger instance.
func (s *Settings) Logger() *log.Logger {
	return s.logger
}

// MaxKDCResponseBytes sets the cap on a KDC TCP response.
//
// s := NewSettings(MaxKDCResponseBytes(2 << 20))
func MaxKDCResponseBytes(n int) func(*Settings) {
	return func(s *Settings) {
		s.maxKDCResponseBytes = n
	}
}

// MaxKDCResponseBytes returns the configured cap for a KDC TCP response.
func (s *Settings) MaxKDCResponseBytes() int {
	return s.maxKDCResponseBytes
}

// Log will write to the service's logger if it is configured.
func (cl *Client) Log(format string, v ...interface{}) {
	if cl.settings.Logger() != nil {
		cl.settings.Logger().Output(2, fmt.Sprintf(format, v...))
	}
}

// JSON returns a JSON representation of the settings.
func (s *Settings) JSON() (string, error) {
	js := jsonSettings{
		AssumePreAuthentication: s.assumePreAuthentication.Load(),
		MaxKDCResponseBytes:     s.maxKDCResponseBytes,
	}
	b, err := json.MarshalIndent(js, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil

}
