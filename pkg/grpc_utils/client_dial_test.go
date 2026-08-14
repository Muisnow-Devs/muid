package grpcutils

import (
	"crypto/tls"
	"testing"
)

func TestDialTLSClientRejectsNilConfig(t *testing.T) {
	t.Parallel()

	conn, err := DialTLSClient("localhost:443", nil, ClientResilienceConfig{})
	if err == nil {
		conn.Close()
		t.Fatal("DialTLSClient succeeded with nil config")
	}
}

func TestDialTLSClientRejectsEmptyTarget(t *testing.T) {
	t.Parallel()

	conn, err := DialTLSClient("  ", &tls.Config{MinVersion: tls.VersionTLS12}, ClientResilienceConfig{})
	if err == nil {
		conn.Close()
		t.Fatal("DialTLSClient succeeded with empty target")
	}
}
