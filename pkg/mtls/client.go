package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadClientTLSConfig loads a client certificate and the server root CA bundle
// required for mutually authenticated outbound TLS connections.
func LoadClientTLSConfig(certPath, keyPath, rootCAPath string) (*tls.Config, error) {
	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load client key pair: %w", err)
	}

	rootPEM, err := os.ReadFile(rootCAPath)
	if err != nil {
		return nil, fmt.Errorf("read server CA roots: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, ErrNoRoots
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      roots,
	}, nil
}
