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

// LoadServerTLSConfig loads a server certificate and client CA bundle for a
// listener that requires mutually authenticated TLS.
func LoadServerTLSConfig(certPath, keyPath, clientCAPath string) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server key pair: %w", err)
	}

	rootPEM, err := os.ReadFile(clientCAPath)
	if err != nil {
		return nil, fmt.Errorf("read client CA roots: %w", err)
	}
	roots, err := NewStaticRootsFromPEM(rootPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client CA roots: %w", err)
	}
	return ServerTLSConfig(roots, serverCert)
}
