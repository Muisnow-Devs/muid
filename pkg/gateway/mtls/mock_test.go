package mtls

import (
	"context"
	"crypto/x509"
)

// MockRootProvider is a test double returning a fixed pool (or error).
type MockRootProvider struct {
	Pool *x509.CertPool
	Err  error
}

// Roots implements RootProvider.
func (m MockRootProvider) Roots(context.Context) (*x509.CertPool, error) {
	if m.Err != nil {
		return nil, m.Err
	}
	if m.Pool == nil {
		return nil, ErrNoRoots
	}
	return m.Pool, nil
}
