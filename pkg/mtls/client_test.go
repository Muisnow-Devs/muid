package mtls_test

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"sanzi.io/muid/pkg/mtls"
)

func TestLoadClientTLSConfig(t *testing.T) {
	t.Parallel()

	server := makeCA(t, "server")
	client := makeCA(t, "client")
	certPath, keyPath := writeCertificatePair(t, client)
	rootPath := filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(rootPath, server.caPEM, 0o600); err != nil {
		t.Fatalf("write server CA: %v", err)
	}

	config, err := mtls.LoadClientTLSConfig(certPath, keyPath, rootPath)
	if err != nil {
		t.Fatalf("LoadClientTLSConfig: %v", err)
	}
	if config.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d", config.MinVersion, tls.VersionTLS12)
	}
	if config.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is enabled")
	}
	if len(config.Certificates) != 1 {
		t.Errorf("Certificates length = %d, want 1", len(config.Certificates))
	}
	if config.RootCAs == nil {
		t.Fatal("RootCAs is nil")
	}

	clientConfig := config.Clone()
	clientConfig.ServerName = "localhost"
	if err := handshake(t, mustServerTLSConfig(t, client.caPEM, server.tls), clientConfig); err != nil {
		t.Fatalf("verified mTLS handshake: %v", err)
	}
}

func TestLoadClientTLSConfigRejectsInvalidRoots(t *testing.T) {
	t.Parallel()

	client := makeCA(t, "client")
	certPath, keyPath := writeCertificatePair(t, client)
	rootPath := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(rootPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write roots: %v", err)
	}
	if _, err := mtls.LoadClientTLSConfig(certPath, keyPath, rootPath); err == nil {
		t.Fatal("LoadClientTLSConfig succeeded with invalid roots")
	}
}

func writeCertificatePair(t *testing.T, pair certPair) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(certPath, pair.caPEM, 0o600); err != nil {
		t.Fatalf("write client certificate: %v", err)
	}

	if err := os.WriteFile(keyPath, pair.keyPEM, 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	return certPath, keyPath
}

func mustServerTLSConfig(t *testing.T, clientCAPEM []byte, serverCert tls.Certificate) *tls.Config {
	t.Helper()
	roots, err := mtls.NewStaticRootsFromPEM(clientCAPEM)
	if err != nil {
		t.Fatalf("NewStaticRootsFromPEM: %v", err)
	}
	config, err := mtls.ServerTLSConfig(roots, serverCert)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	return config
}
