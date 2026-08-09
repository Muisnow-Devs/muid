package mtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"sanzi.io/muid/pkg/mtls"
)

type certPair struct {
	tls    tls.Certificate
	leaf   *x509.Certificate
	caPEM  []byte
	keyPEM []byte
}

// makeCA creates a self-signed CA usable both as the server cert and as the
// signer/root for client certs (sufficient for handshake tests).
func makeCA(t *testing.T, cn string) certPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("x509 pair: %v", err)
	}
	return certPair{tls: pair, leaf: leaf, caPEM: certPEM, keyPEM: keyPEM}
}

func handshake(t *testing.T, serverCfg *tls.Config, clientCfg *tls.Config) error {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	errCh := make(chan error, 1)
	go func() {
		s := tls.Server(serverConn, serverCfg)
		_ = s.SetDeadline(time.Now().Add(2 * time.Second))
		errCh <- s.Handshake()
	}()

	c := tls.Client(clientConn, clientCfg)
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	clientErr := c.Handshake()
	serverErr := <-errCh

	return errors.Join(clientErr, serverErr)
}

func TestServerTLSConfigAcceptsValidClient(t *testing.T) {
	t.Parallel()

	server := makeCA(t, "server")
	client := makeCA(t, "client")

	roots, err := mtls.NewStaticRootsFromPEM(client.caPEM)
	if err != nil {
		t.Fatalf("roots: %v", err)
	}
	serverCfg, err := mtls.ServerTLSConfig(roots, server.tls)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	clientCfg := &tls.Config{
		Certificates:       []tls.Certificate{client.tls},
		InsecureSkipVerify: true, // we are testing client-auth, not server-name
	}
	if err := handshake(t, serverCfg, clientCfg); err != nil {
		t.Fatalf("expected successful mTLS handshake, got %v", err)
	}
}

func TestServerTLSConfigRejectsMissingClientCert(t *testing.T) {
	t.Parallel()

	server := makeCA(t, "server")
	client := makeCA(t, "client")

	roots, err := mtls.NewStaticRootsFromPEM(client.caPEM)
	if err != nil {
		t.Fatalf("roots: %v", err)
	}
	serverCfg, err := mtls.ServerTLSConfig(roots, server.tls)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	clientCfg := &tls.Config{InsecureSkipVerify: true} // no client cert presented
	if err := handshake(t, serverCfg, clientCfg); err == nil {
		t.Fatal("expected handshake to fail without a client certificate")
	}
}

func TestNewStaticRootsRejectsGarbage(t *testing.T) {
	t.Parallel()

	if _, err := mtls.NewStaticRootsFromPEM([]byte("not a pem")); !errors.Is(err, mtls.ErrNoRoots) {
		t.Fatalf("expected ErrNoRoots, got %v", err)
	}
}

func TestServerTLSConfigRequiresProvider(t *testing.T) {
	t.Parallel()

	server := makeCA(t, "server")
	if _, err := mtls.ServerTLSConfig(nil, server.tls); !errors.Is(err, mtls.ErrNoRoots) {
		t.Fatalf("expected ErrNoRoots for nil provider, got %v", err)
	}
	if _, err := mtls.ServerTLSConfig(mtls.MockRootProvider{Err: mtls.ErrNoRoots}, server.tls); !errors.Is(err, mtls.ErrNoRoots) {
		t.Fatalf("expected ErrNoRoots from provider, got %v", err)
	}
}
