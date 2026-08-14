package app

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

func TestRequireAdminIngressWorkload(t *testing.T) {
	t.Parallel()

	config := requireAdminIngressWorkload(&tls.Config{})
	tests := []struct {
		name    string
		state   tls.ConnectionState
		wantErr bool
	}{
		{name: "admin ingress", state: workloadTLSState(t, grpcutils.WorkloadAdminIngress)},
		{name: "gateway internal rejected", state: workloadTLSState(t, grpcutils.WorkloadGatewayInternal), wantErr: true},
		{name: "unverified rejected", state: tls.ConnectionState{}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := config.VerifyConnection(test.state)
			if (err != nil) != test.wantErr {
				t.Fatalf("VerifyConnection() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestRequireAdminIngressWorkloadWrapsSelectedTLSConfig(t *testing.T) {
	t.Parallel()

	base := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{}, nil
		},
	}
	config := requireAdminIngressWorkload(base)
	selected, err := config.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient() error = %v", err)
	}
	if selected.VerifyConnection == nil {
		t.Fatal("selected TLS config lost the workload verifier")
	}
	if err := selected.VerifyConnection(workloadTLSState(t, grpcutils.WorkloadAuthn)); err == nil {
		t.Fatal("selected TLS config accepted the authn workload")
	}
	if err := selected.VerifyConnection(workloadTLSState(t, grpcutils.WorkloadAdminIngress)); err != nil {
		t.Fatalf("selected TLS config rejected admin-ingress: %v", err)
	}
}

func workloadTLSState(t *testing.T, workload grpcutils.WorkloadID) tls.ConnectionState {
	t.Helper()
	uri, err := url.Parse("spiffe://muid/service/" + string(workload))
	if err != nil {
		t.Fatalf("parse workload URI: %v", err)
	}
	leaf := &x509.Certificate{URIs: []*url.URL{uri}}
	return tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf}}}
}
