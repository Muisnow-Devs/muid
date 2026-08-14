package app

import (
	"testing"

	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
	"sanzi.io/muid/internal/signature"
)

func TestNewSessionAccessTokenVerifierAvailability(t *testing.T) {
	t.Parallel()

	manager, err := signature.NewSignatureManager(
		gcpsecretmanager.NewFakeSecretManager("test-project"),
		signature.ManagerConfig{SecretName: "session-signing-key"},
	)
	if err != nil {
		t.Fatalf("NewSignatureManager: %v", err)
	}
	t.Cleanup(func() { _ = manager.Close() })

	tests := []struct {
		name    string
		infra   *InfraDependencies
		wantNil bool
	}{
		{name: "disabled", infra: &InfraDependencies{SignatureManager: manager}, wantNil: true},
		{name: "missing signature manager", infra: &InfraDependencies{GlobalConfig: Config{SessionAccessTokenIssuer: "https://id.test"}}, wantNil: true},
		{name: "configured", infra: &InfraDependencies{
			GlobalConfig:     Config{SessionAccessTokenIssuer: "https://id.test"},
			SignatureManager: manager,
		}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := newSessionAccessTokenVerifier(tc.infra)
			if (got == nil) != tc.wantNil {
				t.Fatalf("verifier nil = %v, want %v", got == nil, tc.wantNil)
			}
		})
	}
}
