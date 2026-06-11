package app

import (
	"context"
	"strings"
	"testing"
)

func TestWireSignatureManagerValidation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		cfg         Config
		wantErrPart string
	}{
		{
			name: "no signing features configured",
			cfg:  Config{},
		},
		{
			name:        "oidc provider requires secret name",
			cfg:         Config{OIDCIssuer: "https://id.example.com"},
			wantErrPart: "AUTHN_OIDC_ISSUER",
		},
		{
			name:        "session access tokens require secret name",
			cfg:         Config{SessionAccessTokenIssuer: "https://id.example.com"},
			wantErrPart: "AUTHN_SESSION_ACCESS_TOKEN_ISSUER",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			deps := &InfraDependencies{}
			err := wireSignatureManager(context.Background(), tc.cfg, deps)
			if tc.wantErrPart == "" {
				if err != nil {
					t.Fatalf("wireSignatureManager error = %v", err)
				}
				if deps.SignatureManager != nil {
					t.Fatal("SignatureManager wired without signing config")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErrPart) {
				t.Fatalf("wireSignatureManager error = %v, want mention of %q", err, tc.wantErrPart)
			}
		})
	}
}
