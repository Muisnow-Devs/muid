package authngrpc

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
	"sanzi.io/muid/internal/authn/accesstoken"
	"sanzi.io/muid/internal/oidctoken"
	"sanzi.io/muid/internal/signature"
)

func TestIssueAccessTokenUnavailable(t *testing.T) {
	t.Parallel()

	handler := &GRPCHandler{}
	_, err := handler.IssueAccessToken(context.Background(), nil)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("IssueAccessToken code = %v, want %v", status.Code(err), codes.Unavailable)
	}
}

func TestIssueAccessTokenRequiresResolvedSession(t *testing.T) {
	t.Parallel()

	manager, err := signature.NewSignatureManager(
		gcpsecretmanager.NewFakeSecretManager("test-project"),
		signature.ManagerConfig{SecretName: "signing-key"},
	)
	if err != nil {
		t.Fatalf("NewSignatureManager: %v", err)
	}
	_, err = manager.RotateSecret(context.Background())
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	handler := &GRPCHandler{
		accessTokens: accesstoken.NewMinter(
			oidctoken.NewSigner(manager, "https://id.test"), nil, time.Second, time.Minute),
	}
	// No resolved session on the context (interceptor not in play here).
	_, err = handler.IssueAccessToken(context.Background(), nil)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("IssueAccessToken code = %v, want %v", status.Code(err), codes.Unauthenticated)
	}
}
