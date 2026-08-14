package authngrpc

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	pb "sanzi.io/muid/api/proto/authn/v1"
	sessionpb "sanzi.io/muid/api/proto/authn/v1/session"
	"sanzi.io/muid/internal/identity/issuer"
	"sanzi.io/muid/internal/session"
)

func TestGetSessionPrincipalReturnsCredentialFreePrincipal(t *testing.T) {
	t.Parallel()

	issuedAt := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	expiresAt := issuedAt.Add(time.Hour)
	userID := uuid.New()
	handler := &GRPCHandler{issuer: &mockSessionIssuer{resolved: issuer.ResolvedSession{
		UserID:    userID,
		Email:     "private@example.test",
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}}}
	wire := validWireToken(t)
	resp, err := handler.GetSessionPrincipal(
		ctxWithHeaderToken(t, wire),
		&pb.GetSessionPrincipalRequest{},
	)
	if err != nil {
		t.Fatalf("GetSessionPrincipal() error = %v", err)
	}
	if !resp.GetValid() {
		t.Fatal("GetSessionPrincipal() valid = false, want true")
	}
	principal := resp.GetPrincipal()
	if principal.GetUserId() != userID.String() {
		t.Errorf("user id = %q, want %q", principal.GetUserId(), userID)
	}
	if principal.GetAuthLevel() != sessionpb.AuthLevel_AUTH_LEVEL_MEDIUM {
		t.Errorf("auth level = %v, want medium", principal.GetAuthLevel())
	}
	if !principal.GetIssuedAt().AsTime().Equal(issuedAt) {
		t.Errorf("issued at = %v, want %v", principal.GetIssuedAt(), issuedAt)
	}
	if !principal.GetExpiresAt().AsTime().Equal(expiresAt) {
		t.Errorf("expires at = %v, want %v", principal.GetExpiresAt(), expiresAt)
	}

	wireJSON, err := protojson.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	for _, secret := range []string{wire, "private@example.test", "sessionToken", "accessToken"} {
		if strings.Contains(string(wireJSON), secret) {
			t.Errorf("response contains credential/private value %q: %s", secret, wireJSON)
		}
	}
}

func TestGetSessionPrincipalInvalidSessionReturnsInvalid(t *testing.T) {
	t.Parallel()

	handler := &GRPCHandler{issuer: &mockSessionIssuer{err: session.ErrSessionExpired}}
	resp, err := handler.GetSessionPrincipal(
		ctxWithHeaderToken(t, validWireToken(t)),
		&pb.GetSessionPrincipalRequest{},
	)
	if err != nil {
		t.Fatalf("GetSessionPrincipal() error = %v", err)
	}
	if resp.GetValid() {
		t.Fatal("GetSessionPrincipal() valid = true, want false")
	}
	if resp.GetPrincipal() != nil {
		t.Fatalf("GetSessionPrincipal() principal = %v, want nil", resp.GetPrincipal())
	}
}

func TestGetSessionPrincipalMissingTokenReturnsInvalid(t *testing.T) {
	t.Parallel()

	handler := &GRPCHandler{issuer: &mockSessionIssuer{}}
	resp, err := handler.GetSessionPrincipal(context.Background(), &pb.GetSessionPrincipalRequest{})
	if err != nil {
		t.Fatalf("GetSessionPrincipal() error = %v", err)
	}
	if resp.GetValid() || resp.GetPrincipal() != nil {
		t.Fatalf("GetSessionPrincipal() = %+v, want invalid without principal", resp)
	}
}
