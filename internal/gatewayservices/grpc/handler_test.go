package servicesgrpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	gatewaypb "sanzi.io/muid/api/proto/gateway/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/jwtauth"
)

type fakeProfile struct {
	profilepb.ProfileServiceClient
	gotUserIDs []string
}

func (f *fakeProfile) GetProfile(ctx context.Context, req *profilepb.GetProfileRequest, _ ...grpc.CallOption) (*profilepb.GetProfileResponse, error) {
	if md, ok := metadata.FromOutgoingContext(ctx); ok {
		f.gotUserIDs = append([]string(nil), md.Get(httpmeta.UserIDKey)...)
	}
	resp := &profilepb.GetProfileResponse{}
	resp.SetId(req.GetId())
	resp.SetUsername("alice")
	resp.SetDisplayName("Alice")
	resp.SetEmail("alice@test")
	return resp, nil
}

func TestGetMeRequiresAuth(t *testing.T) {
	t.Parallel()

	h := NewHandler(&fakeProfile{})
	_, err := h.GetMe(context.Background(), &gatewaypb.GetMeRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestGetMeReturnsProfileAndForwardsIdentity(t *testing.T) {
	t.Parallel()

	profile := &fakeProfile{}
	h := NewHandler(profile)
	sub := uuid.New()
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		httpmeta.UserIDKey, uuid.NewString(),
		httpmeta.UserIDKey, uuid.NewString(),
	))
	ctx = jwtauth.WithClaims(ctx, jwtauth.Claims{UserID: sub})

	resp, err := h.GetMe(ctx, &gatewaypb.GetMeRequest{})
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	if got := resp.GetUser().GetId(); got != sub.String() {
		t.Fatalf("user id = %q, want %q", got, sub.String())
	}
	if resp.GetUser().GetUsername() != "alice" {
		t.Fatalf("username = %q", resp.GetUser().GetUsername())
	}
	if len(profile.gotUserIDs) != 1 || profile.gotUserIDs[0] != sub.String() {
		t.Fatalf("profile received x-user-id values %v, want [%q]", profile.gotUserIDs, sub.String())
	}
}
