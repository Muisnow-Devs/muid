package accesstoken

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
	"sanzi.io/muid/internal/oidctoken"
	"sanzi.io/muid/internal/signature"
)

const testIssuer = "https://id.test"

func newTestSignerVerifier(t *testing.T) (context.Context, *oidctoken.Signer, *oidctoken.Verifier) {
	t.Helper()

	ctx := context.Background()
	manager, err := signature.NewSignatureManager(
		gcpsecretmanager.NewFakeSecretManager("test-project"),
		signature.ManagerConfig{SecretName: "signing-key"},
	)
	if err != nil {
		t.Fatalf("NewSignatureManager: %v", err)
	}
	_, err = manager.RotateSecret(ctx)
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}

	return ctx, oidctoken.NewSigner(manager, testIssuer), oidctoken.NewVerifier(manager, testIssuer)
}

// fakeProfileClient serves GetProfile from a canned response; everything else
// is unimplemented.
type fakeProfileClient struct {
	profile *profilepb.GetProfileResponse
}

func (f *fakeProfileClient) GetProfile(
	_ context.Context,
	_ *profilepb.GetProfileRequest,
	_ ...grpc.CallOption,
) (*profilepb.GetProfileResponse, error) {
	if f.profile == nil {
		return nil, status.Error(codes.NotFound, "profile not found")
	}
	return f.profile, nil
}

func (f *fakeProfileClient) CreateProfile(
	context.Context, *profilepb.CreateProfileRequest, ...grpc.CallOption,
) (*profilepb.CreateProfileResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeProfileClient) UpdateProfile(
	context.Context, *profilepb.UpdateProfileRequest, ...grpc.CallOption,
) (*profilepb.UpdateProfileResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeProfileClient) StartAvatarUpload(
	context.Context, *profilepb.StartAvatarUploadRequest, ...grpc.CallOption,
) (*profilepb.StartAvatarUploadResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeProfileClient) CompleteAvatarUpload(
	context.Context, *profilepb.CompleteAvatarUploadRequest, ...grpc.CallOption,
) (*profilepb.CompleteAvatarUploadResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func TestMintWithProfileClaims(t *testing.T) {
	t.Parallel()

	ctx, signer, verifier := newTestSignerVerifier(t)
	userID := uuid.New()

	profile := &profilepb.GetProfileResponse{}
	profile.SetId(userID.String())
	profile.SetEmail("profile@test.example")
	profile.SetDisplayName("Profile Name")
	profile.SetUsername("profileuser")
	profile.SetAvatarUrl("https://img.test/avatar.png")

	minter := NewMinter(signer, &fakeProfileClient{profile: profile}, time.Second, time.Minute)
	tok, err := minter.Mint(ctx, MintInput{UserID: userID, FallbackEmail: "fallback@test.example"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	claims, err := verifier.VerifySessionAccessToken(ctx, tok.GetValue())
	if err != nil {
		t.Fatalf("VerifySessionAccessToken: %v", err)
	}
	if claims.UserID != userID {
		t.Fatalf("sub = %s, want %s", claims.UserID, userID)
	}
	if claims.Email != "profile@test.example" || claims.Name != "Profile Name" ||
		claims.PreferredUsername != "profileuser" || claims.Picture != "https://img.test/avatar.png" {
		t.Fatalf("identity claims = %+v", claims)
	}
	if claims.JTI == uuid.Nil {
		t.Fatal("jti missing")
	}
	// JWT iat/exp carry second precision; the proto timestamps keep nanos.
	if !tok.GetIssuedAt().AsTime().Truncate(time.Second).Equal(claims.IssuedAt) {
		t.Fatalf("proto issued_at = %v, claim iat = %v",
			tok.GetIssuedAt().AsTime(), claims.IssuedAt)
	}
	if !tok.GetExpiresAt().AsTime().Truncate(time.Second).Equal(claims.ExpiresAt) {
		t.Fatalf("proto expires_at = %v, claim exp = %v",
			tok.GetExpiresAt().AsTime(), claims.ExpiresAt)
	}
}

func TestMintDegradesOnProfileFailure(t *testing.T) {
	t.Parallel()

	ctx, signer, verifier := newTestSignerVerifier(t)
	userID := uuid.New()

	tests := []struct {
		name    string
		profile profilepb.ProfileServiceClient
	}{
		{name: "nil client", profile: nil},
		{name: "profile error", profile: &fakeProfileClient{}},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			minter := NewMinter(signer, tc.profile, time.Second, time.Minute)
			tok, err := minter.Mint(ctx, MintInput{
				UserID:        userID,
				FallbackEmail: "fallback@test.example",
			})
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}

			claims, err := verifier.VerifySessionAccessToken(ctx, tok.GetValue())
			if err != nil {
				t.Fatalf("VerifySessionAccessToken: %v", err)
			}
			if claims.Email != "fallback@test.example" {
				t.Fatalf("email = %q, want fallback", claims.Email)
			}
			if claims.Name != "" || claims.PreferredUsername != "" || claims.Picture != "" {
				t.Fatalf("profile claims = %+v, want degraded (empty)", claims)
			}
		})
	}
}

func TestNewMinterClampsTTL(t *testing.T) {
	t.Parallel()

	ctx, signer, verifier := newTestSignerVerifier(t)

	tests := []struct {
		name string
		ttl  time.Duration
		want time.Duration
	}{
		{name: "zero", ttl: 0, want: oidctoken.MaxSessionAccessTokenTTL},
		{name: "negative", ttl: -time.Minute, want: oidctoken.MaxSessionAccessTokenTTL},
		{name: "above max", ttl: time.Hour, want: oidctoken.MaxSessionAccessTokenTTL},
		{name: "in range", ttl: time.Minute, want: time.Minute},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			minter := NewMinter(signer, nil, time.Second, tc.ttl)
			tok, err := minter.Mint(ctx, MintInput{UserID: uuid.New()})
			if err != nil {
				t.Fatalf("Mint: %v", err)
			}

			claims, err := verifier.VerifySessionAccessToken(ctx, tok.GetValue())
			if err != nil {
				t.Fatalf("VerifySessionAccessToken: %v", err)
			}
			if got := claims.ExpiresAt.Sub(claims.IssuedAt); got != tc.want {
				t.Fatalf("lifetime = %v, want %v", got, tc.want)
			}
		})
	}
}
