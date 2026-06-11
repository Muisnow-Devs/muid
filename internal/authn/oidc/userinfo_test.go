package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
)

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return out
}

// issueTokensWithScopes runs the full code flow for the given scopes.
func issueTokensWithScopes(
	t *testing.T,
	ctx context.Context,
	fx providerFixture,
	scopes []string,
) TokenOutput {
	t.Helper()

	user := &SessionUser{UserID: fx.userID, SessionID: uuid.New(), AuthTime: time.Now()}
	verifier, challenge := pkcePair()
	in := authorizeInput(challenge)
	in.Scopes = scopes

	result, err := fx.provider.Authorize(ctx, in, user)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	outcome, err := fx.provider.DecideConsent(ctx, *user, result.Consent.AuthorizationID, true)
	if err != nil {
		t.Fatalf("DecideConsent: %v", err)
	}
	tokens, err := fx.provider.ExchangeToken(ctx, ExchangeInput{
		ClientID: "client-abc",
		Code: &CodeGrantInput{
			Code:         outcome.Granted.Code,
			RedirectURI:  "https://app.test/cb",
			CodeVerifier: verifier,
		},
	})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	return tokens
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

func TestUserInfoFromProfileService(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcprofileinfo")

	profile := &profilepb.GetProfileResponse{}
	profile.SetId(fx.userID.String())
	profile.SetEmail("profile@test.example")
	profile.SetDisplayName("Profile Name")
	profile.SetUsername("profileuser")
	profile.SetAvatarUrl("https://img.test/avatar.png")
	profile.SetLocale("zh-TW")
	profile.SetTimezone("Asia/Taipei")
	fx.provider.profile = &fakeProfileClient{profile: profile}

	tokens := issueTokensWithScopes(t, ctx, fx, []string{ScopeOpenID, ScopeProfile, ScopeEmail})

	info, err := fx.provider.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}

	stringChecks := []struct {
		name string
		got  *string
		want string
	}{
		{name: "name", got: info.Name, want: "Profile Name"},
		{name: "picture", got: info.Picture, want: "https://img.test/avatar.png"},
		{name: "preferred_username", got: info.PreferredUsername, want: "profileuser"},
		{name: "locale", got: info.Locale, want: "zh-TW"},
		{name: "zoneinfo", got: info.Zoneinfo, want: "Asia/Taipei"},
		{name: "email", got: info.Email, want: "profile@test.example"},
	}
	for _, check := range stringChecks {
		if check.got == nil || *check.got != check.want {
			t.Fatalf("claim %s = %v, want %q", check.name, check.got, check.want)
		}
	}
	if info.EmailVerified == nil || !*info.EmailVerified {
		t.Fatalf("email_verified = %v, want true", info.EmailVerified)
	}

	// The ID token from the flow carries the same profile-sourced claims.
	payload := decodeJWTPayload(t, tokens.IDToken)
	for claim, want := range map[string]string{
		"name":               "Profile Name",
		"preferred_username": "profileuser",
		"locale":             "zh-TW",
		"zoneinfo":           "Asia/Taipei",
		"email":              "profile@test.example",
	} {
		if payload[claim] != want {
			t.Fatalf("id token claim %q = %v, want %q", claim, payload[claim], want)
		}
	}
}

func TestUserInfoScopeGating(t *testing.T) {
	t.Parallel()

	ctx, fx := newProviderFixture(t, "oidcscopegate")

	profile := &profilepb.GetProfileResponse{}
	profile.SetId(fx.userID.String())
	profile.SetEmail("profile@test.example")
	profile.SetDisplayName("Profile Name")
	fx.provider.profile = &fakeProfileClient{profile: profile}

	// openid + email only: no profile claims.
	tokens := issueTokensForTest(t, ctx, fx)
	info, err := fx.provider.UserInfo(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if info.Name != nil || info.PreferredUsername != nil {
		t.Fatalf("profile claims leaked without profile scope: %+v", info)
	}
	if info.Email == nil || *info.Email != "profile@test.example" {
		t.Fatalf("email = %v, want profile@test.example", info.Email)
	}
}
