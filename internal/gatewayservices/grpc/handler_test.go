package servicesgrpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	gatewaypb "sanzi.io/muid/api/proto/gateway/v1"
	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
)

type fakeAccount struct {
	authnpb.AccountServiceClient
	get func(context.Context, *authnpb.GetMyAccountRequest) (*authnpb.GetMyAccountResponse, error)
}

func (f *fakeAccount) GetMyAccount(
	ctx context.Context,
	req *authnpb.GetMyAccountRequest,
	_ ...grpc.CallOption,
) (*authnpb.GetMyAccountResponse, error) {
	return f.get(ctx, req)
}

type fakeProfile struct {
	profilepb.ProfileServiceClient
	get func(context.Context, *profilepb.GetProfileRequest) (*profilepb.GetProfileResponse, error)
}

func (f *fakeProfile) GetProfile(
	ctx context.Context,
	req *profilepb.GetProfileRequest,
	_ ...grpc.CallOption,
) (*profilepb.GetProfileResponse, error) {
	return f.get(ctx, req)
}

type staticKeySource struct {
	kid string
	key *rsa.PublicKey
}

func (s staticKeySource) Keys(context.Context) (map[string]*rsa.PublicKey, error) {
	return map[string]*rsa.PublicKey{s.kid: s.key}, nil
}

func TestGetMeRequiresClaimsAndRawBearer(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	h := NewHandler(&fakeAccount{get: func(context.Context, *authnpb.GetMyAccountRequest) (*authnpb.GetMyAccountResponse, error) {
		t.Fatal("account called without complete authentication context")
		return nil, nil
	}}, &fakeProfile{get: func(context.Context, *profilepb.GetProfileRequest) (*profilepb.GetProfileResponse, error) {
		t.Fatal("profile called without complete authentication context")
		return nil, nil
	}})
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{name: "missing claims and bearer", ctx: context.Background()},
		{name: "missing raw bearer", ctx: jwtauth.WithClaims(context.Background(), jwtauth.Claims{UserID: userID})},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := h.GetMe(tc.ctx, &gatewaypb.GetMeRequest{})
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("code = %v, want Unauthenticated", status.Code(err))
			}
		})
	}
}

func TestGetMeComposesAccountAndProfileWithIsolatedMetadata(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	base := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(
		httpmeta.UserIDKey, uuid.NewString(),
		httpmeta.UserIDKey, uuid.NewString(),
		grpcutils.AuthorizationMetadataKey, "Bearer inherited-one",
		grpcutils.AuthorizationMetadataKey, "Bearer inherited-two",
		"x-trace-id", "trace",
	))
	ctx, raw := verifiedContext(t, base, userID)
	var accountMD, profileMD metadata.MD
	order := make([]string, 0, 2)
	accountClient := &fakeAccount{get: func(ctx context.Context, _ *authnpb.GetMyAccountRequest) (*authnpb.GetMyAccountResponse, error) {
		order = append(order, "account")
		accountMD, _ = metadata.FromOutgoingContext(ctx)
		accountMD = accountMD.Copy()
		return accountResponse(userID, authnpb.AccountStatus_ACCOUNT_STATUS_ACTIVE, "account@example.com", true), nil
	}}
	profileClient := &fakeProfile{get: func(ctx context.Context, req *profilepb.GetProfileRequest) (*profilepb.GetProfileResponse, error) {
		order = append(order, "profile")
		profileMD, _ = metadata.FromOutgoingContext(ctx)
		profileMD = profileMD.Copy()
		if req.GetId() != userID.String() {
			t.Fatalf("profile request id = %q, want %q", req.GetId(), userID)
		}
		resp := &profilepb.GetProfileResponse{}
		resp.SetId(userID.String())
		resp.SetUsername("alice")
		resp.SetDisplayName("Alice")
		resp.SetEmail("profile@example.com")
		resp.SetAvatarUrl("https://img.example/alice.png")
		return resp, nil
	}}

	resp, err := NewHandler(accountClient, profileClient).GetMe(ctx, &gatewaypb.GetMeRequest{})
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	if len(order) != 2 || order[0] != "account" || order[1] != "profile" {
		t.Fatalf("call order = %v, want [account profile]", order)
	}
	assertMetadataValues(t, accountMD, httpmeta.UserIDKey, userID.String())
	assertMetadataValues(t, accountMD, grpcutils.AuthorizationMetadataKey, "Bearer "+raw)
	assertMetadataValues(t, profileMD, httpmeta.UserIDKey, userID.String())
	if got := profileMD.Get(grpcutils.AuthorizationMetadataKey); len(got) != 0 {
		t.Fatalf("profile authorization = %v, want none", got)
	}
	if got := accountMD.Get("x-trace-id"); len(got) != 1 || got[0] != "trace" {
		t.Fatalf("account trace metadata = %v", got)
	}
	if got := profileMD.Get("x-trace-id"); len(got) != 1 || got[0] != "trace" {
		t.Fatalf("profile trace metadata = %v", got)
	}

	user := resp.GetUser()
	if user.GetId() != userID.String() || user.GetEmail() != "account@example.com" {
		t.Fatalf("account-backed fields = (id %q, email %q)", user.GetId(), user.GetEmail())
	}
	if user.GetUsername() != "alice" || user.GetDisplayName() != "Alice" ||
		user.GetAvatarUrl() != "https://img.example/alice.png" {
		t.Fatalf("profile-backed fields = %v", user)
	}
}

func TestGetMeAccountStatusAndErrorMapping(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	ctx, _ := verifiedContext(t, context.Background(), userID)
	tests := []struct {
		name        string
		response    *authnpb.GetMyAccountResponse
		accountErr  error
		wantCode    codes.Code
		wantMessage string
		wantProfile bool
	}{
		{name: "active", response: accountResponse(userID, authnpb.AccountStatus_ACCOUNT_STATUS_ACTIVE, "user@example.com", true), wantCode: codes.OK, wantProfile: true},
		{name: "disabled", response: accountResponse(userID, authnpb.AccountStatus_ACCOUNT_STATUS_DISABLED, "user@example.com", true), wantCode: codes.PermissionDenied},
		{name: "pending deletion", response: accountResponse(userID, authnpb.AccountStatus_ACCOUNT_STATUS_PENDING_DELETION, "user@example.com", true), wantCode: codes.FailedPrecondition},
		{name: "unspecified", response: accountResponse(userID, authnpb.AccountStatus_ACCOUNT_STATUS_UNSPECIFIED, "user@example.com", true), wantCode: codes.Internal, wantMessage: "internal error"},
		{name: "nil response", wantCode: codes.Internal, wantMessage: "internal error"},
		{name: "nil account", response: &authnpb.GetMyAccountResponse{}, wantCode: codes.Internal, wantMessage: "internal error"},
		{name: "mismatched id", response: accountResponse(uuid.New(), authnpb.AccountStatus_ACCOUNT_STATUS_ACTIVE, "user@example.com", true), wantCode: codes.Internal, wantMessage: "internal error"},
		{name: "blank email", response: accountResponse(userID, authnpb.AccountStatus_ACCOUNT_STATUS_ACTIVE, " ", true), wantCode: codes.Internal, wantMessage: "internal error"},
		{name: "unverified email", response: accountResponse(userID, authnpb.AccountStatus_ACCOUNT_STATUS_ACTIVE, "user@example.com", false), wantCode: codes.Internal, wantMessage: "internal error"},
		{name: "not found", accountErr: status.Error(codes.NotFound, "missing"), wantCode: codes.Unauthenticated, wantMessage: "authentication required"},
		{name: "unauthenticated", accountErr: status.Error(codes.Unauthenticated, "invalid delegation"), wantCode: codes.Unauthenticated, wantMessage: "invalid delegation"},
		{name: "permission denied", accountErr: status.Error(codes.PermissionDenied, "denied"), wantCode: codes.PermissionDenied, wantMessage: "denied"},
		{name: "unavailable", accountErr: status.Error(codes.Unavailable, "unavailable"), wantCode: codes.Unavailable, wantMessage: "unavailable"},
		{name: "deadline", accountErr: status.Error(codes.DeadlineExceeded, "deadline"), wantCode: codes.DeadlineExceeded, wantMessage: "deadline"},
		{name: "canceled", accountErr: status.Error(codes.Canceled, "canceled"), wantCode: codes.Canceled, wantMessage: "canceled"},
		{name: "wrapped deadline", accountErr: fmt.Errorf("account call: %w", context.DeadlineExceeded), wantCode: codes.DeadlineExceeded, wantMessage: "account call: context deadline exceeded"},
		{name: "wrapped canceled", accountErr: fmt.Errorf("account call: %w", context.Canceled), wantCode: codes.Canceled, wantMessage: "account call: context canceled"},
		{name: "unexpected", accountErr: errors.New("database details"), wantCode: codes.Internal, wantMessage: "internal error"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			profileCalled := false
			h := NewHandler(
				&fakeAccount{get: func(context.Context, *authnpb.GetMyAccountRequest) (*authnpb.GetMyAccountResponse, error) {
					return tc.response, tc.accountErr
				}},
				&fakeProfile{get: func(context.Context, *profilepb.GetProfileRequest) (*profilepb.GetProfileResponse, error) {
					profileCalled = true
					resp := &profilepb.GetProfileResponse{}
					resp.SetId(userID.String())
					return resp, nil
				}},
			)
			_, err := h.GetMe(ctx, &gatewaypb.GetMeRequest{})
			if got := status.Code(err); got != tc.wantCode {
				t.Fatalf("code = %v, want %v (err %v)", got, tc.wantCode, err)
			}
			if tc.wantMessage != "" && status.Convert(err).Message() != tc.wantMessage {
				t.Fatalf("message = %q, want %q", status.Convert(err).Message(), tc.wantMessage)
			}
			if profileCalled != tc.wantProfile {
				t.Fatalf("profile called = %v, want %v", profileCalled, tc.wantProfile)
			}
		})
	}
}

func TestGetMeProfileResponseAndErrorMapping(t *testing.T) {
	t.Parallel()

	userID := uuid.New()
	ctx, _ := verifiedContext(t, context.Background(), userID)
	tests := []struct {
		name        string
		response    *profilepb.GetProfileResponse
		profileErr  error
		wantCode    codes.Code
		wantMessage string
	}{
		{name: "nil response", wantCode: codes.Internal, wantMessage: "internal error"},
		{name: "mismatched id", response: profileResponse(uuid.New()), wantCode: codes.Internal, wantMessage: "internal error"},
		{name: "not found", profileErr: status.Error(codes.NotFound, "missing"), wantCode: codes.FailedPrecondition, wantMessage: "profile provisioning incomplete"},
		{name: "unavailable", profileErr: status.Error(codes.Unavailable, "unavailable"), wantCode: codes.Unavailable, wantMessage: "unavailable"},
		{name: "explicit deadline", profileErr: status.Error(codes.DeadlineExceeded, "deadline"), wantCode: codes.DeadlineExceeded, wantMessage: "deadline"},
		{name: "explicit canceled", profileErr: status.Error(codes.Canceled, "canceled"), wantCode: codes.Canceled, wantMessage: "canceled"},
		{name: "wrapped deadline", profileErr: fmt.Errorf("profile call: %w", context.DeadlineExceeded), wantCode: codes.DeadlineExceeded, wantMessage: "profile call: context deadline exceeded"},
		{name: "wrapped canceled", profileErr: fmt.Errorf("profile call: %w", context.Canceled), wantCode: codes.Canceled, wantMessage: "profile call: context canceled"},
		{name: "unexpected", profileErr: errors.New("database details"), wantCode: codes.Internal, wantMessage: "internal error"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := NewHandler(
				&fakeAccount{get: func(context.Context, *authnpb.GetMyAccountRequest) (*authnpb.GetMyAccountResponse, error) {
					return accountResponse(userID, authnpb.AccountStatus_ACCOUNT_STATUS_ACTIVE, "user@example.com", true), nil
				}},
				&fakeProfile{get: func(context.Context, *profilepb.GetProfileRequest) (*profilepb.GetProfileResponse, error) {
					return tc.response, tc.profileErr
				}},
			)
			_, err := h.GetMe(ctx, &gatewaypb.GetMeRequest{})
			if got := status.Code(err); got != tc.wantCode {
				t.Fatalf("code = %v, want %v (err %v)", got, tc.wantCode, err)
			}
			if status.Convert(err).Message() != tc.wantMessage {
				t.Fatalf("message = %q, want %q", status.Convert(err).Message(), tc.wantMessage)
			}
		})
	}
}

func verifiedContext(
	t *testing.T,
	ctx context.Context,
	userID uuid.UUID,
) (context.Context, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	kid := uuid.NewString()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"token_use": "session",
		"sub":       userID.String(),
		"iss":       "https://id.test",
		"aud":       []string{"gateway-services", "authn-account"},
		"iat":       jwt.NewNumericDate(time.Now()),
		"exp":       jwt.NewNumericDate(time.Now().Add(time.Minute)),
	})
	token.Header["typ"] = "muid-session+jwt"
	token.Header["kid"] = kid
	raw, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	verifier := jwtauth.NewVerifier(staticKeySource{kid: kid, key: &key.PublicKey}, jwtauth.Config{
		Issuer:           "https://id.test",
		RequiredAudience: "gateway-services",
	})
	verified, err := verifier.VerifyContext(ctx, raw)
	if err != nil {
		t.Fatalf("VerifyContext: %v", err)
	}
	return verified, raw
}

func accountResponse(
	userID uuid.UUID,
	accountStatus authnpb.AccountStatus,
	email string,
	verified bool,
) *authnpb.GetMyAccountResponse {
	account := &authnpb.Account{}
	account.SetUserId(userID.String())
	account.SetPrimaryEmail(email)
	account.SetPrimaryEmailVerified(verified)
	account.SetAccountStatus(accountStatus)
	resp := &authnpb.GetMyAccountResponse{}
	resp.SetAccount(account)
	return resp
}

func profileResponse(userID uuid.UUID) *profilepb.GetProfileResponse {
	resp := &profilepb.GetProfileResponse{}
	resp.SetId(userID.String())
	return resp
}

func assertMetadataValues(t *testing.T, md metadata.MD, key string, want string) {
	t.Helper()
	got := md.Get(key)
	if len(got) != 1 || got[0] != want {
		t.Fatalf("metadata %q = %v, want [%q]", key, got, want)
	}
}
