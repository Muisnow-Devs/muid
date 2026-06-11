package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/oidcclient"
)

type fakeMembership struct {
	member bool
	err    error
	calls  int
}

func (f *fakeMembership) IsMember(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	f.calls++
	return f.member, f.err
}

type fakeAllowlist struct {
	allowed bool
	err     error
}

func (f *fakeAllowlist) HasAccess(context.Context, uuid.UUID, uuid.UUID) (bool, error) {
	return f.allowed, f.err
}

func testClient(mutate func(*ent.OIDCClient)) *ent.OIDCClient {
	client := &ent.OIDCClient{
		ID:                      uuid.New(),
		ClientID:                "client-abc",
		OwnerOrganizationID:     uuid.New(),
		Scopes:                  []string{"openid", "profile", "email"},
		GrantTypes:              []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken},
		TokenEndpointAuthMethod: oidcclient.TokenEndpointAuthMethodNone,
		AccessPolicy:            oidcclient.AccessPolicyPublic,
		PublishStatus:           oidcclient.PublishStatusPublished,
	}
	if mutate != nil {
		mutate(client)
	}
	return client
}

func TestEvaluatorAuthorizeUser(t *testing.T) {
	t.Parallel()

	deleted := time.Now()
	tests := []struct {
		name      string
		mutate    func(*ent.OIDCClient)
		member    bool
		allowed   bool
		scopes    []string
		wantErr   error
		wantCalls int
	}{
		{
			name:   "public published anyone",
			scopes: []string{"openid"},
		},
		{
			name:    "deleted client",
			mutate:  func(c *ent.OIDCClient) { c.DeletedAt = &deleted },
			wantErr: ErrClientDisabled,
		},
		{
			name:    "disabled client",
			mutate:  func(c *ent.OIDCClient) { c.PublishStatus = oidcclient.PublishStatusDisabled },
			wantErr: ErrClientDisabled,
		},
		{
			name:      "public draft requires membership",
			mutate:    func(c *ent.OIDCClient) { c.PublishStatus = oidcclient.PublishStatusDraft },
			member:    false,
			wantErr:   ErrAccessDenied,
			wantCalls: 1,
		},
		{
			name:      "public testing member ok",
			mutate:    func(c *ent.OIDCClient) { c.PublishStatus = oidcclient.PublishStatusTesting },
			member:    true,
			wantCalls: 1,
		},
		{
			name: "organization policy member ok",
			mutate: func(c *ent.OIDCClient) {
				c.AccessPolicy = oidcclient.AccessPolicyOrganization
			},
			member:    true,
			wantCalls: 1,
		},
		{
			name: "organization policy non-member denied",
			mutate: func(c *ent.OIDCClient) {
				c.AccessPolicy = oidcclient.AccessPolicyOrganization
			},
			member:    false,
			wantErr:   ErrAccessDenied,
			wantCalls: 1,
		},
		{
			name: "organization draft checks membership once",
			mutate: func(c *ent.OIDCClient) {
				c.AccessPolicy = oidcclient.AccessPolicyOrganization
				c.PublishStatus = oidcclient.PublishStatusDraft
			},
			member:    true,
			wantCalls: 1,
		},
		{
			name: "private allowlisted ok",
			mutate: func(c *ent.OIDCClient) {
				c.AccessPolicy = oidcclient.AccessPolicyPrivate
			},
			allowed: true,
		},
		{
			name: "private not allowlisted denied",
			mutate: func(c *ent.OIDCClient) {
				c.AccessPolicy = oidcclient.AccessPolicyPrivate
			},
			allowed: false,
			wantErr: ErrAccessDenied,
		},
		{
			name:    "scope outside client scopes",
			scopes:  []string{"openid", "organization:write"},
			wantErr: ErrScopeNotAllowed,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			membership := &fakeMembership{member: tc.member}
			evaluator := NewEvaluator(membership, &fakeAllowlist{allowed: tc.allowed})

			err := evaluator.AuthorizeUser(
				context.Background(),
				testClient(tc.mutate),
				uuid.New(),
				tc.scopes,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("AuthorizeUser err = %v, want %v", err, tc.wantErr)
			}
			if membership.calls != tc.wantCalls {
				t.Fatalf("membership calls = %d, want %d", membership.calls, tc.wantCalls)
			}
		})
	}
}

func TestEvaluatorPropagatesCheckerErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("authz unavailable")
	evaluator := NewEvaluator(
		&fakeMembership{err: wantErr},
		&fakeAllowlist{},
	)

	err := evaluator.AuthorizeUser(
		context.Background(),
		testClient(func(c *ent.OIDCClient) {
			c.AccessPolicy = oidcclient.AccessPolicyOrganization
		}),
		uuid.New(),
		nil,
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("AuthorizeUser err = %v, want %v", err, wantErr)
	}
}

func TestValidateAuthorizeRequest(t *testing.T) {
	t.Parallel()

	registered := []string{"https://app.test/cb", "https://app.test/cb2"}
	tests := []struct {
		name            string
		mutate          func(*ent.OIDCClient)
		redirectURI     string
		responseType    string
		challenge       string
		challengeMethod string
		wantErr         error
	}{
		{
			name:            "public client with S256",
			redirectURI:     "https://app.test/cb",
			responseType:    "code",
			challenge:       "challenge",
			challengeMethod: "S256",
		},
		{
			name:         "unregistered redirect uri",
			redirectURI:  "https://evil.test/cb",
			responseType: "code",
			wantErr:      ErrRedirectURINotRegistered,
		},
		{
			name:         "redirect uri prefix is not a match",
			redirectURI:  "https://app.test/cb/extra",
			responseType: "code",
			wantErr:      ErrRedirectURINotRegistered,
		},
		{
			name:         "unsupported response type",
			redirectURI:  "https://app.test/cb",
			responseType: "token",
			wantErr:      ErrUnsupportedResponseType,
		},
		{
			name:         "public client missing pkce",
			redirectURI:  "https://app.test/cb",
			responseType: "code",
			wantErr:      ErrPKCERequired,
		},
		{
			name:            "plain method rejected",
			redirectURI:     "https://app.test/cb",
			responseType:    "code",
			challenge:       "challenge",
			challengeMethod: "plain",
			wantErr:         ErrPKCEMethodUnsupported,
		},
		{
			name: "confidential client without pkce ok",
			mutate: func(c *ent.OIDCClient) {
				c.TokenEndpointAuthMethod = oidcclient.TokenEndpointAuthMethodClientSecretBasic
			},
			redirectURI:  "https://app.test/cb2",
			responseType: "code",
		},
		{
			name: "confidential client with bad pkce method rejected",
			mutate: func(c *ent.OIDCClient) {
				c.TokenEndpointAuthMethod = oidcclient.TokenEndpointAuthMethodClientSecretPost
			},
			redirectURI:     "https://app.test/cb",
			responseType:    "code",
			challenge:       "challenge",
			challengeMethod: "plain",
			wantErr:         ErrPKCEMethodUnsupported,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := ValidateAuthorizeRequest(
				testClient(tc.mutate),
				registered,
				tc.redirectURI,
				tc.responseType,
				tc.challenge,
				tc.challengeMethod,
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateAuthorizeRequest err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestGrantTypeEnabled(t *testing.T) {
	t.Parallel()

	client := testClient(nil)
	if err := GrantTypeEnabled(client, GrantTypeAuthorizationCode); err != nil {
		t.Fatalf("GrantTypeEnabled authorization_code: %v", err)
	}
	err := GrantTypeEnabled(client, GrantTypeDeviceCode)
	if !errors.Is(err, ErrGrantTypeNotEnabled) {
		t.Fatalf("GrantTypeEnabled device_code err = %v, want ErrGrantTypeNotEnabled", err)
	}
}
