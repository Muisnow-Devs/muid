package account

import (
	"testing"

	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/identity"
)

func TestProfileInputFromRegisterRequired(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		reg       *identity.RegisterRequired
		wantEmail string
		wantNil   bool
		wantErr   bool
	}{
		{
			name: "email otp verified",
			reg: func() *identity.RegisterRequired {
				claims := &claimspb.IdentityInformation{}
				claims.SetEmail("User@Example.com")
				claims.SetEmailVerified(true)
				return &identity.RegisterRequired{Identity: claims}
			}(),
			wantEmail: "user@example.com",
		},
		{
			name: "oidc full claims",
			reg: func() *identity.RegisterRequired {
				claims := &claimspb.IdentityInformation{}
				claims.SetEmail("oidc@example.com")
				claims.SetEmailVerified(true)
				claims.SetName("Ada")
				claims.SetFederatedProvider("google")
				claims.SetFederatedSubject("sub-1")
				return &identity.RegisterRequired{Identity: claims}
			}(),
			wantEmail: "oidc@example.com",
		},
		{
			name:    "missing email",
			reg:     &identity.RegisterRequired{Identity: &claimspb.IdentityInformation{}},
			wantErr: true,
		},
		{
			name: "federated missing subject",
			reg: func() *identity.RegisterRequired {
				claims := &claimspb.IdentityInformation{}
				claims.SetEmail("a@b.com")
				claims.SetFederatedProvider("google")
				return &identity.RegisterRequired{Identity: claims}
			}(),
			wantEmail: "a@b.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			email, claims, err := profileInputFromRegisterRequired(tc.reg)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if email != tc.wantEmail {
				t.Fatalf("email: got %q want %q", email, tc.wantEmail)
			}
			if tc.wantNil && claims != nil {
				t.Fatal("expected nil profile claims")
			}
			id := tc.reg.Identity
			if id.GetEmailVerified() && !id.HasFederatedProvider() {
				if claims == nil || !claims.GetEmailVerified() {
					t.Fatal("expected email_verified in profile claims")
				}
			}
			if id.HasFederatedProvider() && id.HasFederatedSubject() && claims != id {
				t.Fatal("expected OIDC identity claims unchanged")
			}
		})
	}
}
