package session

import (
	"strings"

	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
)

// PendingRegisterState returns pending register data when present.
func (s SessionStore) PendingRegisterState() (*RegisterPending, bool) {
	if s.PendingRegister == nil {
		return nil, false
	}
	return s.PendingRegister, true
}

// WithRegisterPending records signup claims and moves the transition to [StepRegister].
func (s SessionStore) WithRegisterPending(claims RegisterPendingClaims) SessionStore {
	s.PendingRegister = &RegisterPending{Claims: claims}
	s.Step = StepRegister
	return s
}

// WithRegisterResolution records whether flow resolved an existing user before finish-register.
func (s SessionStore) WithRegisterResolution(existingUser bool) SessionStore {
	if s.PendingRegister == nil {
		return s
	}
	s.PendingRegister.ResolvedExistingUser = existingUser
	return s
}

// RegisterPendingClaimsFromProto copies shared identity claims into session storage form.
func RegisterPendingClaimsFromProto(id *claimspb.IdentityInformation) RegisterPendingClaims {
	if id == nil {
		return RegisterPendingClaims{}
	}
	return RegisterPendingClaims{
		Email:             strings.TrimSpace(strings.ToLower(id.GetEmail())),
		EmailVerified:     id.GetEmailVerified(),
		FederatedProvider: strings.TrimSpace(id.GetFederatedProvider()),
		FederatedSubject:  strings.TrimSpace(id.GetFederatedSubject()),
		Name:              strings.TrimSpace(id.GetName()),
		Picture:           strings.TrimSpace(id.GetPicture()),
	}
}

// ToProto builds shared identity claims from session storage form.
func (c RegisterPendingClaims) ToProto() *claimspb.IdentityInformation {
	out := &claimspb.IdentityInformation{}
	if c.Email != "" {
		out.SetEmail(c.Email)
	}
	if c.EmailVerified {
		out.SetEmailVerified(true)
	}
	if c.FederatedProvider != "" {
		out.SetFederatedProvider(c.FederatedProvider)
	}
	if c.FederatedSubject != "" {
		out.SetFederatedSubject(c.FederatedSubject)
	}
	if c.Name != "" {
		out.SetName(c.Name)
	}
	if c.Picture != "" {
		out.SetPicture(c.Picture)
	}
	return out
}
