package account

import (
	"context"
	"strings"

	"github.com/google/uuid"
	claimspb "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/identity"
)

// ProvisionUser creates profile and UserRef from register-required data.
// Federated identity linking is handled by the OIDC provider on register finish Continue.
func (s *Store) ProvisionUser(ctx context.Context, reg *identity.RegisterRequired) (uuid.UUID, error) {
	if reg == nil || reg.Identity == nil {
		return uuid.Nil, errOIDCRegisterData
	}

	email, profileClaims, err := profileInputFromRegisterRequired(reg)
	if err != nil {
		return uuid.Nil, err
	}

	return s.provisionFromProfile(ctx, email, profileClaims)
}

func profileInputFromRegisterRequired(reg *identity.RegisterRequired) (string, *claimspb.IdentityInformation, error) {
	id := reg.Identity
	if id == nil {
		return "", nil, errOIDCRegisterData
	}

	email := strings.TrimSpace(strings.ToLower(id.GetEmail()))
	if email == "" {
		return "", nil, errOIDCRegisterData
	}

	if id.GetEmailVerified() {
		return email, id, nil
	}

	return email, nil, nil
}
