package account

import (
	"context"
	"errors"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/userpasskey"
	idn "sanzi.io/muid/internal/identity"
)

// PasskeyCeremonyUser is the WebAuthn user handle and credentials for ceremony flows.
type PasskeyCeremonyUser struct {
	UserID      uuid.UUID
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func (p *passkeyService) LoadCeremonyUser(
	ctx context.Context,
	userID uuid.UUID,
) (*PasskeyCeremonyUser, error) {
	ref, err := p.store.DB.UserRef.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	rows, err := p.store.DB.UserPasskey.Query().
		Where(userpasskey.UserIDEQ(userID), userpasskey.RevokedEQ(false)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	return &PasskeyCeremonyUser{
		UserID:      ref.ID,
		Name:        ref.Email,
		DisplayName: ref.Email,
		Credentials: passkeyCredentialsFromRows(rows),
	}, nil
}

func (p *passkeyService) LoadCeremonyUserDiscoverable(
	ctx context.Context,
	credentialID, userHandle []byte,
) (*PasskeyCeremonyUser, error) {
	row, err := p.store.DB.UserPasskey.Query().
		Where(userpasskey.CredentialIDEQ(credentialID), userpasskey.RevokedEQ(false)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, idn.ErrPasskeyNotLinked
	}
	if err != nil {
		return nil, err
	}

	userID, err := uuid.FromBytes(userHandle)
	if err != nil {
		return nil, errors.Join(idn.ErrInvalidInput, err)
	}
	if userID != row.UserID {
		return nil, idn.ErrInvalidSessionState
	}

	return p.LoadCeremonyUser(ctx, row.UserID)
}

func passkeyCredentialsFromRows(rows []*ent.UserPasskey) []webauthn.Credential {
	credentials := make([]webauthn.Credential, 0, len(rows))
	for _, row := range rows {
		credentials = append(credentials, passkeyCredentialFromRow(row))
	}
	return credentials
}

func passkeyCredentialFromRow(row *ent.UserPasskey) webauthn.Credential {
	var flags protocol.AuthenticatorFlags
	if row.BackupEligible {
		flags |= protocol.FlagBackupEligible
	}
	if row.BackupState {
		flags |= protocol.FlagBackupState
	}

	transports := make([]protocol.AuthenticatorTransport, 0, len(row.Transports))
	for _, transport := range row.Transports {
		if transport != "" {
			transports = append(transports, protocol.AuthenticatorTransport(transport))
		}
	}

	return webauthn.Credential{
		ID:        row.CredentialID,
		PublicKey: row.PublicKey,
		Transport: transports,
		Flags:     webauthn.NewCredentialFlags(flags),
		Authenticator: webauthn.Authenticator{
			AAGUID:    row.Aaguid,
			SignCount: row.SignCount,
		},
	}
}
