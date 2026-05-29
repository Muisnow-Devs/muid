package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"sanzi.io/muid/internal/authn/ent"
	"sanzi.io/muid/internal/authn/ent/useremail"
	"sanzi.io/muid/internal/authn/ent/useridentity"
	"sanzi.io/muid/internal/authn/ent/userpasskey"
	"sanzi.io/muid/pkg/enttx"
)

// EntPasskeyIdentityStore is the Ent-backed PasskeyIdentityStore.
type EntPasskeyIdentityStore struct {
	db *ent.Client
}

func NewEntPasskeyIdentityStore(db *ent.Client) PasskeyIdentityStore {
	return &EntPasskeyIdentityStore{db: db}
}

// FindUser returns the active UserIdentity for the passkey method.
// subject must be the base64-RawURL-encoded credential ID (as set by the method).
func (s *EntPasskeyIdentityStore) FindUser(
	ctx context.Context,
	provider, subject string,
) (*Identity, error) {
	credentialID, err := base64.RawURLEncoding.DecodeString(subject)
	if err != nil {
		return nil, fmt.Errorf("store/passkey FindUser: decode subject: %w", err)
	}

	pkRow, err := s.db.UserPasskey.Query().
		Where(
			userpasskey.CredentialIDEQ(credentialID),
			userpasskey.RevokedEQ(false),
		).
		WithIdentity().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	identityEdge, err := pkRow.Edges.IdentityOrErr()
	if err != nil {
		return nil, err
	}
	// Guard: parent identity itself must not be revoked.
	if !identityEdge.RevokedAt.IsZero() {
		return nil, nil
	}

	return identityFromRow(identityEdge), nil
}

// LinkIdentity atomically creates UserIdentity + UserPasskey.
// Returns ErrCredentialAlreadyRegistered if the credential ID already exists.
func (s *EntPasskeyIdentityStore) LinkIdentity(
	ctx context.Context,
	userID uuid.UUID,
	claims IdentityClaims,
) (*Identity, error) {
	pc, ok := claims.(PasskeyIdentityClaims)
	if !ok {
		return nil, fmt.Errorf("store/passkey: expected PasskeyIdentityClaims, got %T", claims)
	}

	// Duplicate-credential guard (returns a user-visible sentinel, not internal error).
	exists, err := s.db.UserPasskey.Query().
		Where(userpasskey.CredentialIDEQ(pc.CredentialId)).
		Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, ErrCredentialAlreadyRegistered
	}

	subject := base64.RawURLEncoding.EncodeToString(pc.CredentialId)

	return enttx.Run(ctx, s.db.Tx, func(ctx context.Context, tx *ent.Tx) (*Identity, error) {
		identityRow, err := tx.UserIdentity.Create().
			SetUserID(userID).
			SetProvider("passkey").
			SetSubject(subject).
			Save(ctx)
		if err != nil {
			return nil, err
		}

		pkCreate := tx.UserPasskey.Create().
			SetIdentityID(identityRow.ID).
			SetCredentialID(pc.CredentialId).
			SetPublicKey(pc.PublicKey).
			SetRpID(pc.RpId).
			SetDeviceType(pc.DeviceType).
			SetBackupEligible(pc.BackupEligible).
			SetBackupState(pc.BackupState).
			SetName(pc.DisplayName)

		if len(pc.Transports) > 0 {
			pkCreate = pkCreate.SetTransports(pc.Transports)
		}

		if err = pkCreate.Exec(ctx); err != nil {
			return nil, err
		}

		return identityFromRow(identityRow), nil
	})
}

// UpdateLastUsed sets UserPasskey.last_used_at for all credentials under this identity.
func (s *EntPasskeyIdentityStore) UpdateLastUsed(ctx context.Context, identityID uuid.UUID) error {
	return s.db.UserPasskey.Update().
		Where(userpasskey.IdentityIDEQ(identityID)).
		SetLastUsedAt(time.Now()).
		Exec(ctx)
}

// RevokeIdentity marks the UserIdentity and the associated UserPasskey row as revoked.
func (s *EntPasskeyIdentityStore) RevokeIdentity(ctx context.Context, identityID uuid.UUID) error {
	return enttx.Do(ctx, s.db.Tx, func(ctx context.Context, tx *ent.Tx) error {
		if err := tx.UserIdentity.UpdateOneID(identityID).
			SetRevokedAt(time.Now()).
			Exec(ctx); err != nil {
			return err
		}

		return tx.UserPasskey.Update().
			Where(userpasskey.IdentityIDEQ(identityID)).
			SetRevoked(true).
			Exec(ctx)
	})
}

// LoadCeremonyUser loads the WebAuthn user (email + active credentials) for the
// given user ID. The result implements webauthn.User and can be passed directly
// to webauthn ceremony functions.
func (s *EntPasskeyIdentityStore) LoadCeremonyUser(
	ctx context.Context,
	userID uuid.UUID,
) (*PasskeyCeremonyUser, error) {
	// Verify the user exists.
	if _, err := s.db.UserRef.Get(ctx, userID); err != nil {
		return nil, err
	}

	// Fetch the primary active email for the user (used as WebAuthn display name).
	email := ""
	ue, err := s.db.UserEmail.Query().
		Where(
			useremail.UserIDEQ(userID),
			useremail.IsPrimaryEQ(true),
			useremail.RevokedAtIsNil(),
		).
		Only(ctx)
	if err == nil {
		email = ue.Email
	}

	rows, err := s.db.UserPasskey.Query().
		Where(
			userpasskey.HasIdentityWith(useridentity.UserIDEQ(userID)),
			userpasskey.RevokedEQ(false),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	return &PasskeyCeremonyUser{
		ID:          userID,
		Email:       email,
		Credentials: buildCredentials(rows),
	}, nil
}

// FindCeremonyUserByCredential loads the ceremony user associated with a raw
// credential ID (used during WebAuthn discoverable login).
func (s *EntPasskeyIdentityStore) FindCeremonyUserByCredential(
	ctx context.Context,
	credentialID []byte,
) (*PasskeyCeremonyUser, error) {
	row, err := s.db.UserPasskey.Query().
		Where(userpasskey.CredentialIDEQ(credentialID), userpasskey.RevokedEQ(false)).
		WithIdentity().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, errors.New("store/passkey: passkey not found for discoverable login")
	}
	if err != nil {
		return nil, err
	}

	identityEdge, err := row.Edges.IdentityOrErr()
	if err != nil {
		return nil, err
	}

	return s.LoadCeremonyUser(ctx, identityEdge.UserID)
}

// buildCredentials converts ent UserPasskey rows into webauthn.Credential values.
func buildCredentials(rows []*ent.UserPasskey) []webauthn.Credential {
	credentials := make([]webauthn.Credential, 0, len(rows))
	for _, row := range rows {
		var flags protocol.AuthenticatorFlags
		if row.BackupEligible {
			flags |= protocol.FlagBackupEligible
		}
		if row.BackupState {
			flags |= protocol.FlagBackupState
		}

		transports := make([]protocol.AuthenticatorTransport, 0, len(row.Transports))
		for _, tr := range row.Transports {
			if tr != "" {
				transports = append(transports, protocol.AuthenticatorTransport(tr))
			}
		}

		credentials = append(credentials, webauthn.Credential{
			ID:        row.CredentialID,
			PublicKey: row.PublicKey,
			Transport: transports,
			Flags:     webauthn.NewCredentialFlags(flags),
			Authenticator: webauthn.Authenticator{
				AAGUID:    row.Aaguid,
				SignCount: row.SignCount,
			},
		})
	}
	return credentials
}
