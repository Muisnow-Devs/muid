package core

import (
	"context"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	idclaims "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/shared/tracing"
)

// UpdateProfile applies allowlisted mask paths in one transaction, snapshots
// the committed row in-tx, and publishes ProfileChangedEvent after commit.
// Mask errors: updatemask.ErrEmptyMask / updatemask.ErrUnknownPath /
// ErrUnsupportedMaskPath. Value errors: InvalidArgumentError.
func (m *Manager) UpdateProfile(
	ctx context.Context,
	userID uuid.UUID,
	mask *fieldmaskpb.FieldMask,
	identity *idclaims.IdentityInformation,
) error {
	paths, err := patchablePaths(mask)
	if err != nil {
		return err
	}

	ctx = tracing.WithSpanName(ctx, "profile.update_profile.tx")
	snapshot, err := enttx.Run(
		ctx,
		m.db.Tx,
		func(ctx context.Context, tx *ent.Tx) (*ent.UserProfile, error) {
			upd := tx.UserProfile.UpdateOneID(userID)
			for _, p := range paths {
				spec := profileFields[p]
				value, err := spec.parse(identity)
				if err != nil {
					return nil, err
				}
				spec.set(upd, value)
			}

			err := upd.Exec(ctx)
			if ent.IsNotFound(err) {
				return nil, ErrProfileNotFound
			}
			if ent.IsConstraintError(err) {
				return nil, ErrUpdateConflict
			}
			if err != nil {
				return nil, err
			}

			return tx.UserProfile.Get(ctx, userID)
		},
	)
	if err != nil {
		return err
	}

	responsePaths := responsePathsFor(paths)
	m.publishProfileChanged(ctx, userID, responsePaths, claimsFromSnapshot(snapshot, responsePaths))

	return nil
}
