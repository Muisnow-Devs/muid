package profilegrpc

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/userpreference"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/internal/profile/updatemask"
)

// profilePatchFn applies one allowlisted profile field inside an ent transaction.
// Register new updatable scalars here when extending UpdateProfileFields (and add buf validate rules on the proto field).
type profilePatchFn func(ctx context.Context, g *GRPCHandler, tx *ent.Tx, userID uuid.UUID, prof *pb.UpdateProfileFields) error

var errProfileUpdateUnsupportedPath = errors.New("unsupported update_mask path")

// profilePatchRegistry is the security allowlist: only these mask paths run mutators.
var profilePatchRegistry = map[string]profilePatchFn{
	"profile.display_name": patchProfileDisplayName,
	"profile.locale":       patchProfileLocale,
	"profile.username":     patchProfileUsername,
}

func patchProfileDisplayName(
	ctx context.Context,
	g *GRPCHandler,
	tx *ent.Tx,
	id uuid.UUID,
	prof *pb.UpdateProfileFields,
) error {
	dn := strings.TrimSpace(prof.GetDisplayName())
	if dn == "" {
		return status.Error(codes.InvalidArgument, "display_name must not be empty")
	}
	if _, err := tx.UserProfile.UpdateOneID(id).SetDisplayName(dn).Save(ctx); err != nil {
		if ent.IsNotFound(err) {
			return status.Error(codes.NotFound, "profile not found")
		}
		return grpcInternal(
			ctx,
			"profile update display_name",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}
	return nil
}

func patchProfileLocale(
	ctx context.Context,
	g *GRPCHandler,
	tx *ent.Tx,
	id uuid.UUID,
	prof *pb.UpdateProfileFields,
) error {
	loc := strings.TrimSpace(prof.GetLocale())
	n, err := tx.UserPreference.Update().
		Where(userpreference.HasUserWith(userprofile.ID(id))).
		SetLocale(loc).
		Save(ctx)
	if err != nil {
		return grpcInternal(
			ctx,
			"profile update preference",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}
	if n == 0 {
		return status.Error(codes.NotFound, "preference not found for profile")
	}
	return nil
}

func patchProfileUsername(
	ctx context.Context,
	g *GRPCHandler,
	tx *ent.Tx,
	id uuid.UUID,
	prof *pb.UpdateProfileFields,
) error {
	candidate := sanitizeUsername(prof.GetUsername())
	if candidate == "" {
		return status.Error(codes.InvalidArgument, "username must not be empty")
	}
	taken, err := tx.UserProfile.Query().
		Where(userprofile.UsernameEQ(candidate), userprofile.IDNEQ(id)).
		Exist(ctx)
	if err != nil {
		return grpcInternal(
			ctx,
			"profile update username taken check",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}
	if taken {
		return status.Error(codes.AlreadyExists, "username already taken")
	}
	if _, err := tx.UserProfile.UpdateOneID(id).SetUsername(candidate).Save(ctx); err != nil {
		if ent.IsNotFound(err) {
			return status.Error(codes.NotFound, "profile not found")
		}
		if ent.IsConstraintError(err) {
			return status.Error(codes.AlreadyExists, "username already taken")
		}
		return grpcInternal(
			ctx,
			"profile update username",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}
	return nil
}

func sortedPatchableProfileMaskPaths(mask *fieldmaskpb.FieldMask) ([]string, error) {
	paths, err := updatemask.SortedUniqueCanonicalPaths(mask)
	if err != nil {
		return nil, err
	}
	for _, p := range paths {
		if _, ok := profilePatchRegistry[p]; !ok {
			return nil, errProfileUpdateUnsupportedPath
		}
	}
	return paths, nil
}
