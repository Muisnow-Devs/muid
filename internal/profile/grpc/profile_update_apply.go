package profilegrpc

import (
	"context"
	"errors"
	"slices"
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
	"sanzi.io/muid/pkg/validation"
)

// profilePatchFn applies one allowlisted field inside an ent transaction.
// Register new updatable scalars here when extending UpdateProfileRequest (and add buf validate rules on the proto field).
type profilePatchFn func(ctx context.Context, g *GRPCHandler, tx *ent.Tx, userID uuid.UUID, req *pb.UpdateProfileRequest) error

var errProfileUpdateUnsupportedPath = errors.New("unsupported update_mask path")

// profilePatchRegistry is the security allowlist: only these mask paths run mutators.
var profilePatchRegistry = map[string]profilePatchFn{
	"identity.username":    patchIdentityUsername,
	"identity.email":       patchIdentityEmail,
	"identity.locale":      patchIdentityLocale,
	"identity.name":        patchIdentityDisplayFromNameFields,
	"identity.given_name":  patchIdentityDisplayFromNameFields,
	"identity.family_name": patchIdentityDisplayFromNameFields,
}

func patchErrorHelper(ctx context.Context, action string, err error, userId uuid.UUID) error {
	if ent.IsNotFound(err) {
		return status.Error(codes.NotFound, "requested resource not found")
	}

	if ent.IsConstraintError(err) {
		return status.Error(codes.AlreadyExists, "conflicting update value already in use")
	}

	return grpcInternal(
		ctx,
		action,
		err,
		"profile_id_prefix",
		userIDPrefix(userId.String()),
	)
}

func patchIdentityUsername(
	ctx context.Context,
	g *GRPCHandler,
	tx *ent.Tx,
	id uuid.UUID,
	req *pb.UpdateProfileRequest,
) error {
	idn := req.GetIdentity()
	if idn == nil {
		return status.Error(
			codes.InvalidArgument,
			"identity payload required for identity.username",
		)
	}

	raw := strings.TrimSpace(idn.GetUsername())
	if raw == "" {
		return status.Error(codes.InvalidArgument, "username must not be empty")
	}

	if !validation.ValidUsername(raw) {
		return status.Error(
			codes.InvalidArgument,
			"username must be 5–32 characters: letters, digits, underscore only",
		)
	}

	candidate := strings.ToLower(raw)
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

	err = tx.UserProfile.UpdateOneID(id).SetUsername(candidate).Exec(ctx)
	if err != nil {
		return patchErrorHelper(ctx, "profile update username", err, id)
	}

	return nil
}

func patchIdentityEmail(
	ctx context.Context,
	g *GRPCHandler,
	tx *ent.Tx,
	id uuid.UUID,
	req *pb.UpdateProfileRequest,
) error {
	c := req.GetIdentity()
	if c == nil {
		return status.Error(codes.InvalidArgument, "identity payload required for identity.email")
	}

	email := strings.TrimSpace(strings.ToLower(c.GetEmail()))
	if email == "" {
		return status.Error(codes.InvalidArgument, "email must not be empty")
	}

	taken, err := tx.UserProfile.Query().
		Where(userprofile.EmailRefEQ(email), userprofile.IDNEQ(id)).
		Exist(ctx)
	if err != nil {
		return grpcInternal(
			ctx,
			"profile update email taken check",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}
	if taken {
		return status.Error(codes.AlreadyExists, "email already in use")
	}

	err = tx.UserProfile.UpdateOneID(id).SetEmailRef(email).Exec(ctx)
	if err != nil {
		return patchErrorHelper(ctx, "profile update email", err, id)
	}

	return nil
}

func patchIdentityLocale(
	ctx context.Context,
	g *GRPCHandler,
	tx *ent.Tx,
	id uuid.UUID,
	req *pb.UpdateProfileRequest,
) error {
	c := req.GetIdentity()
	if c == nil {
		return status.Error(codes.InvalidArgument, "identity payload required for identity.locale")
	}

	loc := strings.TrimSpace(c.GetLocale())
	_, err := tx.UserPreference.Update().
		Where(userpreference.HasUserWith(userprofile.ID(id))).
		SetLocale(loc).
		Save(ctx)

	if err != nil {
		return patchErrorHelper(ctx, "profile update locale", err, id)
	}

	return nil
}

func patchIdentityDisplayFromNameFields(
	ctx context.Context,
	g *GRPCHandler,
	tx *ent.Tx,
	id uuid.UUID,
	req *pb.UpdateProfileRequest,
) error {
	c := req.GetIdentity()
	if c == nil {
		return status.Error(
			codes.InvalidArgument,
			"identity payload required for display name identity paths",
		)
	}

	var username string
	if c.GetName() != "" {
		username = strings.TrimSpace(c.GetName())
	} else if c.GetGivenName() != "" || c.GetFamilyName() != "" {
		username = strings.TrimSpace(c.GetGivenName() + " " + c.GetFamilyName())
	}

	if username == "" {
		return status.Error(codes.InvalidArgument, "no name fields provided for display name update")
	}

	err := tx.UserProfile.UpdateOneID(id).SetDisplayName(username).Exec(ctx)
	if err != nil {
		return patchErrorHelper(ctx, "profile update display name", err, id)
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

func shouldBootstrapAvatarAfterCommit(paths []string) bool {
	return slices.Contains(paths, "identity.email")
}
