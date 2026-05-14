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
	"identity.picture":     patchIdentityPictureValidate,
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
	if _, err := tx.UserProfile.UpdateOneID(id).SetEmailRef(email).Save(ctx); err != nil {
		if ent.IsNotFound(err) {
			return status.Error(codes.NotFound, "profile not found")
		}
		if ent.IsConstraintError(err) {
			return status.Error(codes.AlreadyExists, "email already in use")
		}
		return grpcInternal(
			ctx,
			"profile update email",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
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
	up, err := tx.UserProfile.Get(ctx, id)
	if err != nil {
		if ent.IsNotFound(err) {
			return status.Error(codes.NotFound, "profile not found")
		}
		return grpcInternal(
			ctx,
			"profile update display load",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}
	dn := displayNameFromIdentity(c, emailLocalPart(up.EmailRef))
	if dn == "" {
		return status.Error(codes.InvalidArgument, "resolved display name must not be empty")
	}
	if _, err := tx.UserProfile.UpdateOneID(id).SetDisplayName(dn).Save(ctx); err != nil {
		if ent.IsNotFound(err) {
			return status.Error(codes.NotFound, "profile not found")
		}
		return grpcInternal(
			ctx,
			"profile update display from identity",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}
	return nil
}

func patchIdentityPictureValidate(
	ctx context.Context,
	g *GRPCHandler,
	tx *ent.Tx,
	id uuid.UUID,
	req *pb.UpdateProfileRequest,
) error {
	pic := strings.TrimSpace(avatarFromIdentity(req.GetIdentity()))
	if pic == "" {
		return status.Error(codes.InvalidArgument, "picture must not be empty")
	}
	if g.avatarIngest == nil {
		return status.Error(codes.FailedPrecondition, "avatar ingest not configured")
	}
	if _, err := tx.UserProfile.Get(ctx, id); err != nil {
		if ent.IsNotFound(err) {
			return status.Error(codes.NotFound, "profile not found")
		}
		return grpcInternal(
			ctx,
			"profile update picture profile lookup",
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

func shouldBootstrapAvatarAfterCommit(paths []string) bool {
	for _, p := range paths {
		if p == "identity.picture" {
			return true
		}
	}
	return false
}
