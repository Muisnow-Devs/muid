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
	"sanzi.io/muid/internal/profile/updatemask"
	"sanzi.io/muid/pkg/validation"
)

// profilePatchFn applies one allowlisted field inside an ent transaction.
// Register new updatable scalars here when extending UpdateProfileRequest (and add buf validate rules on the proto field).
type profilePatchFn func(ctx context.Context, userID uuid.UUID, profile *ent.UserProfileUpdateOne, req *pb.UpdateProfileRequest) error

var errProfileUpdateUnsupportedPath = errors.New("unsupported update_mask path")

// profilePatchRegistry is the security allowlist: only these mask paths run mutators.
var profilePatchRegistry = map[string]profilePatchFn{
	"identity.username":    patchIdentityUsername,
	"identity.locale":      patchIdentityLocale,
	"identity.name":        patchIdentityDisplayFromNameFields,
	"identity.given_name":  patchIdentityDisplayFromNameFields,
	"identity.family_name": patchIdentityDisplayFromNameFields,
	"identity.bio":         patchIdentityBio,
}

func patchIdentityUsername(
	ctx context.Context,
	userID uuid.UUID,
	profile *ent.UserProfileUpdateOne,
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
			"username must be 5-32 characters: letters, digits, underscore only",
		)
	}

	candidate := strings.ToLower(raw)
	profile.SetUsername(candidate)

	return nil
}

func patchIdentityLocale(
	ctx context.Context,
	userID uuid.UUID,
	profile *ent.UserProfileUpdateOne,
	req *pb.UpdateProfileRequest,
) error {
	c := req.GetIdentity()
	if c == nil {
		return status.Error(codes.InvalidArgument, "identity payload required for identity.locale")
	}

	loc := strings.TrimSpace(c.GetLocale())
	if loc == "" {
		return status.Error(codes.InvalidArgument, "locale must not be empty")
	}

	if len(loc) > 32 {
		return status.Error(codes.InvalidArgument, "locale must be at most 32 characters")
	}

	profile.SetLocale(loc)
	return nil
}

func patchIdentityBio(
	ctx context.Context,
	userID uuid.UUID,
	profile *ent.UserProfileUpdateOne,
	req *pb.UpdateProfileRequest,
) error {
	c := req.GetIdentity()
	if c == nil {
		return status.Error(codes.InvalidArgument, "identity payload required for identity.bio")
	}

	loc := strings.TrimSpace(c.GetBio())
	if len(loc) > 1024 {
		return status.Error(codes.InvalidArgument, "biography must be at most 1024 characters")
	}

	profile.SetBiography(loc)
	return nil
}

func patchIdentityDisplayFromNameFields(
	ctx context.Context,
	userID uuid.UUID,
	profile *ent.UserProfileUpdateOne,
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
		return status.Error(
			codes.InvalidArgument,
			"no name fields provided for display name update",
		)
	}

	profile.SetDisplayName(username)
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
