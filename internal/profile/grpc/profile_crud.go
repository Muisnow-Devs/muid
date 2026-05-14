package profilegrpc

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	pb "sanzi.io/muid/api/proto/profile/v1"
	idclaims "sanzi.io/muid/api/proto/shared/v1/claims"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/internal/profile/updatemask"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/topics"
	"sanzi.io/muid/pkg/validation"
)

func (g *GRPCHandler) CreateProfile(
	ctx context.Context,
	req *pb.CreateProfileRequest,
) (*pb.CreateProfileResponse, error) {
	email := strings.TrimSpace(strings.ToLower(req.GetEmail()))
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	identity := req.GetIdentity()

	userID := shared.UUIDV7()
	local := emailLocalPart(email)

	displayName := displayNameFromIdentity(identity, local)
	if displayName == "" {
		displayName = randomDisplayName()
	}

	var oidcPictureURL string
	if pic := avatarFromIdentity(identity); pic != "" {
		oidcPictureURL = pic
	}

	username, err := g.allocateUsername(ctx, randomUsernameBase())
	if err != nil {
		return nil, err
	}

	locale := "en"
	if identity != nil && identity.GetLocale() != "" {
		locale = identity.GetLocale()
	}

	tx, err := g.db.Tx(ctx)
	if err != nil {
		return nil, grpcInternal(
			ctx,
			"profile create tx begin",
			err,
			"user_id_prefix",
			userIDPrefix(userID.String()),
		)
	}
	defer func() { errutil.Discard(tx.Rollback()) }()

	_, err = tx.UserProfile.Create().
		SetID(userID).
		SetEmailRef(email).
		SetDisplayName(displayName).
		SetUsername(username).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, status.Error(
				codes.AlreadyExists,
				"profile with this email or username already exists",
			)
		}
		return nil, grpcInternal(
			ctx,
			"profile create user_profile",
			err,
			"user_id_prefix",
			userIDPrefix(userID.String()),
		)
	}

	_, err = tx.UserPreference.Create().
		SetUserID(userID).
		SetLocale(locale).
		Save(ctx)
	if err != nil {
		return nil, grpcInternal(
			ctx,
			"profile create user_preference",
			err,
			"user_id_prefix",
			userIDPrefix(userID.String()),
		)
	}

	if err := tx.Commit(); err != nil {
		return nil, grpcInternal(
			ctx,
			"profile create tx commit",
			err,
			"user_id_prefix",
			userIDPrefix(userID.String()),
		)
	}

	if g.avatarIngest != nil {
		g.avatarIngest.GoBootstrap(ctx, userID, oidcPictureURL)
	}

	createPaths, err := updatemask.SortedUniqueGetProfileResponsePaths([]string{
		"id", "email", "display_name", "username", "locale",
	})
	if err != nil {
		return nil, grpcInternal(
			ctx,
			"profile create event paths",
			err,
			"user_id_prefix",
			userIDPrefix(userID.String()),
		)
	}
	changed := &fieldmaskpb.FieldMask{Paths: createPaths}
	if err := g.publishChange(ctx, userID.String(), changed); err != nil {
		return nil, grpcInternal(
			ctx,
			"profile create publish",
			err,
			"user_id_prefix",
			userIDPrefix(userID.String()),
		)
	}

	resp := &pb.CreateProfileResponse{}
	resp.SetId(userID.String())
	return resp, nil
}

func (g *GRPCHandler) GetProfile(
	ctx context.Context,
	req *pb.GetProfileRequest,
) (*pb.GetProfileResponse, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid profile id")
	}

	p, err := g.db.UserProfile.Query().
		Where(userprofile.ID(id)).
		WithPreference().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "profile not found")
	}
	if err != nil {
		return nil, grpcInternal(
			ctx,
			"profile get query",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}

	locale := "en"
	if p.Edges.Preference != nil {
		locale = p.Edges.Preference.Locale
	}
	avatarURL, objectKey, err := g.queryDisplayAvatar(ctx, id)
	if err != nil {
		return nil, grpcInternal(
			ctx,
			"profile get avatar",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}

	resp := &pb.GetProfileResponse{}
	resp.SetId(p.ID.String())
	resp.SetEmail(p.EmailRef)
	resp.SetDisplayName(p.DisplayName)
	resp.SetUsername(p.Username)
	resp.SetAvatarUrl(avatarURL)
	resp.SetLocale(locale)
	resp.SetAvatarObjectKey(objectKey)
	return resp, nil
}

func (g *GRPCHandler) UpdateProfile(
	ctx context.Context,
	req *pb.UpdateProfileRequest,
) (*pb.UpdateProfileResponse, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid profile id")
	}

	paths, err := sortedPatchableProfileMaskPaths(req.GetUpdateMask())
	if err != nil {
		switch {
		case errors.Is(err, updatemask.ErrEmptyMask):
			return nil, status.Error(
				codes.InvalidArgument,
				"update_mask must list at least one field path",
			)
		case errors.Is(err, errProfileUpdateUnsupportedPath):
			return nil, status.Error(codes.InvalidArgument, "unsupported update_mask path")
		case errors.Is(err, updatemask.ErrUnknownPath):
			return nil, status.Error(codes.InvalidArgument, "unknown update_mask path")
		default:
			return nil, status.Error(codes.InvalidArgument, "invalid update_mask path")
		}
	}

	tx, err := g.db.Tx(ctx)
	if err != nil {
		return nil, grpcInternal(
			ctx,
			"profile update tx begin",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}
	defer func() { errutil.Discard(tx.Rollback()) }()

	for _, p := range paths {
		if err := profilePatchRegistry[p](ctx, g, tx, id, req); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, grpcInternal(
			ctx,
			"profile update tx commit",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}

	resPaths, err := updatemask.GetProfileResponsePathsFromUpdateRequestPaths(paths)
	if err != nil {
		return nil, grpcInternal(
			ctx,
			"profile update event paths",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}
	changed := &fieldmaskpb.FieldMask{Paths: resPaths}
	if shouldBootstrapAvatarAfterCommit(paths) {
		pic := strings.TrimSpace(avatarFromIdentity(req.GetIdentity()))
		if pic != "" && g.avatarIngest != nil {
			g.avatarIngest.GoBootstrap(ctx, id, pic)
		}
	}

	if err := g.publishChange(ctx, id.String(), changed); err != nil {
		return nil, grpcInternal(
			ctx,
			"profile update publish",
			err,
			"profile_id_prefix",
			userIDPrefix(id.String()),
		)
	}

	resp := &pb.UpdateProfileResponse{}
	resp.SetId(id.String())
	return resp, nil
}

func (g *GRPCHandler) allocateUsername(
	ctx context.Context,
	base string,
) (string, error) {
	candidates := generateUsernameCandidates(base)

	for _, candidate := range candidates {
		if !validation.ValidUsername(candidate) {
			continue
		}
		available, err := g.isUsernameAvailable(ctx, candidate)
		if err != nil {
			return "", err
		}

		if available {
			return candidate, nil
		}
	}

	return "", status.Error(
		codes.ResourceExhausted,
		"could not allocate unique username",
	)
}

func (g *GRPCHandler) isUsernameAvailable(
	ctx context.Context,
	username string,
) (bool, error) {
	exists, err := g.db.UserProfile.
		Query().
		Where(userprofile.UsernameEQ(username)).
		Exist(ctx)

	if err != nil {
		return false, grpcInternal(
			ctx,
			"username availability",
			err,
			"candidate_prefix",
			userIDPrefix(username),
		)
	}

	return !exists, nil
}

func (g *GRPCHandler) publishChange(
	ctx context.Context,
	userID string,
	changed *fieldmaskpb.FieldMask,
) error {
	id, err := uuid.Parse(userID)
	if err != nil {
		return err
	}
	msg := &profileevent.ProfileChangedEvent{}
	msg.SetUserId(userID)
	msg.SetChangedFields(changed)
	msg.SetOccurredAt(timestamppb.New(time.Now().UTC()))
	ch, err := g.buildProfileChangedClaims(ctx, id, changed.GetPaths())
	if err != nil {
		return err
	}
	if ch != nil {
		msg.SetChanges(ch)
	}
	b, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	return g.pub.Publish(topics.TopicProfileChange, b)
}

func (g *GRPCHandler) buildProfileChangedClaims(
	ctx context.Context,
	id uuid.UUID,
	responsePaths []string,
) (*idclaims.IdentityInformation, error) {
	if len(responsePaths) == 0 {
		return nil, nil
	}
	ch := &idclaims.IdentityInformation{}
	p, err := g.db.UserProfile.Query().
		Where(userprofile.ID(id)).
		WithPreference().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, errors.New("profile missing for event payload")
	}
	if err != nil {
		return nil, err
	}
	locale := "en"
	if p.Edges.Preference != nil {
		locale = p.Edges.Preference.Locale
	}
	avatarURL, _, err := g.queryDisplayAvatar(ctx, id)
	if err != nil {
		return nil, err
	}
	setAny := false
	for _, path := range responsePaths {
		switch path {
		case "email":
			ch.SetEmail(p.EmailRef)
			setAny = true
		case "locale":
			ch.SetLocale(locale)
			setAny = true
		case "display_name":
			ch.SetName(p.DisplayName)
			setAny = true
		case "username":
			ch.SetUsername(p.Username)
			setAny = true
		case "avatar_url":
			if avatarURL != "" {
				ch.SetPicture(avatarURL)
				setAny = true
			}
		}
	}
	if !setAny {
		return nil, nil
	}
	return ch, nil
}
