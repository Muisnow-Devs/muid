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
	"sanzi.io/muid/pkg/shared/topics"
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
	var (
		displayName string
		pictureURL  string
		preference  *ent.UserPreference
	)

	if identity != nil {
		displayName = displayNameFromIdentity(identity, emailLocalPart(email))
		pictureURL = avatarFromIdentity(identity)
		preference = &ent.UserPreference{
			Locale: strings.TrimSpace(identity.GetLocale()),
		}
	}

	usernameCandidate := generateUsernameCandidates(randomUsernameBase())
	tx, err := g.db.Tx(ctx)
	if err != nil {
		return nil, grpcInternal(
			ctx,
			"profile create tx begin",
			err,
		)
	}
	defer func() { errutil.Discard(tx.Rollback()) }()

	var user *ent.UserProfile
	for _, candidate := range usernameCandidate {
		user, err = tx.UserProfile.Create().
			SetEmailRef(email).
			SetDisplayName(displayName).
			SetUsername(candidate).
			SetPreference(preference).
			Save(ctx)

		if err == nil {
			break
		}

		if !ent.IsConstraintError(err) {
			continue
		}

		return nil, status.Error(
			codes.ResourceExhausted,
			"could not allocate unique username",
		)
	}

	if err := tx.Commit(); err != nil {
		return nil, internalErrorWithUserId(
			ctx,
			err,
			"profile create tx commit",
			user.ID,
		)
	}

	if g.avatarIngest != nil && pictureURL != "" {
		bgctx := context.WithoutCancel(ctx)
		g.avatarIngest.GoBootstrap(bgctx, user.ID, pictureURL)
	}

	resp := &pb.CreateProfileResponse{}
	resp.SetId(user.ID.String())
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
		return nil, internalErrorWithUserId(
			ctx,
			err,
			"profile get query",
			id,
		)
	}

	locale := "en"
	if p.Edges.Preference != nil {
		locale = p.Edges.Preference.Locale
	}

	avatarURL, objectKey, err := g.queryDisplayAvatar(ctx, id)
	if err != nil {
		return nil, internalErrorWithUserId(
			ctx,
			err,
			"profile get avatar",
			id,
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
		return nil, internalErrorWithUserId(
			ctx,
			err,
			"profile update tx begin",
			id,
		)
	}
	defer func() { errutil.Discard(tx.Rollback()) }()

	for _, p := range paths {
		if err := profilePatchRegistry[p](ctx, g, tx, id, req); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, internalErrorWithUserId(
			ctx,
			err,
			"profile update tx commit",
			id,
		)
	}

	resPaths, err := updatemask.GetProfileResponsePathsFromUpdateRequestPaths(paths)
	if err != nil {
		return nil, internalErrorWithUserId(
			ctx,
			err,
			"profile update event paths",
			id,
		)
	}

	changed := &fieldmaskpb.FieldMask{Paths: resPaths}
	if shouldBootstrapAvatarAfterCommit(paths) {
		pic := strings.TrimSpace(avatarFromIdentity(req.GetIdentity()))
		if pic != "" && g.avatarIngest != nil {
			g.avatarIngest.GoBootstrap(ctx, id, pic)
		}
	}

	g.publishChange(ctx, id.String(), changed)

	resp := &pb.UpdateProfileResponse{}
	resp.SetId(id.String())

	return resp, nil
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
