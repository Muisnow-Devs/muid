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
	"sanzi.io/muid/pkg/enttx"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/topics"
	"sanzi.io/muid/pkg/shared/tracing"
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
		locale      = "en"
		timezone    string
	)

	if identity != nil {
		displayName = displayNameFromIdentity(identity, emailLocalPart(email))
		pictureURL = avatarFromIdentity(identity)
		locale = strings.TrimSpace(identity.GetLocale())
		timezone = strings.TrimSpace(identity.GetTimezone())
	}

	usernameCandidate := generateUsernameCandidates(randomUsernameBase())
	ctx = tracing.WithSpanName(ctx, "profile.create_profile.tx")
	user, err := enttx.Run(
		ctx,
		g.db.Tx,
		func(ctx context.Context, tx *ent.Tx) (*ent.UserProfile, error) {
			var user *ent.UserProfile
			for _, candidate := range usernameCandidate {
				exists, err := tx.UserProfile.Query().
					Where(userprofile.UsernameEQ(candidate)).
					Exist(ctx)
				if err != nil {
					log.LogUnexpected(ctx, "profile create username existence check", err.Error())
					return nil, grpcutils.GRPCInternalError()
				}

				if exists {
					continue
				}

				user, err = tx.UserProfile.Create().
					SetEmailRef(email).
					SetLocale(locale).
					SetTimezone(timezone).
					SetDisplayName(displayName).
					SetUsername(candidate).
					Save(ctx)

				if err == nil {
					break
				}

				log.LogUnexpected(ctx, "profile create", err.Error())
				return nil, grpcutils.GRPCInternalError()
			}
			return user, nil
		},
	)
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		reason := "profile create tx begin"
		logCtx := ctx
		if user != nil {
			reason = "profile create tx commit"
			logCtx = log.WithAttrs(ctx, log.ProfileID(user.ID))
		}
		log.LogUnexpected(logCtx, reason, err.Error())
		return nil, grpcutils.GRPCInternalError()
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
	id, err := requiredProfileUserID(ctx)
	if err != nil {
		return nil, err
	}

	p, err := g.db.UserProfile.Query().
		WithOriginalIdentity().
		Where(userprofile.ID(id)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "profile not found")
	}
	if err != nil {
		log.LogUnexpected(ctx, "profile get query", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	locale := "en"
	if strings.TrimSpace(p.Locale) != "" {
		locale = p.Locale
	}

	avatarURL, objectKey, err := g.queryDisplayAvatar(ctx, id)
	if err != nil {
		log.LogUnexpected(ctx, "profile get avatar", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	resp := &pb.GetProfileResponse{}
	resp.SetId(p.ID.String())
	resp.SetEmail(p.EmailRef)
	resp.SetDisplayName(p.DisplayName)
	resp.SetUsername(p.Username)
	resp.SetAvatarUrl(avatarURL)
	resp.SetLocale(locale)
	resp.SetTimezone(strings.TrimSpace(p.Timezone))
	resp.SetAvatarObjectKey(objectKey)

	if p.Edges.OriginalIdentity != nil {
		resp.SetOriginalIdentity(p.Edges.OriginalIdentity.OriginalIdentity)
	}

	return resp, nil
}

func (g *GRPCHandler) UpdateProfile(
	ctx context.Context,
	req *pb.UpdateProfileRequest,
) (*pb.UpdateProfileResponse, error) {
	id, err := requiredProfileUserID(ctx)
	if err != nil {
		return nil, err
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

	ctx = tracing.WithSpanName(ctx, "profile.update_profile.tx")
	err = enttx.Do(ctx, g.db.Tx, func(ctx context.Context, tx *ent.Tx) error {
		profile := tx.UserProfile.UpdateOneID(id)
		for _, p := range paths {
			err = profilePatchRegistry[p](ctx, id, profile, req)
			if err != nil {
				return err
			}
		}

		err = profile.Exec(ctx)
		if ent.IsNotFound(err) {
			return status.Error(codes.NotFound, "requested resource not found")
		}

		if ent.IsConstraintError(err) {
			return status.Error(codes.AlreadyExists, "conflicting update value already in use")
		}

		if err != nil {
			log.LogUnexpected(ctx, "profile update save", err.Error())
			return grpcutils.GRPCInternalError()
		}
		return nil
	})
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		log.LogUnexpected(ctx, "profile update tx", err.Error())
		return nil, grpcutils.GRPCInternalError()
	}

	resPaths, err := updatemask.GetProfileResponsePathsFromUpdateRequestPaths(paths)
	if err != nil {
		log.LogUnexpected(ctx, "profile update event paths", err.Error())
		return nil, grpcutils.GRPCInternalError()
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
	ctx, span := tracing.StartSpan(ctx, "profile.publish_change")
	defer span.End()

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

	err = g.pub.PublishWithOptions(
		topics.TopicProfileChange,
		b,
		pubsub.PublishOptions{
			Reliable:    true,
			RetryPolicy: pubsub.CriticalRetryPolicy(),
		},
	)
	if err != nil {
		span.RecordError(err)
	}
	return err
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
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, errors.New("profile missing for event payload")
	}
	if err != nil {
		return nil, err
	}

	locale := p.Locale
	avatarURL, _, err := g.queryDisplayAvatar(ctx, id)
	if err != nil {
		return nil, err
	}

	setAny := false
	for _, path := range responsePaths {
		switch path {
		case "locale":
			ch.SetLocale(locale)
			setAny = true
		case "timezone":
			ch.SetTimezone(strings.TrimSpace(p.Timezone))
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
