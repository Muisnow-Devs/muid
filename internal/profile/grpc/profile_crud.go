package profilegrpc

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/internal/profile/updatemask"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/topics"
)

func (g *GRPCHandler) CreateProfile(ctx context.Context, req *pb.CreateProfileRequest) (*pb.CreateProfileResponse, error) {
	email := strings.TrimSpace(strings.ToLower(req.GetEmail()))
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	claims := req.GetClaims()
	anonymous := !claimsAreMeaningful(claims)

	userID := shared.UUIDV7()
	local := emailLocalPart(email)

	var displayName, username string
	var oidcPictureURL string
	if anonymous {
		displayName = randomDisplayName()
	} else {
		displayName = displayNameFromClaims(claims, local)
		if displayName == "" {
			displayName = randomDisplayName()
		}
		if pic := avatarFromClaims(claims); pic != "" {
			oidcPictureURL = pic
		}
	}

	var err error
	if anonymous {
		username, err = g.allocateUsername(ctx, randomUsernameBase())
	} else {
		baseUser := sanitizeUsername(local)
		if baseUser == "" {
			baseUser = "user"
		}
		username, err = g.allocateUsername(ctx, baseUser)
	}
	if err != nil {
		return nil, err
	}

	locale := ""
	if !anonymous && claims != nil && claims.GetLocale() != "" {
		locale = claims.GetLocale()
	}

	tx, err := g.db.Tx(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "profile create tx begin", err, "user_id_prefix", userIDPrefix(userID.String()))
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
			return nil, status.Error(codes.AlreadyExists, "profile with this email or username already exists")
		}
		return nil, grpcInternal(ctx, "profile create user_profile", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	_, err = tx.UserPreference.Create().
		SetUserID(userID).
		SetLocale(locale).
		Save(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "profile create user_preference", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if err := tx.Commit(); err != nil {
		return nil, grpcInternal(ctx, "profile create tx commit", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if g.avatarIngest != nil {
		g.avatarIngest.GoBootstrap(ctx, userID, oidcPictureURL)
	}

	if err := g.publishChange(userID.String(), email, profileevent.ProfileChangedEvent_CHANGE_TYPE_CREATED); err != nil {
		return nil, grpcInternal(ctx, "profile create publish", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	return &pb.CreateProfileResponse{Id: userID.String()}, nil
}

func (g *GRPCHandler) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.GetProfileResponse, error) {
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
		return nil, grpcInternal(ctx, "profile get query", err, "profile_id_prefix", userIDPrefix(id.String()))
	}

	locale := ""
	if p.Edges.Preference != nil {
		locale = p.Edges.Preference.Locale
	}
	avatarURL, objectKey, err := g.queryDisplayAvatar(ctx, id)
	if err != nil {
		return nil, grpcInternal(ctx, "profile get avatar", err, "profile_id_prefix", userIDPrefix(id.String()))
	}

	return &pb.GetProfileResponse{
		Id:              p.ID.String(),
		Email:           p.EmailRef,
		DisplayName:     p.DisplayName,
		Username:        p.Username,
		AvatarUrl:       avatarURL,
		Locale:          locale,
		AvatarObjectKey: objectKey,
	}, nil
}

func (g *GRPCHandler) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.UpdateProfileResponse, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid profile id")
	}

	paths, err := sortedPatchableProfileMaskPaths(req.GetUpdateMask())
	if err != nil {
		switch {
		case errors.Is(err, updatemask.ErrEmptyMask):
			return nil, status.Error(codes.InvalidArgument, "update_mask must list at least one field path")
		case errors.Is(err, errProfileUpdateUnsupportedPath):
			return nil, status.Error(codes.InvalidArgument, "unsupported update_mask path")
		case errors.Is(err, updatemask.ErrUnknownPath):
			return nil, status.Error(codes.InvalidArgument, "unknown update_mask path")
		default:
			return nil, status.Error(codes.InvalidArgument, "invalid update_mask path")
		}
	}

	prof := req.GetProfile()
	if prof == nil {
		prof = &pb.UpdateProfileFields{}
	}

	tx, err := g.db.Tx(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "profile update tx begin", err, "profile_id_prefix", userIDPrefix(id.String()))
	}
	defer func() { errutil.Discard(tx.Rollback()) }()

	for _, p := range paths {
		if err := profilePatchRegistry[p](ctx, g, tx, id, prof); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, grpcInternal(ctx, "profile update tx commit", err, "profile_id_prefix", userIDPrefix(id.String()))
	}

	p, err := g.db.UserProfile.Get(ctx, id)
	if err != nil {
		return nil, grpcInternal(ctx, "profile update reload", err, "profile_id_prefix", userIDPrefix(id.String()))
	}

	if err := g.publishChange(id.String(), p.EmailRef, profileevent.ProfileChangedEvent_CHANGE_TYPE_UPDATED); err != nil {
		return nil, grpcInternal(ctx, "profile update publish", err, "profile_id_prefix", userIDPrefix(id.String()))
	}

	return &pb.UpdateProfileResponse{Id: id.String()}, nil
}

func (g *GRPCHandler) allocateUsername(ctx context.Context, base string) (string, error) {
	candidate := base
	for i := 0; i < 24; i++ {
		exists, err := g.db.UserProfile.Query().Where(userprofile.UsernameEQ(candidate)).Exist(ctx)
		if err != nil {
			return "", grpcInternal(ctx, "username availability", err, "candidate_prefix", userIDPrefix(candidate))
		}
		if !exists {
			return candidate, nil
		}
		candidate = base + "-" + strconv.Itoa(i+1)
	}
	for range 32 {
		candidate := randomUsernameBase()
		exists, err := g.db.UserProfile.Query().Where(userprofile.UsernameEQ(candidate)).Exist(ctx)
		if err != nil {
			return "", grpcInternal(ctx, "username availability random", err, "candidate_prefix", userIDPrefix(candidate))
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", status.Error(codes.ResourceExhausted, "could not allocate a unique username")
}

func (g *GRPCHandler) publishChange(userID, email string, ct profileevent.ProfileChangedEvent_ChangeType) error {
	msg := &profileevent.ProfileChangedEvent{
		UserId:         userID,
		Email:          email,
		ChangeType:     ct,
		OccurredAtUnix: time.Now().Unix(),
	}
	b, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	return g.pub.Publish(topics.TopicProfileChange, b)
}
