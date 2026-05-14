package profilegrpc

import (
	"context"
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
	"sanzi.io/muid/internal/profile/ent/userpreference"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/pkg/shared/topics"
)

func (g *GRPCHandler) CreateProfile(ctx context.Context, req *pb.CreateProfileRequest) (*pb.CreateProfileResponse, error) {
	email := strings.TrimSpace(strings.ToLower(req.GetEmail()))
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	claims := req.GetClaims()
	anonymous := !claimsAreMeaningful(claims)

	userID := uuid.New()
	local := emailLocalPart(email)

	var displayName, username, avatarURL string
	if anonymous {
		displayName = randomDisplayName()
		avatarURL = githubIdenticonURL(userID)
	} else {
		displayName = displayNameFromClaims(claims, local)
		if displayName == "" {
			displayName = randomDisplayName()
		}
		if pic := avatarFromClaims(claims); pic != "" {
			avatarURL = pic
		} else {
			avatarURL = githubIdenticonURL(userID)
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
	defer func() { _ = tx.Rollback() }()

	prefID := uuid.New()
	avID := uuid.New()

	_, err = tx.UserProfile.Create().
		SetID(userID).
		SetEmail(email).
		SetDisplayName(displayName).
		SetUsername(username).
		SetAvatarURL(avatarURL).
		Save(ctx)
	if err != nil {
		if ent.IsConstraintError(err) {
			return nil, status.Error(codes.AlreadyExists, "profile with this email or username already exists")
		}
		return nil, grpcInternal(ctx, "profile create user_profile", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	_, err = tx.UserPreference.Create().
		SetID(prefID).
		SetUserID(userID).
		SetLocale(locale).
		Save(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "profile create user_preference", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	_, err = tx.UserAvatar.Create().
		SetID(avID).
		SetUserID(userID).
		Save(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "profile create user_avatar", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if err := tx.Commit(); err != nil {
		return nil, grpcInternal(ctx, "profile create tx commit", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if err := g.publishChange(ctx, userID.String(), email, profileevent.ProfileChangedEvent_CHANGE_TYPE_CREATED); err != nil {
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
		WithAvatar().
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
	objectKey := ""
	if p.Edges.Avatar != nil {
		objectKey = p.Edges.Avatar.ObjectKey
	}

	return &pb.GetProfileResponse{
		Id:              p.ID.String(),
		Email:           p.Email,
		DisplayName:     p.DisplayName,
		Username:        p.Username,
		AvatarUrl:       p.AvatarURL,
		Locale:          locale,
		AvatarObjectKey: objectKey,
	}, nil
}

func (g *GRPCHandler) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.UpdateProfileResponse, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid profile id")
	}
	if req.DisplayName == nil && req.Locale == nil {
		return nil, status.Error(codes.InvalidArgument, "no fields to update")
	}

	tx, err := g.db.Tx(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "profile update tx begin", err, "profile_id_prefix", userIDPrefix(id.String()))
	}
	defer func() { _ = tx.Rollback() }()

	if req.DisplayName != nil {
		dn := strings.TrimSpace(*req.DisplayName)
		if dn == "" {
			return nil, status.Error(codes.InvalidArgument, "display_name must not be empty")
		}
		if _, err := tx.UserProfile.UpdateOneID(id).SetDisplayName(dn).Save(ctx); err != nil {
			if ent.IsNotFound(err) {
				return nil, status.Error(codes.NotFound, "profile not found")
			}
			return nil, grpcInternal(ctx, "profile update display_name", err, "profile_id_prefix", userIDPrefix(id.String()))
		}
	}

	if req.Locale != nil {
		loc := strings.TrimSpace(*req.Locale)
		n, err := tx.UserPreference.Update().
			Where(userpreference.HasUserWith(userprofile.ID(id))).
			SetLocale(loc).
			Save(ctx)
		if err != nil {
			return nil, grpcInternal(ctx, "profile update preference", err, "profile_id_prefix", userIDPrefix(id.String()))
		}
		if n == 0 {
			return nil, status.Error(codes.NotFound, "preference not found for profile")
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, grpcInternal(ctx, "profile update tx commit", err, "profile_id_prefix", userIDPrefix(id.String()))
	}

	p, err := g.db.UserProfile.Get(ctx, id)
	if err != nil {
		return nil, grpcInternal(ctx, "profile update reload", err, "profile_id_prefix", userIDPrefix(id.String()))
	}

	if err := g.publishChange(ctx, id.String(), p.Email, profileevent.ProfileChangedEvent_CHANGE_TYPE_UPDATED); err != nil {
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

func (g *GRPCHandler) publishChange(ctx context.Context, userID, email string, ct profileevent.ProfileChangedEvent_ChangeType) error {
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
