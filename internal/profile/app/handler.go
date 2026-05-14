package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	profileevent "sanzi.io/muid/api/proto/event/v1/profile"
	pb "sanzi.io/muid/api/proto/profile/v1"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/internal/profile/ent/useravatar"
	"sanzi.io/muid/internal/profile/ent/userpreference"
	"sanzi.io/muid/internal/profile/ent/userprofile"
	"sanzi.io/muid/pkg/shared/pubsub"
	"sanzi.io/muid/pkg/shared/storage"
	"sanzi.io/muid/pkg/shared/topics"
	"sanzi.io/muid/pkg/traceid"
)

// maxAvatarUploadBytes caps how much we read from the staging bucket into memory.
const maxAvatarUploadBytes = 15 << 20

func grpcInternal(ctx context.Context, reason string, err error, pairs ...string) error {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	traceid.LogUnexpected(ctx, reason, detail, pairs...)
	return grpcutils.GRPCInternalError()
}

func userIDPrefix(userID string) string {
	if len(userID) >= 8 {
		return userID[:8]
	}
	return userID
}

type GRPCHandler struct {
	pb.UnimplementedProfileServiceServer

	db         *ent.Client
	pub        pubsub.PubSub
	avatars    *AvatarMedia
	avatarProc media.RasterAvatarProcessor
}

func NewGRPCHandler(db *ent.Client, ps pubsub.PubSub, avatars *AvatarMedia, avatarProc media.RasterAvatarProcessor) pb.ProfileServiceServer {
	return &GRPCHandler{db: db, pub: ps, avatars: avatars, avatarProc: avatarProc}
}

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

func (g *GRPCHandler) StartAvatarUpload(ctx context.Context, req *pb.StartAvatarUploadRequest) (*pb.StartAvatarUploadResponse, error) {
	if g.avatars == nil {
		return nil, status.Error(codes.FailedPrecondition, "avatar uploads are not configured (set PROFILE_R2_* variables)")
	}

	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	if _, err := g.db.UserProfile.Get(ctx, userID); ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "profile not found")
	} else if err != nil {
		return nil, grpcInternal(ctx, "avatar start profile lookup", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	ct := strings.TrimSpace(req.GetContentType())
	if !media.AllowedRasterContentType(ct) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported content type %q (use image/jpeg, image/png, image/gif, or image/webp)", ct)
	}

	objectKey := fmt.Sprintf("avatars/%s/%s", userID.String(), uuid.NewString())
	exp := 15 * time.Minute
	url, expTime, err := g.avatars.Store.PresignPut(ctx, g.avatars.UploadBucket, objectKey, ct, exp)
	if err != nil {
		return nil, grpcInternal(ctx, "avatar presign put", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	_, err = g.db.UserAvatar.Update().
		Where(useravatar.HasUserWith(userprofile.ID(userID))).
		SetObjectKey(objectKey).
		SetContentType(ct).
		ClearUploadedAt().
		SetByteSize(0).
		Save(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "avatar start record pending", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	return &pb.StartAvatarUploadResponse{
		UploadUrl:     url,
		ObjectKey:     objectKey,
		ExpiresAtUnix: expTime.Unix(),
	}, nil
}

func (g *GRPCHandler) CompleteAvatarUpload(ctx context.Context, req *pb.CompleteAvatarUploadRequest) (*pb.CompleteAvatarUploadResponse, error) {
	if g.avatars == nil {
		return nil, status.Error(codes.FailedPrecondition, "avatar uploads are not configured (set PROFILE_R2_* variables)")
	}

	userID, err := uuid.Parse(req.GetUserId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}
	if !strings.HasPrefix(req.GetObjectKey(), "avatars/"+userID.String()+"/") {
		return nil, status.Error(codes.InvalidArgument, "object_key does not belong to this user")
	}

	av, err := g.db.UserAvatar.Query().
		Where(useravatar.HasUserWith(userprofile.ID(userID))).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, status.Error(codes.NotFound, "avatar row not found")
	}
	if err != nil {
		return nil, grpcInternal(ctx, "avatar complete query row", err, "user_id_prefix", userIDPrefix(userID.String()))
	}
	if av.ObjectKey != req.GetObjectKey() {
		return nil, status.Error(codes.FailedPrecondition, "object_key does not match the active upload session")
	}

	head, err := g.avatars.Store.HeadObject(ctx, g.avatars.UploadBucket, req.GetObjectKey())
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotFound) {
			return nil, status.Error(codes.FailedPrecondition, "object not found in storage")
		}
		return nil, grpcInternal(ctx, "avatar head staging", err, "bucket", g.avatars.UploadBucket, "user_id_prefix", userIDPrefix(userID.String()))
	}
	if head.Size != req.GetByteSize() {
		return nil, status.Errorf(codes.InvalidArgument, "byte_size mismatch: head reports %d", head.Size)
	}
	if head.Size <= 0 || head.Size > maxAvatarUploadBytes {
		return nil, status.Errorf(codes.InvalidArgument, "unreasonable object size %d", head.Size)
	}
	if !media.AllowedRasterContentType(head.ContentType) {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported content type %q (expected raster image)", head.ContentType)
	}

	rc, _, err := g.avatars.Store.GetObject(ctx, g.avatars.UploadBucket, req.GetObjectKey())
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotFound) {
			return nil, status.Error(codes.FailedPrecondition, "object not found in storage")
		}
		return nil, grpcInternal(ctx, "avatar download staging", err, "user_id_prefix", userIDPrefix(userID.String()))
	}
	raw, err := readAllLimited(rc, maxAvatarUploadBytes)
	_ = rc.Close()
	if err != nil {
		return nil, grpcInternal(ctx, "avatar read staging", err, "user_id_prefix", userIDPrefix(userID.String()))
	}
	if int64(len(raw)) > maxAvatarUploadBytes {
		return nil, status.Error(codes.InvalidArgument, "object too large")
	}

	webpBytes, err := g.avatarProc.ProcessToSquareWebP(raw, head.ContentType)
	if err != nil {
		if errors.Is(err, media.ErrEmptyRasterInput) || errors.Is(err, media.ErrUnsupportedRasterContentType) || errors.Is(err, media.ErrRasterDecodeFailed) {
			return nil, status.Error(codes.InvalidArgument, "invalid avatar image")
		}
		return nil, grpcInternal(ctx, "avatar raster process", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	prodKey := fmt.Sprintf("avatars/%s.webp", userID.String())
	if err := g.avatars.Store.PutObject(ctx, g.avatars.AssetsBucket, prodKey, webpBytes, "image/webp"); err != nil {
		return nil, grpcInternal(ctx, "avatar store processed", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	publicURL := g.avatars.publicProdURL(prodKey)
	now := time.Now()

	tx, err := g.db.Tx(ctx)
	if err != nil {
		return nil, grpcInternal(ctx, "avatar complete tx begin", err, "user_id_prefix", userIDPrefix(userID.String()))
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.UserAvatar.UpdateOneID(av.ID).
		SetObjectKey(prodKey).
		SetUploadedAt(now).
		SetByteSize(int64(len(webpBytes))).
		SetContentType("image/webp").
		Save(ctx); err != nil {
		return nil, grpcInternal(ctx, "avatar complete update row", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if _, err := tx.UserProfile.UpdateOneID(userID).
		SetAvatarURL(publicURL).
		Save(ctx); err != nil {
		return nil, grpcInternal(ctx, "avatar complete update profile", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if err := tx.Commit(); err != nil {
		return nil, grpcInternal(ctx, "avatar complete tx commit", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if err := g.avatars.Store.DeleteObject(ctx, g.avatars.UploadBucket, req.GetObjectKey()); err != nil {
		tid, _ := traceid.FromContext(ctx)
		log.Printf("avatar: delete staging object trace_id=%s object_key=%s err=%v", tid, req.GetObjectKey(), err)
	}

	p, err := g.db.UserProfile.Get(ctx, userID)
	if err != nil {
		return nil, grpcInternal(ctx, "avatar complete reload profile", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	if err := g.publishChange(ctx, userID.String(), p.Email, profileevent.ProfileChangedEvent_CHANGE_TYPE_AVATAR_UPDATED); err != nil {
		return nil, grpcInternal(ctx, "avatar complete publish", err, "user_id_prefix", userIDPrefix(userID.String()))
	}

	return &pb.CompleteAvatarUploadResponse{AvatarUrl: publicURL}, nil
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

func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, limit+1))
}

// RunProfileSubscriber blocks, unmarshalling profile.change payloads (for side effects / fan-out).
func RunProfileSubscriber(ctx context.Context, ps pubsub.PubSub) error {
	return ps.Subscribe(topics.TopicProfileChange, pubsub.SubscribeOptions{}, func(ctx context.Context, message []byte) error {
		var ev profileevent.ProfileChangedEvent
		if err := proto.Unmarshal(message, &ev); err != nil {
			return errors.Join(ErrMalformedProfileChangePayload, err)
		}
		log.Printf("profile.change user_id=%s change_type=%s", ev.GetUserId(), ev.GetChangeType().String())
		return nil
	})
}
