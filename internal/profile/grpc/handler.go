package profilegrpc

import (
	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/pkg/shared/pubsub"
)

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
