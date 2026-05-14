package profilegrpc

import (
	pb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/avataringest"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/pkg/shared/pubsub"
)

type GRPCHandler struct {
	pb.UnimplementedProfileServiceServer

	db           *ent.Client
	pub          pubsub.PubSub
	avatars      *AvatarMedia
	avatarProc   media.RasterAvatarProcessor
	avatarIngest *avataringest.ExternalAvatarIngestor
}

func NewGRPCHandler(db *ent.Client, ps pubsub.PubSub, avatars *AvatarMedia, avatarProc media.RasterAvatarProcessor) pb.ProfileServiceServer {
	h := &GRPCHandler{db: db, pub: ps, avatars: avatars, avatarProc: avatarProc}
	if avatars != nil {
		h.avatarIngest = avataringest.NewExternalAvatarIngestor(db, avatars.Store, avatars.AssetsBucket, avatars.PublicAssetURL, avatarProc)
	}
	return h
}
