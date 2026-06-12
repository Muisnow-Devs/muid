// Package core implements the profile domain: profile CRUD, partial updates,
// avatar upload orchestration, and profile.change event publishing. It owns the
// ent client and transactions; errors are sentinels/typed errors translated to
// gRPC statuses by internal/profile/grpc.
package core

import (
	"context"

	"github.com/google/uuid"

	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/pkg/shared/pubsub"
)

// AvatarBootstrapper schedules async avatar ingestion after profile creation
// (implemented by avataringest.ExternalAvatarIngestor). Nil disables bootstrap.
type AvatarBootstrapper interface {
	GoBootstrap(ctx context.Context, userID uuid.UUID, oidcPictureURL string)
}

// Manager is the profile domain authority. Construct with NewManager.
type Manager struct {
	db     *ent.Client
	pub    pubsub.PubSub
	media  *AvatarMedia
	proc   media.RasterAvatarProcessor
	ingest AvatarBootstrapper
}

// ManagerConfig collects Manager dependencies.
type ManagerConfig struct {
	DB     *ent.Client
	PubSub pubsub.PubSub
	// Media is optional; when nil, StartAvatarUpload / CompleteAvatarUpload return ErrAvatarNotConfigured.
	Media *AvatarMedia
	Proc  media.RasterAvatarProcessor
	// Ingest is optional; when nil, no avatar bootstrap runs on profile creation.
	Ingest AvatarBootstrapper
}

func NewManager(cfg ManagerConfig) *Manager {
	return &Manager{
		db:     cfg.DB,
		pub:    cfg.PubSub,
		media:  cfg.Media,
		proc:   cfg.Proc,
		ingest: cfg.Ingest,
	}
}
