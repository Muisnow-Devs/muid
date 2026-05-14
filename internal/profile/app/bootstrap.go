package app

import (
	"context"
	"fmt"
	"io"
	"log"
	"strings"

	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/ent"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/infra/r2"
)

func NewInfra(ctx context.Context, cfg Config) (*InfraDependencies, error) {
	pubSub, err := nats.NewNATSPubSub(cfg.NATSURL)
	if err != nil {
		return nil, fmt.Errorf("nats: %w", err)
	}

	client, err := ent.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		closeIfCloser(pubSub)
		return nil, fmt.Errorf("ent open: %w", err)
	}

	if err := client.Schema.Create(ctx); err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "already exists") || strings.Contains(msg, "duplicate") {
			log.Printf("ent: reusing existing schema (%v)", err)
		} else {
			_ = client.Close()
			closeIfCloser(pubSub)
			return nil, fmt.Errorf("ent schema: %w", err)
		}
	}

	var avatars *AvatarMedia
	if cfg.R2AccountID != "" || cfg.R2AccessKeyID != "" || cfg.R2SecretAccessKey != "" || cfg.R2UploadBucket != "" || cfg.R2AssetsBucket != "" {
		if cfg.R2AccountID == "" || cfg.R2AccessKeyID == "" || cfg.R2SecretAccessKey == "" || cfg.R2UploadBucket == "" || cfg.R2AssetsBucket == "" {
			_ = client.Close()
			closeIfCloser(pubSub)
			return nil, fmt.Errorf("partial R2 configuration: set PROFILE_R2_ACCOUNT_ID, PROFILE_R2_ACCESS_KEY_ID, PROFILE_R2_SECRET_ACCESS_KEY, PROFILE_R2_UPLOAD_BUCKET, PROFILE_R2_ASSETS_BUCKET together")
		}
		if cfg.PublicAssetURL == "" {
			_ = client.Close()
			closeIfCloser(pubSub)
			return nil, fmt.Errorf("PROFILE_PUBLIC_ASSETS_URL is required when R2 avatar upload is enabled")
		}
		store, err := r2.NewR2ObjectStore(ctx, cfg.R2AccountID, cfg.R2AccessKeyID, cfg.R2SecretAccessKey)
		if err != nil {
			_ = client.Close()
			closeIfCloser(pubSub)
			return nil, fmt.Errorf("r2: %w", err)
		}
		avatars = &AvatarMedia{
			Store:          store,
			UploadBucket:   cfg.R2UploadBucket,
			AssetsBucket:   cfg.R2AssetsBucket,
			PublicAssetURL: cfg.PublicAssetURL,
		}
	}

	return &InfraDependencies{
		GlobalConfig: cfg,
		PubSub:       pubSub,
		Ent:          client,
		Avatars:      avatars,
	}, nil
}

func closeIfCloser(v any) {
	if c, ok := v.(io.Closer); ok {
		_ = c.Close()
	}
}

type ProfileApp struct {
	server *ProfileGRPC
	infra  *InfraDependencies
}

func NewProfileApp(infra *InfraDependencies) (*ProfileApp, error) {
	h := NewGRPCHandler(infra.Ent, infra.PubSub, infra.Avatars, media.NewWebPRasterAvatarProcessor())
	svc, err := NewProfileGRPC(infra.GlobalConfig, h)
	if err != nil {
		return nil, err
	}
	return &ProfileApp{
		server: svc,
		infra:  infra,
	}, nil
}

func (a *ProfileApp) Start(ctx context.Context) error {
	go func() {
		if err := RunProfileSubscriber(context.Background(), a.infra.PubSub); err != nil {
			log.Printf("profile subscriber: %v", err)
		}
	}()
	return a.server.Start(ctx)
}

func (a *ProfileApp) Stop() {
	a.server.Stop()
	a.infra.Close()
}
