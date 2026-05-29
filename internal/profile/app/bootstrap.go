package app

import (
	"context"
	"fmt"

	"entgo.io/ent/dialect"

	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/infra/r2"
	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/ent"
	profilegrpc "sanzi.io/muid/internal/profile/grpc"
	"sanzi.io/muid/pkg/entpostgres"
	"sanzi.io/muid/pkg/errutil"
)

func NewInfra(ctx context.Context, cfg Config) (*InfraDependencies, error) {
	pubSub, err := nats.NewNATSPubSub(cfg.NATSURL)
	if err != nil {
		return nil, fmt.Errorf("nats: %w", err)
	}

	client, _, err := entpostgres.OpenEntPostgres(ctx, cfg.DatabaseURL,
		func(d dialect.Driver) *ent.Client {
			return ent.NewClient(ent.Driver(d))
		},
		func(c *ent.Client) entpostgres.SchemaMigrator { return c.Schema },
		func() { errutil.CloseIf(pubSub) },
		"profile ent: ",
	)
	if err != nil {
		return nil, err
	}

	var avatars *profilegrpc.AvatarMedia
	if cfg.R2AccountID != "" || cfg.R2AccessKeyID != "" || cfg.R2SecretAccessKey != "" ||
		cfg.R2UploadBucket != "" ||
		cfg.R2AssetsBucket != "" {
		if cfg.R2AccountID == "" || cfg.R2AccessKeyID == "" || cfg.R2SecretAccessKey == "" ||
			cfg.R2UploadBucket == "" ||
			cfg.R2AssetsBucket == "" {
			errutil.Close(client)
			errutil.CloseIf(pubSub)
			return nil, fmt.Errorf(
				"partial R2 configuration: set PROFILE_R2_ACCOUNT_ID, PROFILE_R2_ACCESS_KEY_ID, PROFILE_R2_SECRET_ACCESS_KEY, PROFILE_R2_UPLOAD_BUCKET, PROFILE_R2_ASSETS_BUCKET together",
			)
		}
		if cfg.PublicAssetURL == "" {
			errutil.Close(client)
			errutil.CloseIf(pubSub)
			return nil, fmt.Errorf(
				"PROFILE_PUBLIC_ASSETS_URL is required when R2 avatar upload is enabled",
			)
		}
		store, err := r2.NewR2ObjectStore(
			ctx,
			cfg.R2AccountID,
			cfg.R2AccessKeyID,
			cfg.R2SecretAccessKey,
		)
		if err != nil {
			errutil.Close(client)
			errutil.CloseIf(pubSub)
			return nil, fmt.Errorf("r2: %w", err)
		}
		avatars = &profilegrpc.AvatarMedia{
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

type ProfileApp struct {
	server *ProfileGRPC
	infra  *InfraDependencies
}

func NewProfileApp(infra *InfraDependencies) (*ProfileApp, error) {
	h := profilegrpc.NewGRPCHandler(
		infra.Ent,
		infra.PubSub,
		infra.Avatars,
		media.NewWebPRasterAvatarProcessor(),
	)

	svc, err := NewProfileGRPC(infra.GlobalConfig, h, nil)
	if err != nil {
		return nil, err
	}

	return &ProfileApp{
		server: svc,
		infra:  infra,
	}, nil
}

func (a *ProfileApp) Start(ctx context.Context) error {
	return a.server.Start(ctx)
}

func (a *ProfileApp) Stop() {
	a.infra.Close()
}
