package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	"google.golang.org/grpc"

	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/infra/r2"
	"sanzi.io/muid/internal/media"
	"sanzi.io/muid/internal/profile/avataringest"
	"sanzi.io/muid/internal/profile/core"
	"sanzi.io/muid/internal/profile/ent"
	profilegrpc "sanzi.io/muid/internal/profile/grpc"
	"sanzi.io/muid/pkg/authzclient"
	"sanzi.io/muid/pkg/entpostgres"
	"sanzi.io/muid/pkg/errutil"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/mtls"
)

func NewInfra(ctx context.Context, cfg Config) (*InfraDependencies, error) {
	if err := mtls.ValidatePathGroup(
		true,
		cfg.GRPCClientCertPath,
		cfg.GRPCClientKeyPath,
		cfg.GRPCRootCAPath,
	); err != nil {
		return nil, fmt.Errorf("profile outbound gRPC TLS: %w", err)
	}
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

	var avatars *core.AvatarMedia
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
		avatars = &core.AvatarMedia{
			Store:          store,
			UploadBucket:   cfg.R2UploadBucket,
			AssetsBucket:   cfg.R2AssetsBucket,
			PublicAssetURL: cfg.PublicAssetURL,
		}
	}

	var authzConn *grpc.ClientConn
	var authzEnforcer *authzclient.Enforcer
	if addr := strings.TrimSpace(cfg.AuthzInternalGRPCAddr); addr != "" {
		clientTLS, tlsErr := mtls.LoadClientTLSConfig(
			cfg.GRPCClientCertPath,
			cfg.GRPCClientKeyPath,
			cfg.GRPCRootCAPath,
		)
		if tlsErr != nil {
			errutil.Close(client)
			errutil.CloseIf(pubSub)
			return nil, fmt.Errorf("authz grpc TLS: %w", tlsErr)
		}
		authzConn, err = grpcutils.DialTLSClient(addr, clientTLS, grpcutils.ClientResilienceConfig{})
		if err != nil {
			errutil.Close(client)
			errutil.CloseIf(pubSub)
			return nil, fmt.Errorf("authz grpc dial: %w", err)
		}
		authzEnforcer, err = authzclient.NewEnforcer(authzclient.Config{
			Namespace:       "organization",
			Client:          authzpb.NewAuthzServiceClient(authzConn),
			PubSub:          pubSub,
			RoleCacheTTL:    time.Duration(cfg.AuthzRoleCacheTTLSeconds) * time.Second,
			RefreshInterval: time.Duration(cfg.AuthzPolicyRefreshSeconds) * time.Second,
		})
		if err != nil {
			errutil.Close(authzConn)
			errutil.Close(client)
			errutil.CloseIf(pubSub)
			return nil, fmt.Errorf("authz enforcer: %w", err)
		}
		err = authzEnforcer.Start(ctx)
		if err != nil {
			errutil.Close(authzConn)
			errutil.Close(client)
			errutil.CloseIf(pubSub)
			return nil, fmt.Errorf("authz enforcer start: %w", err)
		}
	}

	return &InfraDependencies{
		GlobalConfig:  cfg,
		PubSub:        pubSub,
		Ent:           client,
		Avatars:       avatars,
		AuthzEnforcer: authzEnforcer,
		authzConn:     authzConn,
	}, nil
}

type ProfileApp struct {
	server *ProfileGRPC
	infra  *InfraDependencies
}

func NewProfileApp(infra *InfraDependencies) (*ProfileApp, error) {
	proc := media.NewWebPRasterAvatarProcessor()
	mcfg := core.ManagerConfig{
		DB:     infra.Ent,
		PubSub: infra.PubSub,
		Media:  infra.Avatars,
		Proc:   proc,
	}
	// Assign Ingest only when a concrete ingestor exists so the interface
	// field stays nil (a typed-nil ingestor would pass != nil checks).
	if infra.Avatars != nil {
		mcfg.Ingest = avataringest.NewExternalAvatarIngestor(
			core.NewAvatarRepo(infra.Ent),
			infra.Avatars,
			proc,
		)
	}

	mgr := core.NewManager(mcfg)
	h := profilegrpc.NewGRPCHandler(mgr)

	// Pass a true nil interface (not a typed-nil enforcer) when unconfigured so
	// the handler's nil check works.
	var orgEnforcer profilegrpc.OrgPermissionEnforcer
	if infra.AuthzEnforcer != nil {
		orgEnforcer = infra.AuthzEnforcer
	}
	orgHandler := profilegrpc.NewOrganizationGRPCHandler(mgr, orgEnforcer)

	svc, err := NewProfileGRPC(infra.GlobalConfig, h, orgHandler, nil)
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
