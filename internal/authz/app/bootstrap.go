package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect"
	"google.golang.org/grpc"

	profilepb "sanzi.io/muid/api/proto/profile/v1"
	"sanzi.io/muid/infra/nats"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/policy"
	"sanzi.io/muid/pkg/entpostgres"
	"sanzi.io/muid/pkg/errutil"
	grpcutils "sanzi.io/muid/pkg/grpc_utils"
	"sanzi.io/muid/pkg/mtls"
)

func NewAuthzInfra(ctx context.Context, cfg Config) (*InfraDependencies, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	pubSub, err := nats.NewNATSPubSub(cfg.NATSURL)
	if err != nil {
		return nil, fmt.Errorf("nats: %w", err)
	}

	fatalCleanup := func() {
		errutil.CloseIf(pubSub)
	}
	entClient, _, err := entpostgres.OpenEntPostgres(ctx, cfg.DatabaseURL,
		func(d dialect.Driver) *authzent.Client {
			return authzent.NewClient(authzent.Driver(d))
		},
		func(c *authzent.Client) entpostgres.SchemaMigrator { return c.Schema },
		fatalCleanup,
		"authz ent: ",
	)
	if err != nil {
		return nil, err
	}

	staticConfig, err := policy.LoadStaticConfig(cfg.PolicyConfigPath, cfg.PolicyConfigJSON)
	if err != nil {
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		return nil, fmt.Errorf("policy config: %w", err)
	}

	manager, err := policy.NewManager(policy.ManagerConfig{
		DB:             entClient,
		PubSub:         pubSub,
		Config:         staticConfig,
		ReloadInterval: time.Duration(cfg.PolicyReloadSeconds) * time.Second,
	})
	if err != nil {
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		return nil, fmt.Errorf("policy manager: %w", err)
	}

	_, _, err = manager.Reconcile(ctx)
	if err != nil {
		errutil.Discard(manager.Close())
		errutil.Close(entClient)
		errutil.CloseIf(pubSub)
		return nil, fmt.Errorf("policy reconcile: %w", err)
	}

	var profileConn *grpc.ClientConn
	var profileClient profilepb.OrganizationProfileServiceClient
	if addr := strings.TrimSpace(cfg.ProfileGRPCAddr); addr != "" {
		if cfg.clientTLSConfigured() {
			clientTLS, tlsErr := mtls.LoadClientTLSConfig(
				cfg.GRPCClientCertPath,
				cfg.GRPCClientKeyPath,
				cfg.GRPCRootCAPath,
			)
			if tlsErr != nil {
				errutil.Discard(manager.Close())
				errutil.Close(entClient)
				errutil.CloseIf(pubSub)
				return nil, fmt.Errorf("profile grpc TLS: %w", tlsErr)
			}
			profileConn, err = grpcutils.DialTLSClient(addr, clientTLS, grpcutils.ClientResilienceConfig{})
		} else {
			profileConn, err = grpcutils.DialInsecureClient(addr, grpcutils.ClientResilienceConfig{})
		}
		if err != nil {
			errutil.Discard(manager.Close())
			errutil.Close(entClient)
			errutil.CloseIf(pubSub)
			return nil, fmt.Errorf("profile grpc dial: %w", err)
		}
		profileClient = profilepb.NewOrganizationProfileServiceClient(profileConn)
	}

	return &InfraDependencies{
		GlobalConfig:  cfg,
		entClient:     entClient,
		pubSub:        pubSub,
		PolicyManager: manager,
		profileConn:   profileConn,
		ProfileClient: profileClient,
	}, nil
}
