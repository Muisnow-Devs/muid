package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect"

	gcpsecretmanager "sanzi.io/muid/infra/secretmanager"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/signature"
	"sanzi.io/muid/pkg/entpostgres"
	"sanzi.io/muid/pkg/errutil"
)

func NewAuthzInfra(ctx context.Context, cfg Config) (*InfraDependencies, error) {
	entClient, _, err := entpostgres.OpenEntPostgres(ctx, cfg.DatabaseURL,
		func(d dialect.Driver) *authzent.Client {
			return authzent.NewClient(authzent.Driver(d))
		},
		func(c *authzent.Client) entpostgres.SchemaMigrator { return c.Schema },
		nil,
		"authz ent: ",
	)
	if err != nil {
		return nil, err
	}

	signatureManager, err := newSignatureManager(ctx, cfg)
	if err != nil {
		errutil.Close(entClient)
		return nil, fmt.Errorf("signature manager: %w", err)
	}

	return &InfraDependencies{
		GlobalConfig:     cfg,
		SignatureManager: signatureManager,
		entClient:        entClient,
	}, nil
}

func newSignatureManager(ctx context.Context, cfg Config) (signature.SignatureManager, error) {
	secretName := strings.TrimSpace(cfg.SignatureSecretName)
	if secretName == "" {
		return nil, signature.ErrInvalidConfig
	}

	secretStore, err := gcpsecretmanager.NewGCPSecretManager(ctx, gcpsecretmanager.GCPConfig{
		ProjectID:       cfg.SecretManagerGCPProjectID,
		CredentialsFile: cfg.SecretManagerGCPCredentials,
	})
	if err != nil {
		return nil, err
	}

	manager, err := signature.NewSignatureManager(secretStore, signature.ManagerConfig{
		SecretName:          secretName,
		KeyBits:             cfg.SignatureKeyBits,
		PreviousGenerations: cfg.SignaturePreviousGenerations,
		RotationPeriod:      signatureRotationPeriod(cfg),
	})
	if err != nil {
		errutil.CloseIf(secretStore)
		return nil, err
	}
	return manager, nil
}

func signatureRotationPeriod(cfg Config) time.Duration {
	if cfg.SignatureRotationPeriodHours <= 0 {
		return -1
	}
	return time.Duration(cfg.SignatureRotationPeriodHours) * time.Hour
}
