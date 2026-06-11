package app

import (
	"context"

	"entgo.io/ent/dialect"

	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/pkg/entpostgres"
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

	return &InfraDependencies{
		GlobalConfig: cfg,
		entClient:    entClient,
	}, nil
}
