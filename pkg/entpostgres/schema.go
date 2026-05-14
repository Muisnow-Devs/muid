package entpostgres

import (
	"context"
	"errors"
	"log"
	"strings"

	"entgo.io/ent/dialect/sql/schema"
)

// SchemaMigrator matches Ent generated migrate.Schema.Create.
type SchemaMigrator interface {
	Create(context.Context, ...schema.MigrateOption) error
}

// SchemaCreateBestEffort runs Ent schema creation. If the driver reports objects already
// present (common substrings in the error text), it logs and returns nil. Otherwise it
// returns errors.Join(ErrSchemaCreate, err). It does not close the Ent client.
func SchemaCreateBestEffort(
	ctx context.Context,
	m SchemaMigrator,
	logPrefix string,
	opts ...schema.MigrateOption,
) error {
	err := m.Create(ctx, opts...)
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "already exists") || strings.Contains(msg, "duplicate") {
		log.Printf("%sreusing existing schema (%v)", logPrefix, err)
		return nil
	}
	return errors.Join(ErrSchemaCreate, err)
}
