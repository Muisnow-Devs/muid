package entpostgres

import (
	"context"
	"database/sql"
	"errors"
	"io"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"

	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/sqldb"
)

// OpenEntPostgres opens PostgreSQL via pkg/sqldb, wraps it with entsql.OpenDB, builds
// the domain Ent client with newClient, then runs SchemaCreateBestEffort using schema(client).
// On open failure: onFatalCleanup is invoked (no Ent client exists). On schema hard failure:
// the Ent client is closed, then onFatalCleanup runs. Callers own the returned *sql.DB lifecycle.
func OpenEntPostgres[Client io.Closer](
	ctx context.Context,
	dsn string,
	newClient func(dialect.Driver) Client,
	schema func(Client) SchemaMigrator,
	onFatalCleanup func(),
	schemaLogPrefix string,
) (Client, *sql.DB, error) {
	var zero Client

	db, err := sqldb.OpenPostgres(ctx, dsn)
	if err != nil {
		if onFatalCleanup != nil {
			onFatalCleanup()
		}
		return zero, nil, errors.Join(ErrOpenPostgres, err)
	}

	drv := entsql.OpenDB(dialect.Postgres, db)
	client := newClient(drv)

	err = SchemaCreateBestEffort(ctx, schema(client), schemaLogPrefix)
	if err != nil {
		errutil.Close(client)
		if onFatalCleanup != nil {
			onFatalCleanup()
		}
		return zero, nil, err
	}

	return client, db, nil
}
