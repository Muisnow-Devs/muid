// Package sqldb centralizes database/sql bootstrap for PostgreSQL using jackc/pgx via database/sql.
package sqldb

import (
	"context"
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib" // registers driver name returned by EntDriverName

	"sanzi.io/muid/pkg/errutil"
)

// EntDriverName is the database/sql driver name registered by github.com/jackc/pgx/v5/stdlib.
// Use with sql.Open when not going through OpenPostgres.
func EntDriverName() string {
	return "pgx"
}

// OpenPostgres opens a *sql.DB with the pgx stdlib driver and verifies connectivity with PingContext.
func OpenPostgres(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open(EntDriverName(), dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		errutil.Close(db)
		return nil, err
	}
	return db, nil
}
