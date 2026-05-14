package entpostgres

import "errors"

// ErrOpenPostgres indicates sql.Open / Ping against PostgreSQL failed during Ent bootstrap.
var ErrOpenPostgres = errors.New("entpostgres: open postgres")

// ErrSchemaCreate indicates Ent schema migration (Create) failed with a non-idempotent error.
var ErrSchemaCreate = errors.New("entpostgres: schema create")
