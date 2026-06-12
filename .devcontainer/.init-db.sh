#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# .devcontainer/.init-db.sh
#
# Mounted as /docker-entrypoint-initdb.d/init-db.sh inside the postgres
# container.  PostgreSQL runs this script as the superuser on first start,
# so we can create additional databases here.
#
# NOTE: this only runs when the postgres-data volume is empty. On an existing
# volume, create missing databases manually, e.g.:
#   docker compose exec postgres psql -U muid -d muid_authn \
#     -c "CREATE DATABASE muid_authz" -c "GRANT ALL PRIVILEGES ON DATABASE muid_authz TO muid"
# ---------------------------------------------------------------------------
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Create the per-service databases (authn DB is created by POSTGRES_DB env)
    SELECT 'CREATE DATABASE muid_profile'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'muid_profile')\gexec

    SELECT 'CREATE DATABASE muid_authz'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'muid_authz')\gexec

    -- Grant the muid user access
    GRANT ALL PRIVILEGES ON DATABASE muid_profile TO muid;
    GRANT ALL PRIVILEGES ON DATABASE muid_authz TO muid;
EOSQL
