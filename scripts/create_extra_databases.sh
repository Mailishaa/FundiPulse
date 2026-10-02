#!/bin/bash
# Create additional databases listed in POSTGRES_MULTIPLE_DATABASES.
#
# Runs once, from the official postgres image's entrypoint, before the server
# accepts connections. Used to provision the dedicated test database so the test
# suite can never touch development or production data.
set -euo pipefail

if [ -z "${POSTGRES_MULTIPLE_DATABASES:-}" ]; then
    exit 0
fi

for db in $(echo "$POSTGRES_MULTIPLE_DATABASES" | tr ',' ' '); do
    echo "  creating database '$db'"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
        CREATE DATABASE "$db" OWNER "$POSTGRES_USER";
EOSQL
done