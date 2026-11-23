#!/bin/sh
set -eu

# The official PostgreSQL entrypoint reads POSTGRES_PASSWORD_FILE as root and
# exports POSTGRES_PASSWORD before running init scripts as the postgres user.
# The host file stays owner-only; this script does not read it or put its value
# into psql process arguments.
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=ON_ERROR_STOP=1 \
  --file=/opt/hallpass-bootstrap/application-role.sql
