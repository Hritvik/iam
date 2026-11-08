#!/usr/bin/env bash
# Provisions the IAM database roles before Flyway runs. Executed once by the postgres image
# entrypoint on an empty data directory. Credentials arrive as container environment variables.
set -euo pipefail

: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${IAM_MIGRATOR_PASSWORD:?IAM_MIGRATOR_PASSWORD is required}"
: "${IAM_RUNTIME_PASSWORD:?IAM_RUNTIME_PASSWORD is required}"
: "${IAM_RELAY_PASSWORD:?IAM_RELAY_PASSWORD is required}"
: "${IAM_REGISTRATION_RECONCILER_PASSWORD:?IAM_REGISTRATION_RECONCILER_PASSWORD is required}"

psql --set ON_ERROR_STOP=1 \
    --username "${POSTGRES_USER}" \
    --dbname "${POSTGRES_DB}" \
    --set migrator_credential="${IAM_MIGRATOR_PASSWORD}" \
    --set runtime_credential="${IAM_RUNTIME_PASSWORD}" \
    --set relay_credential="${IAM_RELAY_PASSWORD}" \
    --set reconciler_credential="${IAM_REGISTRATION_RECONCILER_PASSWORD}" \
    --set database_name="${POSTGRES_DB}" <<'SQL'
create role iam_migrator login password
    :'migrator_credential';
create role iam_runtime login password
    :'runtime_credential';
create role iam_relay login password
    :'relay_credential';
create role iam_registration_reconciler login password
    :'reconciler_credential';

alter database :"database_name" owner to iam_migrator;

grant iam_runtime to iam_migrator with admin option;
grant iam_relay to iam_migrator with admin option;
grant iam_registration_reconciler to iam_migrator with admin option;
SQL
