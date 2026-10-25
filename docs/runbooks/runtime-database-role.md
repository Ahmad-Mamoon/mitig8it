# Runtime database role and tenant isolation

Production API and worker processes must log in directly with a dedicated, non-owning
PostgreSQL role. `runtimeDatabaseRole.js` verifies this before startup: `LOGIN`,
`NOINHERIT`, `NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEDB`, `NOCREATEROLE`,
`NOREPLICATION`, no parent-role memberships, and no database, schema, relation, or
function ownership. It also checks that the login cannot create schema objects,
truncate tables, write migration history, or execute application `SECURITY DEFINER`
functions. The twelve remediation tenant tables must have both RLS and `FORCE ROW
LEVEL SECURITY` enabled, with policies present. Invalid configuration stops startup.

The runtime role receives `CONNECT`, `USAGE` on `public`, application table
`SELECT/INSERT/UPDATE/DELETE`, and sequence `USAGE/SELECT`. `schema_migrations` is
read-only. The provisioner reruns after each deployment's migrations to grant access
to newly created application tables; it does not grant broad default privileges on
future objects. It revokes `CREATE ON SCHEMA public FROM PUBLIC`, which is necessary
for older PostgreSQL databases where every login could otherwise create objects.
Use a dedicated application database and review other clients before that revocation.

## One-time operator setup

No live database or cloud resource is changed by committing this implementation.
PostgreSQL is externally managed; the existing remediation/monitoring Terraform does
not provision this database or its roles. The following steps need a database owner
or administrator and Secret Manager authority.

1. Retain the existing `codesentry-database-url` secret (`-staging` in staging) as the
   migration credential. Its role must own the application schema and be able to
   create/manage the dedicated runtime role. Keep this credential limited to the
   deployment runner and trusted operators.
2. Generate a separate password with at least 32 characters. Choose a new lowercase
   role name, for example `codesentry_runtime` or `codesentry_runtime_staging`, and
   construct a PostgreSQL URL for that login on the same database. Percent-encode
   special characters in the username/password. Do not place credentials in command
   history, logs, checked-in files, or Terraform state.
3. Store the new URL as `codesentry-database-runtime-url` (or
   `codesentry-database-runtime-url-staging`). Grant the deployment identity access to
   both secrets, and the API runtime identity access only to its runtime secret and
   other application secrets. Remove its access to the old migration secret. Grant
   staging and production identities only their own secret versions.
4. Run the existing API deployment. It migrates using the administrative URL, runs
   `db:provision-runtime` with both URLs, verifies a real direct runtime connection,
   and only then deploys the API with the runtime secret. The provisioner creates the
   role with restricted attributes and records a management marker. Reruns update its
   password/grants; unsafe or unmarked existing roles are refused without silently
   stripping privileges or adopting an unrelated account.
5. Deploy the GitHub service so its unused database secret mount is removed. Its
   deployed gRPC operations do not query PostgreSQL; the optional local HTTP webhook
   adapter still uses the local database URL.
6. Verify API health, login, repository access, an analysis, and any enabled worker
   flow. Run `npm run db:verify-runtime` with the deployed runtime URL from a trusted
   environment. The result reports only role name and protected table count. Record
   the revision and successful live checks before declaring the cutover complete.

Provisioning commands expect `DATABASE_MIGRATION_URL` for administration and
`DATABASE_URL` for the restricted login. Only the provisioner receives both:

```bash
# Supply both URLs through the environment from an approved secret source.
DATABASE_URL="$DATABASE_MIGRATION_URL" npm run db:migrate
npm run db:provision-runtime
npm run db:verify-runtime
```

Production commands require certificate-verified TLS. Do not configure
`AUTO_MIGRATE=true` on a runtime process. Migrations continue to run through
`db:migrate` with the administrative credential, while startup and `db:verify` only
read the ledger. If a managed PostgreSQL provider adds privileged role memberships
automatically, use its supported SQL role-creation path; the verifier must pass before
rollout. Do not weaken startup verification to accommodate an elevated login.

Provisioning changes one managed role and its grants, and the public-schema CREATE
grant, in a transaction. It refuses invalid role identifiers, passwords shorter than
32 characters, existing unmanaged roles, role memberships, elevated attributes, and
ownership. Its CLI intentionally suppresses raw database error text because role
password statements may be present. Review administrative database statement/audit
logging policy before provisioning; no credential should be exposed in logs.

## Isolation coverage and limits

The application sets `app.tenant_id`, `app.user_id`, and `app.remediation_worker`
transaction-locally. Tests with a real restricted login populate every protected table
for two tenants and prove missing scope denies reads, tenant/user scope isolates rows,
cross-tenant writes and forged composite references fail, and pooled connections lose
scope after commit and rollback. They also prove runtime DDL, `TRUNCATE`, migration
history edits, role escalation, and `SET ROLE` to the administrator are denied. Setting
`row_security=off` causes protected queries to fail; it does not bypass the policies.

Worker scope intentionally accesses multiple installations for queue/reconciliation
work. The API and its in-process worker currently share one trusted application role;
custom PostgreSQL context settings are supplied by application code. These policies
guard application scoping errors, not compromise of an application that can set worker
context. Core tables such as `findings`, `repositories`, and `finding_outcomes` retain
their existing query-level authorization; this change does not claim RLS on them.

Run against disposable loopback databases ending in `_test`; each suite recreates
`public` and provisions/removes a uniquely named runtime role. Never point these tests
at a shared database. The input URL must have role-management/schema privileges.

```bash
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/mitig8it_runtime_role_test npm run test:integration:runtime-role
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/mitig8it_remediation_test npm run test:integration:remediation
```

The remediation integration suite also runs its complete workflow under a restricted
login. Synthetic release evidence is enabled only in memory for that test process;
the committed release-evidence gate remains unchanged. Both suites run in CI.

## Recovery

If verification fails, keep the currently healthy revision and inspect the role's
attributes, memberships, ownership, grants, RLS flags, and credential target with an
administrator. A missing Secret Manager value or failed provision step stops deployment
before replacing the API. Restore the intended least-privilege grants and rerun the
verification. Do not restore service by granting `BYPASSRLS` or disabling RLS.

Password rotation changes new connections immediately, while existing pooled sessions
remain authenticated. Coordinate secret version creation, provisioning, and API/worker
rollout, and drain old revisions; rotating only the database password can interrupt
reconnections. Credential separation and local tests are implemented; initial secret
creation, IAM restriction, live smoke checks, and evidence of completed rollout remain
operator actions.
