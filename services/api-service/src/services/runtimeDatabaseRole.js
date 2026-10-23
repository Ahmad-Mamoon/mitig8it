const RUNTIME_ROLE_MARKER = 'mitig8it runtime role v1';
const TENANT_TABLES = Object.freeze([
  'remediation_jobs', 'remediation_candidates', 'remediation_attempts', 'verification_runs',
  'remediation_actions', 'merge_intents', 'workflow_events', 'workflow_outbox',
  'usage_reservations', 'repair_memory', 'remediation_writer_leases', 'remediation_job_evidence',
]);

function identifier(value) {
  return `"${String(value).replace(/"/g, '""')}"`;
}

function validateRoleName(role) {
  if (typeof role !== 'string' || !/^[a-z_][a-z0-9_]{0,62}$/.test(role) || role.startsWith('pg_')) {
    throw new Error('Runtime role must be a lowercase PostgreSQL identifier of at most 63 characters');
  }
}

async function roleDetails(client, role) {
  const { rows } = await client.query(`
    SELECT r.oid, r.rolname, r.rolsuper, r.rolbypassrls, r.rolcreaterole,
           r.rolcreatedb, r.rolreplication, r.rolinherit, r.rolcanlogin,
           shobj_description(r.oid, 'pg_authid') AS marker,
           EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = r.oid) AS has_memberships,
           EXISTS (SELECT 1 FROM pg_database d WHERE d.datdba = r.oid) AS owns_database,
           EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspowner = r.oid) AS owns_schema,
           EXISTS (SELECT 1 FROM pg_class c WHERE c.relowner = r.oid) AS owns_relation,
           EXISTS (SELECT 1 FROM pg_proc p WHERE p.proowner = r.oid) AS owns_function
      FROM pg_roles r WHERE r.rolname = $1`, [role]);
  return rows[0];
}

function assertRestrictedRole(role) {
  if (!role || !role.rolcanlogin || role.rolsuper || role.rolbypassrls || role.rolcreaterole ||
      role.rolcreatedb || role.rolreplication || role.rolinherit || role.has_memberships ||
      role.owns_database || role.owns_schema || role.owns_relation || role.owns_function) {
    throw new Error('Database runtime role must be a non-owning LOGIN NOINHERIT role without elevated attributes or memberships');
  }
}

// Read-only and safe to run at every production startup. Checking memberships as
// well as attributes prevents SET ROLE from recovering a migration owner's powers.
async function verifyRuntimeDatabaseRole(client) {
  const identity = (await client.query(`SELECT current_user AS role, session_user AS login,
    current_setting('row_security') AS row_security`)).rows[0];
  if (identity.role !== identity.login || identity.row_security !== 'on') {
    throw new Error('Runtime database connections must log in directly with row_security enabled');
  }
  const role = await roleDetails(client, identity.role);
  assertRestrictedRole(role);

  const privileges = (await client.query(`SELECT
    has_schema_privilege(current_user, 'public', 'CREATE') AS schema_create,
    has_database_privilege(current_user, current_database(), 'CREATE') AS database_create,
    has_table_privilege(current_user, 'public.schema_migrations', 'SELECT') AS ledger_read,
    has_table_privilege(current_user, 'public.schema_migrations', 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS ledger_write,
    EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind IN ('r','p')
        AND has_table_privilege(current_user, c.oid, 'TRUNCATE,REFERENCES,TRIGGER')) AS table_admin,
    EXISTS (SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname='public' AND p.prosecdef
        AND has_function_privilege(current_user, p.oid, 'EXECUTE')) AS security_definer`)).rows[0];
  if (privileges.schema_create || privileges.database_create || !privileges.ledger_read ||
      privileges.ledger_write || privileges.table_admin || privileges.security_definer) {
    throw new Error('Database runtime privileges permit schema changes, privileged functions, or migration-ledger writes');
  }
  const { rows } = await client.query(`SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
      EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid=c.oid) AS has_policy
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='public' AND c.relname=ANY($1::text[])`, [TENANT_TABLES]);
  if (rows.length !== TENANT_TABLES.length || rows.some((row) =>
    !row.relrowsecurity || !row.relforcerowsecurity || !row.has_policy)) {
    throw new Error('Required tenant tables must have forced row-level security and policies');
  }
  return { role: role.rolname, tenantTables: rows.length };
}

// Only a migration/administrative connection may invoke this provisioning step.
// Existing unmanaged or elevated roles are refused rather than silently modified.
async function provisionRuntimeDatabaseRole(client, { role, password }) {
  validateRoleName(role);
  if (typeof password !== 'string' || password.length < 32 || password.includes('\0')) {
    throw new Error('Runtime database password must contain at least 32 characters and no NUL');
  }
  await client.query('BEGIN');
  try {
    await client.query('SELECT pg_advisory_xact_lock($1)', [727275]);
    const existing = await roleDetails(client, role);
    if (existing) {
      assertRestrictedRole(existing);
      if (existing.marker !== RUNTIME_ROLE_MARKER) {
        throw new Error('Refusing to modify an unmanaged existing database role');
      }
    } else {
      await client.query(`CREATE ROLE ${identifier(role)} LOGIN NOINHERIT NOSUPERUSER
        NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION`);
      await client.query(`COMMENT ON ROLE ${identifier(role)} IS '${RUNTIME_ROLE_MARKER}'`);
    }
    // PostgreSQL quotes the password. Callers must never print this statement or
    // database errors that could contain password-bearing SQL.
    const statement = (await client.query("SELECT format('ALTER ROLE %I PASSWORD %L', $1::text, $2::text) AS sql",
      [role, password])).rows[0].sql;
    await client.query(statement);
    const database = (await client.query('SELECT current_database() AS name')).rows[0].name;
    await client.query('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
    await client.query(`REVOKE ALL ON SCHEMA public FROM ${identifier(role)}`);
    await client.query(`GRANT USAGE ON SCHEMA public TO ${identifier(role)}`);
    await client.query(`REVOKE ALL ON DATABASE ${identifier(database)} FROM ${identifier(role)}`);
    await client.query(`GRANT CONNECT ON DATABASE ${identifier(database)} TO ${identifier(role)}`);
    await client.query(`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ${identifier(role)}`);
    await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${identifier(role)}`);
    await client.query(`REVOKE ALL ON public.schema_migrations FROM ${identifier(role)}`);
    await client.query(`GRANT SELECT ON public.schema_migrations TO ${identifier(role)}`);
    await client.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM ${identifier(role)}`);
    await client.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${identifier(role)}`);
    await client.query('COMMIT');
    return { role };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
}

module.exports = { TENANT_TABLES, provisionRuntimeDatabaseRole, verifyRuntimeDatabaseRole };
