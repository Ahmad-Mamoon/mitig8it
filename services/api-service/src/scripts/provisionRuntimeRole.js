const path = require('path');
require('dotenv').config();
require('dotenv').config({ path: path.resolve(__dirname, '../../../../.env'), override: false });
const { Pool } = require('pg');
const { provisionRuntimeDatabaseRole, verifyRuntimeDatabaseRole } = require('../services/runtimeDatabaseRole');

function parseDatabaseUrl(value, name) {
  try {
    const url = new URL(value);
    if (!['postgres:', 'postgresql:'].includes(url.protocol) || !url.username || !url.pathname.slice(1)) throw new Error();
    return url;
  } catch (_) {
    throw new Error(`${name} must be a PostgreSQL connection URL`);
  }
}

async function main() {
  const migrationUrl = parseDatabaseUrl(process.env.DATABASE_MIGRATION_URL, 'DATABASE_MIGRATION_URL');
  const runtimeUrl = parseDatabaseUrl(process.env.DATABASE_URL, 'DATABASE_URL');
  if (migrationUrl.pathname !== runtimeUrl.pathname || migrationUrl.username === runtimeUrl.username) {
    throw new Error('Migration and runtime URLs must use distinct roles for the same database');
  }
  const role = decodeURIComponent(runtimeUrl.username);
  const password = decodeURIComponent(runtimeUrl.password);
  const ssl = process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false;
  const admin = new Pool({ connectionString: process.env.DATABASE_MIGRATION_URL, ssl, max: 1 });
  const runtime = new Pool({ connectionString: process.env.DATABASE_URL, ssl, max: 1 });
  let client;
  try {
    client = await admin.connect();
    await provisionRuntimeDatabaseRole(client, { role, password });
    const result = await verifyRuntimeDatabaseRole(runtime);
    console.log(JSON.stringify({ level: 'info', msg: 'Runtime database role provisioned and verified', ...result }));
  } finally {
    if (client) client.release();
    await Promise.all([admin.end(), runtime.end()]);
  }
}

main().catch(() => {
  // Provisioning executes password-bearing SQL. Never print database error text.
  console.error(JSON.stringify({ level: 'error', msg: 'Runtime database role provisioning failed; check credentials, role ownership, and required privileges' }));
  process.exitCode = 1;
});
