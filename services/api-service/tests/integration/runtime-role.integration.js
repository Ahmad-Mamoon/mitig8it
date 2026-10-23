// Explicitly invoked against a disposable loopback *_test database. Never loads .env.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const adminUrl = new URL(process.env.DATABASE_URL || 'postgres://invalid');
assert.ok(['postgres:', 'postgresql:'].includes(adminUrl.protocol)
  && ['localhost', '127.0.0.1'].includes(adminUrl.hostname)
  && /^\/[a-zA-Z0-9_]+_test$/.test(adminUrl.pathname),
'DATABASE_URL must be a disposable loopback PostgreSQL *_test database');
process.env.NODE_ENV = 'test';
const runtimeRole = `mitig8it_runtime_test_${process.pid}`;
const runtimeUrl = new URL(adminUrl);
runtimeUrl.username = runtimeRole;
runtimeUrl.password = 'isolated-runtime-password-with-32-characters';
process.env.DATABASE_URL = runtimeUrl.toString();
const admin = new Pool({ connectionString: adminUrl.toString(), max: 1 });
const runtime = new Pool({ connectionString: runtimeUrl.toString(), max: 1 });
const { pool } = require('../../src/config/database');
const { applyMigrations, getPendingMigrations } = require('../../src/services/migrationRunner');
const { ensureDatabaseSchema } = require('../../src/services/schemaBootstrap');
const { TENANT_TABLES, provisionRuntimeDatabaseRole, verifyRuntimeDatabaseRole } = require('../../src/services/runtimeDatabaseRole');
const remediationDb = require('../../src/db/remediation');
const fixtures = [];

async function provision() {
  const client = await admin.connect();
  try {
    return await provisionRuntimeDatabaseRole(client, {
      role: runtimeRole, password: decodeURIComponent(runtimeUrl.password),
    });
  } finally { client.release(); }
}

async function scope(settings, fn, { rollback = false } = {}) {
  const client = await runtime.connect();
  try {
    await client.query('BEGIN');
    for (const [name, value] of Object.entries(settings)) {
      await client.query('SELECT set_config($1, $2, true)', [name, String(value)]);
    }
    const result = await fn(client);
    await client.query(rollback ? 'ROLLBACK' : 'COMMIT');
    return result;
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

async function fixture(installation) {
  return scope({ 'app.tenant_id': installation }, async (client) => {
    const repo = randomUUID();
    const pr = randomUUID();
    const run = randomUUID();
    const user = randomUUID();
    const job = randomUUID();
    const candidate = randomUUID();
    const action = randomUUID();
    await client.query("INSERT INTO installations(id,status) VALUES ($1,'active')", [installation]);
    await client.query('INSERT INTO users(id,github_id,github_username) VALUES ($1,$2,$3)', [user, installation, `runtime-user-${installation}`]);
    await client.query("INSERT INTO repositories(id,github_id,installation_id,name,full_name) VALUES ($1,$2,$2,'fixture',$3)", [repo, installation, `fixture/runtime-${installation}`]);
    await client.query('INSERT INTO repository_access(user_id,repository_id) VALUES ($1,$2)', [user, repo]);
    await client.query("INSERT INTO pull_requests(id,repository_id,pr_number,head_sha,base_sha,state) VALUES ($1,$2,1,$3,$4,'open')", [pr, repo, 'a'.repeat(40), 'b'.repeat(40)]);
    await client.query("INSERT INTO analysis_runs(id,repository_id,pull_request_id,commit_sha,status) VALUES ($1,$2,$3,$4,'completed')", [run, repo, pr, 'a'.repeat(40)]);
    await client.query(`INSERT INTO remediation_jobs(id,installation_id,repository_id,pull_request_id,analysis_run_id,
      head_sha,base_sha,selection_hash,finding_snapshot_ids,state,stage,deadline_at,policy_version,policy_manifest,created_by)
      VALUES ($1,$2,$3,$4,$5,$6,$7,'selection','{}','queued','snapshotting',NOW()+INTERVAL '1 hour','test','{}',$8)`,
    [job, installation, repo, pr, run, 'a'.repeat(40), 'b'.repeat(40), user]);
    await client.query(`INSERT INTO remediation_candidates(id,job_id,installation_id,repository_id,candidate_version,
      finding_snapshot_ids,artifact_digest,context_manifest_digest,file_manifest,preview,verification_level)
      VALUES ($1,$2,$3,$4,1,'{}','artifact','context','{}','{}','not_verified')`, [candidate, job, installation, repo]);
    await client.query(`INSERT INTO remediation_attempts(job_id,installation_id,repository_id,stage,attempt_number,fencing_token)
      VALUES ($1,$2,$3,'snapshotting',1,1)`, [job, installation, repo]);
    await client.query(`INSERT INTO verification_runs(job_id,candidate_id,installation_id,repository_id,original_tree_sha,base_sha,policy_version,outcome)
      VALUES ($1,$2,$3,$4,'tree','base','test','inconclusive')`, [job, candidate, installation, repo]);
    await client.query(`INSERT INTO remediation_actions(id,job_id,installation_id,repository_id,pull_request_id,actor_id,actor_login,
      action_type,head_sha,base_sha,batch_manifest_digest,candidate_ids,idempotency_key,payload_hash,state)
      VALUES ($1,$2,$3,$4,$5,$6,'fixture','apply','head','base','manifest',$7,'test','hash','requested')`,
    [action, job, installation, repo, pr, user, [candidate]]);
    await client.query(`INSERT INTO merge_intents(action_id,installation_id,repository_id,actor_id,approved_manifest_digest,
      approved_head_sha,approved_base_sha,expires_at,state) VALUES ($1,$2,$3,$4,'manifest','head','base',NOW()+INTERVAL '1 hour','waiting_for_checks')`,
    [action, installation, repo, user]);
    await client.query(`INSERT INTO workflow_events(aggregate_id,aggregate_type,installation_id,repository_id,sequence,event_type,payload)
      VALUES ($1,'remediation_job',$2,$3,1,'test','{}')`, [job, installation, repo]);
    await client.query(`INSERT INTO workflow_outbox(aggregate_id,installation_id,repository_id,event_sequence,event_type,payload)
      VALUES ($1,$2,$3,1,'test','{}')`, [job, installation, repo]);
    await client.query(`INSERT INTO usage_reservations(job_id,installation_id,repository_id,stage,reservation_key,reserved_amount,state)
      VALUES ($1,$2,$3,'snapshotting','test',0,'reserved')`, [job, installation, repo]);
    await client.query(`INSERT INTO repair_memory(installation_id,repository_id,weakness_signature,source_digest,patch_digest,verification_outcome,status)
      VALUES ($1,$2,'weakness','source','patch','inconclusive','observed')`, [installation, repo]);
    await client.query(`INSERT INTO remediation_writer_leases(pull_request_id,installation_id,repository_id,expires_at)
      VALUES ($1,$2,$3,NOW()+INTERVAL '1 hour')`, [pr, installation, repo]);
    await client.query(`INSERT INTO remediation_job_evidence(job_id,installation_id,repository_id,attempt,kind,payload)
      VALUES ($1,$2,$3,1,'usage','{}')`, [job, installation, repo]);
    return { installation, repo, pr, run, user, job };
  });
}

before(async () => {
  await admin.query('DROP SCHEMA public CASCADE');
  await admin.query('CREATE SCHEMA public');
  await applyMigrations(undefined, admin);
  await provision();
  fixtures.push(await fixture(97001), await fixture(97002));
});

after(async () => {
  await Promise.all([runtime.end(), pool.end()]);
  await admin.query(`DROP OWNED BY "${runtimeRole}"`);
  await admin.query(`DROP ROLE "${runtimeRole}"`);
  await admin.end();
});

test('provisioning is repeatable and the direct runtime login passes verification', async () => {
  await provision();
  assert.deepEqual(await verifyRuntimeDatabaseRole(runtime), { role: runtimeRole, tenantTables: 12 });
  assert.deepEqual(await getPendingMigrations(), []);
  process.env.NODE_ENV = 'production';
  try { await ensureDatabaseSchema(); }
  finally { process.env.NODE_ENV = 'test'; }
});

test('unscoped reads deny all rows on every protected table', async () => {
  for (const table of TENANT_TABLES) {
    assert.equal((await runtime.query(`SELECT * FROM "${table}"`)).rowCount, 0, table);
  }
});

test('tenant context isolates reads on every protected table and resets after commit', async () => {
  for (const f of fixtures) {
    await scope({ 'app.tenant_id': f.installation }, async (client) => {
      for (const table of TENANT_TABLES) {
        const result = await client.query(`SELECT installation_id FROM "${table}"`);
        assert.equal(result.rowCount, 1, table);
        assert.equal(String(result.rows[0].installation_id), String(f.installation), table);
      }
    });
    assert.equal((await runtime.query('SELECT * FROM remediation_jobs')).rowCount, 0);
  }
});

test('repository user context exposes only the authorized tenant and cannot write without tenant scope', async () => {
  const [f, other] = fixtures;
  await scope({ 'app.user_id': f.user }, async (client) => {
    assert.deepEqual((await client.query('SELECT id FROM remediation_jobs')).rows, [{ id: f.job }]);
    assert.equal((await client.query('SELECT id FROM remediation_jobs WHERE id=$1', [other.job])).rowCount, 0);
    await assert.rejects(client.query(`INSERT INTO workflow_events(aggregate_id,aggregate_type,installation_id,sequence,event_type,payload)
      VALUES ($1,'test',$2,2,'forbidden','{}')`, [f.job, f.installation]), { code: '42501' });
  }, { rollback: true });
});

test('cross-tenant writes and forged tenant relations fail under the runtime role', async () => {
  const [f, other] = fixtures;
  await scope({ 'app.tenant_id': f.installation }, async (client) => {
    assert.equal((await client.query("UPDATE remediation_jobs SET stage='forbidden' WHERE id=$1", [other.job])).rowCount, 0);
    await assert.rejects(client.query(`INSERT INTO remediation_job_evidence(job_id,installation_id,repository_id,attempt,kind,payload)
      VALUES ($1,$2,$3,2,'usage','{}')`, [other.job, other.installation, other.repo]), { code: '42501' });
  }, { rollback: true });
  await scope({ 'app.tenant_id': f.installation }, async (client) => {
    await assert.rejects(client.query(`INSERT INTO remediation_job_evidence(job_id,installation_id,repository_id,attempt,kind,payload)
      VALUES ($1,$2,$3,2,'usage','{}')`, [other.job, f.installation, f.repo]), { code: '23503' });
  }, { rollback: true });
});

test('worker context works without BYPASSRLS and resets after rollback on the pooled connection', async () => {
  await scope({ 'app.remediation_worker': '1' }, async (client) => {
    assert.equal((await client.query('SELECT * FROM remediation_jobs')).rowCount, 2);
  }, { rollback: true });
  assert.equal((await runtime.query('SELECT * FROM remediation_jobs')).rowCount, 0);
  const job = await remediationDb.claimJobById(fixtures[0].job, 'runtime-test');
  assert.equal(job.id, fixtures[0].job);
  assert.equal((await pool.query('SELECT * FROM remediation_jobs')).rowCount, 0);
});

test('runtime cannot change schema, policies, migration history, role attributes, or truncate protected rows', async () => {
  for (const sql of [
    'CREATE TABLE public.runtime_forbidden(id int)',
    'ALTER TABLE remediation_jobs DISABLE ROW LEVEL SECURITY',
    'TRUNCATE remediation_jobs CASCADE',
    "UPDATE schema_migrations SET checksum='forged'",
    `ALTER ROLE "${runtimeRole}" BYPASSRLS`,
    `SET ROLE "${decodeURIComponent(adminUrl.username)}"`,
  ]) {
    await assert.rejects(runtime.query(sql), { code: '42501' }, sql);
  }
  const client = await runtime.connect();
  await client.query('SET row_security=off');
  try {
    await assert.rejects(client.query('SELECT * FROM remediation_jobs'), { code: '42501' });
    await assert.rejects(verifyRuntimeDatabaseRole(client), /row_security enabled/);
  } finally {
    await client.query('SET row_security=on');
    client.release();
  }
});

test('verification rejects elevated runtime attributes, memberships, and disabled tenant policies', async () => {
  await admin.query(`ALTER ROLE "${runtimeRole}" BYPASSRLS`);
  try {
    await assert.rejects(verifyRuntimeDatabaseRole(runtime), /without elevated attributes/);
    await assert.rejects(provision(), /without elevated attributes/);
  } finally { await admin.query(`ALTER ROLE "${runtimeRole}" NOBYPASSRLS`); }
  await admin.query(`GRANT "${decodeURIComponent(adminUrl.username)}" TO "${runtimeRole}"`);
  try { await assert.rejects(verifyRuntimeDatabaseRole(runtime), /without elevated attributes/); }
  finally { await admin.query(`REVOKE "${decodeURIComponent(adminUrl.username)}" FROM "${runtimeRole}"`); }
  await admin.query('ALTER TABLE remediation_job_evidence NO FORCE ROW LEVEL SECURITY');
  try { await assert.rejects(verifyRuntimeDatabaseRole(runtime), /forced row-level security/); }
  finally { await admin.query('ALTER TABLE remediation_job_evidence FORCE ROW LEVEL SECURITY'); }
});

test('provisioning refuses unmanaged roles and invalid identifiers before changing grants', async () => {
  const client = await admin.connect();
  try {
    await assert.rejects(provisionRuntimeDatabaseRole(client, { role: 'unsafe;role', password: 'x'.repeat(40) }), /identifier/);
    const unmanaged = `mitig8it_unmanaged_test_${process.pid}`;
    await client.query(`CREATE ROLE "${unmanaged}" LOGIN NOINHERIT`);
    try {
      await assert.rejects(provisionRuntimeDatabaseRole(client, { role: unmanaged, password: 'x'.repeat(40) }), /unmanaged/);
    } finally { await client.query(`DROP ROLE "${unmanaged}"`); }
  } finally { client.release(); }
});
