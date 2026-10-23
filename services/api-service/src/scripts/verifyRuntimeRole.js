const path = require('path');
require('dotenv').config();
require('dotenv').config({ path: path.resolve(__dirname, '../../../../.env'), override: false });
const { pool } = require('../config/database');
const { verifyRuntimeDatabaseRole } = require('../services/runtimeDatabaseRole');

verifyRuntimeDatabaseRole(pool)
  .then((result) => console.log(JSON.stringify({ level: 'info', msg: 'Runtime database role verified', ...result })))
  .catch((error) => {
    console.error(JSON.stringify({ level: 'error', msg: 'Runtime database role verification failed', error: error.message }));
    process.exitCode = 1;
  })
  .finally(() => pool.end());
