# End-to-end successes, 2026-10-13

Each case below went through tier 1 and tier 2 detection on the vulnerable file, the template repair
engine with its own verifier, and then the fixture's exploit and behavior tests run independently
against the patched tree. Exploit test fails before the patch and passes after; behavior test passes
both times. Tier 3 (model triage and recommendation) did not run: no working model key.

| Fixture | Family | Detected by | Line | Severity |
| --- | --- | --- | ---: | --- |
| js-command-module-function | command_arguments | `opengrep.cwe-78.js-exec-interpolated` | 4 | critical |
| js-credential-api-key | hardcoded_credential | `opengrep.cwe-798.hardcoded-secret-js` | 2 | critical |
| js-eval-request-body | code_injection_eval | `code.injection.eval` | 4 | critical |
| js-hardcoded-config-secret | hardcoded_credential | `opengrep.cwe-798.js-credential-config-key` | 2 | critical |
| js-hardcoded-config-secret | hardcoded_credential | `secret.entropy.credential_assignment` | 5 | high |
| js-hardcoded-secret | hardcoded_credential | `opengrep.cwe-798.hardcoded-secret-js` | 2 | critical |
| js-module-scope-credential | hardcoded_credential | `opengrep.cwe-798.js-credential-constant` | 5 | critical |
| js-module-scope-env-command | command_arguments | `opengrep.cwe-78.js-exec-interpolated` | 7 | critical |
| js-path-sendfile | path_containment | `opengrep.cwe-22.js-sendfile-request-path` | 8 | critical |
| js-path-sendfile | path_containment | `opengrep.cwe-22.js-sendfile-request-path` | 12 | critical |
| js-session-secret-object | hardcoded_credential | `opengrep.cwe-798.js-session-secret-literal` | 8 | critical |
| js-sql-exports-assignment | sql_parameterization | `opengrep.cwe-89.sql-template-literal` | 2 | critical |
| js-sql-module-function | sql_parameterization | `opengrep.cwe-89.sql-template-literal` | 2 | critical |
| python-command-shell-true | command_arguments | `opengrep.cwe-78.py-subprocess-shell-interpolated` | 6 | critical |
| python-eval | code_injection_eval | `code.injection.eval` | 6 | critical |
| python-hardcoded-secret | hardcoded_credential | `secret.hardcoded.credential` | 3 | critical |
| python-module-scope-env | command_arguments | `opengrep.cwe-78.command-injection-input` | 10 | critical |
| python-sql-fstring | sql_parameterization | `opengrep.cwe-89.py-execute-fstring-direct` | 13 | critical |
| python-sql-psycopg-format | sql_parameterization | `opengrep.cwe-89.sql-injection-format` | 6 | critical |
| python-sql-sqlite | sql_parameterization | `opengrep.cwe-89.py-execute-concat-direct` | 10 | critical |
| python-sql-two-queries | sql_parameterization | `opengrep.cwe-89.py-execute-concat-direct` | 11 | critical |
| python-sql-two-queries | sql_parameterization | `opengrep.cwe-89.py-execute-fstring-direct` | 17 | critical |

## js-command-module-function

**Finding:** `opengrep.cwe-78.js-exec-interpolated` at `app.js:4`, critical, CWE-78, confidence 0.85. Shell command assembled by interpolation. Use execFile or spawn with an argument list

**Flagged code:** `return exec(`wkhtmltopdf ${name} report.pdf`, callback);`

```diff
--- a/app.js
+++ b/app.js
@@ -1,7 +1,7 @@
-const { exec } = require('child_process');
+const { exec, execFile } = require('child_process');

 function renderReport(name, callback) {
-  return exec(`wkhtmltopdf ${name} report.pdf`, callback);
+  return execFile('wkhtmltopdf', [name, 'report.pdf'], callback);
 }

 module.exports = { renderReport };
```

## js-credential-api-key

**Finding:** `opengrep.cwe-798.hardcoded-secret-js` at `app.js:2`, critical, CWE-798, confidence 0.99. Hardcoded credential — use environment variables

**Flagged code:** `const API_KEY = 'sk-live-3f9ab2c1d4e5f6a7';`

```diff
--- a/app.js
+++ b/app.js
@@ -1,5 +1,5 @@
 // Vendor billing client.
-const API_KEY = 'sk-live-3f9ab2c1d4e5f6a7';
+const API_KEY = process.env.API_KEY;

 function vendorHeaders(requestId) {
   return {
```

## js-eval-request-body

**Finding:** `code.injection.eval` at `app.js:4`, critical, CWE-95, confidence 0.92. Code injection via eval or dynamic execution

**Flagged code:** `return eval(expression);`

```diff
--- a/app.js
+++ b/app.js
@@ -1,7 +1,7 @@
 // Pricing rules evaluated per request.
 function applyRule(body, row) {
   const expression = body.expression;
-  return eval(expression);
+  return JSON.parse(expression);
 }

 module.exports = { applyRule };
```

## js-hardcoded-config-secret

**Finding:** `opengrep.cwe-798.js-credential-config-key` at `config.js:2`, critical, CWE-798, confidence 0.80. Credential held as a literal config value. Read it from process.env instead

**Flagged code:** `const config = {
  baseUrl: 'https://payments.example.com',
  timeoutMs: 5000,
  clientSecret: 'MFyZ2h0LWNsaWVudC1zZWNyZXQ',
};`

```diff
--- a/config.js
+++ b/config.js
@@ -1,6 +1,6 @@
 // Runtime configuration for the payments integration.
 const config = {
-  baseUrl: 'https://payments.example.com',
+  baseUrl: process.env.BASE_URL,
   timeoutMs: 5000,
   clientSecret: 'MFyZ2h0LWNsaWVudC1zZWNyZXQ',
 };
```

**Finding:** `secret.entropy.credential_assignment` at `config.js:5`, high, CWE-798, confidence 0.80. High-entropy credential value committed in this change

**Flagged code:** `clientSecret: 'MFyZ2h0LWNsaWVudC1zZWNyZXQ',`

```diff
--- a/config.js
+++ b/config.js
@@ -2,7 +2,7 @@
 const config = {
   baseUrl: 'https://payments.example.com',
   timeoutMs: 5000,
-  clientSecret: 'MFyZ2h0LWNsaWVudC1zZWNyZXQ',
+  clientSecret: process.env.CLIENT_SECRET,
 };

 function authorization() {
```

## js-hardcoded-secret

**Finding:** `opengrep.cwe-798.hardcoded-secret-js` at `app.js:2`, critical, CWE-798, confidence 0.99. Hardcoded credential — use environment variables

**Flagged code:** `const apiKey = "sk-live-7f3a91bc44de2210";`

```diff
--- a/app.js
+++ b/app.js
@@ -1,5 +1,5 @@
 // Client for the vendor billing API.
-const apiKey = "sk-live-7f3a91bc44de2210";
+const apiKey = process.env.API_KEY;

 function authHeaders() {
   return { Authorization: `Bearer ${apiKey}` };
```

## js-module-scope-credential

**Finding:** `opengrep.cwe-798.js-credential-constant` at `app.js:5`, critical, CWE-798, confidence 0.85. Credential held as a literal. Read it from process.env instead

**Flagged code:** `const signingSecret = 'whsec_2f8c11ad93be40f7';`

```diff
--- a/app.js
+++ b/app.js
@@ -2,7 +2,7 @@
 // time and there is no function a test could call instead.
 const crypto = require('node:crypto');

-const signingSecret = 'whsec_2f8c11ad93be40f7';
+const signingSecret = process.env.SIGNING_SECRET;
 const algorithm = 'sha256';

 function sign(payload) {
```

## js-module-scope-env-command

**Finding:** `opengrep.cwe-78.js-exec-interpolated` at `app.js:7`, critical, CWE-78, confidence 0.85. Shell command assembled by interpolation. Use execFile or spawn with an argument list

**Flagged code:** `const log = execSync(`git log --oneline ${branch}`).toString();`

```diff
--- a/app.js
+++ b/app.js
@@ -1,9 +1,9 @@
 // A release note generator. Everything here runs once, when the module is required: there is
 // no function enclosing the sink, so a test can only drive it by setting the environment the
 // module reads and then importing it.
-const { execSync } = require('child_process');
+const { execSync, execFileSync } = require('child_process');

 const branch = process.env.BUILD_BRANCH;
-const log = execSync(`git log --oneline ${branch}`).toString();
+const log = execFileSync('git', ['log', '--oneline', branch]).toString();

 module.exports = { log, branch };
```

## js-path-sendfile

**Finding:** `opengrep.cwe-22.js-sendfile-request-path` at `app.js:8`, critical, CWE-22, confidence 0.90. Response file chosen by request input. Resolve against the base and reject anything outside it

**Flagged code:** `return res.sendFile(path.join(ASSETS, req.params.name));`

```diff
--- a/app.js
+++ b/app.js
@@ -5,7 +5,10 @@

 // Two routes in this file send a file named by the request.
 function sendAsset(req, res) {
-  return res.sendFile(path.join(ASSETS, req.params.name));
+  const baseDir = path.resolve(ASSETS);
+  const target = path.resolve(baseDir, String(req.params.name));
+  if (target !== baseDir && !target.startsWith(baseDir + path.sep)) return res.status(400).end();
+  return res.sendFile(target);
 }

 function sendThumbnail(req, res) {
```

**Finding:** `opengrep.cwe-22.js-sendfile-request-path` at `app.js:12`, critical, CWE-22, confidence 0.90. Response file chosen by request input. Resolve against the base and reject anything outside it

**Flagged code:** `return res.sendFile(path.join(THUMBS, req.query.name));`

```diff
--- a/app.js
+++ b/app.js
@@ -9,7 +9,10 @@
 }

 function sendThumbnail(req, res) {
-  return res.sendFile(path.join(THUMBS, req.query.name));
+  const baseDir = path.resolve(THUMBS);
+  const target = path.resolve(baseDir, String(req.query.name));
+  if (target !== baseDir && !target.startsWith(baseDir + path.sep)) return res.status(400).end();
+  return res.sendFile(target);
 }

 module.exports = { sendAsset, sendThumbnail, ASSETS, THUMBS };
```

## js-session-secret-object

**Finding:** `opengrep.cwe-798.js-session-secret-literal` at `server.js:8`, critical, CWE-798, confidence 0.85. Session signing secret is a literal. Read it from process.env instead

**Flagged code:** `secret: 'keyboard cat',`

```diff
--- a/server.js
+++ b/server.js
@@ -5,7 +5,7 @@

 function install(app) {
   app.use(session({
-    secret: 'keyboard cat',
+    secret: process.env.SECRET,
     resave: true,
     saveUninitialized: true,
   }));
```

## js-sql-exports-assignment

**Finding:** `opengrep.cwe-89.sql-template-literal` at `app.js:2`, critical, CWE-89, confidence 0.90. SQL query built with template literal — use parameterized queries

**Flagged code:** `return db.query(`SELECT id FROM customers WHERE email = '${email}'`);`

```diff
--- a/app.js
+++ b/app.js
@@ -1,3 +1,3 @@
 exports.findCustomer = function (db, email) {
-  return db.query(`SELECT id FROM customers WHERE email = '${email}'`);
+  return db.query('SELECT id FROM customers WHERE email = $1', [email]);
 };
```

## js-sql-module-function

**Finding:** `opengrep.cwe-89.sql-template-literal` at `app.js:2`, critical, CWE-89, confidence 0.90. SQL query built with template literal — use parameterized queries

**Flagged code:** `return db.query(`SELECT id, total FROM orders WHERE reference = '${reference}'`);`

```diff
--- a/app.js
+++ b/app.js
@@ -1,5 +1,5 @@
 function loadOrder(db, reference) {
-  return db.query(`SELECT id, total FROM orders WHERE reference = '${reference}'`);
+  return db.query('SELECT id, total FROM orders WHERE reference = $1', [reference]);
 }

 module.exports = { loadOrder };
```

## python-command-shell-true

**Finding:** `opengrep.cwe-78.py-subprocess-shell-interpolated` at `app.py:6`, critical, CWE-78, confidence 0.95. subprocess with shell=True on a built command string. Pass an argument list and drop shell

**Flagged code:** `subprocess.run("convert " + source_name + " -resize 200x200 thumb.png", shell=True, check=True)`

```diff
--- a/app.py
+++ b/app.py
@@ -3,5 +3,5 @@


 def render_thumbnail(source_name):
-    subprocess.run("convert " + source_name + " -resize 200x200 thumb.png", shell=True, check=True)
+    subprocess.run(["convert", source_name, "-resize", "200x200", "thumb.png"], check=True)
     return "thumb.png"
```

## python-eval

**Finding:** `code.injection.eval` at `app.py:6`, critical, CWE-95, confidence 0.92. Code injection via eval or dynamic execution

**Flagged code:** `return eval(raw)`

```diff
--- a/app.py
+++ b/app.py
@@ -1,6 +1,7 @@
 """Settings parsing for the reporting job."""
+import ast


 def parse_settings(raw):
     """Parses a settings literal such as "{'retries': 3, 'hosts': ['a', 'b']}"."""
-    return eval(raw)
+    return ast.literal_eval(raw)
```

## python-hardcoded-secret

**Finding:** `secret.hardcoded.credential` at `app.py:3`, critical, CWE-798, confidence 0.94. Hardcoded secret or credential

**Flagged code:** `API_KEY = "sk-live-aaaaaaaaaaaaaaaa"`

```diff
--- a/app.py
+++ b/app.py
@@ -1,6 +1,7 @@
 """Client for the vendor billing API."""
+import os

-API_KEY = "sk-live-aaaaaaaaaaaaaaaa"
+API_KEY = os.environ["API_KEY"]


 def auth_headers():
```

## python-module-scope-env

**Finding:** `opengrep.cwe-78.command-injection-input` at `app.py:10`, critical, CWE-78, confidence 0.99. Command execution with user-controlled input — use subprocess with argument list

**Flagged code:** `RESULT = subprocess.run("rsync -a /var/data " + TARGET, shell=True)`

```diff
--- a/app.py
+++ b/app.py
@@ -7,4 +7,4 @@
 import subprocess

 TARGET = os.environ["BACKUP_TARGET"]
-RESULT = subprocess.run("rsync -a /var/data " + TARGET, shell=True)
+RESULT = subprocess.run(["rsync", "-a", "/var/data", TARGET])
```

## python-sql-fstring

**Finding:** `opengrep.cwe-89.py-execute-fstring-direct` at `app.py:13`, critical, CWE-89, confidence 0.95. SQL passed to execute() as an f-string. Pass the value as a bound parameter

**Flagged code:** `cursor.execute(f"SELECT id, total FROM invoices WHERE customer_id = '{customer_id}'")`

```diff
--- a/app.py
+++ b/app.py
@@ -10,5 +10,5 @@

 def invoices_for_customer(conn, customer_id):
     cursor = conn.cursor()
-    cursor.execute(f"SELECT id, total FROM invoices WHERE customer_id = '{customer_id}'")
+    cursor.execute("SELECT id, total FROM invoices WHERE customer_id = ?", (customer_id,))
     return cursor.fetchall()
```

## python-sql-psycopg-format

**Finding:** `opengrep.cwe-89.sql-injection-format` at `app.py:6`, critical, CWE-89, confidence 0.95. SQL query built with string formatting — use parameterized queries

**Flagged code:** `sql = "SELECT id, subject FROM tickets WHERE status = '%s'" % status`

```diff
--- a/app.py
+++ b/app.py
@@ -3,8 +3,8 @@


 def find_tickets(cursor, status):
-    sql = "SELECT id, subject FROM tickets WHERE status = '%s'" % status
-    cursor.execute(sql)
+    sql = "SELECT id, subject FROM tickets WHERE status = %s"
+    cursor.execute(sql, (status,))
     return cursor.fetchall()
```

## python-sql-sqlite

**Finding:** `opengrep.cwe-89.py-execute-concat-direct` at `app.py:10`, critical, CWE-89, confidence 0.93. SQL passed to execute() as a built string. Pass the value as a bound parameter

**Flagged code:** `cursor.execute("SELECT id, email FROM users WHERE email = '" + email + "'")`

```diff
--- a/app.py
+++ b/app.py
@@ -7,5 +7,5 @@

 def find_user(conn, email):
     cursor = conn.cursor()
-    cursor.execute("SELECT id, email FROM users WHERE email = '" + email + "'")
+    cursor.execute("SELECT id, email FROM users WHERE email = ?", (email,))
     return cursor.fetchone()
```

## python-sql-two-queries

**Finding:** `opengrep.cwe-89.py-execute-concat-direct` at `app.py:11`, critical, CWE-89, confidence 0.93. SQL passed to execute() as a built string. Pass the value as a bound parameter

**Flagged code:** `cursor.execute("SELECT id, email FROM contacts WHERE account = '" + account + "'")`

```diff
--- a/app.py
+++ b/app.py
@@ -8,7 +8,7 @@

 def contacts_for_account(conn, account):
     cursor = conn.cursor()
-    cursor.execute("SELECT id, email FROM contacts WHERE account = '" + account + "'")
+    cursor.execute("SELECT id, email FROM contacts WHERE account = ?", (account,))
     return cursor.fetchall()
```

**Finding:** `opengrep.cwe-89.py-execute-fstring-direct` at `app.py:17`, critical, CWE-89, confidence 0.90. SQL passed to execute() as an f-string. Pass the value as a bound parameter

**Flagged code:** `cursor.execute(f"SELECT id, body FROM notes WHERE account = '{account}'")`

```diff
--- a/app.py
+++ b/app.py
@@ -14,5 +14,5 @@

 def notes_for_account(conn, account):
     cursor = conn.cursor()
-    cursor.execute(f"SELECT id, body FROM notes WHERE account = '{account}'")
+    cursor.execute("SELECT id, body FROM notes WHERE account = ?", (account,))
     return cursor.fetchall()
```
