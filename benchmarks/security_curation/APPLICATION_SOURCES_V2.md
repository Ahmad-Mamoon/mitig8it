# Application recommendation dataset v2 sources

`application_cases_v2.json` contains 120 locally authored benchmark cases for Mitig8it's Python, JavaScript, and TypeScript PR-triage path. It has 40 distinct scenario lineages, each with a vulnerable, explicitly safe, and genuinely missing-context variant. The source snippets are synthetic adaptations of documented security properties; they do not reproduce proprietary code or claim to reproduce a CVE.

The frozen `application_cases.json` remains the 24-case v1 record. V2 migrates those 24 case IDs and records the v1 SHA-256 in dataset metadata. The v2 copies use one neutral finding title, confidence value, evidence statement, and conditional remediation per lineage; remove standalone repository comments that disclosed adjudication context; and add split-isolation metadata. V1 itself is unchanged.

## Distribution and isolation

| Split | Lineages | Cases | Label balance |
| --- | ---: | ---: | --- |
| `dev` | 24 | 72 | 24 true positive, 24 false positive, 24 uncertain |
| `validation` | 8 | 24 | 8 true positive, 8 false positive, 8 uncertain |
| `holdout` | 8 | 24 | 8 true positive, 8 false positive, 8 uncertain |
| **Total** | **40** | **120** | **40 per verdict** |

Every member of a lineage has the same split, `isolation_group`, neutral title, confidence, evidence, and remediation. A lineage therefore cannot leak a near-copy into another split or reveal its verdict through those scanner metadata fields. The evidence asks the evaluator to validate the code path, while the remediation states the control conditionally instead of asserting that the control is missing.

## Label policy

- `true_positive` requires an explicit request-controlled or untrusted source, the relevant dangerous operation or boundary, and the absence of the decisive control in the supplied patch.
- `false_positive` requires the decisive control in executable code or configuration in the supplied patch. A helper name or comment is never accepted as proof.
- `uncertain` withholds exactly the helper, transport, renderer, repository, policy, or runtime configuration that decides the reported issue. The visible code does not independently prove either outcome.

The labels address only the reported vulnerability class. For example, a safe argument-boundary case does not claim that archive contents are safe, and a safe canonical-path case documents the residual check-to-open race. `expected_fix_terms` is a search aid, not grading authority.

## Coverage map

| Split | Lineage | Distinct decision boundary | Primary or authoritative basis |
| --- | --- | --- | --- |
| dev | `sql-binding` | sqlite3 value placeholder versus SQL interpolation | [Python sqlite3](https://docs.python.org/3/library/sqlite3.html) |
| dev | `postgres-value-binding` | node-postgres `$1` values array versus template SQL | [node-postgres queries](https://node-postgres.com/features/queries) |
| dev | `query-builder-raw-fragment` | Knex raw value binding versus interpolated fragment | [Knex raw queries](https://knexjs.org/guide/raw.html) |
| dev | `dynamic-sql-identifier` | fixed identifier mapping versus request-selected SQL grammar | [Python sqlite3](https://docs.python.org/3/library/sqlite3.html) |
| dev | `shell-argument-boundaries` | shell command string versus validated argv and option boundary | [Python subprocess](https://docs.python.org/3/library/subprocess.html) |
| dev | `command-option-injection` | argument separation plus validation and `--` | [OWASP command injection defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) |
| dev | `interpreter-code-argument` | request data as interpreter code versus fixed application logic | [Node child processes](https://nodejs.org/api/child_process.html) |
| dev | `executable-search-path` | request-mutable `PATH` versus absolute executable and controlled environment | [Python subprocess](https://docs.python.org/3/library/subprocess.html) |
| dev | `path-containment` | unrestricted joined path versus strict opaque server ID | [Node path](https://nodejs.org/api/path.html) |
| dev | `symlink-canonical-containment` | lexical path check versus descriptor-relative no-follow open | [Python pathlib resolve](https://docs.python.org/3/library/pathlib.html#pathlib.Path.resolve), [Python os.open](https://docs.python.org/3/library/os.html#os.open) |
| dev | `archive-extraction-containment` | fully trusted tar extraction versus the `data` filter | [Python tarfile](https://docs.python.org/3/library/tarfile.html) |
| dev | `upload-filename-containment` | client filename versus generated server filename | [Werkzeug secure_filename](https://werkzeug.palletsprojects.com/en/stable/utils/#werkzeug.utils.secure_filename), [OWASP file upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) |
| dev | `ssrf-redirect-ip-validation` | request URL with automatic redirects versus server-owned destination mapping and manual redirects | [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) |
| dev | `ssrf-ip-literal-normalization` | string prefix block versus canonical address classification | [Python ipaddress](https://docs.python.org/3/library/ipaddress.html) |
| dev | `ssrf-url-authority-validation` | substring URL check versus server-owned complete destination mapping | [Node URL](https://nodejs.org/api/url.html), [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) |
| dev | `ssrf-egress-proxy-policy` | caller-selected proxy and URL versus server-controlled proxy and destination map | [OWASP SSRF prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) |
| dev | `pickle-deserialization` | untrusted pickle versus JSON plus shape validation | [Python pickle warning](https://docs.python.org/3/library/pickle.html) |
| dev | `yaml-loader-safety` | PyYAML object loader versus `safe_load` plus shape validation | [PyYAML documentation](https://pyyaml.org/wiki/PyYAMLDocumentation) |
| dev | `upload-active-content` | client MIME served inline versus verified inert format and safe headers | [OWASP file upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) |
| dev | `upload-storage-execution-boundary` | uploaded script under executable public root versus private generated-name storage | [OWASP file upload](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html) |
| dev | `hardcoded-secret` | credential-shaped source constant versus runtime secret injection | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) |
| dev | `password-hashing` | fast unsalted hash versus scrypt with random salt | [OWASP password storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [Node crypto.scrypt](https://nodejs.org/api/crypto.html#cryptoscryptpassword-salt-keylen-options-callback) |
| dev | `security-token-randomness` | simulation PRNG versus operating-system-backed token generation | [Python secrets](https://docs.python.org/3/library/secrets.html) |
| dev | `tls-certificate-verification` | explicit `verify=False` versus peer verification | [Requests SSL verification](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification) |
| validation | `html-context-escaping` | raw HTML text versus output encoding | [OWASP XSS overview](https://owasp.org/www-community/attacks/xss/) |
| validation | `html-attribute-context` | raw quoted attribute versus attribute-context encoding | [OWASP XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) |
| validation | `url-scheme-validation` | HTML encoding alone versus URL-origin validation plus encoding | [OWASP XSS prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) |
| validation | `browser-dom-sink` | `innerHTML` versus plain-text `textContent` | [MDN textContent](https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent) |
| validation | `object-level-authorization` | global object lookup versus authenticated organization scope | [OWASP API1:2023](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) |
| validation | `function-level-authorization` | authentication-only admin route versus explicit permission | [OWASP API5:2023](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/) |
| validation | `property-level-authorization` | mass assignment versus writable-property allowlist | [OWASP API3:2023](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/) |
| validation | `tenant-context-access` | global ID lookup versus server-verified tenant scope | [OWASP multi-tenant security](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html) |
| holdout | `authentication-middleware-order` | handler registered before auth versus ordered authentication and authorization | [Express middleware](https://expressjs.com/en/guide/using-middleware.html) |
| holdout | `jwt-algorithm-validation` | unverified decode versus pinned signature and claim validation | [PyJWT usage](https://pyjwt.readthedocs.io/en/stable/usage.html) |
| holdout | `session-cookie-protection` | production session flags disabled versus Secure, HttpOnly, SameSite | [express-session cookies](https://github.com/expressjs/session#cookie), [OWASP session management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| holdout | `password-reset-token` | plaintext reusable token versus digest, expiry, and one-time use | [OWASP forgot password](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html) |
| holdout | `dependency-artifact-integrity` | exact affected package artifact versus patched exact artifact versus unresolved range | [GitHub advisory GHSA-f29h-pxvx-f335](https://github.com/advisories/GHSA-f29h-pxvx-f335) |
| holdout | `dependency-lifecycle-script` | arbitrary request-selected package install versus exact catalog with scripts disabled | [npm lifecycle scripts](https://docs.npmjs.com/cli/v11/using-npm/scripts/) |
| holdout | `ci-untrusted-pr-secrets` | untrusted fork code with deployment token versus explicit secret-free environment | [GitHub Actions secure use](https://docs.github.com/en/actions/reference/security/secure-use) |
| holdout | `artifact-checksum-verification` | remote artifact unpacked without integrity check versus trusted digest before parsing | [Python hashlib](https://docs.python.org/3/library/hashlib.html) |

## Review boundaries

- All examples use reserved `.invalid` domains, synthetic identifiers, and synthetic credential placeholders.
- The positive lifecycle-script and CI cases show an actual attacker-controlled artifact or checkout crossing an explicit execution and credential boundary. Ordinary package scripts, mutable search paths, session settings, or CI activity are not treated as vulnerabilities on their own.
- SSRF safe cases remove request control over complete destinations or canonically classify direct IPs, and disable redirects where relevant. The symlink-safe case uses a single-component allowlist with a directory-relative no-follow open to avoid a check-to-open gap.
- Each finding line maps exactly to its patch. New patches contain 10–40 source lines, and all Python snippets pass local AST parsing through the offline validator.
- Source pages were opened and reviewed on 2026-10-06. Dates embedded in inherited v1 advisory references remain in the dataset source objects; access dates are not presented as publication dates.
- No snippet, helper, package, credential, or service endpoint is copied from a vulnerable product implementation. `scenario_basis: adapted_synthetic` is the controlling provenance label.
