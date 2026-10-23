# Application recommendation dataset sources

`application_cases.json` contains 24 authored benchmark cases for Mitig8it PR triage. The existing six-case recommendation file remains the independent smoke baseline.

The new suite uses eight scenario lineages. Each lineage contains one supported vulnerability, one explicit safe control, and one case that is genuinely undecidable because the security-relevant helper or artifact is absent. All three members of a lineage stay in the same split to prevent near-copy leakage.

| Split | Lineages | Cases |
| --- | --- | ---: |
| `dev` | SQL binding; shell/argument boundaries; path containment; SSRF redirect/IP validation | 12 |
| `validation` | HTML context escaping; object-level authorization | 6 |
| `holdout` | authentication middleware order; dependency/artifact integrity | 6 |

Every snippet is synthetic and was written for this benchmark. `scenario_basis: adapted_synthetic` means a case is grounded in a documented vulnerability class or failure pattern; it does not reproduce an affected product, proprietary source, exploit payload, or exact CVE implementation. Source references support the security property being reviewed. They are not labels by themselves.

## Label policy

- `true_positive`: the supplied patch contains a complete source-to-dangerous-operation path and lacks the relevant control.
- `false_positive`: the relevant control is explicit in the supplied patch. The label is limited to the reported vulnerability class.
- `uncertain`: a named helper, middleware policy, transport, renderer, or lockfile contains the deciding behavior and is absent. Names and comments are never treated as proof.

`expected_fix_terms` is only a coarse recommendation-quality aid. The human review rubric and the supplied evidence determine whether advice is correct.

## Primary and authoritative sources reviewed

| Lineage | Source | Date | Evidence use |
| --- | --- | --- | --- |
| `sql` | [Python sqlite3 documentation](https://docs.python.org/3/library/sqlite3.html) | accessed 2026-10-06 | `official_documentation` |
| `sql` | [Metabase unauthenticated SQL injection advisory](https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf) | 2026-08-06 | `vendor_advisory` |
| `shell` | [Python subprocess documentation](https://docs.python.org/3/library/subprocess.html) | accessed 2026-10-06 | `official_documentation` |
| `shell` | [Ubuntu CVE-2026-24061 record for GNU InetUtils argument injection](https://ubuntu.com/security/CVE-2026-24061) | 2026-01-21 | `vendor_security_record` |
| `path` | [Node.js path documentation](https://nodejs.org/api/path.html) | accessed 2026-10-06 | `official_documentation` |
| `path` | [GitLab critical patch release describing CVE-2026-85706](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-3-2-released/) | 2026-09-10 | `vendor_advisory` |
| `ssrf` | [MLflow webhook redirect and DNS-rebinding SSRF advisory](https://github.com/mlflow/mlflow/security/advisories/GHSA-7gwp-5pfp-969j) | 2026-08-02 | `vendor_advisory` |
| `ssrf` | [OWASP API7:2023 Server Side Request Forgery](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/) | accessed 2026-10-06 | `security_standard` |
| `html` | [OWASP Cross Site Scripting overview](https://owasp.org/www-community/attacks/xss/) | accessed 2026-10-06 | `security_standard` |
| `object_auth` | [OWASP API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/) | accessed 2026-10-06 | `security_standard` |
| `object_auth` | [Adobe Commerce security bulletin APSB26-92](https://www.adobe.com/trust/security/products/commerce/apsb26-92.html) | 2026-08-11 | `vendor_advisory` |
| `auth_middleware` | [Express using middleware guide](https://expressjs.com/en/guide/using-middleware.html) | accessed 2026-10-06 | `official_documentation` |
| `auth_middleware` | [OWASP API2:2023 Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/) | accessed 2026-10-06 | `security_standard` |
| `dependency` | [GitHub advisory for malicious eslint-config-prettier package versions](https://github.com/advisories/GHSA-f29h-pxvx-f335) | 2025-07-19 | `reviewed_advisory` |
| `dependency` | [Gemini CLI notice about the September 2025 npm supply-chain attack](https://github.com/google-gemini/gemini-cli/discussions/8385) | 2025-09-12 | `vendor_incident_notice` |

## Review boundaries

- Findings cite the exact changed line and code snippet in each synthetic patch.
- Safe controls are visible: parameter tuples, fixed argv with `shell=False`, strict opaque path IDs, disabled redirects with an exact host allowlist, executed output encoding, tenant-scoped queries, ordered route middleware, or a documented patched dependency version.
- Uncertain cases identify the exact unavailable component needed for adjudication and state what evidence would resolve the label.
- Domains use the reserved `.invalid` namespace. No credentials, live services, or production identifiers appear in the suite.
- The dependency cases distinguish a declared range from the resolved artifact and from proof of installation or execution.
- The SSRF cases avoid requests to real metadata services; tests should use local controlled redirect and address fixtures.
