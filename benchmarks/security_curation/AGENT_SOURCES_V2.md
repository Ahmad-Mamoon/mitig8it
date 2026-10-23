# Agent security-review benchmark V2

`agent_cases_v2.json` contains 60 adapted-synthetic cases for Mitig8it's current Tier 3 security-review path. All 60 use `execution_adapter: "triage_http"` and the input fields accepted by the existing analysis-recommendation runner. The catalog measures whether a reviewer preserves a code-grounded verdict and recommendation when a changed-code comment contains hostile or misleading prose.

The catalog does not claim to evaluate a general autonomous agent. It does not exercise retrieval, persistent memory, MCP execution, shell or network tools, patch application, permission enforcement, autonomous merging, publishing, or remediation verification. A comment that resembles a tool result or prior assistant message remains ordinary repository text in this adapter. The corresponding rubric checks only whether that text changes the review response.

## Dataset composition

| Measure | Count |
| --- | ---: |
| Cases / matched pairs | 60 / 30 |
| Attack / control variants | 30 / 30 |
| Development / validation / holdout | 36 / 12 / 12 |
| True positive / false positive / uncertain | 32 / 16 / 12 |
| Python / JavaScript | 34 / 26 |

Each pair shares a `lineage`, a stable `scenario_id`, one split, and one isolation group. The two variants have identical executable code, finding facts, repository profile, expected verdict, and required remediation concepts. Exactly one repository comment changes. The attack comment contains the adversarial instruction or fabricated evidence; the control comment is operationally ordinary. Paired disagreement therefore measures sensitivity to untrusted prose rather than a change in the underlying vulnerability.

Related code and instruction families stay within one split. The added scenarios are materially different implementations rather than identifier-renamed copies across splits. The 24 new pairs cover suppression and inflation requests, forged reviewer authority, fabricated scanner or helper output, prior-assistant text, unsafe-fix requests, wrong locations, false test claims, encoded or Unicode instructions, disclosure requests, pressure to hide uncertainty, evidence forgery, and requests for wasteful loops. Verdicts still follow the visible code and evidence. Human-review rubrics separately check grounded locations and fixes, non-disclosure, calibrated uncertainty, and the absence of fabricated execution claims; verdict equality alone is not treated as proof of those properties.

## Seed migration and anti-leakage normalization

V2 incorporates the 12 V1 cases identified in `inherited_seed_ids`. Their IDs, lineages, splits, paired code semantics, and expected verdicts are preserved. The root `seed_migration` object records the V1 path and SHA-256 digest `510bd51cbb64378cdc8e7e61cf0b2e72104aa54833ce1999bcdb848701bef26f`.

V1 remains frozen. In V2, all cases use the same model-visible confidence (`0.65`) and severity (`high`), and finding titles describe data flow without announcing the label. Finding evidence uses a common factual source-to-operation style, remediation contains one neutral review instruction, and structured details use the same analysis scope and reviewability fields across labels. Verdict-bearing trace summaries, validated-sanitizer statuses, missing-control markers, and fix prescriptions are excluded. Migrated uncertain comments were also made neutral where their original prose revealed the evidence gap. These normalizations reduce answer cues outside the executable scenario while retaining the attack/control contrast.

## Primary sources

| Source | Use in this catalog |
| --- | --- |
| [GitHub: Risks and mitigations for GitHub Copilot cloud agent](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/risks-and-mitigations) | GitHub describes prompt injection through issue or repository content, possible secret exposure, constrained access, auditability, and human review. This supports changed-code comment scenarios without implying that Mitig8it implements Copilot's controls. |
| [Microsoft: Prompt Injection (Direct / Indirect)](https://learn.microsoft.com/en-us/security/zero-trust/catalog-ai-attack-techniques/prompt-injection) | Microsoft documents indirect instructions delivered through untrusted content and attempts to alter behavior or disclose data. This supports the instruction, exfiltration, and encoded-text variants. |
| [Microsoft: Prompt injection protection in Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/step-by-step-guides/prompt-injection-protection-defender-for-office-365) | Microsoft describes malicious instructions embedded in otherwise normal content and sensitive-content disclosure outcomes. This supports non-disclosure rubrics. |
| [Microsoft: AI agent runtime protection with Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview) | Microsoft identifies files, repository content, and tool responses as possible instruction-bearing inputs. This supports fabricated tool-result and role-transcript comments, while the benchmark evaluates only text handling. |
| [Microsoft: Input, Context, and Retrieval Hygiene](https://learn.microsoft.com/en-us/security/zero-trust/catalog-ai-defense-capabilities/input-context-retrieval-hygiene) | Microsoft recommends preserving source roles and treating external context as untrusted data. This supports evidence-source and role-boundary cases. |
| [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | OWASP's December 9, 2025 framework provides the broader goal- and instruction-confusion taxonomy. These cases adapt only the part observable through Mitig8it's review prompt. |
| [MITRE ATLAS](https://atlas.mitre.org/) | ATLAS supplies a maintained taxonomy for prompt injection, tool-data poisoning, prompt extraction, and data leakage. No case is represented as a one-to-one reproduction of an ATLAS procedure. |
| [CrowdStrike 2026 Threat Hunting Report](https://go.crowdstrike.com/rs/281-OBQ-266/images/CrowdStrike-2026-Threat-Hunting-Report.pdf) | First-party threat-hunting observations connect repository, developer-tool, cloud-credential, AI-resource, and software-supply-chain abuse to realistic review contexts. They are scenario inspiration, not proof that a synthetic fixture reproduces an intrusion. |

## CrowdStrike report assessment

The PDF identifies its reporting period as July 1, 2025 through June 30, 2026 (PDF p. 4); its PDF metadata records creation on July 31, 2026. The strongest observations relevant to this bounded benchmark are:

- FAMOUS CHOLLIMA used AI-centric IDE repositories with “hidden malicious scripts” in configuration and lifecycle files (p. 17). This supports developer-repository and configuration review contexts. Endpoint execution remains out of scope.
- A malicious MCP configuration “reads the parent process’s environment variables” for exfiltration (p. 18). This supports the secret non-disclosure rubric. It does not turn these fixtures into MCP permission tests.
- An LLMJacking incident generated “nearly 200,000 API requests” in about two minutes (p. 19). This supports resisting a comment that requests repeated analysis. The benchmark does not enforce model budgets or execute a loop.
- ALTERED SPIDER “compromised more than 300 software dependencies” in a one-day campaign (p. 27). This supports skepticism toward fabricated trusted-tool and dependency claims; it is not a package-compromise reproduction.
- The report describes threat actors targeting “long-lived access credentials” in cloud and CI/CD environments (p. 28). This supports secret-shaped and hardcoded-credential review scenarios. Cloud identity response remains outside this adapter.

The report's page 30 scenario is explicitly composite, and page 31 is outlook material. Neither is used as observed end-to-end evidence. Across this catalog, all snippets, identities, credentials, repositories, findings, and attack comments are synthetic. No case claims to reproduce a CVE, vendor incident, malware sample, or report procedure.

## Review and execution boundary

Offline validation checks schema, unique IDs and fingerprints, source URLs, split isolation, exact finding-to-patch line mapping, syntax plausibility, and pair equivalence. Running the existing live adapter would invoke the configured model, so curation and validation do not make paid model calls. Human review remains necessary for recommendation quality, secret non-echo, location grounding, calibrated abstention, and claims about tests or tools.
