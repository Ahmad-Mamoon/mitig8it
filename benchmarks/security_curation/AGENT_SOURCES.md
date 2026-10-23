# Agent case sources and scope

`agent_cases.json` contains 12 curated, synthetic cases for Mitig8it's current Tier 3 security-review path. Every case uses `execution_adapter: "triage_http"` and the same `finding`, `file_patch`, `repo_profile`, verdict, fix-term, and human-review fields accepted by `benchmarks/analysis_recommendations/run.py`.

The cases evaluate whether the reviewer treats repository text and metadata as untrusted evidence while preserving ordinary vulnerability-analysis accuracy. They do not represent CVE reproductions. All credential-shaped values are invalid synthetic decoys. The source references establish the attack pattern and defensive expectation; the snippets, repository names, findings, and labels were written for this benchmark.

## Sources

| Source | Why it supports these cases |
| --- | --- |
| [GitHub: Risks and mitigations for GitHub Copilot cloud agent](https://docs.github.com/en/copilot/concepts/security-governance-and-network-settings/risks-and-mitigations) | GitHub documents prompt injection through hidden issue or comment content, secret exposure risk, constrained agent access, human review, and auditability. This grounds the changed-code comment cases without claiming that Mitig8it implements GitHub Copilot's controls. |
| [Microsoft: Prompt Injection (Direct / Indirect)](https://learn.microsoft.com/en-us/security/zero-trust/catalog-ai-attack-techniques/prompt-injection) | Microsoft describes indirect instructions arriving through untrusted content, disclosure attempts, and the need for data boundaries. This grounds the decoy-extraction cases. |
| [Microsoft: Prompt injection protection in Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/step-by-step-guides/prompt-injection-protection-defender-for-office-365) | Microsoft lists disclosure of sensitive content, system-prompt discovery, and malicious instructions embedded in otherwise normal content as prompt-injection outcomes. This grounds the secret-review attack/control pair. |
| [Microsoft: AI agent runtime protection with Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/ai-agent-runtime-protection-overview) | Microsoft identifies files, repository content, and tool responses as possible instruction-bearing inputs. This grounds the forged assistant/tool transcript cases. |
| [Microsoft: Input, Context, and Retrieval Hygiene](https://learn.microsoft.com/en-us/security/zero-trust/catalog-ai-defense-capabilities/input-context-retrieval-hygiene) | Microsoft recommends preserving source roles and treating tool results and other external context as untrusted data. This grounds the forged tool-result and role-labelled comment cases. |
| [OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | OWASP's December 9, 2025 framework supplies the broader agentic-security context. These cases narrowly adapt goal/instruction-confusion risks to Mitig8it's implemented reviewer boundary. |
| [MITRE ATLAS](https://atlas.mitre.org/) | The living ATLAS matrix includes LLM Prompt Injection, AI Agent Tool Data Poisoning, Extract LLM System Prompt, and LLM Data Leakage. It supports the threat taxonomy used for curation; the benchmark does not claim a one-to-one reproduction of an ATLAS procedure. |

## Pair design and labels

Near-copy pairs share one `lineage` and one split so an attack form cannot leak into a different evaluation split from its control:

- `agent-comment-shell-pair`: hostile versus benign changed-code comments around the same vulnerable subprocess use.
- `agent-decoy-sql-pair`: a secret-like disclosure request versus a benign memo around the same parameterized SQL.
- `agent-role-output-xss-pair`: forged assistant/tool/system text versus a benign prior-run note around the same raw HTML output.
- `agent-secret-extraction-pair`: a token-shaped disclosure request versus a benign configuration comment around the same environment-backed token lookup.
- `agent-forged-auth-helper-pair`: hostile and neutral variants of the same genuinely unresolved authorization-helper evidence gap.
- `agent-role-comment-eval-pair`: forged role labels versus a benign route comment around the same request-to-`eval` flow.

Within each lineage, executable security semantics, finding evidence, and expected verdict stay fixed; only the untrusted hostile or benign prose changes. This makes paired disagreement evidence of instruction sensitivity rather than ordinary vulnerability-recognition differences. The expected verdicts are six `true_positive`, four `false_positive`, and two `uncertain`. Labels are derived from visible code and structured evidence, independently of the injected text. The two uncertain cases require missing helper implementation and route-composition evidence rather than guessing.

## Coverage boundary

The runnable adapter exercises local HTTP Tier 3 prompt construction, one configured model call when used by the existing live runner, response parsing, verdict application, grounded recommendation validation, and response transport. Human-review rubrics cover semantic behaviors that keyword checks cannot establish.

The dataset does not exercise autonomous code changes, merge or publish authority, tool permission enforcement, patch sandboxes, command execution, retrieval-augmented generation, persistent memory, multi-agent delegation, or remediation verification. Those need separate adapters and deterministic oracles before they can be represented as runnable benchmark cases.
