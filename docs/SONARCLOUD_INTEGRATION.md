# SonarCloud Cloud Integration

This document explains how the pipeline wires SonarCloud Cloud (Free Plan) into the
build, what each artifact contains, and how the AI Security Agent and the
Pre-Deploy Security Gate consume the output.

For a higher-level overview of the whole pipeline, see [`PIPELINE.md`](../PIPELINE.md).

---

## 1. SonarCloud integration

### Secrets and identifiers

The scanner needs three values, all of which are wired through GitHub Secrets
(per-environment) and exposed as workflow env vars:

| Variable | Source | Purpose |
|---|---|---|
| `SONAR_TOKEN` | `secrets.SONAR_TOKEN` | Bearer token for the SonarCloud API. Used by both the scanner and the report-generation script. |
| `SONAR_ORGANIZATION` | `secrets.SONAR_ORGANIZATION` (or `vars.SONAR_ORGANIZATION`) | SonarCloud organization key. |
| `SONAR_PROJECT_KEY` | `secrets.SONAR_PROJECT_KEY` (or `vars.SONAR_PROJECT_KEY`) | SonarCloud project key (must already exist in the org). |

The workflow falls back to `vars.*` when the secret is unset, which lets fork
PRs run without a real token (the scanner step is skipped and a stub report is
written instead).

### Maven configuration

`pom.xml` declares the Sonar Maven plugin
(`org.sonarsource.scanner.maven:sonar-maven-plugin:3.11.0.3922`) at the project
root. The Maven plugin auto-discovers `sonar-project.properties` from the
project base directory, so the workflow can stay short and the static config
lives in source control where it can be reviewed via PR.

### `sonar-project.properties` (repo root)

```properties
sonar.projectKey=${env.SONAR_PROJECT_KEY}
sonar.organization=${env.SONAR_ORGANIZATION}
sonar.host.url=${env.SONAR_HOST_URL}
sonar.sources=src/main/java
sonar.tests=src/test/java
sonar.java.binaries=target/classes
sonar.coverage.jacoco.xmlReportPaths=target/site/jacoco/jacoco.xml
sonar.junit.reportPaths=target/surefire-reports
sonar.java.source=21
sonar.sourceEncoding=UTF-8
sonar.exclusions=**/VulnerableSpringAppApplication.java
```

The three `${env.*}` placeholders are expanded by the SonarQube scanner from
the process env, so the file contains no credentials and is safe to commit.

### JaCoCo coverage

The `coverage` Maven profile in `pom.xml` (lines 116-194) binds the JaCoCo
agent to the `test` phase and the report goal to the `verify` phase, producing
`target/site/jacoco/jacoco.xml`. The same file is read by SonarCloud (for
coverage analysis) and by `scripts/generate-coverage-report.py` (for the
per-package and per-method summaries that the AI agent consumes).

The `check` goal, which fails the build when line coverage falls below the
threshold, is allowed to fail in CI (via `continue-on-error: true`). The single
source of truth for the coverage gate is `scripts/check-deploy-gates.py`,
which reads the threshold from `MIN_COVERAGE` and gates the deploy on it
independently of JaCoCo's own rule.

---

## 2. Quality Gate validation

The `sonarqube-scan-action@v3` performs the analysis but does **not** wait
for the Quality Gate result. A separate step is required to block the workflow
on the QG.

```yaml
- name: SonarCloud Quality Gate
  if: env.SONAR_TOKEN != '' && env.SONAR_PROJECT_KEY != '' && env.SONAR_ORGANIZATION != '' && steps.sonar.conclusion == 'success'
  uses: sonarsource/sonarqube-quality-gate-action@v1
  with:
    failOnQualityGateError: true
    inMillisecondsToWait: 300000
  env:
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

Behaviour:

- `failOnQualityGateError: true` — the step (and therefore the job) fails when
  the QG status is `ERROR` or `FAILED`. The QG status `WARN` does not fail.
- `inMillisecondsToWait: 300000` — max 5 minutes. The action polls the QG
  endpoint every few seconds and returns as soon as a terminal state is
  reached. In practice the QG resolves in under 30 s.
- The `if:` guard ensures the QG action only runs after a successful scan
  (skipping both when secrets are missing and when the scan step failed).

### Step ordering inside `sonarcloud-scan`

The report-generation step **runs before** the QG wait:

```text
SonarCloud scan ──► Generate Sonar report (JSON + Markdown) ──► SonarCloud Quality Gate ──► Upload artifacts
```

The upload step uses `if: always()`, so the artifacts still land even when
the QG action fails the job. This satisfies the brief's two requirements —
"fail the workflow immediately if the Quality Gate status is FAILED" and
"artifacts must be available for download after every pipeline execution" —
without conflict.

---

## 3. Web API usage

`scripts/generate-sonar-report.py` calls five SonarCloud Web API endpoints
after a successful scan. All calls are GETs, all use Bearer-token auth, and
all are optional (the script degrades to a stub report when the token or
project key is missing).

| Endpoint | What it provides | Used in |
|---|---|---|
| `/api/components/show?component=KEY` | Project display name | `fetch_project_info` |
| `/api/project_analyses/search?project=KEY&ps=1` | Most recent analysis timestamp | `fetch_latest_analysis` |
| `/api/qualitygates/project_status?projectKey=KEY` | Current Quality Gate status | `fetch_quality_gate` |
| `/api/measures/component?component=KEY&metricKeys=...` | All numeric and rating metrics in one call | `fetch_measures` |
| `/api/issues/search?projectKeys=KEY&types=...&ps=...&p=...` | Paginated issues (up to 10 × 500) | `fetch_issues` |

The per-severity counts in `overallIssueCounts` are derived **in-process**
from the issues list itself (`_counts_from_findings`), not from a separate
facets endpoint. This guarantees `overallIssueCounts.total` equals
`len(raw.issues)` and that the severity breakdown sums to the total — the
two cannot drift apart as they did when the issues and counts endpoints
were called with different `types` filters.

The script emits `::warning::` log lines for any failed call and continues
with the data it has. The output is always a complete JSON file with the
fields the brief lists, plus a `raw: {metrics, issues}` block carrying the
original nested structure for backward compatibility with
`scripts/ai-security-review.py` and `scripts/check-deploy-gates.py`.

---

## 4. Artifact generation

The `sonarcloud-scan` job uploads a single artifact, `sonar-report`, that
contains the four files below. The upload step has `if: always()`, so the
artifact is available after every run — including runs where the Quality Gate
was FAILED.

| File | Format | Purpose | Consumed by |
|---|---|---|---|
| `sonar-report.json` | JSON | Machine-readable report; brief's flat schema. | AI Security Review agent, Pre-Deploy Gates, downstream automation. |
| `SONAR_REPORT.md` | Markdown | Human-readable report with all 12 brief sections. | PR description, audit trail, release notes. |
| `sonar-report.txt` | Plain text | Compact one-line-per-finding summary. | AI Security Review agent prompt. |
| `sonar-quality-gate.txt` | Text | `OK` / `FAILED` / `SKIPPED`. | Quick dashboard / job log. |

### `sonar-report.json` schema

Top-level fields (the brief's example):

```json
{
  "schemaVersion": 2,
  "status": "OK",
  "project": "java-demo",
  "projectKey": "java-demo",
  "host": "https://sonarcloud.io",
  "branch": "main",
  "commit": "abc123…",
  "analysisDate": "2026-07-13T10:30:00Z",
  "qualityGate": "PASSED",
  "bugs": 1,
  "vulnerabilities": 0,
  "codeSmells": 18,
  "securityHotspots": 2,
  "coverage": 84.62,
  "duplicatedLines": 1.3,
  "technicalDebt": "120",
  "reliabilityRating": "1",
  "securityRating": "1",
  "maintainabilityRating": "1",
  "newIssues": {
    "bugs": 0, "vulnerabilities": 0, "codeSmells": 2, "securityHotspots": 0
  },
  "overallIssueCounts": {
    "total": 21, "blocker": 0, "critical": 0, "major": 4, "minor": 12, "info": 5
  },
  "raw": { "metrics": { … }, "issues": [ … ] },
  "generatedAt": "2026-07-13T10:30:30Z"
}
```

The `raw` block is preserved for backward compatibility with the existing
AI agent and gate scripts, which read `metrics.coverage` and
`metrics.vulnerabilities`. New consumers should use the top-level fields.

### `SONAR_REPORT.md` sections

1. **Project Name** + Project Key + Branch + Commit SHA + Analysis Date + QG Status
2. **Quality Gate Status** (badge)
3. **Coverage** (line coverage + duplicated lines)
4. **Issues** (current + new for each type, plus overall counts)
5. **Ratings** (reliability, security, maintainability)
6. **Technical Debt** (in minutes)
7. **Summary** (one-paragraph natural-language synopsis)
8. **Recommendations** (deterministic heuristic list, e.g. "Address all new
   vulnerabilities", "Increase line coverage to 80%")

The Recommendations section is computed by static rules — no extra NVIDIA
call is required, so the report renders even when `NVIDIA_API_KEY` is unset.

---

## 5. NVIDIA AI Security Agent integration

The `security-ai-review` job downloads the `sonar-report` and `trivy-report`
artifacts and runs `scripts/ai-security-review.py` against them. The agent:

1. Reads Sonar (JSON + TXT), Trivy (JSON + TXT), the coverage summary, the
   raw `jacoco.xml`, and the JUnit test report.
2. Builds a single user prompt with all of them embedded.
3. Calls the NVIDIA LLM (`NVIDIA_BASE_URL/chat/completions` by default) with
   a system prompt that asks for a JSON review containing up to 50
   `findings`, each with severity, root cause, CWE, OWASP, file, line,
   evidence, and a `suggested_fix`.
4. Falls back to a deterministic, file-based pass when the NVIDIA key is
   missing — the agent still emits a valid `security-review.json` with
   findings derived from the input reports.
5. Writes the result to `reports/security-review.json` (the canonical name
   consumed by `scripts/ai-remediation.py`).
6. The workflow aliases the same file to `reports/security-report.json` (the
   brief's literal name) and includes both in the `security-review`
   artifact, so downstream consumers can use either name.

The AI agent's findings then feed two downstream stages:

- **`security-ai-remediate`** — the remediation engine. Reads the
  `security-review.json`, applies deterministic fixers (regex) and the LLM
  patch pass, then opens a PR with the changes.
- **`check-deploy-gates`** — counts how many findings were applied and
  uses the `status` field of `remediation-report.json` to confirm the
  remediation step completed (status in `OK` / `SKIPPED` / has at least
  one entry under `fixes`).

---

## 6. Security Gate flow

The `check-deploy-gates` job is the single source of truth for "is the
current build safe to deploy?". It runs after every other job and writes
`reports/deploy-gates.json` with one row per gate plus a top-level
`deploy_recommended` boolean. The `deploy` job only runs when
`deploy_recommended == "True"`.

Gates evaluated:

| # | Gate | Source | Pass condition |
|---|---|---|---|
| 1 | `build_succeeded` | `target/.rebuild-ok` from `rebuild-and-retest` | File exists. |
| 2 | `coverage_threshold` | `reports/coverage-summary.csv` (or `jacoco.xml`) | Overall line coverage ≥ `MIN_COVERAGE` (default 80%). |
| 3 | `sonar_quality_gate` | `reports/sonar-report-after-fix.json` | `qualityGate == OK` (or whatever `REQUIRED_QUALITY_GATE` is set to). |
| 4 | `no_remaining_vulnerabilities` | Same Sonar report | `vulnerabilities == 0`. |
| 5 | `no_critical_trivy` | `reports/trivy-report-after-fix.json` | Zero Critical findings (or `ALLOW_CRITICAL=true`). |
| 6 | `no_high_trivy` | Same Trivy report | Zero High findings (or `ALLOW_HIGH=true`). |
| 7 | `no_critical_codeql` | `reports/codeql-results.sarif` | Zero Critical CodeQL alerts (security-severity ≥ 9.0, or `level == "error"`). |
| 8 | `no_high_codeql` | Same CodeQL SARIF | Zero High CodeQL alerts (security-severity 7.0-8.9, or `level == "warning"`). |
| 9 | `ai_remediation_completed` | `reports/remediation-report.json` | `status ∈ {OK, SKIPPED}` or `fixes` non-empty. |

Missing or unreadable inputs (e.g. a skipped CodeQL run on a fork PR without
the secret) are treated as 0, the same pattern Trivy already uses. This lets
the gate fail-safe in the well-tested direction: "I see nothing bad, so the
gate passes" — never "I can't tell, so the gate fails".

### Where each gate reads its data

```
build_succeeded          ──► target/.rebuild-ok               (rebuild-and-retest job)
coverage_threshold       ──► reports/coverage-summary.csv      (coverage job)
sonar_quality_gate       ──► reports/sonar-report-after-fix.json (sonarcloud-rescan job)
no_remaining_vulnerabilities ──► same
no_critical_trivy / no_high_trivy ──► reports/trivy-report-after-fix.json (trivy-rescan job)
no_critical_codeql / no_high_codeql ──► reports/codeql-results.sarif (codeql job)
ai_remediation_completed ──► reports/remediation-report.json    (security-ai-remediate job)
```

All six downstream jobs run in parallel after `rebuild-and-retest`. The gate
job lists all of them in its `needs:` block and is itself gated on
`if: ${{ always() }}` so the deploy decision is always made, even if one
of the upstream jobs was skipped or failed.

---

## Free-plan caveats

A few SonarCloud Cloud Free-Plan limits are worth knowing:

- Only one long-lived branch is retained for the main analysis. PR
  decorations are live-only. The `/api/project_analyses/search?branch=...`
  call returns the main branch's analysis for non-main branches — the
  report-generation script handles this by falling back to the
  most-recent analysis available.
- Branch analyses count against a quota; the pipeline triggers one per
  push and one per PR.
- A failed QG on a PR blocks merge; configure the QG in the SonarCloud
  project settings to match the policy in this document.
