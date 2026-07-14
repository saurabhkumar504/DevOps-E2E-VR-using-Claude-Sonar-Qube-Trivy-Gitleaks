
# DevSecOps CI/CD Pipeline

This repository ships a production-grade **11-stage DevSecOps pipeline** that
builds, tests, scans, and — when gates pass — deploys a Java 21 / Maven /
Spring Boot 3 application. Two NVIDIA-powered AI agents (security review +
remediation) sit at the heart of the pipeline and produce human-readable
artifacts at every step.

> The current Spring Boot codebase is an **OWASP Top 10 learning lab** and
> contains intentional vulnerabilities. The pipeline is configured to
> *report* and *gate* on those vulnerabilities rather than to be satisfied
> by them.

---

## Pipeline at a glance

```
┌──────────────┐
│   1. Build   │  Maven, Java 21, cached
└──────┬───────┘
       ▼
┌──────────────┐
│ 2. Unit Test │  JUnit 5, Surefire
└──────┬───────┘
       ▼
┌──────────────┐
│ 3. Coverage  │  JaCoCo (-Pcoverage profile)
└──────┬───────┘
       ▼
┌────────────┐ ┌────────────┐ ┌────────────┐
│ 4. Sonar   │ │ 5. CodeQL  │ │ 6. Trivy   │
│  Cloud     │ │ (static    │ │  Scan      │
│ scan + QG  │ │  analysis) │ │            │
└─────┬──────┘ └─────┬──────┘ └─────┬──────┘
      └───────┬──────┴──────┬───────┘
              ▼             ▼
       ┌─────────────────────┐
       │ 7. AI Security      │
       │    Review (NVIDIA)  │
       └──────────┬──────────┘
                  ▼
       ┌─────────────────────┐
       │ 8. AI Remediation   │
       │   (local commit +   │
       │    auto PR)         │
       └──────────┬──────────┘
                  ▼
       ┌─────────────────────┐
       │ 9. Rebuild & Retest │
       └──────────┬──────────┘
                  ▼
┌──────────────┐ ┌──────────────┐
│10. Sonar     │ │11. Trivy     │
│   Re-Scan    │ │   Re-Scan    │
└──────┬───────┘ └──────┬───────┘
       └──────┬─────────┘
              ▼
         ┌──────────────────────┐
         │  Pre-Deploy Gates    │
         │  (security + coverage│
         │   + Sonar QG + CodeQL│
         │   + Trivy + AI rem.) │
         └──────────┬───────────┘
                    ▼
         ┌──────────────────────┐
         │ 12. Deploy (dev/qa/  │
         │     production)      │
         └──────────────────────┘
```

Source: [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

---

## Required GitHub configuration

### Secrets (Settings → Secrets and variables → Actions → New repository secret)

| Secret | Required | Description |
| --- | --- | --- |
| `SONAR_TOKEN` | ✅ | SonarCloud **account** token (not a project token). Generate at <https://sonarcloud.io/account/security>. |
| `SONAR_ORGANIZATION` | ✅ | Your SonarCloud organisation key (the value before the project key in the dashboard URL). |
| `SONAR_PROJECT_KEY` | ✅ | The project key as it appears in the SonarCloud dashboard URL. |
| `NVIDIA_API_KEY` | ✅ | NVIDIA build / integrate API key. Get one at <https://build.nvidia.com>. |
| `GITHUB_TOKEN` | (auto) | The default `GITHUB_TOKEN` is enough for `gh pr create`. No extra setup required. |
| `DEPLOY_SSH_KEY`, `KUBE_CONFIG`, `AZURE_CREDENTIALS`, `AWS_*` | ⚠️ | Add whatever your real deploy step needs. The shipped `deploy` job is a stub — wire it up to your platform. |

### Variables (Settings → Secrets and variables → Actions → Variables tab)

| Variable | Default | Description |
| --- | --- | --- |
| `MIN_COVERAGE` | `70` | Minimum JaCoCo line coverage % required to deploy. |
| `ALLOW_CRITICAL` | `false` | Set to `true` to allow deploys with Trivy CRITICAL findings. **Use with extreme caution.** |
| `ALLOW_HIGH` | `false` | Set to `true` to allow deploys with Trivy HIGH findings. |

### GitHub Environments (Settings → Environments)

| Environment | Recommended protection rules |
| --- | --- |
| `dev` | No required reviewers; deployment branch = any. |
| `qa` | 1 required reviewer; deployment branch = `main`. |
| `production` | 2 required reviewers; deployment branch = `main` only; wait timer = 5 min; restrict secrets to those needed. |

If the `production` environment has required reviewers, the deploy job will
pause and the GitHub UI will surface an **approval** before continuing.

---

## How the pipeline is triggered

| Trigger | What happens |
| --- | --- |
| `push` to `main` / `master` | Full pipeline; deploys to `dev` automatically when gates pass. |
| `pull_request` opened against `main` / `master` | Full pipeline **up to the re-scans**. Deploy is skipped. The AI agent still commits fixes and opens a PR from `ai-remediation/<sha>`. |
| `workflow_dispatch` (manual) | Lets you pick the `environment` (`dev` / `qa` / `production`) and `skip_remediation`. |

---

## Stage-by-stage details

### 1. Build

- Java 21 (Temurin).
- Caches `~/.m2/repository` keyed on the contents of `pom.xml`.
- Runs `mvn -B -ntp -DskipTests package` so a compile error fails the job.
- Uploads `target/classes`, `target/*.jar`, and a `target/.build-ok` marker
  as the `build-output` artifact.

### 2. Unit Tests

- Runs `mvn -B -ntp test` (Surefire + JUnit 5).
- Uploads `target/surefire-reports/` as the `junit-reports` artifact.

### 3. Test Coverage

- Activates the `coverage` profile from `pom.xml`, which wires the JaCoCo
  `prepare-agent` and `report` goals.
- Produces `target/site/jacoco/jacoco.xml`.
- A small Python step derives `target/site/jacoco/coverage-summary.csv`
  (per-package line-coverage %).
- Uploads `coverage-build-output` with `jacoco.xml`, the summary CSV, and
  the Surefire reports.

### 4. SonarCloud Scan

- Runs `sonarsource/sonarqube-scan-action@v3`. Static config (sources, tests,
  coverage path, exclusions, Java version) lives in
  `sonar-project.properties` at the repo root; the workflow only passes the
  three secret-derived values.
- A follow-up step calls `scripts/generate-sonar-report.py` to query the
  SonarCloud Web API and write:
  - `sonar-report.json` — flat-schema report matching the brief (project,
    analysisDate, qualityGate, bugs, vulnerabilities, codeSmells,
    securityHotspots, coverage, duplicatedLines, technicalDebt, ratings,
    newIssues, overallIssueCounts), plus a backward-compat `raw` block.
  - `SONAR_REPORT.md` — human-readable markdown with project name, branch,
    commit SHA, analysis date, QG status, coverage, bugs, vulnerabilities,
    code smells, security hotspots, ratings, technical debt, summary, and
    deterministic recommendations.
  - `sonar-report.txt` — plain-text summary consumed by the AI agent.
- **Waits for the Quality Gate** with `sonarsource/sonarqube-quality-gate-action@v1`,
  `failOnQualityGateError: true`, `inMillisecondsToWait: 300000`. A
  `FAILED` or `ERROR` gate fails the job; the report-generation step runs
  *before* the QG wait so the artifacts still upload via `if: always()`.
- Skips gracefully when `SONAR_TOKEN` is missing (still uploads a stub
  `sonar-report.json` and `SONAR_REPORT.md` so the downstream AI agent has
  something to ingest).
- See [`docs/SONARCLOUD_INTEGRATION.md`](docs/SONARCLOUD_INTEGRATION.md) for
  the full breakdown of secrets, the Web API, the report schema, and the
  Quality Gate flow.

### 5. CodeQL Static Analysis

- Runs `github/codeql-action/init@v3` + `analyze@v3` with
  `language: java` and `queries: security-extended,security-and-quality`.
- The SARIF is uploaded to the GitHub Security tab automatically (category
  `codeql`) and also mirrored to `reports/codeql-results.sarif` and uploaded
  as the `codeql-results` artifact so the Pre-Deploy Gates job can parse it.
- CodeQL counts as one of the four inputs to the Pre-Deploy Security Gate
  (alongside SonarCloud, Trivy, and the AI agent). See section "Pre-Deploy
  Security Gate" below.

### 6. Trivy Scan

- Runs `scripts/generate-trivy-report.sh`, which:
  1. Installs the `trivy` CLI (or uses the existing one).
  2. Produces `trivy-fs.sarif` and uploads it to the GitHub Security tab
     (category `trivy-fs`).
  3. Produces a normalised `trivy-report.json` (via `parse-sarif.py`) and a
     human-readable `trivy-report.txt`.
- The single filesystem scan covers:
  - dependency vulnerabilities (CVE / GHSA)
  - secret detection
  - misconfigurations (IaC)
  - license compliance (UNKNOWN severity)

### 7. AI Security Review (NVIDIA)

- Downloads the Sonar + Trivy + JaCoCo + JUnit artifacts.
- Calls `scripts/ai-security-review.py`, which posts the artefacts to
  `https://integrate.api.nvidia.com/v1/chat/completions` and asks the
  model to return a structured JSON review.
- The script:
  - Defaults to model `meta/llama-3.1-70b-instruct` (override with
    `NVIDIA_MODEL`).
  - Caps each input at 32 KB to keep the prompt under token limits.
  - Validates the LLM's response and re-sorts findings by severity + risk
    score.
  - **Falls back to a deterministic stub** when `NVIDIA_API_KEY` is missing
    or the API call fails, so the pipeline never hard-fails on a missing
    key in a learning environment.
- Outputs:
  - `security-review.json` — structured findings.
  - `security-review.md` — human-readable report.
  - `security-summary.txt` — one-line-per-finding, easy to grep.

### 8. AI Remediation (NVIDIA)

- Reads the security review, Sonar report, and Trivy report.
- `scripts/ai-remediation.py` applies **safe, deterministic** patches to
  the working tree:
  1. Removes hardcoded `app.secret.*` lines from
     `application.properties`/`.yml`/`.yaml`.
  2. Parameterises a small set of unambiguous SQL concatenation patterns
     in `createNativeQuery(...)` calls.
  3. Replaces `String.equals(password)` style checks with
     `BCryptPasswordEncoder.matches(...)` (only when Spring Security is on
     the classpath, which it is via `spring-boot-starter-security`).
  4. Bumps Trivy-flagged dependency versions in `pom.xml` to the minimum
     fixed version (patch / minor bump only — never major).
  5. Adds a default `Content-Security-Policy` header to
     `SecurityConfig.java` when one isn't already set.
- For every **other** finding the deterministic engine refuses to touch
  (architectural issues, complex business-logic changes, etc.), the script
  records the rule + reason in `remediation-report.json` under
  `skipped_findings` so a human reviewer can pick them up.
- After applying fixes:
  - Saves `git diff` as `ai-patch.diff` (for traceability).
  - Saves `git diff --stat` as `git-diff-stat.txt`.
  - Saves the list of changed files as `changed-files.txt`.
  - `git add -A && git commit -m "AI auto-remediation: <count> safe fixes"`
    **locally**.
  - Pushes the new branch (`ai-remediation/<sha>`) to `origin`.
  - Runs `gh pr create --base <main|PR base> --head <branch>` to open a PR.
    If a PR already exists, it returns the existing URL.
- Outputs:
  - `remediation-summary.md`
  - `remediation-report.json`
  - `changed-files.txt`
  - `ai-patch.diff` (unified diff)
  - `git-diff-stat.txt`
- The remediation job exposes three outputs for downstream jobs:
  `remediation_branch`, `remediation_pr_url`, `has_fixes`.

### 9. Rebuild & Retest

- Checks out the **remediation branch** (if the AI agent produced one)
  instead of the source branch.
- Re-runs the full Maven lifecycle: `compile` → `test` → `-Pcoverage verify`.
- **Hard-fails** on any compile error or test failure.
- Re-uploads `jacoco.xml` and the coverage summary as `rebuild-output`.

### 10. SonarCloud Re-Scan

- Re-runs `sonarsource/sonarqube-scan-action@v3` against the remediated
  code.
- Writes `sonar-report-after-fix.json` and `sonar-report-after-fix.txt`.
- Calls `scripts/generate-sonar-diff.py` to produce
  `sonar-diff-report.md`, which lists **Fixed**, **Remaining**, and
  **Newly introduced** issues.

### 11. Trivy Re-Scan

- Re-runs `scripts/generate-trivy-report.sh` against the remediated code.
- Writes `trivy-report-after-fix.json` and `trivy-report-after-fix.txt`.
- Calls `scripts/generate-trivy-diff.py` to produce `trivy-diff.md` with
  **Fixed**, **Remaining**, and **New** findings.
- Uploads the new SARIF to the Security tab under the `trivy-fs-after-fix`
  category.

### 12. Deploy

- Runs only if `check-deploy-gates` outputs `deploy_recommended == true`.
- The deploy job uses `environment: ${{ env.DEPLOY_ENV }}`, so GitHub
  Enforces approval / branch restrictions / wait timers.
- The shipped **deploy step is a stub** that copies the JAR to a
  `deploy-artifacts/` directory and writes a fake `deploy-url.txt`.
  **Replace it with your real transport** (Azure Web Apps, AWS ECS,
  Kubernetes, SCP, etc.).
- The `DEPLOY_ENV` is selected by the `environment` input on
  `workflow_dispatch` (defaults to `dev`).

---

## Pre-deploy gates

`scripts/check-deploy-gates.py` runs in the `check-deploy-gates` job after
the re-scans. All of these must pass for `deploy_recommended` to be
`true`:

| Gate | Default expectation |
| --- | --- |
| `build_succeeded` | The `rebuild-and-retest` job produced `target/.rebuild-ok`. |
| `coverage_threshold` | JaCoCo line coverage ≥ `MIN_COVERAGE` (default 70%). |
| `sonar_quality_gate` | SonarCloud Quality Gate is `OK` (or `REQUIRED_QUALITY_GATE` env). |
| `no_remaining_vulnerabilities` | SonarCloud reports `0` vulnerabilities after the re-scan. |
| `no_critical_trivy` | Trivy has 0 CRITICAL findings (unless `ALLOW_CRITICAL=true`). |
| `no_high_trivy` | Trivy has 0 HIGH findings (unless `ALLOW_HIGH=true`). |
| `no_critical_codeql` | CodeQL has 0 CRITICAL findings (unless `ALLOW_CRITICAL=true`). |
| `no_high_codeql` | CodeQL has 0 HIGH findings (unless `ALLOW_HIGH=true`). |
| `ai_remediation_completed` | `remediation-report.json` exists and is non-empty. |

The result is written to `reports/deploy-gates.json` and uploaded as the
`deploy-gates` artifact. Inspect it to see which gate failed when deploy
is skipped.

---

## Artifact reference

| Artifact | Contents |
| --- | --- |
| `build-output` | `target/classes`, `target/*.jar`, `target/.build-ok` |
| `junit-reports` | `target/surefire-reports/*.xml` |
| `coverage-build-output` | `target/site/jacoco/jacoco.xml`, `target/site/jacoco/coverage-summary.csv`, `target/surefire-reports/` |
| `sonar-report` | `reports/sonar-report.json`, `reports/SONAR_REPORT.md`, `reports/sonar-report.txt`, `reports/sonar-quality-gate.txt` |
| `codeql-results` | `reports/codeql-results.sarif` |
| `trivy-report` | `reports/trivy-report.json`, `reports/trivy-report.txt`, `reports/trivy-fs.sarif`, `reports/trivy-report.raw.json` |
| `security-review` | `reports/security-review.json`, `reports/security-report.json`, `reports/security-review.md`, `reports/security-summary.txt` |
| `remediation` | `reports/remediation-summary.md`, `reports/remediation-report.json`, `reports/changed-files.txt`, `reports/ai-patch.diff`, `reports/git-diff-stat.txt` |
| `rebuild-output` | `target/` (post-remediation) |
| `sonar-report-after-fix` | `reports/sonar-report-after-fix.json`, `reports/sonar-report-after-fix.txt`, `reports/sonar-diff-report.md` |
| `trivy-report-after-fix` | `reports/trivy-report-after-fix.json`, `reports/trivy-report-after-fix.txt`, `reports/trivy-fs-after-fix.sarif`, `reports/trivy-diff.md` |
| `deploy-gates` | `reports/deploy-gates.json` |
| `deploy-artifacts` | Whatever your deploy step writes |

See `reports/samples/*.example.{json,md,txt}` for canonical examples of
each report's shape.

---

## Reading the reports

### `security-review.md`

Each finding has:
- **Priority** (`P0`–`P3`) — mapped from severity.
- **Category** — `vulnerability`, `code-smell`, `bug`, `secret`,
  `misconfig`, `dependency`, `coverage`.
- **CWE** — CWE identifiers derived from the rule or CVE.
- **OWASP** — OWASP Top 10 (2021) categories.
- **Location** — `file:line`.
- **Root cause** — one-sentence technical explanation.
- **Evidence** — quoted source line or finding message.
- **Suggested fix** — concrete code snippet or procedure.
- **Risk score** — 0–100 (likelihood × impact, rounded).

### `sonar-diff-report.md`

| Column | Meaning |
| --- | --- |
| Fixed | Issue present in the pre-fix scan, absent in the post-fix scan. |
| Remaining | Issue present in both. |
| Newly introduced | Issue present in the post-fix scan, absent in the pre-fix scan. |

A clean remediation shows **Fixed > 0**, **Remaining = 0**, **Newly
introduced = 0**.

### `trivy-diff.md`

Same structure as the Sonar diff, with packages + CVEs as identifiers.

---

## How to roll back a deploy

1. Find the previous successful deploy under
   <https://github.com/<org>/<repo>/deployments> (or your platform's
   release page).
2. Re-run the `deploy` job from the older run via the GitHub Actions UI
   (`Re-run jobs` → select only the deploy job).
3. If the source branch already contains the bad code, push a revert
   commit (e.g. `git revert <sha>`), then re-run the pipeline.

For Kubernetes / cloud deploys, the recommended pattern is:
**`kubectl rollout undo deployment/<name>`** or your platform's
rollback command.

---

## Local sanity check

```bash
# 1. Run the build + coverage locally
mvn -B -ntp -Pcoverage verify

# 2. Run the AI security review locally (needs NVIDIA_API_KEY in env)
NVIDIA_API_KEY=... python3 scripts/ai-security-review.py --reports reports

# 3. Run the deploy-gate checker locally
python3 scripts/check-deploy-gates.py \
  --coverage-summary target/site/jacoco/coverage-summary.csv \
  --sonar-report        reports/sonar-report-after-fix.json \
  --trivy-report        reports/trivy-report-after-fix.json \
  --remediation-report  reports/remediation-report.json \
  --rebuild-result      target/.rebuild-ok \
  --output              reports/deploy-gates.json
```

---

## Operational notes

- **Concurrency**: the workflow does **not** cancel in-progress runs on a
  new push. If you want that, add a top-level
  `concurrency: { group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true }`
  block.
- **Timeouts**: each job defaults to 360 minutes. Trivy + the re-scans can
  be long for large repos; tighten or relax with `timeout-minutes: …` on
  individual jobs.
- **Permissions**: the workflow starts with `contents: read` and only the
  jobs that need more widen their `permissions:` block. Keep the
  principle-of-least-privilege in mind when adding new jobs.
- **Secret rotation**: rotate `SONAR_TOKEN` and `NVIDIA_API_KEY` regularly.
  The pipeline never echoes either; both are passed only to the steps that
  consume them.

---

## File map

```
.github/
  workflows/
    ci.yml                              # 11-stage pipeline (this file's subject)

scripts/
  parse-sarif.py                        # SARIF → normalised JSON findings
  generate-sonar-report.py              # SonarCloud /api/issues/search → JSON + TXT
  generate-sonar-diff.py                # two Sonar reports → diff Markdown
  generate-trivy-report.sh              # Trivy fs scan → JSON + TXT + SARIF
  generate-trivy-diff.py                # two Trivy reports → diff Markdown
  ai-security-review.py                 # NVIDIA AI Security Review
  ai-remediation.py                     # NVIDIA AI Remediation (safe fixes + PR)
  check-deploy-gates.py                 # pre-deploy gate enforcement

reports/
  .gitkeep
  samples/
    security-review.example.json
    security-review.example.md
    security-summary.example.txt
    remediation-summary.example.md
    sonar-diff-report.example.md
    trivy-diff.example.md
```
