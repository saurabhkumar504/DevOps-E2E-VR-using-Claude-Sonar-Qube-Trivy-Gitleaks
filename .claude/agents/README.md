# Sonar-Trivy Auto Remediation Agent

This agent automates the safe remediation of SonarQube and Trivy findings
on the **currently checked-out branch** in a GitHub Actions runner.

## Files

| File | Purpose |
|---|---|
| `.claude/agents/sonar-trivy-remediator.md` | Agent definition (system prompt, behavior spec, tool list) |
| `scripts/parse-reports.mjs` | Node.js script that discovers and normalizes SARIF/JSON/XML/HTML/TXT reports into a single JSON list of findings |
| `.github/workflows/build-and-security.yml` (job: `auto-remediate`) | Wires the agent into CI: downloads the Trivy fs + image SARIF artifacts, fetches the SonarQube issues JSON via API, then invokes the agent |

## How it works

1. **CI runs the existing Trivy fs + image scans** (jobs `trivy-fs` and `trivy-image`) and uploads the SARIF reports as artifacts (`trivy-fs-report`, `trivy-image-report`).
2. **The new `auto-remediate` job** downloads those artifacts to `reports/`, flattens them, and (if `SONAR_TOKEN` + `SONAR_HOST_URL` + `SONAR_PROJECT_KEY` are set) fetches the SonarQube issues JSON via the SonarQube Web API.
3. **The agent** (`.claude/agents/sonar-trivy-remediator.md`) is invoked via the Claude Code CLI. It:
   - Discovers reports via `scripts/parse-reports.mjs`.
   - Prioritizes findings (Critical → High → Medium → Low → Info).
   - Applies only safe, backward-compatible, behavior-preserving fixes.
   - Validates with `mvn -B -ntp -DskipTests package`.
   - Emits `reports/auto-remediation-report.md` and the working-tree patch as artifacts.
4. **Nothing is pushed or committed by the agent.** Review the patch artifact, then commit/push manually.

## Required secrets

| Secret | Purpose |
|---|---|
| `nvdai_api_key` | NVIDIA API key for the `integrate.api.nvidia.com/v1/chat/completions` endpoint used to invoke the agent |
| `SONAR_TOKEN` | SonarQube/SonarCloud token (for fetching issues JSON) |
| `SONAR_HOST_URL` | e.g. `https://sonarcloud.io` |
| `SONAR_PROJECT_KEY` | SonarQube project key (e.g. `vulnerable-spring-app`) |
| `SONAR_ORGANIZATION` | SonarCloud organization key |

The `auto-remediate` job will **skip the SonarQube fetch** with a warning if any of the three Sonar variables are missing. It will **fail the job** if `nvdai_api_key` is missing.

## How the agent is invoked

The job POSTs a chat-completions request to the NVIDIA API:

```bash
curl -s https://integrate.api.nvidia.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $NVDAI_API_KEY" \
  -d @payload.json
```

The payload uses `meta/llama-3.1-70b-instruct` and embeds:
- a **system** message with the agent's behavior spec (rules, workflow, safety guarantees), and
- a **user** message instructing the model to analyze `./reports/` and emit the Markdown report in the exact required format.

The model's `choices[0].message.content` is printed to the runner log and persisted to `reports/auto-remediation-report.md`, which is then uploaded as the `auto-remediation-report` artifact.

## Required permissions

The job declares:

```yaml
permissions:
  contents: read
```

It does not require `contents: write` because the agent only modifies files in the working tree — never pushes or commits.

## Local invocation

You can run the agent locally against this repo (no Trivy/SonarQube needed — just point it at any reports you place under `reports/`):

```bash
# 1. Generate a Trivy fs SARIF
trivy fs --format sarif --output reports/trivy-fs.sarif --severity CRITICAL,HIGH --ignore-unfixed .

# 2. (optional) Drop a SonarQube issues JSON
cp /path/to/sonar-report.json reports/

# 3. Invoke the agent via the NVIDIA API
export NVDAI_API_KEY=...
curl -s https://integrate.api.nvidia.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $NVDAI_API_KEY" \
  -d @payload.json | jq -r '.choices[0].message.content'
```

(`payload.json` is the same structure as in the workflow job — see
`.github/workflows/build-and-security.yml` → `auto-remediate` → `Run auto-remediation agent`.)

## Safety guarantees

The agent definition enforces, at the prompt level:

- Never push, commit, switch branches, merge, rebase, or modify build outputs.
- Prefer minimal code change → secure solution → backward compatibility → readability → maintainability.
- Skip any finding it cannot safely automate (record the reason in the report).
- Always validate with `mvn` after every change.

If the working tree is dirty for reasons unrelated to the agent, those changes are **not** claimed in the report.
