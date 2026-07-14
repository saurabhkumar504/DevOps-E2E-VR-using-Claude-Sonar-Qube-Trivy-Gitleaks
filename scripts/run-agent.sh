#!/usr/bin/env bash
#
# Invokes the Sonar-Trivy Auto Remediation agent via the NVIDIA API.
# Reads reports from ./reports/ and writes the agent's Markdown report to
# ./reports/auto-remediation-report.md.
#
# Required env:
#   NVDAI_API_KEY      - NVIDIA API key
# Optional env:
#   NVDAI_MODEL        - model id (default: meta/llama-3.1-70b-instruct)
#   NVDAI_MAX_TOKENS   - max tokens (default: 4000)

set -euo pipefail

if [ -z "${NVDAI_API_KEY:-}" ]; then
  echo "::error::NVDAI_API_KEY is not set; cannot invoke the agent." >&2
  exit 1
fi

REPORTS_DIR="${REPORTS_DIR:-reports}"
mkdir -p "$REPORTS_DIR"

# Truncate large files to avoid blowing up the request payload.
truncate -s 10240 "$REPORTS_DIR/trivy-fs.sarif"     2>/dev/null || true
truncate -s 10240 "$REPORTS_DIR/trivy-image.sarif"   2>/dev/null || true
truncate -s 10240 "$REPORTS_DIR/sonar-report.json"   2>/dev/null || true

MODEL="${NVDAI_MODEL:-meta/llama-3.1-70b-instruct}"
MAX_TOKENS="${NVDAI_MAX_TOKENS:-4000}"

# Sanity: list the available reports so the model knows what's there.
echo "📂 Available reports under $REPORTS_DIR/:" >&2
ls -la "$REPORTS_DIR" >&2 || true

SYSTEM_PROMPT='You are an Enterprise DevSecOps AI Agent named "Sonar-Trivy Auto Remediation Agent".

Your responsibility is to safely remediate SonarQube and Trivy findings in the CURRENT Git branch only. You are executing inside a GitHub Actions runner.

RULES (non-negotiable):
1. Operate ONLY on the currently checked-out branch. Never push, commit, switch branches, merge, rebase, or reset.
2. Process findings in order: Critical -> High -> Medium -> Low -> Info.
3. For dependencies: choose the LOWEST stable version that fixes the vulnerability. Avoid major version upgrades unless required.
4. For SonarQube: apply only safe, behavior-preserving fixes. Never disable rules or suppress warnings.
5. For Dockerfile: prefer minimal changes, pin base images, remove unnecessary packages.
6. NEVER delete production logic, remove tests, break compilation, or modify generated files / vendor libraries / build outputs.
7. After every modification, the project MUST still build (mvn -B -ntp -DskipTests package must succeed).
8. If a fix cannot be safely automated, skip it and record the reason.
9. Prefer minimal code change -> secure solution -> backward compatibility -> readability -> maintainability.

INPUTS (already on disk under reports/):
- trivy-fs.sarif    : Trivy filesystem scan (SARIF v2.1.0)
- trivy-image.sarif : Trivy image scan (SARIF v2.1.0, if present)
- sonar-report.json : SonarQube issues JSON (if fetch succeeded)

WORKFLOW:
1. Parse the SARIF / JSON reports.
2. For each finding, decide: FIX, SKIP, or OUT-OF-SCOPE.
3. Apply safe fixes to the working tree.
4. Validate with: mvn -B -ntp -DskipTests package
5. Emit a single Markdown report in EXACTLY the format below.'

USER_PROMPT='Analyze the reports under ./reports/ and apply safe, automated remediations to the current branch. Do not push or commit.

At the end, output a Markdown report in EXACTLY this format (no extra explanation outside the report):

# Sonar-Trivy Auto Remediation Report

## Scan Summary

SonarQube Issues: <count>
Trivy Findings: <count>

Critical: <count>
High: <count>
Medium: <count>
Low: <count>

## Automatically Fixed
- <one bullet per fixed issue>

## Files Modified
- <repo-relative path>

## Dependency Updates
- <package> : <old version> -> <new version>

## Docker Improvements
- <one bullet per change>

## Skipped Findings
- <issue> -- <reason>

## Remaining Critical Issues
- <list>

## Remaining High Issues
- <list>

## Manual Recommendations
- <list>

## Overall Result
SUCCESS or PARTIAL SUCCESS or MANUAL ACTION REQUIRED'

# Write the two prompts to files so python can read them with no shell escaping.
printf '%s' "$SYSTEM_PROMPT" > system-prompt.txt
printf '%s' "$USER_PROMPT"   > user-prompt.txt

# Build payload.json from the prompt files.
# NOTE: On Windows, the MS Store "python3" alias may shadow the real
# interpreter. The CI runner is Ubuntu so this is a non-issue there; for
# local Windows testing, set PYTHON to the real interpreter, e.g.
#   PYTHON=/c/Python314/python bash scripts/run-agent.sh
PY="${PYTHON:-python3}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY="python"
fi
if ! command -v "$PY" >/dev/null 2>&1; then
  echo "::error::Neither python3 nor python is available; cannot build payload." >&2
  exit 1
fi
"$PY" - <<'PYEOF'
import json, os
with open("system-prompt.txt", "r", encoding="utf-8") as f:
    system_content = f.read()
with open("user-prompt.txt", "r", encoding="utf-8") as f:
    user_content = f.read()
payload = {
    "model": os.environ.get("NVDAI_MODEL", "meta/llama-3.1-70b-instruct"),
    "max_tokens": int(os.environ.get("NVDAI_MAX_TOKENS", "4000")),
    "messages": [
        {"role": "system", "content": system_content},
        {"role": "user",   "content": user_content},
    ],
}
with open("payload.json", "w", encoding="utf-8") as f:
    json.dump(payload, f, ensure_ascii=False)
print("payload.json written:", os.path.getsize("payload.json"), "bytes")
PYEOF

echo "────────────────────────────────────────────"
echo "🤖 Agent - Sonar-Trivy Auto Remediation"
echo "────────────────────────────────────────────"

RESPONSE=$(curl -s https://integrate.api.nvidia.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $NVDAI_API_KEY" \
  -d @payload.json)

echo "$RESPONSE" | jq -r '.choices[0].message.content // "Agent response unavailable"' 2>/dev/null || echo "$RESPONSE"

echo "────────────────────────────────────────────"

# Persist the report as an artifact.
echo "$RESPONSE" | jq -r '.choices[0].message.content // ""' 2>/dev/null \
  > "$REPORTS_DIR/auto-remediation-report.md" \
  || echo "Agent response processing failed" > "$REPORTS_DIR/auto-remediation-report.md"

# Clean up the payload and prompt files (they may contain the prompt content).
rm -f payload.json system-prompt.txt user-prompt.txt
