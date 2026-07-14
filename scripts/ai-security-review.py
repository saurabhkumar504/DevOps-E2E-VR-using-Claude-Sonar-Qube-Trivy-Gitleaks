#!/usr/bin/env python3
"""
ai-security-review.py

NVIDIA-powered security review agent. Reads SonarCloud + Trivy + coverage
artifacts and asks an NVIDIA-hosted LLM to produce a structured security
review. Falls back to a deterministic stub when NVIDIA_API_KEY is missing
or the API call fails — so the pipeline never hard-fails on a missing
key in a learning environment.

Inputs (paths configurable via --reports, default ./reports):
  sonar-report.json, sonar-report.txt,
  trivy-report.json, trivy-report.txt,
  jacoco.xml (or jacoco.csv), junit.xml,
  coverage-summary.json, coverage-summary.md, coverage-summary.csv

Outputs (under --reports):
  security-review.json   - structured findings (severity, root_cause, cwe,
                           owasp, file, line, suggested_fix, risk_score,
                           priority)
  security-review.md     - human-readable markdown
  security-summary.txt   - one-line-per-finding text

Required env:
  NVIDIA_API_KEY         - NVIDIA build / integrate API key
  MIN_COVERAGE           - line-coverage threshold in percent (default 80);
                           a finding must be raised if overall coverage
                           falls below this number
Optional env:
  NVIDIA_MODEL           - default "meta/llama-3.1-70b-instruct"
  NVIDIA_BASE_URL        - default "https://integrate.api.nvidia.com/v1"
  NVIDIA_MAX_TOKENS      - default 4000
"""
import argparse
import json
import os
import re
import sys
import textwrap
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
                 "BLOCKER": 5, "MAJOR": 3, "MINOR": 2, "UNKNOWN": 0}

# Coverage threshold (in percent). The agent must raise a HIGH finding when
# overall line coverage is below this number, and an INFO finding per
# package whose coverage is below the threshold. Override with MIN_COVERAGE
# env var.
MIN_COVERAGE_PCT = float(os.environ.get("MIN_COVERAGE", "80"))


SYSTEM_PROMPT = f"""You are an Enterprise DevSecOps AI Agent named "Security Reviewer".

Your responsibility is to read SonarCloud, Trivy and test-coverage reports
and produce a STRICTLY STRUCTURED security review of the Java/Maven project
under review.

OUTPUT FORMAT (return ONLY this JSON, no prose, no markdown fences):
{{
  "status": "OK",
  "summary": "<one-paragraph executive summary>",
  "risk_score": <integer 0-100>,
  "overall_priority": "P0|P1|P2|P3",
  "findings": [
    {{
      "id": "<stable id, e.g. SR-001>",
      "title": "<short title>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "priority": "P0|P1|P2|P3",
      "category": "<vulnerability|code-smell|bug|secret|misconfig|dependency|coverage>",
      "cwe": ["CWE-89", "CWE-79"],
      "owasp": ["A01:2021-Broken Access Control", "A03:2021-Injection"],
      "root_cause": "<one-sentence technical root cause>",
      "file": "<repo-relative path or package name>",
      "line": <line number or null>,
      "rule_id": "<Sonar rule id or Trivy rule id>",
      "evidence": "<quote the relevant source line(s) or finding message>",
      "suggested_fix": "<concrete fix, ideally a code snippet>",
      "risk_score": <integer 0-100>
    }}
  ]
}}

RULES:
- Be specific: every finding must reference a file + line number OR a
  package@cve (for Trivy dependency findings).
- Do not invent findings. Only consolidate / re-prioritise what the
  reports show.
- For Trivy findings, the CWE is whatever the CVE references. The OWASP
  category is "A06:2021-Vulnerable and Outdated Components".
- For SonarCloud findings, derive CWE + OWASP from the rule id where
  possible (sql-injection -> CWE-89 / A03; reflected-xss -> CWE-79 / A03;
  hardcoded credentials -> CWE-798 / A07; missing-csrf -> CWE-352 / A01;
  etc.).
- Severity escalates to CRITICAL if the finding is exploitable in the
  default app configuration (e.g. unauthenticated SQL injection).
- Cap findings at 50 entries; sort by severity desc, then risk_score desc.
- `risk_score` is 0-100 (likelihood × impact, rounded).
- Return valid JSON. Do not include any commentary outside the JSON.

COVERAGE RULES (threshold = {MIN_COVERAGE_PCT:.0f}% line coverage):
- If coverage-summary.json is present and the overall line_pct is below the
  threshold, emit ONE HIGH finding with category="coverage",
  owasp=["A05:2021-Security Misconfiguration"], cwe=["CWE-1126"],
  file="<the package(s) with the lowest coverage, comma-separated>",
  evidence quoting the actual overall line_pct value from the report.
- For each package whose line_pct is below the threshold, emit ONE INFO
  finding with category="coverage", file=package name, evidence quoting
  the per-package pct. Cap the per-package coverage findings at 10 to
  stay within the overall 50-finding budget.
- If coverage-summary.json reports "error" (no jacoco.xml), do NOT raise
  a coverage finding — the build was unable to measure coverage.
- If overall coverage is at or above the threshold, do NOT raise any
  coverage findings.
"""


def _read(path: Path) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace")
    # Truncate to keep the prompt within reasonable token bounds.
    return text[:32_000]


def _build_user_prompt(reports_dir: Path) -> str:
    parts: list[str] = [
        f"Analyse the following scanner outputs and return the JSON review described in the system prompt.\n"
        f"Coverage threshold for this pipeline: {MIN_COVERAGE_PCT:.0f}% line coverage.\n"
    ]
    # Order matters: human-readable first (so the LLM has the narrative),
    # then structured (so it can quote precise numbers).
    for name in (
        "sonar-report.txt",
        "trivy-report.txt",
        "coverage-summary.md",
        "coverage-summary.json",
        "coverage-summary.csv",
        "sonar-report.json",
        "trivy-report.json",
        "jacoco.xml",
        "junit.xml",
    ):
        content = _read(reports_dir / name)
        if content:
            parts.append(f"===== {name} =====\n{content}\n")
    parts.append(
        "\nReturn ONLY the JSON object. No commentary, no markdown fences."
    )
    return "\n".join(parts)


def _call_nvidia(prompt: str, model: str, base_url: str, max_tokens: int) -> str:
    api_key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if not api_key:
        return ""
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
    }
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError) as exc:
        print(f"WARN: NVIDIA API call failed: {exc}", file=sys.stderr)
        return ""
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return ""


def _extract_json(text: str) -> dict | None:
    """Best-effort JSON extraction (handles ```json fences)."""
    if not text:
        return None
    # Strip code fences if present
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"```$", "", text.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find the first {...} block
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


def _load_coverage(reports_dir: Path) -> dict | None:
    """Return the structured coverage summary if present."""
    p = reports_dir / "coverage-summary.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _coverage_findings(counter_start: int, coverage: dict | None) -> tuple[list[dict], int]:
    """Emit coverage findings for the fallback review. Returns
    (findings, next_counter)."""
    if not coverage or coverage.get("error"):
        return [], counter_start
    overall = coverage.get("overall") or {}
    overall_pct = overall.get("line_pct")
    if overall_pct is None:
        return [], counter_start
    findings: list[dict] = []
    counter = counter_start
    threshold = float(coverage.get("threshold_pct", MIN_COVERAGE_PCT))
    if overall_pct < threshold:
        counter += 1
        worst = sorted(
            coverage.get("packages") or [],
            key=lambda p: p.get("line_pct", 0.0),
        )[:5]
        worst_names = ", ".join(p.get("package", "?") for p in worst)
        findings.append({
            "id": f"SR-{counter:03d}",
            "title": f"Line coverage {overall_pct}% is below threshold {threshold:.0f}%",
            "severity": "HIGH",
            "priority": "P1",
            "category": "coverage",
            "cwe": ["CWE-1126"],
            "owasp": ["A05:2021-Security Misconfiguration"],
            "root_cause": (
                "Unit-test coverage is below the policy threshold, so security-critical "
                "code paths are not exercised by automated tests."
            ),
            "file": worst_names or "(no packages)",
            "line": None,
            "rule_id": "coverage-threshold",
            "evidence": (
                f"Overall line coverage: {overall_pct}% "
                f"({overall.get('line_covered', 0):,}/{overall.get('line_total', 0):,} lines); "
                f"threshold: {threshold:.0f}%"
            ),
            "suggested_fix": (
                "Add unit tests targeting the lowest-covered packages first. "
                "Focus on service-layer and controller code that handles untrusted input."
            ),
            "risk_score": 70,
        })
    return findings, counter


def _fallback_review(reports_dir: Path) -> dict:
    """Deterministic stub when the NVIDIA API is unavailable."""
    sonar = _load_sonar(reports_dir / "sonar-report.json")
    trivy = _load_trivy(reports_dir / "trivy-report.json")
    coverage = _load_coverage(reports_dir)
    findings: list[dict] = []
    counter = 0

    cov_findings, counter = _coverage_findings(counter, coverage)
    findings.extend(cov_findings)

    for sev, f in _highest(sonar, 10):
        counter += 1
        findings.append({
            "id": f"SR-{counter:03d}",
            "title": f.get("message", "(no message)")[:120],
            "severity": _normalize_severity(sev),
            "priority": _priority_for(_normalize_severity(sev)),
            "category": (f.get("type") or "code-smell").lower(),
            "cwe": [],
            "owasp": [],
            "root_cause": "Imported from SonarCloud issue.",
            "file": f.get("file") or "",
            "line": f.get("line"),
            "rule_id": f.get("rule") or "",
            "evidence": (f.get("message") or "")[:200],
            "suggested_fix": "Review the SonarCloud rule documentation and refactor accordingly.",
            "risk_score": _severity_to_score(_normalize_severity(sev)),
        })
    for sev, f in _highest(trivy, 10):
        counter += 1
        findings.append({
            "id": f"SR-{counter:03d}",
            "title": f.get("cve") or f.get("ruleId") or "Trivy finding",
            "severity": _normalize_severity(sev),
            "priority": _priority_for(_normalize_severity(sev)),
            "category": f.get("category", "vulnerability"),
            "cwe": [],
            "owasp": ["A06:2021-Vulnerable and Outdated Components"],
            "root_cause": "Outdated / vulnerable dependency.",
            "file": f.get("pkgName") or f.get("file") or "",
            "line": f.get("line"),
            "rule_id": f.get("ruleId") or "",
            "evidence": (f.get("description") or "")[:200],
            "suggested_fix": f.get("recommendation") or "Review the Trivy advisory.",
            "risk_score": _severity_to_score(_normalize_severity(sev)),
        })

    findings.sort(key=lambda x: (-SEVERITY_RANK.get(x["severity"], 0), -x["risk_score"]))
    return {
        "status": "STUB",
        "summary": "NVIDIA API unavailable — generated a deterministic fallback review from the scanner outputs.",
        "risk_score": sum(f["risk_score"] for f in findings),
        "overall_priority": _priority_for(_max_severity([f["severity"] for f in findings])),
        "findings": findings,
    }


def _load_sonar(path: Path) -> list[tuple[str, dict]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    out = []
    for it in data.get("issues", []) or []:
        out.append(((it.get("severity") or "INFO").upper(), it))
    return out


def _load_trivy(path: Path) -> list[tuple[str, dict]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = data.get("findings", [])
    out = []
    for f in data:
        out.append(((f.get("severity") or "UNKNOWN").upper(), f))
    return out


def _highest(items: list[tuple[str, dict]], n: int) -> list[tuple[str, dict]]:
    items.sort(key=lambda x: -SEVERITY_RANK.get(x[0], 0))
    return items[:n]


def _max_severity(sevs: list[str]) -> str:
    return max(sevs, key=lambda s: SEVERITY_RANK.get(s, 0), default="INFO")


def _normalize_severity(sev: str) -> str:
    sev = (sev or "INFO").upper()
    if sev in {"BLOCKER", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return sev
    return "INFO"


def _severity_to_score(sev: str) -> int:
    return {"CRITICAL": 95, "BLOCKER": 95, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFO": 5}.get(sev, 10)


def _priority_for(sev: str) -> str:
    return {"CRITICAL": "P0", "BLOCKER": "P0", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3", "INFO": "P3"}.get(sev, "P3")


def _render_markdown(review: dict) -> str:
    lines: list[str] = [
        "# Security Review",
        "",
        f"**Status:** `{review.get('status', 'OK')}`  ",
        f"**Overall Risk Score:** {review.get('risk_score', 0)}  ",
        f"**Overall Priority:** {review.get('overall_priority', 'P3')}  ",
        "",
        "## Executive Summary",
        "",
        review.get("summary", "(no summary)"),
        "",
        "## Findings",
        "",
    ]
    findings = review.get("findings", []) or []
    if not findings:
        lines.append("_No findings reported._")
        return "\n".join(lines) + "\n"

    for f in findings:
        lines.append(f"### {f.get('id','?')} — [{f.get('severity','INFO')}] {f.get('title','')}")
        lines.append("")
        lines.append(f"- **Priority:** {f.get('priority','')}")
        lines.append(f"- **Category:** {f.get('category','')}")
        if f.get("cwe"):
            lines.append(f"- **CWE:** {', '.join(f['cwe'])}")
        if f.get("owasp"):
            lines.append(f"- **OWASP:** {', '.join(f['owasp'])}")
        if f.get("file"):
            lines.append(f"- **Location:** `{f['file']}`" + (f":{f['line']}" if f.get("line") else ""))
        if f.get("rule_id"):
            lines.append(f"- **Rule:** `{f['rule_id']}`")
        if f.get("root_cause"):
            lines.append(f"- **Root cause:** {f['root_cause']}")
        if f.get("evidence"):
            lines.append(f"- **Evidence:** {f['evidence']}")
        if f.get("suggested_fix"):
            lines.append(f"- **Suggested fix:** {f['suggested_fix']}")
        lines.append(f"- **Risk score:** {f.get('risk_score', 0)}/100")
        lines.append("")
    return "\n".join(lines) + "\n"


def _render_text(review: dict) -> str:
    lines: list[str] = [
        f"status={review.get('status', 'OK')}",
        f"risk_score={review.get('risk_score', 0)}",
        f"priority={review.get('overall_priority', 'P3')}",
        f"finding_count={len(review.get('findings', []) or [])}",
        "",
    ]
    for f in review.get("findings", []) or []:
        where = f.get("file", "")
        if f.get("line"):
            where = f"{where}:{f['line']}"
        lines.append(
            f"[{f.get('severity','INFO'):8s}] {f.get('id','')} {f.get('title','')}  -- {where}"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--reports", type=Path, default=Path("reports"))
    p.add_argument("--model", default=os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct"))
    p.add_argument("--base-url", default=os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"))
    p.add_argument("--max-tokens", type=int, default=int(os.environ.get("NVIDIA_MAX_TOKENS", "4000")))
    args = p.parse_args()

    args.reports.mkdir(parents=True, exist_ok=True)
    user_prompt = _build_user_prompt(args.reports)
    raw = _call_nvidia(user_prompt, args.model, args.base_url, args.max_tokens)
    review = _extract_json(raw)
    if not review:
        print("WARN: NVIDIA response was not valid JSON; emitting stub review.", file=sys.stderr)
        review = _fallback_review(args.reports)

    # Validate / normalise structure (don't trust the LLM)
    if not isinstance(review.get("findings"), list):
        review["findings"] = []
    for f in review["findings"]:
        f["severity"] = _normalize_severity(f.get("severity", "INFO"))
        f["priority"] = f.get("priority") or _priority_for(f["severity"])
        f["risk_score"] = int(f.get("risk_score", _severity_to_score(f["severity"])))

    review["findings"].sort(
        key=lambda x: (-SEVERITY_RANK.get(x.get("severity", "INFO"), 0), -x.get("risk_score", 0))
    )
    if not review.get("risk_score"):
        review["risk_score"] = sum(f.get("risk_score", 0) for f in review["findings"])
    if not review.get("overall_priority"):
        review["overall_priority"] = _priority_for(_max_severity([f.get("severity", "INFO") for f in review["findings"]]))
    review.setdefault("status", "OK")

    (args.reports / "security-review.json").write_text(json.dumps(review, indent=2), encoding="utf-8")
    (args.reports / "security-review.md").write_text(_render_markdown(review), encoding="utf-8")
    (args.reports / "security-summary.txt").write_text(_render_text(review), encoding="utf-8")
    print(f"Security review written to {args.reports}/security-review.{{json,md}} and security-summary.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
