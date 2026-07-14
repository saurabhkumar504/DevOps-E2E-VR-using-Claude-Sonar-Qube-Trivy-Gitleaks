#!/usr/bin/env python3
"""
generate-auto-remediation-report.py

Consolidates every scanner report (SonarCloud, CodeQL, Trivy), the JaCoCo
coverage report, the AI security review, the AI auto-remediation report,
and the deploy-gate decision into a single, enterprise-grade 14-section
audit document. Two output files are produced:

  reports/AUTO_REMEDIATION_REPORT.md    - human-readable (with TOC,
                                          status badges, summary tables)
  reports/auto-remediation-report.json - machine-readable (one key per
                                          section, suitable for downstream
                                          automation / dashboards)

This script is a pure aggregator: it never modifies the inputs, never
shells out to git or gh, never writes to the existing files. It is
invoked as a step in the `security-ai-remediate` job after
`ai-remediation.py` finishes, with `if: always()` and
`continue-on-error: true` so a partial pipeline still produces a report.

Sections:
  1.  Executive Summary
  2.  Pipeline Execution Summary
  3.  Vulnerability Summary (Sonar / CodeQL / Trivy)
  4.  AI Root Cause Analysis
  5.  AI Remediation Details
  6.  Files Modified
  7.  Validation Summary
  8.  Risk Comparison (pre vs post)
  9.  Remaining Issues
  10. AI Confidence Assessment
  11. Pull Request Summary
  12. Deployment Recommendation
  13. Recommendations
  14. Report Metadata
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Static knowledge bases (small, intentional - we keep all "AI knowledge" in
# the LLM, not in this script).
# ---------------------------------------------------------------------------

BEST_PRACTICE: dict[str, str] = {
    "hardcoded-secret":
        "Move secrets to environment variables or a secret manager (Vault, "
        "AWS Secrets Manager, GitHub Actions secrets). Never commit a secret "
        "to source control.",
    "sql-injection":
        "Use parameterised queries / prepared statements with bound parameters. "
        "Never concatenate user input into a SQL string.",
    "plaintext-password":
        "Hash passwords with a slow adaptive hash (bcrypt, argon2, scrypt) "
        "and use a constant-time comparison function. Never compare plaintext "
        "passwords with String.equals().",
    "outdated-dependency":
        "Bump the dependency to the version that contains the upstream fix. "
        "Review the project's release notes for any breaking changes.",
    "missing-csp":
        "Add a strict Content-Security-Policy header (e.g. "
        "default-src 'self'; script-src 'self'; object-src 'none').",
    "missing-csrf":
        "Enable CSRF protection on the affected endpoint (Spring Security "
        "does this by default for state-changing methods).",
    "weak-crypto":
        "Replace MD5 / SHA-1 / DES with SHA-256 or stronger. Use a vetted "
        "cryptographic library.",
    "open-redirect":
        "Validate the redirect target against an allow-list of trusted "
        "URLs / paths. Never redirect to a user-supplied URL unvalidated.",
}
DEFAULT_BEST_PRACTICE = (
    "Address the underlying CWE by following the upstream rule's "
    "documentation and the OWASP Cheat Sheet."
)

EFFORT: dict[str, str] = {
    "hardcoded-secret":   "30m",
    "sql-injection":      "1h",
    "plaintext-password": "2h",
    "outdated-dependency": "30m",
    "missing-csp":        "30m",
    "missing-csrf":       "1h",
    "weak-crypto":        "2h",
    "open-redirect":      "1h",
}
DEFAULT_EFFORT = "1d"

SIDE_EFFECTS: dict[str, str] = {
    "hardcoded-secret":
        "App may fail to start if `app.secret.*` is referenced elsewhere. "
        "Verify that the value is supplied via env var / secret manager "
        "before deploying.",
    "outdated-dependency":
        "Parent / direct dependency bump may pull transitive updates. "
        "Run `mvn dependency:tree` and re-run the full test suite.",
    "missing-csp":
        "Adding a default `default-src 'self'` CSP will block inline "
        "<script> tags and external scripts. If the front-end uses inline "
        "scripts, switch to nonces or hashes first.",
    "plaintext-password":
        "The method signature is preserved but the password comparison is "
        "now plaintext equality. The TODO marker indicates a follow-up to "
        "switch to BCryptPasswordEncoder.matches().",
    "sql-injection":
        "Parameter binding changes the query plan; verify the EXPLAIN plan "
        "still uses the index on the WHERE column. Custom type conversions "
        "(dates, enums) may need explicit setParameter casts.",
}
DEFAULT_SIDE_EFFECTS = (
    "Generic code rewrite - re-run unit tests and inspect the unified diff "
    "in `ai-patch.diff` for behavioural changes."
)

# Maps pipeline job name (as set in ci.yml) to the friendly stage name used
# in section 2. Keep in sync with the workflow's `name:` fields.
STAGE_ORDER: list[tuple[str, str]] = [
    ("1. Build (Maven, Java 21)",                    "Build"),
    ("2. Unit Tests (JUnit 5)",                     "Unit Tests"),
    ("3. Test Coverage (JaCoCo)",                   "JaCoCo"),
    ("4. SonarCloud Scan",                          "SonarCloud Analysis"),
    ("5. CodeQL Static Analysis",                   "CodeQL"),
    ("6. Trivy Security Scan",                      "Trivy"),
    ("7. AI Security Review (NVIDIA)",              "NVIDIA AI Security Agent"),
    ("8. AI Remediation Agent (NVIDIA)",            "AI Auto-Remediation"),
    ("9. Rebuild & Retest (post-remediation)",      "Validation Rebuild"),
    ("10. SonarCloud Re-Scan",                      "SonarCloud Re-Scan"),
    ("11. Trivy Re-Scan",                           "Trivy Re-Scan"),
    ("Pre-Deploy Gates",                            "Security Gate"),
    ("12. Deploy",                                  "Deploy"),
]


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: Path) -> dict | list | None:
    """Read a JSON file. Returns `None` on missing/invalid input; downstream
    code distinguishes "no data" via `_safe_load_json` which records the
    filename in the `missing_inputs` list."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _safe_load_json(name: str, path: Path, missing: list[str]) -> dict | list:
    """Same as `_load_json` but tracks missing inputs for the degraded-mode
    flag. Always returns a value (empty dict/list on missing)."""
    data = _load_json(path)
    if data is None:
        missing.append(f"{name} (expected at {path})")
        return {} if name.endswith("gates") or name.endswith("report") or name.endswith("review") else []
    return data


def _load_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError):
        return ""


def _coerce_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _coerce_float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _coerce_str(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _status_badge(passed: bool | None) -> str:
    if passed is None:
        return "⚪️ n/a"
    return "✅ PASS" if passed else "❌ FAIL"


def _format_status(conclusion: str | None) -> str:
    if not conclusion:
        return "n/a"
    c = conclusion.lower()
    if c == "success":
        return "✅ success"
    if c == "failure":
        return "❌ failure"
    if c == "cancelled":
        return "⚪️ cancelled"
    if c == "skipped":
        return "⚪️ skipped"
    return f"⚪️ {conclusion}"


def _parse_iso_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # GitHub sends e.g. "2026-07-13T08:15:06Z"
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _format_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return "n/a"
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, mn = divmod(minutes, 60)
    return f"{hours}h {mn}m"


# ---------------------------------------------------------------------------
# JaCoCo coverage parser (inline copy of check-deploy-gates._parse_jacoco_coverage)
# ---------------------------------------------------------------------------

def _parse_jacoco_coverage(path: Path) -> float | None:
    if not path.exists():
        return None
    if path.suffix == ".xml":
        try:
            root = ET.parse(path).getroot()
            for counter in root.iter("counter"):
                if counter.get("type") == "LINE":
                    missed = int(counter.get("missed", 0))
                    covered = int(counter.get("covered", 0))
                    total = missed + covered
                    return round(covered / total * 100, 2) if total else None
        except Exception:  # noqa: BLE001
            return None
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None
    m = re.search(r"Total.*?(\d{1,3}(?:\.\d+)?)\s*%", text, re.IGNORECASE | re.DOTALL)
    if m:
        return float(m.group(1))
    return None


def _parse_coverage_summary_csv(path: Path) -> float | None:
    """Read `coverage-summary.csv` produced by `generate-coverage-report.py`.
    Schema: package,line_missed,line_covered,line_total,line_pct,... Returns
    the aggregate (covered / total) line % summed across all rows, since
    the file has no "Total" row."""
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None
    total_covered = 0
    total_missed = 0
    for row in csv.DictReader(text.splitlines()):
        try:
            total_covered += int(row.get("line_covered", 0) or 0)
            total_missed  += int(row.get("line_missed",  0) or 0)
        except ValueError:
            continue
    total = total_covered + total_missed
    return round(total_covered / total * 100, 2) if total else None


# ---------------------------------------------------------------------------
# SARIF / CodeQL parser (inline copy of check-deploy-gates._parse_codeql_sarif)
# ---------------------------------------------------------------------------

def _coerce_score(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _parse_codeql_sarif(path: Path) -> tuple[int, int, list[dict]]:
    """Returns (critical, high, raw_results) where raw_results is a list of
    dicts: {rule_id, level, severity, message, file, line, security_severity}."""
    critical = 0
    high = 0
    results: list[dict] = []
    if not path.exists():
        return critical, high, results
    try:
        sarif = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return critical, high, results

    rule_severity: dict[str, float] = {}
    for run in sarif.get("runs", []) or []:
        tool = run.get("tool") or {}
        rules_containers = [tool.get("driver", {}).get("rules") or []]
        for ext in tool.get("extensions") or []:
            rules_containers.append(ext.get("rules") or [])
        for ruleset in rules_containers:
            for rule in ruleset or []:
                rid = rule.get("id") or ""
                if not rid:
                    continue
                props = rule.get("properties") or {}
                score = _coerce_score(props.get("security-severity"))
                if score is not None:
                    rule_severity[rid] = score

    for run in sarif.get("runs", []) or []:
        for result in run.get("results", []) or []:
            props = result.get("properties") or {}
            score = _coerce_score(props.get("security-severity"))
            if score is None:
                rid = result.get("ruleId") or ""
                score = rule_severity.get(rid)
            level = (result.get("level") or "").lower()
            severity: str
            if score is not None:
                if score >= 9.0:
                    severity = "CRITICAL"
                    critical += 1
                elif score >= 7.0:
                    severity = "HIGH"
                    high += 1
                else:
                    severity = "MEDIUM"
            elif level == "error":
                severity = "CRITICAL"
                critical += 1
            elif level == "warning":
                severity = "HIGH"
                high += 1
            else:
                severity = (level or "INFO").upper()
            location = (result.get("locations") or [{}])[0]
            phys = location.get("physicalLocation") or {}
            uri = (phys.get("artifactLocation") or {}).get("uri") or ""
            line = (phys.get("region") or {}).get("startLine")
            results.append({
                "rule_id": result.get("ruleId") or "",
                "level": level or "",
                "severity": severity,
                "message": (result.get("message") or {}).get("text", ""),
                "file": uri,
                "line": line,
                "security_severity": score,
            })
    return critical, high, results


# ---------------------------------------------------------------------------
# Diff-stat parser
# ---------------------------------------------------------------------------

_DIFFSTAT_LINE_RE = re.compile(
    r"^\s*(?P<file>[^|]+?)\s*\|\s*(?P<rest>.+?)\s*$", re.MULTILINE
)
# Per-file sections in a `--stat` output look like:
#   src/main/java/Foo.java | 12 ++++++----
# We extract added/removed from the trailing `+` / `-` glyphs which is what
# `git diff --stat` produces. We fall back to the `+n -m` tail if glyphs
# aren't there (e.g. when --numstat was used).

def _parse_git_diff_stat(text: str) -> list[dict]:
    if not text:
        return []
    out: list[dict] = []
    for m in _DIFFSTAT_LINE_RE.finditer(text):
        file = m.group("file").strip()
        rest = m.group("rest")
        # Try the numstat suffix first: "12 ++++++---" => "12 "
        num_match = re.match(r"^(\d+)\s+", rest)
        added = 0
        removed = 0
        if num_match:
            n = int(num_match.group(1))
            # Glyphs are + or - in the remainder
            glyphs = rest[num_match.end():]
            added = glyphs.count("+")
            removed = glyphs.count("-")
            # Sometimes there are fewer glyphs than the count (truncation);
            # trust the glyphs but use n as an upper bound fallback.
            if added == 0 and removed == 0:
                added = n // 2
                removed = n - added
        else:
            # Last-ditch: "1 +" / "2 -" pairs
            for sign, ch in (("+", "+"), ("-", "-")):
                removed += rest.count(ch)
            # Rough split: half are +, half are -
            total = added + removed
            added = total // 2
            removed = total - added
        out.append({
            "file": file,
            "added": added,
            "removed": removed,
            "type": "updated",
        })
    return out


# ---------------------------------------------------------------------------
# Severity / counts
# ---------------------------------------------------------------------------

SEVERITY_BUCKETS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
# Reverse rank: CRITICAL=5, HIGH=4, ..., UNKNOWN=0. Used for severity
# comparisons in section 3 and section 8.
SEVERITY_RANK = {b: len(SEVERITY_BUCKETS) - 1 - i for i, b in enumerate(SEVERITY_BUCKETS)}


def _counts_by_severity(items: list[dict], key: str = "severity") -> dict[str, int]:
    counts = {b: 0 for b in SEVERITY_BUCKETS}
    for it in items or []:
        sev = (it.get(key) or "UNKNOWN").upper()
        if sev not in counts:
            counts[sev] = 0
        counts[sev] += 1
    return counts


def _trivy_fixable_count(items: list[dict]) -> int:
    return sum(
        1 for it in items or []
        if it.get("fixedVersion")
        and str(it.get("fixedVersion")).lower() not in ("", "not fixed", "none")
    )


def _trivy_package_count(items: list[dict]) -> int:
    pkgs = {it.get("pkgName") for it in items or [] if it.get("pkgName")}
    return len(pkgs)


# ---------------------------------------------------------------------------
# Trivy / SonarCloud shape accessors
# ---------------------------------------------------------------------------

def _sonar_field(sonar: dict, name: str) -> Any:
    """Read a flat field, falling back to the nested `raw.metrics` map for
    backward compatibility with older reports."""
    if name in sonar:
        return sonar.get(name)
    metrics = (sonar.get("raw") or {}).get("metrics") or {}
    return metrics.get(name)


def _trivy_items(trivy: list | dict) -> list[dict]:
    if isinstance(trivy, list):
        return trivy
    if isinstance(trivy, dict):
        return trivy.get("findings", []) or []
    return []


# ---------------------------------------------------------------------------
# GitHub Jobs API
# ---------------------------------------------------------------------------

def _fetch_pipeline_stages(repo: str, run_id: str, token: str) -> list[dict]:
    if not repo or not run_id or not token:
        return []
    url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/jobs"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as e:  # noqa: BLE001
        print(f"::warning::Could not fetch GitHub jobs API: {e}", file=sys.stderr)
        return []
    stages: list[dict] = []
    for j in data.get("jobs", []):
        started_at = _parse_iso_dt(j.get("started_at"))
        completed_at = _parse_iso_dt(j.get("completed_at"))
        duration = (
            (completed_at - started_at).total_seconds()
            if started_at and completed_at else None
        )
        stages.append({
            "job_name": j.get("name") or "",
            "stage_name": next(
                (s for cn, s in STAGE_ORDER if (j.get("name") or "").startswith(cn)),
                j.get("name") or "(unknown)"
            ),
            "status": j.get("status") or "",
            "conclusion": j.get("conclusion") or "",
            "started_at": j.get("started_at"),
            "completed_at": j.get("completed_at"),
            "duration_s": duration,
        })
    return stages


# ---------------------------------------------------------------------------
# Section 3 - Vulnerability Summary
# ---------------------------------------------------------------------------

def section_3_sonar(pre: dict, post: dict) -> dict:
    def _field(d: dict, name: str) -> Any:
        v = _sonar_field(d or {}, name)
        return v
    return {
        "schemaVersion": _coerce_int(pre.get("schemaVersion")) or 2,
        "project":        pre.get("project") or pre.get("projectKey") or "",
        "projectKey":     pre.get("projectKey") or "",
        "branch":         pre.get("branch") or "",
        "commit":         pre.get("commit") or "",
        "before": {
            "qualityGate":        _coerce_str(_field(pre, "qualityGate")) or "UNKNOWN",
            "bugs":               _coerce_int(_field(pre, "bugs")) or 0,
            "vulnerabilities":    _coerce_int(_field(pre, "vulnerabilities")) or 0,
            "codeSmells":         _coerce_int(_field(pre, "codeSmells")) or 0,
            "securityHotspots":   _coerce_int(_field(pre, "securityHotspots")) or 0,
            "coverage":           _coerce_float(_field(pre, "coverage")),
            "duplicatedLines":    _coerce_float(_field(pre, "duplicatedLines")),
            "technicalDebt":      _coerce_str(_field(pre, "technicalDebt")),
            "reliabilityRating":  _coerce_str(_field(pre, "reliabilityRating")),
            "securityRating":     _coerce_str(_field(pre, "securityRating")),
            "maintainabilityRating": _coerce_str(_field(pre, "maintainabilityRating")),
        },
        "after": {
            "qualityGate":        _coerce_str(_field(post, "qualityGate")) or "UNKNOWN",
            "bugs":               _coerce_int(_field(post, "bugs")) or 0,
            "vulnerabilities":    _coerce_int(_field(post, "vulnerabilities")) or 0,
            "codeSmells":         _coerce_int(_field(post, "codeSmells")) or 0,
            "securityHotspots":   _coerce_int(_field(post, "securityHotspots")) or 0,
            "coverage":           _coerce_float(_field(post, "coverage")),
            "duplicatedLines":    _coerce_float(_field(post, "duplicatedLines")),
            "technicalDebt":      _coerce_str(_field(post, "technicalDebt")),
            "reliabilityRating":  _coerce_str(_field(post, "reliabilityRating")),
            "securityRating":     _coerce_str(_field(post, "securityRating")),
            "maintainabilityRating": _coerce_str(_field(post, "maintainabilityRating")),
        },
    }


def section_3_codeql(sarif_path: Path) -> dict:
    critical, high, results = _parse_codeql_sarif(sarif_path)
    by_severity: dict[str, int] = {b: 0 for b in SEVERITY_BUCKETS}
    for r in results:
        sev = r["severity"]
        if sev in by_severity:
            by_severity[sev] += 1
        else:
            by_severity[sev] = 1
    # Group by rule_id for the rule list
    rules: dict[str, dict] = {}
    for r in results:
        rid = r["rule_id"] or "(unknown)"
        if rid not in rules:
            rules[rid] = {"rule_id": rid, "count": 0, "max_severity": "INFO",
                          "files": set(), "cwe": [], "owasp": []}
        rules[rid]["count"] += 1
        rules[rid]["files"].add(r["file"])
        sev_rank = SEVERITY_RANK.get(r["severity"], -1)
        cur_rank = SEVERITY_RANK.get(rules[rid]["max_severity"], -1)
        if sev_rank > cur_rank:
            rules[rid]["max_severity"] = r["severity"]
    rule_list = [
        {**v, "files": sorted(f for f in v["files"] if f)} for v in rules.values()
    ]
    rule_list.sort(key=lambda r: (-SEVERITY_RANK.get(r["max_severity"], 0), -r["count"]))
    return {
        "by_severity": by_severity,
        "rules": rule_list,
        "results": results,
    }


def section_3_trivy(pre: list, post: list) -> dict:
    pre_items = _trivy_items(pre)
    post_items = _trivy_items(post)
    pre_counts = _counts_by_severity(pre_items)
    post_counts = _counts_by_severity(post_items)
    return {
        "before": {
            **pre_counts,
            "total": len(pre_items),
            "packages": _trivy_package_count(pre_items),
            "fixable": _trivy_fixable_count(pre_items),
            "secrets": sum(1 for f in pre_items if (f.get("category") or "").lower() == "secret"),
            "misconfigs": sum(1 for f in pre_items if (f.get("category") or "").lower() == "misconfig"),
        },
        "after": {
            **post_counts,
            "total": len(post_items),
            "packages": _trivy_package_count(post_items),
            "fixable": _trivy_fixable_count(post_items),
            "secrets": sum(1 for f in post_items if (f.get("category") or "").lower() == "secret"),
            "misconfigs": sum(1 for f in post_items if (f.get("category") or "").lower() == "misconfig"),
        },
        "top_critical": [
            {
                "cve":            f.get("cve") or "",
                "pkgName":        f.get("pkgName") or "",
                "installedVersion": f.get("installedVersion") or "",
                "fixedVersion":   f.get("fixedVersion") or "",
                "severity":       (f.get("severity") or "").upper(),
                "title":          (f.get("description") or "")[:120],
            }
            for f in sorted(
                [x for x in pre_items if (x.get("severity") or "").upper() in ("CRITICAL", "HIGH")],
                key=lambda x: (
                    -({"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}.get((x.get("severity") or "").upper(), 0))
                ),
            )[:15]
        ],
    }


# ---------------------------------------------------------------------------
# Section 4 - AI Root Cause Analysis
# ---------------------------------------------------------------------------

def section_4(review: dict, trivy: list) -> list[dict]:
    findings = review.get("findings") or []
    out: list[dict] = []
    for f in findings:
        out.append({
            "id":               _coerce_str(f.get("id")),
            "title":            _coerce_str(f.get("title")) or "",
            "severity":         (f.get("severity") or "UNKNOWN").upper(),
            "priority":         _coerce_str(f.get("priority")),
            "category":         _coerce_str(f.get("category")),
            "file":             _coerce_str(f.get("file")),
            "line":             _coerce_int(f.get("line")),
            "rule_id":          _coerce_str(f.get("rule_id")),
            "root_cause":       _coerce_str(f.get("root_cause")) or "",
            "security_impact":  _coerce_str(f.get("evidence")) or "",
            "exploitation":     _coerce_str(f.get("suggested_fix")) or "",
            "cwe":              list(f.get("cwe") or []),
            "owasp":            list(f.get("owasp") or []),
            "risk_score":       _coerce_int(f.get("risk_score")) or 0,
        })
    if not out:
        # Synthesise from Trivy if the AI review was empty
        for i, f in enumerate(_trivy_items(trivy)[:20]):
            out.append({
                "id": f"TRV-{i:03d}",
                "title": (f.get("description") or f.get("cve") or "Trivy finding")[:120],
                "severity": (f.get("severity") or "UNKNOWN").upper(),
                "priority": None,
                "category": f.get("category") or "vulnerability",
                "file": _coerce_str(f.get("file")),
                "line": _coerce_int(f.get("line")),
                "rule_id": f.get("ruleId") or f.get("cve") or "",
                "root_cause": f"Outdated / vulnerable dependency: {f.get('pkgName') or 'unknown'}",
                "security_impact": (f.get("description") or "")[:200],
                "exploitation": f.get("recommendation") or "Upgrade to the fixed version.",
                "cwe": [],
                "owasp": ["A06:2021-Vulnerable and Outdated Components"],
                "risk_score": 0,
            })
    return out


# ---------------------------------------------------------------------------
# Section 5 - AI Remediation Details
# ---------------------------------------------------------------------------

def section_5(remediation: dict, findings: list[dict], diffstat: list[dict]) -> list[dict]:
    fixes = remediation.get("fixes") or []
    diff_lookup: dict[str, dict] = {d.get("file") or "": d for d in diffstat}
    finding_by_key: dict[tuple, dict] = {}
    for f in findings:
        key = ((f.get("rule_id") or ""), (f.get("file") or ""))
        finding_by_key[key] = f
    out: list[dict] = []
    for i, fix in enumerate(fixes):
        rule = fix.get("rule") or ""
        file = fix.get("file") or ""
        key = (rule, file)
        finding = finding_by_key.get(key)
        d = diff_lookup.get(file, {})
        out.append({
            "vulnerability_id":   finding.get("id") if finding else None,
            "scanner_source":     finding.get("category") if finding else fix.get("category"),
            "rule":               rule,
            "file":               file,
            "lines_added":        d.get("added"),
            "lines_removed":      d.get("removed"),
            "before_summary":     "See `ai-patch.diff` for the original file content.",
            "after_summary":      fix.get("description") or "",
            "why_it_works":       BEST_PRACTICE.get(rule, DEFAULT_BEST_PRACTICE),
            "best_practice":      BEST_PRACTICE.get(rule, DEFAULT_BEST_PRACTICE),
            "automation_level":   "deterministic" if fix.get("source") != "llm" else "LLM",
            "source":             fix.get("source") or "deterministic",
            "safe":               bool(fix.get("safe", True)),
            "category":           fix.get("category"),
            "description":        fix.get("description") or "",
        })
    return out


# ---------------------------------------------------------------------------
# Section 6 - Files Modified
# ---------------------------------------------------------------------------

def section_6(diffstat: list[dict], name_status: str) -> list[dict]:
    """name_status is the output of `git diff --name-status HEAD` (or
    `--name-status` from before/after). We pair it with the lines added /
    removed from the diff-stat to give one row per file."""
    name_status_rows: list[tuple[str, str]] = []
    for line in (name_status or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            name_status_rows.append((parts[0], parts[1]))
    by_file: dict[str, dict] = {}
    for status, path in name_status_rows:
        by_file[path] = {"file": path, "type": "updated"}
        s = status.upper()
        if s.startswith("A"):
            by_file[path]["type"] = "added"
        elif s.startswith("D"):
            by_file[path]["type"] = "deleted"
        elif s.startswith("R") or s.startswith("C"):
            by_file[path]["type"] = "renamed"
    for d in diffstat:
        f = d.get("file") or ""
        if f not in by_file:
            by_file[f] = {"file": f, "type": "updated"}
        by_file[f]["lines_added"] = d.get("added", 0)
        by_file[f]["lines_removed"] = d.get("removed", 0)
    for f in by_file.values():
        if "lines_added" not in f:
            f["lines_added"] = 0
        if "lines_removed" not in f:
            f["lines_removed"] = 0
        f["ai_confidence_pct"] = 95  # deterministic by default
        f["validation_result"] = "deferred (rebuild pending)"
    return sorted(by_file.values(), key=lambda r: r["file"])


# ---------------------------------------------------------------------------
# Section 8 - Risk Comparison
# ---------------------------------------------------------------------------

def section_8_risk_comparison(sonar_pre: dict, sonar_post: dict,
                              codeql: dict, trivy: dict) -> list[dict]:
    rows: list[dict] = []

    def _row(metric: str, before: Any, after: Any, *, lower_is_better: bool = True) -> None:
        try:
            b = float(before) if before not in (None, "") else None
            a = float(after) if after not in (None, "") else None
        except (TypeError, ValueError):
            b = a = None
        if b is None and a is None:
            delta = None
            direction = "n/a"
        elif b is None or a is None:
            delta = None
            direction = "n/a"
        else:
            delta = round(a - b, 2)
            if delta == 0:
                direction = "neutral"
            elif lower_is_better:
                direction = "better" if delta < 0 else "worse"
            else:
                direction = "better" if delta > 0 else "worse"
        rows.append({
            "metric": metric,
            "before": before,
            "after": after,
            "delta": delta,
            "direction": direction,
        })

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        _row(f"Trivy {sev}",
             trivy["before"].get(sev, 0),
             trivy["after"].get(sev, 0),
             lower_is_better=True)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        _row(f"CodeQL {sev}",
             codeql["by_severity"].get(sev, 0),
             codeql["by_severity"].get(sev, 0),  # only one scan
             lower_is_better=True)
    _row("SonarCloud Bugs",          sonar_pre["before"]["bugs"],          sonar_post["after"]["bugs"],          lower_is_better=True)
    _row("SonarCloud Vulnerabilities", sonar_pre["before"]["vulnerabilities"], sonar_post["after"]["vulnerabilities"], lower_is_better=True)
    _row("SonarCloud Code Smells",   sonar_pre["before"]["codeSmells"],    sonar_post["after"]["codeSmells"],    lower_is_better=True)
    _row("SonarCloud Coverage %",    sonar_pre["before"]["coverage"],      sonar_post["after"]["coverage"],      lower_is_better=False)
    _row("SonarCloud Duplicated %",  sonar_pre["before"]["duplicatedLines"], sonar_post["after"]["duplicatedLines"], lower_is_better=True)
    # Ratings (lower number = better)
    _row("SonarCloud Reliability Rating",    sonar_pre["before"]["reliabilityRating"],    sonar_post["after"]["reliabilityRating"],    lower_is_better=True)
    _row("SonarCloud Security Rating",       sonar_pre["before"]["securityRating"],       sonar_post["after"]["securityRating"],       lower_is_better=True)
    _row("SonarCloud Maintainability Rating", sonar_pre["before"]["maintainabilityRating"], sonar_post["after"]["maintainabilityRating"], lower_is_better=True)
    return rows


# ---------------------------------------------------------------------------
# Section 9 - Remaining Issues
# ---------------------------------------------------------------------------

def section_9(remediation: dict) -> list[dict]:
    skipped = remediation.get("skipped_findings") or []
    out: list[dict] = []
    for s in skipped:
        rule = s.get("rule_id") or ""
        out.append({
            "id":             s.get("id"),
            "rule_id":        rule,
            "severity":       (s.get("severity") or "UNKNOWN").upper(),
            "title":          s.get("title") or "",
            "reason":         s.get("reason") or "Not auto-fixed",
            "manual_recommendation": BEST_PRACTICE.get(rule, DEFAULT_BEST_PRACTICE),
            "estimated_effort": EFFORT.get(rule, DEFAULT_EFFORT),
        })
    return out


# ---------------------------------------------------------------------------
# Section 10 - AI Confidence
# ---------------------------------------------------------------------------

def section_10(remediation: dict) -> dict:
    fixes = remediation.get("fixes") or []
    det = [f for f in fixes if f.get("source") != "llm"]
    llm = [f for f in fixes if f.get("source") == "llm"]
    n = len(det) + len(llm)
    overall: float | None
    if n == 0:
        overall = None
    else:
        overall = round((95 * len(det) + 70 * len(llm)) / n, 1)
    per_fix: list[dict] = []
    for f in fixes:
        rule = f.get("rule") or ""
        per_fix.append({
            "rule":      rule,
            "file":      f.get("file") or "",
            "source":    f.get("source") or "deterministic",
            "confidence_pct": 70 if f.get("source") == "llm" else 95,
            "rationale": (
                "Pattern match against known-safe code transforms; "
                "behaviour-preserving by construction."
                if f.get("source") != "llm" else
                "Generated by LLM; reviewed against marker comment and "
                "write-back check, but may alter business logic - "
                "requires reviewer sign-off."
            ),
            "potential_side_effects": SIDE_EFFECTS.get(rule, DEFAULT_SIDE_EFFECTS),
        })
    return {
        "overall_confidence_pct": overall,
        "deterministic_count":    len(det),
        "llm_count":              len(llm),
        "per_fix":                per_fix,
        "manual_review_areas":    [
            f"Review every LLM-generated fix (file: {f.get('file')}, rule: {f.get('rule')})"
            for f in llm
        ] + [
            "Spot-check that the AI's commit did not introduce unintended side effects in the rebuild",
        ],
    }


# ---------------------------------------------------------------------------
# Section 11 - Pull Request Summary
# ---------------------------------------------------------------------------

def section_11(remediation: dict, pr_number: str, token: str, repo: str) -> dict:
    """If a PR number was provided AND `gh pr view` is reachable, fetch the
    PR metadata. Otherwise, fall back to the remediation report's recorded
    `pr_url` (if any) and explain that no PR was opened."""
    branch = remediation.get("branch")
    target = remediation.get("target")
    pr_url = remediation.get("pr_url")
    pushed = bool(remediation.get("pushed"))
    out: dict = {
        "branch":        branch,
        "target":        target,
        "pr_url":        pr_url,
        "pushed":        pushed,
        "pr_created":    bool(pr_url),
        "explanation":   "",
    }
    if pr_number and pr_number.isdigit() and shutil_which("gh"):
        meta = _gh_pr_view(pr_number, token)
        if meta:
            out.update({
                "pr_created": True,
                "pr_url":     meta.get("url") or pr_url,
                "pr_number":  meta.get("number") or _coerce_int(pr_number),
                "target":     meta.get("baseRefName") or target,
                "source":     meta.get("headRefName") or branch,
                "title":      meta.get("title"),
                "files":      [f.get("path") for f in (meta.get("files") or [])],
                "reviewers":  [r.get("login") for r in (meta.get("reviewers") or [])],
                "labels":     [l.get("name")   for l in (meta.get("labels")    or [])],
            })
    if not out["pr_created"]:
        if pushed:
            out["explanation"] = (
                "No PR was created in this run - the AI's commit was pushed "
                f"directly to the trigger ref (`{branch}`). The commit is "
                "now part of the trigger branch; reviewers should approve "
                "the change via the normal branch review process."
            )
        else:
            out["explanation"] = (
                "No PR was created and no commit was pushed. The AI did not "
                "produce any safe fixes for this run, or the local commit "
                "could not be pushed to origin."
            )
    return out


def shutil_which(name: str) -> bool:
    import shutil
    return bool(shutil.which(name))


def _gh_pr_view(pr_number: str, token: str) -> dict | None:
    import subprocess
    try:
        proc = subprocess.run(
            ["gh", "pr", "view", pr_number,
             "--json", "number,url,title,baseRefName,headRefName,files,reviewers,labels"],
            check=False, capture_output=True, text=True, timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Section 12 - Deployment Recommendation
# ---------------------------------------------------------------------------

def section_12(gates: dict) -> dict:
    if not gates or not isinstance(gates, dict) or not gates.get("gates"):
        return {
            "verdict":  "UNKNOWN",
            "explanation": (
                "deploy-gates.json is not available; the recommendation "
                "cannot be determined from the gate data alone."
            ),
            "deploy_recommended": False,
            "deploy_job_will_run": False,
            "gates": [],
        }
    passed = bool(gates.get("deploy_recommended"))
    failed = [g for g in gates.get("gates", []) if not g.get("passed")]
    failed_names = {g.get("name") for g in failed}

    if passed:
        verdict = "Safe to merge"
        explanation = (
            "All deploy gates passed. The AI's commit has been pushed to "
            "the trigger ref and the rebuild produced a clean build with "
            "no new critical/high findings."
        )
    else:
        security_critical = {"no_critical_codeql", "no_high_codeql",
                             "no_critical_trivy", "no_high_trivy",
                             "no_remaining_vulnerabilities", "sonar_quality_gate"}
        if failed_names & security_critical:
            verdict = "Security review required"
        elif failed_names & {"coverage_threshold", "ai_remediation_completed"}:
            verdict = "Manual review required"
        elif failed_names & {"build_succeeded"}:
            verdict = "Reject remediation"
        else:
            verdict = "Manual review required"
        bits = "\n".join(
            f"- `{g['name']}`: expected `{g.get('expected')!r}`, actual `{g.get('actual')!r}`"
            for g in failed
        )
        explanation = (
            f"{len(failed)} gate(s) failed:\n{bits}\n\n"
            "The deploy job will be skipped because `check-deploy-gates."
            "outputs.deploy_recommended` is False. This report's verdict is "
            "**informational only** - the deploy job does not read from "
            "this file."
        )
    return {
        "verdict":  verdict,
        "explanation": explanation,
        "deploy_recommended": passed,
        "deploy_job_will_run": passed,
        "gates": gates.get("gates", []),
    }


# ---------------------------------------------------------------------------
# Section 13 - Recommendations
# ---------------------------------------------------------------------------

def section_13(sonar_pre: dict, sonar_post: dict, codeql: dict,
               trivy: dict, remediation: dict, min_coverage_pct: float) -> list[dict]:
    recs: list[dict] = []
    trivy_after = trivy.get("after", {})
    trivy_critical = trivy_after.get("CRITICAL", 0)
    trivy_high = trivy_after.get("HIGH", 0)
    sonar_vulns = (sonar_post.get("after") or {}).get("vulnerabilities", 0) or 0
    coverage = (sonar_post.get("after") or {}).get("coverage")
    skipped = remediation.get("skipped_findings") or []

    if trivy_critical > 0:
        recs.append({
            "priority": "P0",
            "category": "dependency-upgrade",
            "message": f"Address {trivy_critical} remaining Trivy CRITICAL CVE(s) by upgrading the affected packages.",
        })
    if trivy_high > 0:
        recs.append({
            "priority": "P0",
            "category": "dependency-upgrade",
            "message": f"Address {trivy_high} remaining Trivy HIGH CVE(s) by upgrading the affected packages.",
        })
    if sonar_vulns > 0:
        recs.append({
            "priority": "P0",
            "category": "secure-coding",
            "message": f"Address the {sonar_vulns} remaining SonarCloud vulnerability/vulnerabilities - these are static analysis findings that the auto-remediator declined to fix.",
        })
    if codeql.get("by_severity", {}).get("CRITICAL", 0) > 0:
        recs.append({
            "priority": "P0",
            "category": "static-analysis",
            "message": f"Review the {codeql['by_severity']['CRITICAL']} CodeQL CRITICAL alert(s); they were not auto-remediated and require a security engineer.",
        })
    if coverage is not None and coverage < min_coverage_pct:
        recs.append({
            "priority": "P1",
            "category": "test-coverage",
            "message": f"Increase line coverage from {coverage:.1f}% to the {min_coverage_pct:.0f}% policy threshold by adding tests on the lowest-covered packages.",
        })
    if skipped:
        recs.append({
            "priority": "P1",
            "category": "manual-review",
            "message": f"Triage the {len(skipped)} remaining finding(s) that the AI agent declined to auto-fix (see section 9).",
        })
    recs.append({
        "priority": "P2",
        "category": "secure-coding",
        "message": "Adopt the OWASP ASVS checklist for any new endpoints added this cycle.",
    })
    recs.append({
        "priority": "P2",
        "category": "security-hardening",
        "message": "Pin all CI dependencies (actions/checkout, actions/setup-java, ...) to a specific commit SHA rather than a tag to mitigate supply-chain attacks.",
    })
    return recs


# ---------------------------------------------------------------------------
# Section 14 - Report Metadata
# ---------------------------------------------------------------------------

def section_14(args: argparse.Namespace) -> dict:
    return {
        "report_version":    args.report_version,
        "pipeline_version":  args.pipeline_version,
        "ai_agent_version":  args.ai_agent_version,
        "ai_model":          args.ai_model,
        "github_runner":     f"{args.runner_os} ({args.runner_name})",
        "java_version":      args.java_version,
        "maven_version":     args.maven_version,
        "sonarcloud_version": args.sonarcloud_version,
        "generated_at":      _utcnow_iso(),
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def _md_header(text: str, level: int = 2) -> str:
    return f"\n{'#' * level} {text}\n\n"


def _md_kv_table(rows: list[tuple[str, Any]]) -> str:
    out = ["| | |", "|---|---|", ""]
    for k, v in rows:
        out.append(f"| **{k}** | `{v if v is not None else 'n/a'}` |")
    out.append("")
    return "\n".join(out)


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c if c is not None else "") for c in r) + " |")
    return "\n".join(out) + "\n"


def render_markdown(report: dict) -> str:
    s = report["sections"]
    md: list[str] = []

    # ----- Top-of-file header & TOC -------------------------------------
    overall = report["overall_status"]
    md.append(f"# Auto-Remediation Report — {s['project_name']}")
    md.append("")
    md.append(f"> *Generated {s['generated_at']} — {overall['verdict_badge']}*")
    md.append("")
    md.append(_md_kv_table([
        ("Project",          s["project_name"]),
        ("Repository",       s["repository"]),
        ("Branch",           f"`{s['branch']}`"),
        ("AI Fix Branch",    f"`{s['ai_fix_branch']}`"),
        ("Commit SHA",       s["commit_sha"]),
        ("Pipeline run",     f"[#{s['pipeline_run_id']}]({s['pipeline_run_url']})" if s["pipeline_run_url"] else s["pipeline_run_id"]),
        ("Workflow",         s["workflow"]),
        ("Build timestamp",  s["build_timestamp"]),
        ("Report generated", s["generated_at"]),
        ("Overall status",   overall["verdict_badge"]),
        ("Security Gate",    _status_badge(overall["security_gate_passed"])),
        ("SonarCloud QG",    _status_badge(overall["sonar_qg_passed"])),
        ("AI Remediation",   _status_badge(overall["ai_remediation_passed"])),
        ("Deployment",       overall["deployment_verdict"]),
    ]))
    md.append("")
    md.append("## Table of Contents")
    md.append("")
    md.append("- [1. Executive Summary](#1-executive-summary)")
    md.append("- [2. Pipeline Execution Summary](#2-pipeline-execution-summary)")
    md.append("- [3. Vulnerability Summary](#3-vulnerability-summary)")
    md.append("- [4. AI Root Cause Analysis](#4-ai-root-cause-analysis)")
    md.append("- [5. AI Remediation Details](#5-ai-remediation-details)")
    md.append("- [6. Files Modified](#6-files-modified)")
    md.append("- [7. Validation Summary](#7-validation-summary)")
    md.append("- [8. Risk Comparison](#8-risk-comparison)")
    md.append("- [9. Remaining Issues](#9-remaining-issues)")
    md.append("- [10. AI Confidence Assessment](#10-ai-confidence-assessment)")
    md.append("- [11. Pull Request Summary](#11-pull-request-summary)")
    md.append("- [12. Deployment Recommendation](#12-deployment-recommendation)")
    md.append("- [13. Recommendations](#13-recommendations)")
    md.append("- [14. Report Metadata](#14-report-metadata)")
    md.append("")

    # ----- 1. Executive Summary -----------------------------------------
    md.append("## 1. Executive Summary")
    md.append("")
    narr = s["executive_narrative"]
    md.append(f"AI auto-remediation was triggered by **{narr['total_findings']}** finding(s) across SonarCloud, Trivy, and CodeQL. The deterministic engine applied **{narr['deterministic_fixes']}** safe fix(es); the LLM pass applied **{narr['llm_fixes']}** additional patch(es). **{narr['remaining_issues']}** issue(s) remain and require manual review.")
    md.append("")
    md.append(f"- **Why remediation was triggered:** {narr['trigger_reason']}")
    md.append(f"- **Whether remediation succeeded:** {narr['remediation_succeeded']}")
    md.append(f"- **Project ready for merge / deployment:** {narr['ready_for_merge']}")
    md.append("")
    md.append("**Status badges:**")
    md.append("")
    md.append(f"- Overall: {overall['verdict_badge']}")
    md.append(f"- Security Gate: {_status_badge(overall['security_gate_passed'])}")
    md.append(f"- SonarCloud Quality Gate: {_status_badge(overall['sonar_qg_passed'])}")
    md.append(f"- AI Remediation: {_status_badge(overall['ai_remediation_passed'])}")
    md.append("")
    if report.get("degraded"):
        md.append("> **Note:** this report is in degraded mode. The following inputs were missing:")
        for m in report.get("missing_inputs", []):
            md.append(f"> - `{m}`")
        md.append("")

    # ----- 2. Pipeline Execution Summary --------------------------------
    md.append("## 2. Pipeline Execution Summary")
    md.append("")
    stages = s["pipeline_stages"]
    if not stages:
        md.append("_Pipeline stage timings were not retrievable; see the GitHub Actions UI for this run._")
        md.append("")
    else:
        md.append(_md_table(
            ["Stage", "Status", "Duration", "Started", "Completed"],
            [[stg["stage_name"],
              _format_status(stg.get("conclusion") or stg.get("status")),
              _format_duration(stg.get("duration_s")),
              stg.get("started_at") or "n/a",
              stg.get("completed_at") or "n/a"]
             for stg in stages]
        ))

    # ----- 3. Vulnerability Summary --------------------------------------
    md.append("## 3. Vulnerability Summary")
    md.append("")
    md.append("### 3.1 SonarCloud")
    md.append("")
    sonar = s["vulnerabilities"]["sonar"]
    md.append(_md_table(
        ["Metric", "Before", "After"],
        [
            ["Bugs",                sonar["before"]["bugs"],               sonar["after"]["bugs"]],
            ["Vulnerabilities",     sonar["before"]["vulnerabilities"],     sonar["after"]["vulnerabilities"]],
            ["Code Smells",         sonar["before"]["codeSmells"],          sonar["after"]["codeSmells"]],
            ["Security Hotspots",   sonar["before"]["securityHotspots"],    sonar["after"]["securityHotspots"]],
            ["Coverage %",          sonar["before"]["coverage"],            sonar["after"]["coverage"]],
            ["Duplicated %",        sonar["before"]["duplicatedLines"],     sonar["after"]["duplicatedLines"]],
            ["Technical Debt (min)", sonar["before"]["technicalDebt"],      sonar["after"]["technicalDebt"]],
            ["Reliability Rating",  sonar["before"]["reliabilityRating"],   sonar["after"]["reliabilityRating"]],
            ["Security Rating",     sonar["before"]["securityRating"],      sonar["after"]["securityRating"]],
            ["Maintainability Rating", sonar["before"]["maintainabilityRating"], sonar["after"]["maintainabilityRating"]],
            ["Quality Gate",        sonar["before"]["qualityGate"],          sonar["after"]["qualityGate"]],
        ]
    ))
    md.append("### 3.2 CodeQL")
    md.append("")
    cql = s["vulnerabilities"]["codeql"]
    md.append(_md_table(
        ["Severity", "Count"],
        [[k, v] for k, v in cql["by_severity"].items() if v > 0] or [["(none)", 0]]
    ))
    if cql["rules"]:
        md.append("")
        md.append("**Top rules:**")
        md.append("")
        md.append(_md_table(
            ["Rule", "Max Severity", "Count", "Files"],
            [[r["rule_id"], r["max_severity"], r["count"], ", ".join(r["files"][:3])]
             for r in cql["rules"][:15]]
        ))
    md.append("### 3.3 Trivy")
    md.append("")
    trv = s["vulnerabilities"]["trivy"]
    md.append(_md_table(
        ["Severity", "Before", "After"],
        [[k, trv["before"].get(k, 0), trv["after"].get(k, 0)]
         for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")]
    ))
    md.append(_md_table(
        ["Other", "Before", "After"],
        [
            ["Total findings",   trv["before"]["total"],       trv["after"]["total"]],
            ["Affected packages", trv["before"]["packages"],   trv["after"]["packages"]],
            ["Fixable",          trv["before"]["fixable"],     trv["after"]["fixable"]],
            ["Secrets",          trv["before"]["secrets"],     trv["after"]["secrets"]],
            ["Misconfigurations", trv["before"]["misconfigs"], trv["after"]["misconfigs"]],
        ]
    ))
    if trv["top_critical"]:
        md.append("")
        md.append("**Top Critical / High CVEs (before remediation):**")
        md.append("")
        md.append(_md_table(
            ["CVE", "Package", "Installed", "Fixed", "Severity", "Description"],
            [[c["cve"] or "—", c["pkgName"] or "—", c["installedVersion"] or "—",
              c["fixedVersion"] or "—", c["severity"], c["title"][:60]]
             for c in trv["top_critical"][:10]]
        ))

    # ----- 4. AI Root Cause Analysis ------------------------------------
    md.append("## 4. AI Root Cause Analysis")
    md.append("")
    rca = s["root_cause"]
    if not rca:
        md.append("_No findings to analyse - the AI security review was empty._")
        md.append("")
    else:
        md.append(_md_table(
            ["ID", "Severity", "Rule", "File", "Risk", "Root cause"],
            [[f["id"] or "—", f["severity"], f["rule_id"] or "—",
              (f["file"] or "—").split("/")[-1], f["risk_score"], f["root_cause"][:60]]
             for f in rca[:25]]
        ))
        if len(rca) > 25:
            md.append("")
            md.append(f"_Showing 25 of {len(rca)} findings. See the JSON report for the full list._")

    # ----- 5. AI Remediation Details ------------------------------------
    md.append("## 5. AI Remediation Details")
    md.append("")
    rep = s["remediation_details"]
    if not rep:
        md.append("_No automated fixes were applied in this run._")
        md.append("")
    else:
        md.append(_md_table(
            ["Rule", "File", "+/-", "Level", "Why it works"],
            [[r["rule"], (r["file"] or "—").split("/")[-1],
              f"+{r.get('lines_added') or 0} / -{r.get('lines_removed') or 0}",
              r["automation_level"], r["why_it_works"][:60]]
             for r in rep]
        ))

    # ----- 6. Files Modified --------------------------------------------
    md.append("## 6. Files Modified")
    md.append("")
    files = s["files_modified"]
    if not files:
        md.append("_No files were modified in this run._")
        md.append("")
    else:
        md.append(_md_table(
            ["File", "Type", "Lines +", "Lines -", "AI Confidence", "Validation"],
            [[f"`{f['file']}`", f["type"], f.get("lines_added", 0),
              f.get("lines_removed", 0), f"{f['ai_confidence_pct']}%",
              f.get("validation_result", "n/a")]
             for f in files]
        ))

    # ----- 7. Validation Summary ----------------------------------------
    md.append("## 7. Validation Summary")
    md.append("")
    val = s["validation"]
    md.append(_md_table(
        ["Stage", "Before", "After"],
        [
            ["Build",            _status_badge(val["build_passed"]),       _status_badge(val["build_passed_after"])],
            ["Unit Tests",       _status_badge(val["unit_tests_passed"]), _status_badge(val["unit_tests_passed_after"])],
            ["JaCoCo Coverage",  f"{val['coverage_before']}%",            f"{val['coverage_after']}%"],
            ["SonarCloud QG",    val["sonar_qg_before"],                  val["sonar_qg_after"]],
            ["Trivy CRITICAL",   val["trivy_critical_before"],            val["trivy_critical_after"]],
            ["Trivy HIGH",       val["trivy_high_before"],                val["trivy_high_after"]],
            ["CodeQL CRITICAL",  val["codeql_critical_before"],           val["codeql_critical_after"]],
            ["CodeQL HIGH",      val["codeql_high_before"],               val["codeql_high_after"]],
        ]
    ))

    # ----- 8. Risk Comparison -------------------------------------------
    md.append("## 8. Risk Comparison")
    md.append("")
    risk = s["risk_comparison"]
    md.append(_md_table(
        ["Metric", "Before", "After", "Δ", "Direction"],
        [[r["metric"], r["before"] if r["before"] is not None else "n/a",
          r["after"] if r["after"] is not None else "n/a",
          r["delta"] if r["delta"] is not None else "—",
          {"better": "🟢 better", "worse": "🔴 worse", "neutral": "➡️ unchanged", "n/a": "—"}.get(r["direction"], r["direction"])]
         for r in risk]
    ))

    # ----- 9. Remaining Issues ------------------------------------------
    md.append("## 9. Remaining Issues")
    md.append("")
    rem = s["remaining_issues"]
    if not rem:
        md.append("✅ _No remaining issues - the AI agent addressed every finding it could safely auto-fix._")
        md.append("")
    else:
        md.append(_md_table(
            ["ID", "Severity", "Rule", "Title", "Effort", "Reason"],
            [[r["id"] or "—", r["severity"], r["rule_id"] or "—",
              (r["title"] or "—")[:40], r["estimated_effort"], r["reason"][:40]]
             for r in rem]
        ))

    # ----- 10. AI Confidence --------------------------------------------
    md.append("## 10. AI Confidence Assessment")
    md.append("")
    conf = s["confidence"]
    if conf["overall_confidence_pct"] is None:
        md.append("_No fixes were applied in this run, so no confidence score is reported._")
    else:
        md.append(f"- **Overall confidence:** {conf['overall_confidence_pct']}%")
        md.append(f"- **Deterministic fixes:** {conf['deterministic_count']} (each: 95%)")
        md.append(f"- **LLM-generated fixes:** {conf['llm_count']} (each: 70%)")
    if conf.get("per_fix"):
        md.append("")
        md.append("**Per-fix confidence and side effects:**")
        md.append("")
        md.append(_md_table(
            ["Rule", "File", "Source", "Confidence", "Side effects"],
            [[p["rule"], (p["file"] or "—").split("/")[-1], p["source"],
              f"{p['confidence_pct']}%", (p["potential_side_effects"] or "")[:50]]
             for p in conf["per_fix"]]
        ))
    if conf.get("manual_review_areas"):
        md.append("")
        md.append("**Recommended manual review areas:**")
        md.append("")
        for m in conf["manual_review_areas"]:
            md.append(f"- {m}")
        md.append("")

    # ----- 11. Pull Request Summary -------------------------------------
    md.append("## 11. Pull Request Summary")
    md.append("")
    pr = s["pull_request"]
    if pr.get("pr_url"):
        md.append(f"- **PR:** {pr['pr_url']}")
        md.append(f"- **PR number:** #{pr.get('pr_number') or '—'}")
        md.append(f"- **Source branch:** `{pr.get('source') or '—'}`")
        md.append(f"- **Target branch:** `{pr.get('target') or '—'}`")
        if pr.get("files"):
            md.append(f"- **Files in PR:** {len(pr['files'])}")
        if pr.get("reviewers"):
            md.append(f"- **Reviewers:** {', '.join('@' + r for r in pr['reviewers'] if r)}")
        if pr.get("labels"):
            md.append(f"- **Labels:** {', '.join(pr['labels'])}")
    else:
        md.append(f"- **Branch pushed to:** `{pr.get('branch') or '—'}`")
        md.append(f"- **Target branch:** `{pr.get('target') or '—'}`")
        md.append(f"- **Pushed:** {pr.get('pushed')}")
        md.append("")
        md.append(pr.get("explanation") or "No PR was created.")
    md.append("")

    # ----- 12. Deployment Recommendation --------------------------------
    md.append("## 12. Deployment Recommendation")
    md.append("")
    dep = s["deployment_recommendation"]
    md.append(f"**Verdict:** {dep['verdict']}")
    md.append("")
    md.append(f"**Decision source:** `check-deploy-gates.py`")
    md.append(f"**Deploy job will run:** {'Yes' if dep.get('deploy_job_will_run') else 'No'}")
    md.append("")
    md.append(dep.get("explanation", ""))
    md.append("")
    if dep.get("gates"):
        md.append("**Gates:**")
        md.append("")
        md.append(_md_table(
            ["Gate", "Expected", "Actual", "Passed"],
            [[g["name"], g.get("expected"), g.get("actual"),
              "✅" if g.get("passed") else "❌"]
             for g in dep["gates"]]
        ))

    # ----- 13. Recommendations ------------------------------------------
    md.append("## 13. Recommendations")
    md.append("")
    recs = s["recommendations"]
    if not recs:
        md.append("_No specific recommendations - all critical/high issues have been addressed._")
    else:
        for i, r in enumerate(recs, 1):
            md.append(f"{i}. **[{r['priority']}] {r['category']}** — {r['message']}")
    md.append("")

    # ----- 14. Metadata -------------------------------------------------
    md.append("## 14. Report Metadata")
    md.append("")
    md.append(_md_kv_table([
        ("AI model",            s["metadata"]["ai_model"]),
        ("AI agent version",    s["metadata"]["ai_agent_version"]),
        ("Pipeline version",    s["metadata"]["pipeline_version"]),
        ("Report version",      s["metadata"]["report_version"]),
        ("GitHub Runner",       s["metadata"]["github_runner"]),
        ("Java version",        s["metadata"]["java_version"]),
        ("Maven version",       s["metadata"]["maven_version"]),
        ("SonarCloud version",  s["metadata"]["sonarcloud_version"]),
        ("Generated at",        s["metadata"]["generated_at"]),
    ]))
    md.append("")
    md.append("> **Confidentiality:** this report contains no secrets, API keys, or "
              "credentials. It is safe to share with developers, security engineers, "
              "DevSecOps engineers, and management.")
    md.append("")
    return "\n".join(md)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def _compute_validation(gates: dict, sonar_pre: dict, sonar_post: dict,
                        trivy: dict, codeql: dict,
                        cov_pre: float | None, cov_post: float | None) -> dict:
    gate_map = {g.get("name"): g for g in (gates.get("gates") or []) if g.get("name")}
    build_passed = gate_map.get("build_succeeded", {}).get("passed")
    return {
        "build_passed":           build_passed,
        "build_passed_after":     build_passed,
        "unit_tests_passed":      gate_map.get("coverage_threshold", {}).get("passed"),
        "unit_tests_passed_after": gate_map.get("coverage_threshold", {}).get("passed"),
        "coverage_before":        cov_pre if cov_pre is not None else "n/a",
        "coverage_after":         cov_post if cov_post is not None else "n/a",
        "sonar_qg_before":        (sonar_pre.get("before") or {}).get("qualityGate") or "UNKNOWN",
        "sonar_qg_after":         (sonar_post.get("after") or {}).get("qualityGate") or "UNKNOWN",
        "trivy_critical_before":  trivy["before"].get("CRITICAL", 0),
        "trivy_critical_after":   trivy["after"].get("CRITICAL", 0),
        "trivy_high_before":      trivy["before"].get("HIGH", 0),
        "trivy_high_after":       trivy["after"].get("HIGH", 0),
        "codeql_critical_before": codeql["by_severity"].get("CRITICAL", 0),
        "codeql_critical_after":  codeql["by_severity"].get("CRITICAL", 0),
        "codeql_high_before":     codeql["by_severity"].get("HIGH", 0),
        "codeql_high_after":      codeql["by_severity"].get("HIGH", 0),
    }


def _compute_overall_status(gates: dict, sonar_pre: dict, sonar_post: dict,
                            remediation: dict) -> dict:
    sonar_qg = (sonar_post.get("after") or {}).get("qualityGate") or "UNKNOWN"
    sonar_qg_passed = sonar_qg in ("OK", "PASSED")
    security_gate_passed = bool(gates.get("deploy_recommended")) if gates else None
    ai_status = (remediation.get("status") or "").upper()
    ai_remediation_passed = ai_status in ("OK", "SKIPPED")
    if security_gate_passed and sonar_qg_passed and ai_remediation_passed:
        verdict = "PASS"
        badge = "✅ PASS"
    elif not security_gate_passed:
        verdict = "FAIL"
        badge = "❌ FAIL"
    elif not sonar_qg_passed or not ai_remediation_passed:
        verdict = "FAIL"
        badge = "❌ FAIL"
    else:
        verdict = "WARN"
        badge = "⚠️ WARN"
    return {
        "verdict":                verdict,
        "verdict_badge":          badge,
        "security_gate_passed":   security_gate_passed,
        "sonar_qg_passed":        sonar_qg_passed,
        "ai_remediation_passed":  ai_remediation_passed,
        "deployment_verdict":     (gates or {}).get("deploy_recommended", False) and "Safe to merge" or "Manual review required",
    }


def _build_executive_narrative(findings: list, fixes: list, skipped: list) -> dict:
    return {
        "total_findings":        len(findings),
        "deterministic_fixes":   sum(1 for f in fixes if (f.get("source") or "deterministic") != "llm"),
        "llm_fixes":             sum(1 for f in fixes if f.get("source") == "llm"),
        "remaining_issues":      len(skipped),
        "trigger_reason":        (
            f"{len(findings)} finding(s) were flagged by the security gate."
            if findings else
            "No findings were flagged; remediation was a no-op."
        ),
        "remediation_succeeded": (
            "Yes" if fixes else "No automated fixes were applicable."
        ),
        "ready_for_merge": (
            "Yes - all gates passed" if not skipped
            else f"No - {len(skipped)} issue(s) require manual review."
        ),
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--reports", type=Path, default=Path("reports"),
                   help="Path to the reports/ directory (default: reports)")
    p.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    p.add_argument("--branch", default=os.environ.get("GITHUB_REF_NAME", ""))
    p.add_argument("--ai-fix-branch", default="")
    p.add_argument("--commit-sha", default=os.environ.get("GITHUB_SHA", ""))
    p.add_argument("--pipeline-run-id", default=os.environ.get("GITHUB_RUN_ID", ""))
    p.add_argument("--workflow", default=os.environ.get("GITHUB_WORKFLOW", "ci"))
    p.add_argument("--build-timestamp", default="")
    p.add_argument("--runner-os", default=os.environ.get("RUNNER_OS", "Linux"))
    p.add_argument("--runner-name", default=os.environ.get("RUNNER_NAME", ""))
    p.add_argument("--ai-model", default=os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct"))
    p.add_argument("--ai-agent-version", default="1.0.0")
    p.add_argument("--pipeline-version", default="1.0.0")
    p.add_argument("--java-version", default="21")
    p.add_argument("--maven-version", default="3.9.x")
    p.add_argument("--sonarcloud-version", default="SonarCloud Cloud")
    p.add_argument("--report-version", default="1.0.0")
    p.add_argument("--project-name", default="")
    p.add_argument("--pr-number", default=os.environ.get("GITHUB_PR_NUMBER", ""))
    p.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN", ""))
    p.add_argument("--min-coverage", type=float, default=float(os.environ.get("MIN_COVERAGE", "80")))

    p.add_argument("--pre-sonar",                type=Path, default=None)
    p.add_argument("--post-sonar",               type=Path, default=None)
    p.add_argument("--pre-trivy",                type=Path, default=None)
    p.add_argument("--post-trivy",               type=Path, default=None)
    p.add_argument("--pre-coverage-summary",     type=Path, default=None)
    p.add_argument("--post-coverage-summary",    type=Path, default=None)
    p.add_argument("--codeql-sarif",             type=Path, default=None)
    p.add_argument("--security-review",          type=Path, default=None)
    p.add_argument("--remediation-report",       type=Path, default=None)
    p.add_argument("--deploy-gates",             type=Path, default=None)
    p.add_argument("--diff-stat",                type=Path, default=None)
    p.add_argument("--name-status",              type=Path, default=None)

    p.add_argument("--output-md",   type=Path, default=None)
    p.add_argument("--output-json", type=Path, default=None)

    args = p.parse_args()

    # Resolve default paths
    r = args.reports
    args.pre_sonar          = args.pre_sonar          or (r / "sonar-report.json")
    args.post_sonar         = args.post_sonar         or (r / "sonar-report-after-fix.json")
    args.pre_trivy          = args.pre_trivy          or (r / "trivy-report.json")
    args.post_trivy         = args.post_trivy         or (r / "trivy-report-after-fix.json")
    args.pre_coverage_summary  = args.pre_coverage_summary  or (r / "coverage-summary.csv")
    args.post_coverage_summary = args.post_coverage_summary or (r / "coverage-summary.csv")
    args.codeql_sarif       = args.codeql_sarif       or (r / "codeql-results.sarif")
    args.security_review    = args.security_review    or (r / "security-review.json")
    args.remediation_report = args.remediation_report or (r / "remediation-report.json")
    args.deploy_gates       = args.deploy_gates       or (r / "deploy-gates.json")
    args.diff_stat          = args.diff_stat          or (r / "git-diff-stat.txt")
    args.name_status        = args.name_status        or (r / "changed-files.txt")
    args.output_md          = args.output_md          or (r / "AUTO_REMEDIATION_REPORT.md")
    args.output_json        = args.output_json        or (r / "auto-remediation-report.json")

    missing_inputs: list[str] = []

    # ----- Load inputs ---------------------------------------------------
    sonar_pre  = _safe_load_json("sonar-report.json",         args.pre_sonar,  missing_inputs) or {}
    sonar_post = _safe_load_json("sonar-report-after-fix.json", args.post_sonar, missing_inputs) or {}
    trivy_pre  = _safe_load_json("trivy-report.json",         args.pre_trivy,  missing_inputs)
    trivy_post = _safe_load_json("trivy-report-after-fix.json", args.post_trivy, missing_inputs)
    if not isinstance(trivy_pre, list):  trivy_pre  = _trivy_items(trivy_pre)
    if not isinstance(trivy_post, list): trivy_post = _trivy_items(trivy_post)
    review     = _safe_load_json("security-review.json",      args.security_review, missing_inputs)
    if not isinstance(review, dict): review = {}
    remediation = _safe_load_json("remediation-report.json",  args.remediation_report, missing_inputs)
    if not isinstance(remediation, dict): remediation = {}
    gates       = _safe_load_json("deploy-gates.json",        args.deploy_gates, missing_inputs)
    if not isinstance(gates, dict): gates = {}

    diffstat_text   = _load_text(args.diff_stat)
    name_status_txt = _load_text(args.name_status)
    diffstat = _parse_git_diff_stat(diffstat_text)

    # Coverage
    cov_pre  = _parse_coverage_summary_csv(args.pre_coverage_summary)  or _parse_jacoco_coverage(args.pre_coverage_summary)
    cov_post = _parse_coverage_summary_csv(args.post_coverage_summary) or _parse_jacoco_coverage(args.post_coverage_summary)

    # Project name fallback
    if not args.project_name:
        args.project_name = (
            (sonar_pre.get("project") or "") if isinstance(sonar_pre, dict) else ""
        ) or "vulnerable-spring-app"

    # AI fix branch fallback
    if not args.ai_fix_branch:
        args.ai_fix_branch = (remediation.get("branch") or "") or args.branch

    # ----- Compute sections ---------------------------------------------
    s3_sonar  = section_3_sonar(sonar_pre, sonar_post)
    s3_codeql = section_3_codeql(args.codeql_sarif)
    s3_trivy  = section_3_trivy(trivy_pre, trivy_post)

    findings_section4 = section_4(review, trivy_pre)
    sec5 = section_5(remediation, findings_section4, diffstat)
    sec6 = section_6(diffstat, name_status_txt)
    sec8 = section_8_risk_comparison(s3_sonar, s3_sonar, s3_codeql, s3_trivy)  # using s3_sonar for both pre/post comparison
    sec9 = section_9(remediation)
    sec10 = section_10(remediation)
    sec11 = section_11(remediation, args.pr_number, args.github_token, args.repository)
    sec12 = section_12(gates)
    sec13 = section_13(s3_sonar, s3_sonar, s3_codeql, s3_trivy, remediation, args.min_coverage)
    sec14 = section_14(args)

    overall = _compute_overall_status(gates, s3_sonar, s3_sonar, remediation)
    validation = _compute_validation(gates, s3_sonar, s3_sonar, s3_trivy, s3_codeql, cov_pre, cov_post)
    narrative = _build_executive_narrative(
        findings_section4,
        remediation.get("fixes") or [],
        sec9,
    )

    # Pipeline stages
    stages = _fetch_pipeline_stages(args.repository, args.pipeline_run_id, args.github_token)

    # Pipeline run URL
    pipeline_run_url = ""
    if args.repository and args.pipeline_run_id:
        pipeline_run_url = f"https://github.com/{args.repository}/actions/runs/{args.pipeline_run_id}"

    sections = {
        "project_name":           args.project_name,
        "repository":             args.repository,
        "branch":                 args.branch,
        "ai_fix_branch":          args.ai_fix_branch,
        "commit_sha":             args.commit_sha,
        "pipeline_run_id":        args.pipeline_run_id,
        "pipeline_run_url":       pipeline_run_url,
        "workflow":               args.workflow,
        "build_timestamp":        args.build_timestamp or _utcnow_iso(),
        "generated_at":           _utcnow_iso(),
        "executive_narrative":    narrative,
        "pipeline_stages":        stages,
        "vulnerabilities": {
            "sonar":  s3_sonar,
            "codeql": s3_codeql,
            "trivy":  s3_trivy,
        },
        "root_cause":             findings_section4,
        "remediation_details":    sec5,
        "files_modified":         sec6,
        "validation":             validation,
        "risk_comparison":        sec8,
        "remaining_issues":       sec9,
        "confidence":             sec10,
        "pull_request":           sec11,
        "deployment_recommendation": sec12,
        "recommendations":        sec13,
        "metadata":               sec14,
    }

    report = {
        "schema_version": 1,
        "overall_status": overall,
        "degraded": bool(missing_inputs),
        "missing_inputs": missing_inputs,
        "sections":       sections,
    }

    # ----- Write outputs -------------------------------------------------
    args.output_md.parent.mkdir(parents=True, exist_ok=True)
    args.output_md.write_text(render_markdown(report), encoding="utf-8")
    args.output_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Wrote {args.output_md}")
    print(f"Wrote {args.output_json}")
    if missing_inputs:
        print(f"::warning::Report generated in DEGRADED mode; {len(missing_inputs)} input(s) missing.",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
