#!/usr/bin/env python3
"""
generate-sonar-report.py

Calls the SonarCloud Web API after a `mvn sonar:sonar` analysis and writes:

  <output-dir>/sonar-report.json  - machine-readable report (flat top-level
                                   fields per the pipeline brief, with a
                                   `raw` block carrying the original
                                   metrics/issues for backward compat)
  <output-dir>/SONAR_REPORT.md    - human-readable markdown report
                                   (Project Name, Branch, Commit SHA,
                                   Analysis Date, QG status, coverage,
                                   bugs, vulnerabilities, code smells,
                                   security hotspots, ratings, technical
                                   debt, summary, recommendations)
  <output-dir>/sonar-report.txt   - plain-text summary (kept for the
                                   AI Security Review agent which
                                   embeds it into its prompt)

Endpoints queried:
  GET /api/components/show?component={KEY}                (project display name)
  GET /api/project_analyses/search?project={KEY}&ps=1     (latest analysis date)
  GET /api/qualitygates/project_status?projectKey={KEY}   (quality gate status)
  GET /api/measures/component?component={KEY}&metricKeys=...  (metrics)
  GET /api/issues/search?projectKeys={KEY}&types=...&ps=...&p=...  (issues)

Note: the per-severity issue counts (`overallIssueCounts`) are computed
in-process from the issues list itself (`_counts_from_findings`), not
from a separate API call. This guarantees `overallIssueCounts.total`
equals `len(raw.issues)` and that the severity breakdown sums to the
total — the two cannot drift apart as they did when both endpoints
were queried with different filters.

Required env:
  SONAR_TOKEN         - SonarCloud account token
  SONAR_HOST_URL      - e.g. https://sonarcloud.io
  SONAR_PROJECT_KEY   - the project key

Optional env / flags:
  --branch            (default: $GITHUB_REF_NAME)  used in SONAR_REPORT.md
  --commit            (default: $GITHUB_SHA)       used in SONAR_REPORT.md
  PAGE_SIZE           (default 500)
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_RANK = {"BLOCKER": 5, "CRITICAL": 4, "MAJOR": 3, "MINOR": 2, "INFO": 1}

# Metric keys for the bulk /api/measures/component call. Includes both
# "current" and "new_*" versions so the flat schema and the newIssues
# block are both populated from a single API call.
METRICS = (
    # current / overall
    "bugs,vulnerabilities,security_hotspots,code_smells,"
    "duplicated_lines_density,coverage,reliability_rating,security_rating,"
    "maintainability_rating,technical_debt,open_issues,"
    # new (leak-period)
    "new_bugs,new_vulnerabilities,new_security_hotspots,new_code_smells,"
    "new_coverage"
)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
# SonarCloud briefly returns 404 on /api/measures/component and /api/issues/search
# while the server is still processing the analysis report that was just
# uploaded. Retrying with exponential backoff rides out the processing window
# without the caller needing to know about it. The QG step already waits for
# analysis processing to complete, so retries here are a safety net for the
# small lag between QG finishing and the Web API being readable. Tuned for
# typical 1-3 retries over a few seconds; total worst-case wait per call is
# 1 + 2 + 4 = 7s (1 + 2 + 4 = 7, capped at 5s per step) so the full six-endpoint
# report can't hang the step for more than a minute.
_DEFAULT_MAX_ATTEMPTS = 4
_DEFAULT_INITIAL_BACKOFF_S = 1.0
_DEFAULT_BACKOFF_CAP_S = 5.0


def _http_get_json(
    url: str,
    token: str,
    *,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    initial_backoff_s: float = _DEFAULT_INITIAL_BACKOFF_S,
    backoff_cap_s: float = _DEFAULT_BACKOFF_CAP_S,
    retry_on: tuple = (404, 400, 500, 502, 503, 504),
) -> dict | None:
    """GET a SonarCloud API endpoint and return JSON, or None on failure.

    Retries with exponential backoff for any HTTP status in `retry_on`
    (default: 404/400/5xx — the codes SonarCloud returns while still
    processing an analysis report, or under transient load). Non-retried
    failures (auth, 4xx other than 400/404) return None on the first try.
    """
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")

    backoff = initial_backoff_s
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            last_exc = exc
            if exc.code not in retry_on or attempt == max_attempts:
                print(
                    f"WARN: GET {url} failed: HTTP {exc.code} {exc.reason} "
                    f"(attempt {attempt}/{max_attempts})",
                    file=sys.stderr,
                )
                return None
            print(
                f"INFO: GET {url} -> HTTP {exc.code} (attempt {attempt}/"
                f"{max_attempts}); retrying in {backoff:.1f}s",
                file=sys.stderr,
            )
        except Exception as exc:  # noqa: BLE001
            # Network / DNS / timeout — also worth retrying.
            last_exc = exc
            if attempt == max_attempts:
                print(
                    f"WARN: GET {url} failed: {exc} "
                    f"(attempt {attempt}/{max_attempts})",
                    file=sys.stderr,
                )
                return None
            print(
                f"INFO: GET {url} -> {exc} (attempt {attempt}/"
                f"{max_attempts}); retrying in {backoff:.1f}s",
                file=sys.stderr,
            )
        time.sleep(backoff)
        backoff = min(backoff * 2.0, backoff_cap_s)
    if last_exc is not None:
        print(f"WARN: GET {url} gave up after {max_attempts} attempts: {last_exc}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Web API fetchers
# ---------------------------------------------------------------------------
def fetch_project_info(host: str, project_key: str, token: str) -> dict:
    """Return {"key": ..., "name": ...} for the project, or {} on failure.

    Uses /api/components/show?component=KEY (the display name lives at
    `.component.name` in the response).
    """
    data = _http_get_json(
        f"{host}/api/components/show?component={urllib.parse.quote(project_key, safe='')}",
        token,
    )
    if not data:
        return {}
    component = data.get("component") or {}
    return {
        "key": component.get("key", project_key),
        "name": component.get("name", project_key),
    }


def fetch_latest_analysis(host: str, project_key: str, token: str) -> str:
    """Return the ISO 8601 timestamp of the most recent analysis, or '' on failure.

    Uses /api/project_analyses/search?project=KEY&ps=1 and returns
    `.analyses[0].date`.
    """
    data = _http_get_json(
        f"{host}/api/project_analyses/search?project={urllib.parse.quote(project_key, safe='')}&ps=1",
        token,
    )
    if not data:
        return ""
    analyses = data.get("analyses") or []
    if not analyses:
        return ""
    return analyses[0].get("date", "") or ""


def fetch_quality_gate(host: str, project_key: str, token: str) -> str:
    data = _http_get_json(
        f"{host}/api/qualitygates/project_status?projectKey={urllib.parse.quote(project_key, safe='')}",
        token,
    )
    if data:
        return (data.get("projectStatus", {}) or {}).get("status", "ERROR")
    return "UNKNOWN"


def fetch_measures(host: str, project_key: str, token: str) -> dict:
    data = _http_get_json(
        f"{host}/api/measures/component?component={urllib.parse.quote(project_key, safe='')}&metricKeys={METRICS}",
        token,
    )
    out: dict = {}
    if data:
        for item in (data.get("component", {}) or {}).get("measures", []) or []:
            metric = item.get("metric")
            if metric:
                out[metric] = item.get("value", item.get("bestValue"))
    return out


# Shared filter string for the /api/issues/search endpoint. Used by
# `fetch_issues` so the per-severity counts (derived in-process from the
# returned issues list) match exactly what the issues page returns. Adding
# this filter to overall counts previously fixed a bug where the separate
# facets endpoint silently included issues the issues page had dropped.
ISSUE_TYPE_FILTER = "VULNERABILITY,CODE_SMELL,BUG,SECURITY_HOTSPOT"


def fetch_issues(host: str, project_key: str, token: str, page_size: int) -> list:
    issues: list = []
    for page in range(1, 10):  # 10 pages * 500 = 5000 issues cap
        url = (
            f"{host}/api/issues/search"
            f"?projectKeys={urllib.parse.quote(project_key, safe='')}"
            f"&types={ISSUE_TYPE_FILTER}"
            f"&ps={page_size}&p={page}"
        )
        data = _http_get_json(url, token)
        if not data:
            break
        batch = data.get("issues", []) or []
        if not batch:
            break
        issues.extend(batch)
        if len(batch) < page_size:
            break
    return issues


def _rename_counts(c: dict) -> dict:
    """Map the API's uppercase severity keys to camelCase for the JSON output."""
    return {
        "total": c.get("total", 0),
        "blocker": c.get("BLOCKER", 0),
        "critical": c.get("CRITICAL", 0),
        "major": c.get("MAJOR", 0),
        "minor": c.get("MINOR", 0),
        "info": c.get("INFO", 0),
    }


def _counts_from_findings(findings: list) -> dict:
    """Compute the overall severity counts directly from the findings list.

    Used in place of `fetch_overall_counts` to guarantee that the
    `overallIssueCounts.total` matches `len(raw.issues)` and that the
    severity breakdown sums to the total. The two numbers can never
    disagree because they're derived from the same in-memory list.
    """
    counts = {"total": 0, "BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if sev in counts:
            counts[sev] += 1
        counts["total"] += 1
    return _rename_counts(counts)


# ---------------------------------------------------------------------------
# Issue normalisation
# ---------------------------------------------------------------------------
def _issue_to_finding(it: dict) -> dict:
    component = it.get("component", "") or ""
    file_path = component.split(":", 1)[1] if ":" in component else component
    return {
        "key": it.get("key"),
        "rule": it.get("rule"),
        "severity": (it.get("severity") or "INFO").upper(),
        "type": it.get("type"),
        "status": it.get("status"),
        "message": it.get("message", ""),
        "file": file_path,
        "line": it.get("line"),
        "project": it.get("project"),
        "creationDate": it.get("creationDate"),
        "updateDate": it.get("updateDate"),
        "tags": it.get("tags", []) or [],
    }


# ---------------------------------------------------------------------------
# Reshape: nested metrics -> brief's flat schema
# ---------------------------------------------------------------------------
def _to_int(v) -> int:
    try:
        return int(v) if v is not None else 0
    except (TypeError, ValueError):
        return 0


def _to_float(v) -> float | None:
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def reshape_report(
    project_key: str,
    project_name: str,
    analysis_date: str,
    qg_status: str,
    metrics: dict,
    findings: list,
    overall_counts: dict,
) -> dict:
    """Build the JSON the pipeline's brief asks for.

    Top-level fields match the example in the brief. The original nested
    `metrics` and `issues` are kept under a `raw` block so downstream
    consumers that read `metrics.coverage` etc. keep working.
    """
    flat = {
        "schemaVersion": 2,
        "status": "OK",
        # Identity
        "project": project_name or project_key,
        "projectKey": project_key,
        "host": None,  # filled in by main()
        "branch": None,  # filled in by main()
        "commit": None,  # filled in by main()
        "analysisDate": analysis_date or None,
        "qualityGate": qg_status,
        # Bug/vuln/smell/hotspot counts (current)
        "bugs": _to_int(metrics.get("bugs")),
        "vulnerabilities": _to_int(metrics.get("vulnerabilities")),
        "codeSmells": _to_int(metrics.get("code_smells")),
        "securityHotspots": _to_int(metrics.get("security_hotspots")),
        # Coverage and quality metrics
        "coverage": _to_float(metrics.get("coverage")),
        "duplicatedLines": _to_float(metrics.get("duplicated_lines_density")),
        "technicalDebt": metrics.get("technical_debt"),
        # Ratings (A=1 best, E=5 worst). Sonar stores as "1".."5" strings.
        "reliabilityRating": metrics.get("reliability_rating"),
        "securityRating": metrics.get("security_rating"),
        "maintainabilityRating": metrics.get("maintainability_rating"),
        # New issues (leak period)
        "newIssues": {
            "bugs": _to_int(metrics.get("new_bugs")),
            "vulnerabilities": _to_int(metrics.get("new_vulnerabilities")),
            "codeSmells": _to_int(metrics.get("new_code_smells")),
            "securityHotspots": _to_int(metrics.get("new_security_hotspots")),
        },
        # Overall issue counts (all severities)
        "overallIssueCounts": overall_counts,
        # Backward-compat: the original nested structure.
        "raw": {
            "metrics": metrics,
            "issues": findings,
        },
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return flat


# ---------------------------------------------------------------------------
# Plain-text summary (used by ai-security-review.py)
# ---------------------------------------------------------------------------
def write_text_summary(findings: list, metrics: dict, qg_status: str, path: Path) -> None:
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1

    lines: list[str] = [
        "SonarCloud Issue Summary",
        "========================",
        "",
        f"Quality Gate : {qg_status}",
        f"Bugs         : {metrics.get('bugs', 'N/A')}",
        f"Vulnerabilities: {metrics.get('vulnerabilities', 'N/A')}",
        f"Security Hotspots: {metrics.get('security_hotspots', 'N/A')}",
        f"Code Smells  : {metrics.get('code_smells', 'N/A')}",
        f"Coverage     : {metrics.get('coverage', 'N/A')}%",
        f"Duplication  : {metrics.get('duplicated_lines_density', 'N/A')}%",
        f"Tech Debt    : {metrics.get('technical_debt', 'N/A')}",
        "",
        f"Total issues exported: {len(findings)}",
        "By severity:",
    ]
    for sev in sorted(by_sev, key=lambda s: SEVERITY_RANK.get(s, 0), reverse=True):
        lines.append(f"  {sev:9s} {by_sev[sev]}")
    lines.append("")
    lines.append("Top issues (sorted by severity, then by file):")
    lines.append("----------------------------------------------")
    sorted_findings = sorted(
        findings,
        key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f.get("file") or "", f.get("line") or 0),
    )
    for f in sorted_findings[:50]:
        where = f["file"]
        if f.get("line"):
            where = f"{where}:{f['line']}"
        lines.append(
            f"[{f['severity']:8s}] {f['type']:18s} {f.get('rule', ''):30s} {where}"
        )
        if f.get("message"):
            lines.append(f"            -> {f['message'][:120]}")
    if len(sorted_findings) > 50:
        lines.append("")
        lines.append(f"... and {len(sorted_findings) - 50} more (see sonar-report.json)")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Markdown report (SONAR_REPORT.md)
# ---------------------------------------------------------------------------
def _rating_emoji(rating: str | None) -> str:
    if not rating:
        return "N/A"
    return {"1": "🟢 A", "2": "🟢 B", "3": "🟡 C", "4": "🟠 D", "5": "🔴 E"}.get(
        str(rating), str(rating)
    )


def _qg_badge(status: str) -> str:
    s = (status or "UNKNOWN").upper()
    if s == "OK" or s == "PASSED":
        return f"✅ **{s}**"
    if s in {"FAILED", "ERROR"}:
        return f"❌ **{s}**"
    return f"⚠️ **{s}**"


def _recommendations(report: dict) -> list[str]:
    """Static heuristic recommendations based on the report's numbers.

    Kept deterministic (no LLM call) so the MD report renders even when
    NVIDIA_API_KEY is missing.
    """
    recs: list[str] = []
    new_v = (report.get("newIssues") or {}).get("vulnerabilities", 0) or 0
    vulns = report.get("vulnerabilities", 0) or 0
    cov = report.get("coverage")
    hotspots = report.get("securityHotspots", 0) or 0
    code_smells = report.get("codeSmells", 0) or 0
    dupl = report.get("duplicatedLines")
    qg = (report.get("qualityGate") or "").upper()

    if qg in {"FAILED", "ERROR"}:
        recs.append(f"Quality gate **{qg}** — review the metrics below and address every failing condition before deploying.")
    if new_v > 0:
        recs.append(f"Address all **{new_v}** new vulnerabilities introduced since the last analysis.")
    elif vulns > 0:
        recs.append(f"Address all **{vulns}** open vulnerabilities before deploying.")
    if cov is not None and cov < 80.0:
        recs.append(f"Increase line coverage to at least 80% (currently {cov}%).")
    if hotspots > 0:
        recs.append(f"Review and resolve the **{hotspots}** open security hotspots.")
    if code_smells > 50:
        recs.append(f"Refactor to reduce technical debt (currently {code_smells} code smells).")
    if dupl is not None and dupl > 3.0:
        recs.append(f"Reduce duplicated lines (currently {dupl}%).")
    rel = report.get("reliabilityRating")
    sec = report.get("securityRating")
    if rel in {"4", "5"}:
        recs.append(f"Reliability rating is **{rel}** — address all Blocker/Critical bugs.")
    if sec in {"4", "5"}:
        recs.append(f"Security rating is **{sec}** — address all open security hotspots and vulnerabilities.")
    if not recs:
        recs.append("No outstanding recommendations. The codebase is within policy thresholds.")
    return recs


def write_markdown_summary(
    report: dict, branch: str, commit: str, path: Path
) -> None:
    """Render SONAR_REPORT.md with the sections the brief asks for."""
    qg = report.get("qualityGate", "UNKNOWN")
    new_issues = report.get("newIssues") or {}
    counts = report.get("overallIssueCounts") or {}

    def _fmt_pct(v) -> str:
        return f"{v}%" if v is not None else "N/A"

    def _fmt_num(v) -> str:
        return "N/A" if v is None else str(v)

    lines: list[str] = [
        f"# SonarCloud Report — {report.get('project', report.get('projectKey', 'unknown'))}",
        "",
        f"**Project:** {report.get('project', 'N/A')}  ",
        f"**Project Key:** `{report.get('projectKey', 'N/A')}`  ",
        f"**Branch:** `{branch or 'N/A'}`  ",
        f"**Commit SHA:** `{commit or 'N/A'}`  ",
        f"**Analysis Date:** {report.get('analysisDate') or 'N/A'}  ",
        f"**Quality Gate Status:** {_qg_badge(qg)}  ",
        "",
        "## Quality Gate Status",
        "",
        f"The SonarCloud quality gate is **{qg}**.",
        "",
        "## Coverage",
        "",
        f"- **Line coverage:** {_fmt_pct(report.get('coverage'))}",
        f"- **Duplicated lines:** {_fmt_pct(report.get('duplicatedLines'))}",
        "",
        "## Issues",
        "",
        "| Metric | Current | New (leak period) |",
        "|---|---:|---:|",
        f"| Bugs | {_fmt_num(report.get('bugs'))} | {_fmt_num(new_issues.get('bugs'))} |",
        f"| Vulnerabilities | {_fmt_num(report.get('vulnerabilities'))} | {_fmt_num(new_issues.get('vulnerabilities'))} |",
        f"| Code Smells | {_fmt_num(report.get('codeSmells'))} | {_fmt_num(new_issues.get('codeSmells'))} |",
        f"| Security Hotspots | {_fmt_num(report.get('securityHotspots'))} | {_fmt_num(new_issues.get('securityHotspots'))} |",
        "",
        f"**Overall issue counts:** "
        f"total `{_fmt_num(counts.get('total'))}`, "
        f"blocker `{_fmt_num(counts.get('blocker'))}`, "
        f"critical `{_fmt_num(counts.get('critical'))}`, "
        f"major `{_fmt_num(counts.get('major'))}`, "
        f"minor `{_fmt_num(counts.get('minor'))}`, "
        f"info `{_fmt_num(counts.get('info'))}`.",
        "",
        "## Ratings",
        "",
        "| Dimension | Rating |",
        "|---|---|",
        f"| Reliability | {_rating_emoji(report.get('reliabilityRating'))} |",
        f"| Security | {_rating_emoji(report.get('securityRating'))} |",
        f"| Maintainability | {_rating_emoji(report.get('maintainabilityRating'))} |",
        "",
        "## Technical Debt",
        "",
        f"- **Technical debt:** {_fmt_num(report.get('technicalDebt'))} (minutes)",
        "",
        "## Summary",
        "",
        (
            f"This SonarCloud Cloud analysis scanned **{report.get('project', 'N/A')}** "
            f"on branch `{branch or 'N/A'}` at commit `{commit or 'N/A'}`. "
            f"The quality gate is **{qg}**, line coverage is "
            f"**{_fmt_pct(report.get('coverage'))}**, with "
            f"**{_fmt_num(report.get('vulnerabilities'))}** vulnerabilities, "
            f"**{_fmt_num(report.get('bugs'))}** bugs, "
            f"**{_fmt_num(report.get('codeSmells'))}** code smells, and "
            f"**{_fmt_num(report.get('securityHotspots'))}** security hotspots."
        ),
        "",
        "## Recommendations",
        "",
    ]
    for r in _recommendations(report):
        lines.append(f"- {r}")
    lines.append("")
    lines.append("---")
    lines.append(
        f"_Report generated at {report.get('generatedAt', '')}._  "
        f"_See `sonar-report.json` for the full machine-readable payload._"
    )
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Stub (no token) — writes both the new JSON and the new MD
# ---------------------------------------------------------------------------
def _write_stub(output_dir: Path, host: str, project_key: str, branch: str, commit: str) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    stub_flat = {
        "schemaVersion": 2,
        "status": "SKIPPED",
        "project": project_key or "(unknown)",
        "projectKey": project_key,
        "host": host,
        "branch": branch,
        "commit": commit,
        "analysisDate": None,
        "qualityGate": "UNKNOWN",
        "bugs": 0,
        "vulnerabilities": 0,
        "codeSmells": 0,
        "securityHotspots": 0,
        "coverage": None,
        "duplicatedLines": None,
        "technicalDebt": None,
        "reliabilityRating": None,
        "securityRating": None,
        "maintainabilityRating": None,
        "newIssues": {"bugs": 0, "vulnerabilities": 0, "codeSmells": 0, "securityHotspots": 0},
        "overallIssueCounts": {"total": 0, "blocker": 0, "critical": 0, "major": 0, "minor": 0, "info": 0},
        "raw": {"metrics": {}, "issues": []},
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (output_dir / "sonar-report.json").write_text(
        json.dumps(stub_flat, indent=2), encoding="utf-8"
    )
    (output_dir / "sonar-report.txt").write_text(
        "SonarCloud report skipped (missing SONAR_TOKEN or SONAR_PROJECT_KEY)\n",
        encoding="utf-8",
    )
    write_markdown_summary(stub_flat, branch, commit, output_dir / "SONAR_REPORT.md")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output-dir", required=True, type=Path)
    p.add_argument("--host", default=os.environ.get("SONAR_HOST_URL", "https://sonarcloud.io"))
    p.add_argument("--project-key", default=os.environ.get("SONAR_PROJECT_KEY", ""))
    p.add_argument("--token", default=os.environ.get("SONAR_TOKEN", ""))
    p.add_argument("--branch", default=os.environ.get("GITHUB_REF_NAME", ""))
    p.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    p.add_argument("--page-size", type=int, default=int(os.environ.get("PAGE_SIZE", "500")))
    args = p.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.token or not args.project_key:
        print("WARN: SONAR_TOKEN or SONAR_PROJECT_KEY not set; writing stub report.", file=sys.stderr)
        return _write_stub(args.output_dir, args.host, args.project_key, args.branch, args.commit)

    print(f"Fetching SonarCloud data for {args.project_key} from {args.host}", file=sys.stderr)
    project_info = fetch_project_info(args.host, args.project_key, args.token)
    analysis_date = fetch_latest_analysis(args.host, args.project_key, args.token)
    qg_status = fetch_quality_gate(args.host, args.project_key, args.token)
    metrics = fetch_measures(args.host, args.project_key, args.token)
    issues = fetch_issues(args.host, args.project_key, args.token, args.page_size)
    # Derive overall counts from the issues list itself. This makes the
    # counts and the issues list guaranteed-consistent (single source of
    # truth). Previously we called /api/issues/search?facets=severities
    # separately, which could disagree with the issues list when the API
    # silently dropped rows (e.g. on branches with a different rule set).
    findings = [_issue_to_finding(it) for it in issues]
    findings.sort(
        key=lambda f: (-SEVERITY_RANK.get(f["severity"], 0), f.get("file") or "", f.get("line") or 0)
    )
    overall_counts = _counts_from_findings(findings)

    flat = reshape_report(
        project_key=args.project_key,
        project_name=project_info.get("name", args.project_key),
        analysis_date=analysis_date,
        qg_status=qg_status,
        metrics=metrics,
        findings=findings,
        overall_counts=overall_counts,
    )
    flat["host"] = args.host
    flat["branch"] = args.branch
    flat["commit"] = args.commit

    (args.output_dir / "sonar-report.json").write_text(
        json.dumps(flat, indent=2), encoding="utf-8"
    )
    write_text_summary(findings, metrics, qg_status, args.output_dir / "sonar-report.txt")
    write_markdown_summary(flat, args.branch, args.commit, args.output_dir / "SONAR_REPORT.md")

    print(
        f"Wrote {len(findings)} issues to {args.output_dir}/sonar-report.json "
        f"and SONAR_REPORT.md",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
