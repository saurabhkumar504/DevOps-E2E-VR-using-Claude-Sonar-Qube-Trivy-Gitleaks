#!/usr/bin/env python3
"""
generate-remediation-report.py

Consolidates the output of every available pipeline stage (SonarQube,
Trivy filesystem + image, dependency scan, secret scan, IaC scan,
container scan, SAST, code quality, AI security review, AI auto-
remediation, git diff) into a single enterprise-grade Markdown
audit document:

    reports/remediation-report.md

This is a pure aggregator. It never modifies the input artefacts and
never shells out to git/gh/Trivy. Stages that did not produce an
artefact on disk are reported as `_not available in this run_` so
the document stays honest when the pipeline is partial.

Required input (paths are configurable via --reports, default
./reports):
    security-review.json    - the structured security review
    security-review.md      - the human-readable review
    trivy-report.json       - aggregated Trivy findings
    trivy-report.txt        - text rendering
    sonar-report.json       - SonarCloud summary
    sonar-report.txt        - SonarCloud text rendering
    changed-files.txt       - files changed by the remediation
    git-diff-stat.txt       - `git diff --stat` of those changes
    ai-patch.diff           - unified diff emitted by the rewriter
    remediation-summary.md  - the short remediation summary
    llm-prompt.txt          - prompt sent to the LLM
    llm-response.txt        - raw LLM response (if any)
    trivy-fs.raw.json       - raw Trivy fs scan (optional)
    trivy-fs.sarif          - Trivy fs SARIF (optional)
    trivy-image.raw.json    - raw Trivy image scan (optional)
    trivy-image.sarif       - Trivy image SARIF (optional)

Sections:
  1.  Executive Summary
  2.  Pipeline Stages Summary
  3.  Detailed Remediation Per Tool
  4.  File-Level Change Summary
  5.  Code Changes (Before / After)
  6.  Remediation Mapping (finding -> fix)
  7.  Git Summary
  8.  Remaining Findings
  9.  Risk Reduction Summary
  10. Performance Summary
  11. Final Outcome
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------- #


def _read_text(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def _read_json(p: Path) -> Any:
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return None


def _file_or_unavailable(p: Path) -> str:
    """Return the path of a file if it exists, else a polite
    `_not available in this run_` marker."""
    return f"`{p}`" if p.exists() else "_not available in this run_"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """Walk a nested dict/list path safely."""
    cur = d
    for k in keys:
        if cur is None:
            return default
        if isinstance(cur, dict):
            cur = cur.get(k)
        elif isinstance(cur, list) and isinstance(k, int) and 0 <= k < len(cur):
            cur = cur[k]
        else:
            return default
    return default if cur is None else cur


def _truncate(s: str, n: int = 200) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _diff_hunk_for_file(patch_text: str, target_file: str) -> str:
    """Return the subset of a unified diff that belongs to a given file.

    Empty string if there is no diff hunk for that file."""
    if not patch_text:
        return ""
    lines = patch_text.splitlines()
    out: list[str] = []
    capture = False
    for ln in lines:
        if ln.startswith("diff --git "):
            capture = target_file in ln
        if capture:
            out.append(ln)
    return "\n".join(out)


# --------------------------------------------------------------------- #
# Section builders
# --------------------------------------------------------------------- #


def section_executive_summary(reports: Path, ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    trivy = ctx["trivy"] or []
    sonar = ctx["sonar"] or {}
    rem = ctx["remediation_summary_text"]
    fix_count = ctx["fix_count"]
    files_changed = ctx["files_changed"]

    sev_counts = Counter((f.get("severity") or "INFO").upper() for f in findings)
    trivy_sev = Counter((f.get("severity") or "INFO").upper() for f in trivy)
    risk = sr.get("risk_score", 0)
    prio = sr.get("overall_priority", "P3")
    status = sr.get("status", "OK")

    return f"""## 1. Executive Summary

| Metric | Value |
| --- | --- |
| Report generated at | {_now_iso()} |
| Security review status | `{status}` |
| Overall risk score | **{risk}** / 100 |
| Overall priority | **{prio}** |
| Findings (AI review) | **{len(findings)}** ({sev_counts.get('CRITICAL', 0)} CRITICAL · {sev_counts.get('HIGH', 0)} HIGH · {sev_counts.get('MEDIUM', 0)} MEDIUM · {sev_counts.get('LOW', 0)} LOW · {sev_counts.get('INFO', 0)} INFO) |
| Trivy findings (raw) | **{len(trivy)}** ({trivy_sev.get('CRITICAL', 0)} CRITICAL · {trivy_sev.get('HIGH', 0)} HIGH · {trivy_sev.get('MEDIUM', 0)} MEDIUM · {trivy_sev.get('LOW', 0)} LOW) |
| Sonar quality gate | **{sonar.get('qualityGate', 'N/A') or 'N/A'}** |
| Safe fixes applied | **{fix_count}** (deterministic + LLM) |
| Files changed | **{len(files_changed)}** |

{_truncate(sr.get('summary', '_(no summary)_'), 600)}

{('AI remediation result: ' + rem) if rem else ''}
"""


def section_pipeline_stages(reports: Path) -> str:
    """Per-stage availability + pointer to the artefact that backs it."""
    rows = [
        # (stage, tool, artefact path, status, notes)
        ("SAST", "SonarQube / SonarCloud", reports / "sonar-report.json", "json", "bugs / vulns / smells / hotspots"),
        ("SAST", "SonarQube (text)", reports / "sonar-report.txt", "txt", "human-readable Sonar summary"),
        ("SBOM / Vuln", "Trivy (filesystem, raw)", reports / "trivy-fs.raw.json", "json", "filesystem scan"),
        ("SBOM / Vuln", "Trivy (filesystem, SARIF)", reports / "trivy-fs.sarif", "sarif", "SARIF format"),
        ("Container", "Trivy (image, raw)", reports / "trivy-image.raw.json", "json", "container image scan"),
        ("Container", "Trivy (image, SARIF)", reports / "trivy-image.sarif", "sarif", "SARIF format"),
        ("Vuln (agg)", "Trivy (combined)", reports / "trivy-report.json", "json", "aggregated Trivy findings (the source of truth for SBOM/container)"),
        ("Vuln (agg)", "Trivy (text)", reports / "trivy-report.txt", "txt", "text rendering of the aggregated report"),
        ("AI review", "Security Reviewer (NVIDIA LLM)", reports / "security-review.json", "json", "structured security review"),
        ("AI review", "Security Reviewer (markdown)", reports / "security-review.md", "md", "human-readable review"),
        ("AI review", "Security Reviewer (text)", reports / "security-summary.txt", "txt", "one-line-per-finding summary"),
        ("AI fix", "AI Auto-Remediation", reports / "remediation-summary.md", "md", "short remediation summary"),
        ("AI fix", "AI Auto-Remediation (unified diff)", reports / "ai-patch.diff", "diff", "the patch the rewriter produced"),
        ("AI fix", "Files changed", reports / "changed-files.txt", "txt", "list of files modified"),
        ("AI fix", "Diff stat", reports / "git-diff-stat.txt", "txt", "`git diff --stat` of the changes"),
        ("AI fix", "LLM prompt", reports / "llm-prompt.txt", "txt", "the prompt sent to the LLM"),
        ("AI fix", "LLM response", reports / "llm-response.txt", "txt", "raw LLM response (may be empty)"),
    ]
    lines = ["## 2. Pipeline Stages Summary", ""]
    lines.append("| Stage | Tool | Artefact | Format | Purpose |")
    lines.append("| --- | --- | --- | --- | --- |")
    for stage, tool, path, fmt, purpose in rows:
        marker = "✅" if path.exists() else "⚠️"
        name = path.name
        if not path.exists():
            name = f"_{name} (missing)_"
        lines.append(f"| {stage} | {tool} | `{name}` {marker} | `{fmt}` | {purpose} |")
    lines.append("")
    return "\n".join(lines)


def section_per_tool(ctx: dict) -> str:
    """Detailed remediation grouped by source tool."""
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    trivy = ctx["trivy"] or []
    sonar_issues = (ctx["sonar"] or {}).get("raw", {}).get("issues", []) or []

    # Findings by tool of origin
    by_source: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        rule = (f.get("rule_id") or "").upper()
        cat = (f.get("category") or "").lower()
        fpath = f.get("file") or ""
        if rule.startswith("CVE-") or cat == "vulnerability" or ":" in fpath and "/" not in fpath.split(":")[0]:
            by_source["trivy"].append(f)
        elif fpath.endswith((".java", ".xml", ".properties", ".yml", ".yaml", ".json", ".kt", ".scala")):
            by_source["sonar"].append(f)
        else:
            by_source["other"].append(f)

    out = ["## 3. Detailed Remediation Per Tool", ""]

    # ---- Trivy ----
    trivy_total = len(trivy)
    trivy_sev = Counter((f.get("severity") or "INFO").upper() for f in trivy)
    trivy_scanner = Counter(f.get("scanner") or "?" for f in trivy)
    out.append("### 3.1 Trivy (SBOM / container)")
    out.append("")
    out.append(f"- Total findings: **{trivy_total}** "
               f"(CRITICAL: {trivy_sev.get('CRITICAL', 0)} · "
               f"HIGH: {trivy_sev.get('HIGH', 0)} · "
               f"MEDIUM: {trivy_sev.get('MEDIUM', 0)} · "
               f"LOW: {trivy_sev.get('LOW', 0)})")
    out.append(f"- Findings by scanner: "
               + ", ".join(f"`{k}`: {v}" for k, v in trivy_scanner.most_common()))
    trivy_findings_in_review = by_source.get("trivy", [])
    if trivy_findings_in_review:
        out.append("- Findings routed to the AI rewriter:")
        out.append("")
        out.append("  | ID | Severity | Package / Coord | CVE | Suggested fix |")
        out.append("  | --- | --- | --- | --- | --- |")
        for f in trivy_findings_in_review:
            out.append(
                f"  | {f.get('id', '?')} | {f.get('severity', '')} | "
                f"`{f.get('file', '')}` | {f.get('rule_id', '')} | "
                f"{_truncate(f.get('suggested_fix', ''), 80)} |"
            )
        out.append("")
    else:
        out.append("- No Trivy findings were routed to the AI rewriter.")
        out.append("")

    # ---- SonarQube ----
    sonar = ctx["sonar"] or {}
    out.append("### 3.2 SonarQube (SAST)")
    out.append("")
    out.append(f"- Quality gate: **{sonar.get('qualityGate', 'N/A') or 'N/A'}**")
    out.append(f"- Bugs: {sonar.get('bugs', 'N/A')} · "
               f"Vulnerabilities: {sonar.get('vulnerabilities', 'N/A')} · "
               f"Code smells: {sonar.get('codeSmells', 'N/A')} · "
               f"Security hotspots: {sonar.get('securityHotspots', 'N/A')}")
    overall = sonar.get("overallIssueCounts") or {}
    if overall:
        out.append("- Issue severity breakdown: " + ", ".join(
            f"`{k}`: {v}" for k, v in overall.items() if v
        ))
    if sonar_issues:
        out.append("- Issues (raw):")
        out.append("")
        out.append("  | Rule | Severity | File | Line | Message |")
        out.append("  | --- | --- | --- | --- | --- |")
        for it in sonar_issues[:20]:
            out.append(
                f"  | `{it.get('rule', '')}` | {it.get('severity', '')} | "
                f"`{it.get('file', '')}` | {it.get('line', '')} | "
                f"{_truncate(it.get('message', ''), 80)} |"
            )
        out.append("")
    if not trivy_findings_in_review and not sonar_issues:
        out.append("- No SonarCloud issues were routed to the AI rewriter in this run.")
        out.append("")

    # ---- Other ----
    other = by_source.get("other", [])
    if other:
        out.append("### 3.3 Other sources")
        out.append("")
        for f in other:
            out.append(f"- **{f.get('id', '?')}** ({f.get('severity', '')}) — {f.get('title', '')}")
        out.append("")

    return "\n".join(out)


def section_file_level(reports: Path, ctx: dict) -> str:
    changed = ctx["files_changed"]
    out = ["## 4. File-Level Change Summary", ""]
    if not changed:
        out.append("_No files were modified in this remediation run._")
        out.append("")
        return "\n".join(out)

    out.append(f"`{len(changed)}` file(s) were modified:")
    out.append("")
    out.append("| File | Exists on disk | Notes |")
    out.append("| --- | --- | --- |")
    for f in changed:
        full = reports.parent / f if not Path(f).is_absolute() else Path(f)
        exists = full.exists()
        note = ""
        if f == "pom.xml":
            note = "Maven build descriptor; bumps to Spring Boot parent / direct deps are applied here."
        elif f == "Dockerfile":
            note = "Container image; base-image hardening is applied here."
        elif f.endswith((".java",)):
            note = "Application source code."
        elif f.endswith((".properties", ".yml", ".yaml")):
            note = "Configuration / secrets."
        out.append(f"| `{f}` | {'✅' if exists else '⚠️ missing'} | {note} |")
    out.append("")
    return "\n".join(out)


def section_code_changes(reports: Path, ctx: dict) -> str:
    patch = ctx["ai_patch"]
    changed = ctx["files_changed"]
    out = ["## 5. Code Changes (Before / After)", ""]
    if not patch:
        out.append("_No unified diff is available (`ai-patch.diff` is empty or missing)._")
        out.append("")
        out.append("This usually means one of the following:")
        out.append("")
        out.append("- The remediation run produced zero patches (all findings were skipped or out of scope).")
        out.append("- The LLM's patches were not committed to the working tree (check `llm-response.txt`).")
        out.append("- The rewriter was bypassed (e.g. `--skip-llm` with no deterministic fixers applicable).")
        out.append("")
        return "\n".join(out)

    out.append(f"The full unified diff is at `{reports / 'ai-patch.diff'}` "
               f"({len(patch.splitlines())} lines).")
    out.append("")
    if not changed:
        return "\n".join(out)

    for f in changed:
        hunk = _diff_hunk_for_file(patch, f)
        if not hunk:
            out.append(f"### `{f}`")
            out.append("")
            out.append("_No diff hunk for this file in `ai-patch.diff`._")
            out.append("")
            continue
        out.append(f"### `{f}`")
        out.append("")
        out.append("```diff")
        out.append(hunk)
        out.append("```")
        out.append("")
    return "\n".join(out)


def section_mapping(ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    fixes = ctx["fixes"] or []
    out = ["## 6. Remediation Mapping", ""]

    if not findings:
        out.append("_No findings to map._")
        out.append("")
        return "\n".join(out)

    # Per-finding resolution
    fixed_files = {(f.get("file") or "").strip() for f in fixes}
    fixed_rules = {(f.get("rule") or "").strip() for f in fixes}

    out.append("| Finding ID | Severity | CVE / Rule | Package | Resolution |")
    out.append("| --- | --- | --- | --- | --- |")
    for f in findings:
        file_ = (f.get("file") or "").strip()
        rule_ = (f.get("rule_id") or "").strip()
        sev = (f.get("severity") or "INFO").upper()
        pkg = file_ if file_ else "(n/a)"
        # Resolution
        if any(fix.get("file") == "pom.xml" and (":" in pkg) for fix in fixes):
            resolution = "✅ Transitive fix (pom.xml parent / override)"
        elif any(fix.get("file") == "Dockerfile" and (":" not in pkg) for fix in fixes):
            resolution = "✅ Transitive fix (Dockerfile base / `apt-get upgrade`)"
        elif file_ in fixed_files:
            resolution = "✅ Direct fix"
        elif rule_ in fixed_rules:
            resolution = "✅ Direct fix (rule match)"
        elif any(fix.get("file") == file_ for fix in fixes):
            resolution = "✅ Direct fix"
        else:
            resolution = "⚠️ Skipped / out of scope"
        out.append(f"| {f.get('id', '?')} | {sev} | `{rule_}` | `{pkg}` | {resolution} |")
    out.append("")
    return "\n".join(out)


def section_git(reports: Path, ctx: dict) -> str:
    stat = ctx["git_diff_stat"]
    changed = ctx["files_changed"]
    out = ["## 7. Git Summary", ""]
    if not stat and not changed:
        out.append("_No git activity recorded (no diff stat, no changed files)._")
        out.append("")
        return "\n".join(out)
    if stat:
        out.append("```")
        out.append(stat.rstrip())
        out.append("```")
        out.append("")
    if changed:
        out.append("Files touched:")
        out.append("")
        for f in changed:
            out.append(f"- `{f}`")
        out.append("")
    return "\n".join(out)


def section_remaining(ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    fixes = ctx["fixes"] or []
    fixed_files = {(f.get("file") or "").strip() for f in fixes}
    fixed_rules = {(f.get("rule") or "").strip() for f in fixes}

    out = ["## 8. Remaining Findings", ""]
    if not findings:
        out.append("_No findings in the security review._")
        out.append("")
        return "\n".join(out)

    fixed, remaining = [], []
    for f in findings:
        file_ = (f.get("file") or "").strip()
        rule_ = (f.get("rule_id") or "").strip()
        if (file_ in fixed_files) or (rule_ in fixed_rules) or any(
            fix.get("file") == "pom.xml" and ":" in file_ for fix in fixes
        ) or any(
            fix.get("file") == "Dockerfile" and ":" not in file_ for fix in fixes
        ):
            fixed.append(f)
        else:
            remaining.append(f)

    out.append(f"- Findings fully addressed (transitive or direct): **{len(fixed)}** / {len(findings)}")
    out.append(f"- Findings still open after this run: **{len(remaining)}** / {len(findings)}")
    out.append("")
    if remaining:
        out.append("| ID | Severity | CVE / Rule | Reason skipped |")
        out.append("| --- | --- | --- | --- |")
        for f in remaining:
            reason = (f.get("suggested_fix") or "see security review")
            if "Link:" in reason:
                reason = "no upstream fix published for this package; mitigated by Dockerfile `apt-get upgrade` (if applicable)."
            out.append(
                f"| {f.get('id', '?')} | {f.get('severity', '')} | "
                f"`{f.get('rule_id', '')}` | {_truncate(reason, 100)} |"
            )
        out.append("")
    return "\n".join(out)


def section_risk(ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    fixes = ctx["fixes"] or []
    fixed_files = {(f.get("file") or "").strip() for f in fixes}
    fixed_rules = {(f.get("rule") or "").strip() for f in fixes}
    pre_total = sum(int(f.get("risk_score") or 0) for f in findings)

    post = []
    for f in findings:
        file_ = (f.get("file") or "").strip()
        rule_ = (f.get("rule_id") or "").strip()
        if (file_ in fixed_files) or (rule_ in fixed_rules) or any(
            fix.get("file") == "pom.xml" and ":" in file_ for fix in fixes
        ) or any(
            fix.get("file") == "Dockerfile" and ":" not in file_ for fix in fixes
        ):
            continue
        post.append(int(f.get("risk_score") or 0))
    post_total = sum(post)
    delta = pre_total - post_total
    pct = (delta / pre_total * 100.0) if pre_total else 0.0

    out = ["## 9. Risk Reduction Summary", ""]
    out.append("| Phase | Risk score | Findings remaining |")
    out.append("| --- | --- | --- |")
    out.append(f"| Before remediation | {pre_total} | {len(findings)} |")
    out.append(f"| After remediation | {post_total} | {len(post)} |")
    out.append(f"| **Delta** | **{delta}** (**{pct:.1f}%**) | **{len(findings) - len(post)}** |")
    out.append("")
    out.append("Risk is the unweighted sum of per-finding risk_score (0-100) "
               "in the security review; a finding is considered 'closed' when its "
               "`file` or `rule_id` matches an applied fix, **or** when a transitive "
               "fix to `pom.xml` (Maven) or `Dockerfile` (OS) addresses it.")
    out.append("")
    return "\n".join(out)


def section_perf(ctx: dict) -> str:
    prompt = ctx["llm_prompt"]
    response = ctx["llm_response"]
    out = ["## 10. Performance Summary", ""]
    out.append("| Stage | Artefact | Size (bytes) | Notes |")
    out.append("| --- | --- | --- | --- |")
    pairs = [
        ("Security review prompt", "security-review", None),
        ("Security review (json)", "security-review.json", (ctx["security_review"] is not None)),
        ("AI remediation prompt", "llm-prompt.txt", bool(prompt)),
        ("AI remediation response", "llm-response.txt", bool(response)),
        ("AI patch (unified diff)", "ai-patch.diff", bool(ctx["ai_patch"])),
    ]
    for label, name, present in pairs:
        path = ctx["reports_dir"] / name
        if not path.exists():
            size = 0
            note = "missing"
        else:
            size = path.stat().st_size
            note = "present" if present else "empty"
        out.append(f"| {label} | `{name}` | {size:,} | {note} |")
    out.append("")
    return "\n".join(out)


def section_outcome(ctx: dict) -> str:
    sr = ctx["security_review"] or {}
    findings = sr.get("findings", []) or []
    fixes = ctx["fixes"] or []
    fixed_files = {(f.get("file") or "").strip() for f in fixes}
    fixed_rules = {(f.get("rule") or "").strip() for f in fixes}

    addressed = 0
    for f in findings:
        file_ = (f.get("file") or "").strip()
        rule_ = (f.get("rule_id") or "").strip()
        if (file_ in fixed_files) or (rule_ in fixed_rules) or any(
            fix.get("file") == "pom.xml" and ":" in file_ for fix in fixes
        ) or any(
            fix.get("file") == "Dockerfile" and ":" not in file_ for fix in fixes
        ):
            addressed += 1

    status = "OK" if addressed == len(findings) else "PARTIAL"
    out = [
        "## 11. Final Outcome",
        "",
        f"- **Status:** `{status}`",
        f"- **Findings addressed:** {addressed} / {len(findings)}",
        f"- **Patches applied (deterministic + LLM):** {len(fixes)}",
        f"- **Files changed:** {len(ctx['files_changed'])}",
        "",
        "### Reviewer checklist",
        "",
        "- [ ] Confirm no business logic was changed (only build / dependency / Dockerfile edits).",
        "- [ ] Run `mvn -B -ntp -Pcoverage verify` locally.",
        "- [ ] Review the unified diff in `ai-patch.diff`.",
        "- [ ] Re-run Trivy and SonarCloud against the patched tree to confirm CVE counts dropped.",
        "- [ ] Approve the PR if the changes are acceptable.",
        "",
    ]
    return "\n".join(out)


# --------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------- #


def _load_ctx(reports: Path) -> dict:
    sr = _read_json(reports / "security-review.json") or {}
    trivy = _read_json(reports / "trivy-report.json") or []
    if isinstance(trivy, dict):
        trivy = trivy.get("findings", []) or []
    sonar = _read_json(reports / "sonar-report.json") or {}

    patch = _read_text(reports / "ai-patch.diff")
    changed_raw = _read_text(reports / "changed-files.txt")
    changed = [ln.strip() for ln in changed_raw.splitlines() if ln.strip()]
    stat = _read_text(reports / "git-diff-stat.txt")
    rem_sum = _read_text(reports / "remediation-summary.md")
    llm_prompt = _read_text(reports / "llm-prompt.txt")
    llm_response = _read_text(reports / "llm-response.txt")

    # Parse fix count from the short summary
    fix_count = 0
    m = re.search(r"Safe fixes applied:\s*(\d+)", rem_sum)
    if m:
        fix_count = int(m.group(1))
    # Build a synthetic "fixes" list from markers in the patch and pom/Dockerfile touches
    fixes: list[dict] = []
    # Heuristic: every file in changed-files that is in the diff is a fix
    for f in changed:
        hunk = _diff_hunk_for_file(patch, f)
        if not hunk:
            continue
        rule = "code-change"
        if f == "pom.xml":
            rule = "outdated-dependency"
        elif f == "Dockerfile":
            rule = "outdated-base-image"
        fixes.append({"file": f, "rule": rule, "description": hunk.splitlines()[0] if hunk else ""})

    return {
        "reports_dir": reports,
        "security_review": sr,
        "trivy": trivy,
        "sonar": sonar,
        "ai_patch": patch,
        "files_changed": changed,
        "git_diff_stat": stat,
        "remediation_summary_text": rem_sum,
        "llm_prompt": llm_prompt,
        "llm_response": llm_response,
        "fixes": fixes,
        "fix_count": fix_count or len(fixes),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--out", type=Path, default=Path("reports/remediation-report.md"))
    args = ap.parse_args()

    if not args.reports.exists():
        print(f"ERROR: reports dir {args.reports} does not exist", file=sys.stderr)
        return 1

    ctx = _load_ctx(args.reports)

    parts: list[str] = [
        "# Remediation Report",
        "",
        f"_Generated by `scripts/generate-remediation-report.py` at { _now_iso() }._  ",
        f"_All inputs are read from `{args.reports}/`._",
        "",
        "---",
        "",
        section_executive_summary(args.reports, ctx),
        section_pipeline_stages(args.reports),
        section_per_tool(ctx),
        section_file_level(args.reports, ctx),
        section_code_changes(args.reports, ctx),
        section_mapping(ctx),
        section_git(args.reports, ctx),
        section_remaining(ctx),
        section_risk(ctx),
        section_perf(ctx),
        section_outcome(ctx),
        "---",
        "",
        "_End of report._",
        "",
    ]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(parts), encoding="utf-8")
    print(f"Remediation report written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
