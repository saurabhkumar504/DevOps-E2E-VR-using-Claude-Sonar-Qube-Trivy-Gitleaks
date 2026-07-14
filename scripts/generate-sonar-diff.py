#!/usr/bin/env python3
"""
generate-sonar-diff.py

Compares two SonarCloud issue exports (the "before" and "after" reports) and
emits a Markdown diff report at the requested output path. Matching is done
by Sonar issue key (most reliable) with a fallback to (rule, file, line, type).

Usage:
  python scripts/generate-sonar-diff.py \
      --before reports/sonar-report.json \
      --after  reports/sonar-report-after-fix.json \
      --output reports/sonar-diff-report.md
"""
import argparse
import json
from pathlib import Path

SEVERITY_RANK = {"BLOCKER": 5, "CRITICAL": 4, "MAJOR": 3, "MINOR": 2, "INFO": 1}


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _signature(issue: dict) -> str:
    """Stable signature for diffing. Prefer the issue key; fall back to a
    rule+file+line+message signature so we can still match after a re-scan."""
    if issue.get("key"):
        return f"key:{issue['key']}"
    return f"rule:{issue.get('rule','')}|file:{issue.get('file','')}|line:{issue.get('line','')}|msg:{issue.get('message','')}"


def _severity_counts(issues: list) -> dict:
    counts = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0, "MINOR": 0, "INFO": 0}
    for it in issues:
        sev = (it.get("severity") or "INFO").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--before", required=True, type=Path)
    p.add_argument("--after", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()

    before = _load(args.before)
    after = _load(args.after)

    before_issues = before.get("issues", [])
    after_issues = after.get("issues", [])

    before_idx = {_signature(it): it for it in before_issues}
    after_idx = {_signature(it): it for it in after_issues}

    fixed = [before_idx[k] for k in before_idx.keys() - after_idx.keys()]
    remaining = [after_idx[k] for k in after_idx.keys() & before_idx.keys()]
    new = [after_idx[k] for k in after_idx.keys() - before_idx.keys()]

    # If the before-report had a SKIPPED status (no SONAR_TOKEN), only
    # summarise the after-report so the pipeline still produces something useful.
    if before.get("status") == "SKIPPED":
        intro = (
            "> Note: the initial SonarCloud scan was skipped (missing token). "
            "Only the post-fix scan was available; the diff below is informational."
        )
    else:
        intro = ""

    before_counts = _severity_counts(before_issues)
    after_counts = _severity_counts(after_issues)

    lines = [
        "# SonarCloud Re-Scan Diff Report",
        "",
        intro,
        f"- Before: {args.before} (Quality Gate: {before.get('qualityGate', 'N/A')})",
        f"- After:  {args.after} (Quality Gate: {after.get('qualityGate', 'N/A')})",
        "",
        "## Severity counts",
        "",
        "| Severity | Before | After | Δ |",
        "| --- | --- | --- | --- |",
    ]
    for sev in sorted(set(before_counts) | set(after_counts), key=lambda s: SEVERITY_RANK.get(s, 0), reverse=True):
        b = before_counts.get(sev, 0)
        a = after_counts.get(sev, 0)
        delta = a - b
        sign = "+" if delta > 0 else ""
        lines.append(f"| {sev} | {b} | {a} | {sign}{delta} |")

    lines.extend([
        "",
        "## Totals",
        "",
        f"- Total issues before: {len(before_issues)}",
        f"- Total issues after:  {len(after_issues)}",
        f"- **Fixed:**  {len(fixed)}",
        f"- **Remaining (still present after re-scan):**  {len(remaining)}",
        f"- **New (introduced by remediation):**  {len(new)}",
        "",
        "## Fixed issues",
        "",
    ])
    if fixed:
        for it in sorted(fixed, key=lambda f: (-SEVERITY_RANK.get(f.get("severity", "INFO"), 0), f.get("file", ""))):
            where = it.get("file", "")
            if it.get("line"):
                where = f"{where}:{it['line']}"
            lines.append(
                f"- [{it.get('severity','INFO')}] {it.get('type','')} "
                f"**{it.get('rule','')}** — `{where}` — {it.get('message','')[:120]}"
            )
    else:
        lines.append("- None")

    lines.extend(["", "## Remaining issues", ""])
    if remaining:
        for it in sorted(remaining, key=lambda f: (-SEVERITY_RANK.get(f.get("severity", "INFO"), 0), f.get("file", ""))):
            where = it.get("file", "")
            if it.get("line"):
                where = f"{where}:{it['line']}"
            lines.append(
                f"- [{it.get('severity','INFO')}] {it.get('type','')} "
                f"**{it.get('rule','')}** — `{where}` — {it.get('message','')[:120]}"
            )
    else:
        lines.append("- None 🎉")

    lines.extend(["", "## Newly introduced issues", ""])
    if new:
        for it in sorted(new, key=lambda f: (-SEVERITY_RANK.get(f.get("severity", "INFO"), 0), f.get("file", ""))):
            where = it.get("file", "")
            if it.get("line"):
                where = f"{where}:{it['line']}"
            lines.append(
                f"- [{it.get('severity','INFO')}] {it.get('type','')} "
                f"**{it.get('rule','')}** — `{where}` — {it.get('message','')[:120]}"
            )
    else:
        lines.append("- None 🎉")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote diff report to {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
