#!/usr/bin/env python3
"""
generate-trivy-diff.py

Compares two Trivy JSON reports (before / after) and writes a Markdown
diff report listing fixed, remaining and new findings.

Usage:
  python scripts/generate-trivy-diff.py \
      --before reports/trivy-report.json \
      --after  reports/trivy-report-after-fix.json \
      --output reports/trivy-diff.md
"""
import argparse
import json
from pathlib import Path

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _load(path: Path) -> list:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []


def _signature(f: dict) -> str:
    """Stable signature for diffing Trivy findings."""
    if f.get("cve") and f.get("pkgName"):
        return f"cve:{f['cve']}|pkg:{f['pkgName']}"
    if f.get("ruleId") and f.get("file"):
        return f"rule:{f['ruleId']}|file:{f['file']}|line:{f.get('line','')}"
    return f"adhoc:{f.get('category','')}|{f.get('file','')}|{f.get('line','')}|{f.get('description','')[:80]}"


def _sev_counts(issues: list) -> dict:
    counts = {s: 0 for s in SEV_RANK}
    for it in issues:
        sev = (it.get("severity") or "UNKNOWN").upper()
        if sev not in counts:
            counts[sev] = 0
        counts[sev] += 1
    return counts


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--before", required=True, type=Path)
    p.add_argument("--after", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()

    before = _load(args.before)
    after = _load(args.after)

    before_idx = {_signature(f): f for f in before}
    after_idx = {_signature(f): f for f in after}

    fixed = [before_idx[k] for k in before_idx.keys() - after_idx.keys()]
    remaining = [after_idx[k] for k in after_idx.keys() & before_idx.keys()]
    new = [after_idx[k] for k in after_idx.keys() - before_idx.keys()]

    before_counts = _sev_counts(before)
    after_counts = _sev_counts(after)

    lines = [
        "# Trivy Re-Scan Diff",
        "",
        f"- Before: {args.before} ({len(before)} findings)",
        f"- After:  {args.after} ({len(after)} findings)",
        "",
        "## Severity counts",
        "",
        "| Severity | Before | After | Δ |",
        "| --- | --- | --- | --- |",
    ]
    for sev in sorted(set(before_counts) | set(after_counts), key=lambda s: SEV_RANK.get(s, 0), reverse=True):
        b = before_counts.get(sev, 0)
        a = after_counts.get(sev, 0)
        delta = a - b
        sign = "+" if delta > 0 else ""
        lines.append(f"| {sev} | {b} | {a} | {sign}{delta} |")

    lines.extend([
        "",
        "## Totals",
        "",
        f"- **Fixed:**  {len(fixed)}",
        f"- **Remaining:**  {len(remaining)}",
        f"- **New:**  {len(new)}",
        "",
        "## Fixed vulnerabilities",
        "",
    ])

    def _fmt(f: dict) -> str:
        bits = [f"[{f.get('severity','UNKNOWN')}]"]
        if f.get("cve"):
            bits.append(f.get("cve"))
        if f.get("pkgName"):
            pkg = f.get("pkgName")
            if f.get("installedVersion"):
                pkg += f"@{f['installedVersion']}"
            bits.append(pkg)
            if f.get("fixedVersion") and f.get("fixedVersion") != "not fixed":
                bits.append(f"→ {f['fixedVersion']}")
        elif f.get("ruleId"):
            bits.append(f"({f['ruleId']})")
        if f.get("file"):
            bits.append(f"— {f['file']}")
        return " ".join(bits)

    if fixed:
        for f in sorted(fixed, key=lambda x: (-SEV_RANK.get(x.get("severity", "UNKNOWN"), 0), x.get("file", ""))):
            lines.append(f"- {_fmt(f)}")
    else:
        lines.append("- None")

    lines.extend(["", "## Remaining vulnerabilities", ""])
    if remaining:
        for f in sorted(remaining, key=lambda x: (-SEV_RANK.get(x.get("severity", "UNKNOWN"), 0), x.get("file", ""))):
            lines.append(f"- {_fmt(f)}")
    else:
        lines.append("- None 🎉")

    lines.extend(["", "## Newly introduced findings", ""])
    if new:
        for f in sorted(new, key=lambda x: (-SEV_RANK.get(x.get("severity", "UNKNOWN"), 0), x.get("file", ""))):
            lines.append(f"- {_fmt(f)}")
    else:
        lines.append("- None 🎉")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote Trivy diff to {args.output}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
