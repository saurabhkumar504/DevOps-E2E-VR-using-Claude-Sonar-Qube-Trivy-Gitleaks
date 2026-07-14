#!/usr/bin/env python3
"""
generate-coverage-report.py

Reads target/site/jacoco/jacoco.xml (produced by the `coverage` Maven profile)
and writes three files into the given output directory:

  <out-dir>/coverage-summary.csv   - per-package line coverage
  <out-dir>/coverage-summary.json  - per-package + overall, machine-readable
  <out-dir>/coverage-summary.md    - human-readable markdown with the
                                     overall coverage and the worst-covered
                                     packages first

The JSON output is what the AI security review agent consumes; the markdown is
what shows up in PR comments / artifacts.

Usage:
  generate-coverage-report.py --xml target/site/jacoco/jacoco.xml \
                              --output-dir reports \
                              --min-coverage 80
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


def _percent(covered: int, missed: int) -> float:
    total = covered + missed
    return round(covered / total * 100, 2) if total else 0.0


def _gather_package_rows(root: ET.Element) -> list[dict[str, Any]]:
    """One row per <package> element with line + branch counters."""
    rows: list[dict[str, Any]] = []
    for pkg in root.iter("package"):
        name = pkg.get("name") or "(root)"
        line_missed = line_covered = 0
        branch_missed = branch_covered = 0
        method_missed = method_covered = 0
        class_missed = class_covered = 0
        for c in pkg.iter("counter"):
            t = c.get("type")
            missed = int(c.get("missed", 0))
            covered = int(c.get("covered", 0))
            if t == "LINE":
                line_missed += missed
                line_covered += covered
            elif t == "BRANCH":
                branch_missed += missed
                branch_covered += covered
            elif t == "METHOD":
                method_missed += missed
                method_covered += covered
            elif t == "CLASS":
                class_missed += missed
                class_covered += covered
        rows.append({
            "package": name,
            "line_missed": line_missed,
            "line_covered": line_covered,
            "line_total": line_missed + line_covered,
            "line_pct": _percent(line_covered, line_missed),
            "branch_missed": branch_missed,
            "branch_covered": branch_covered,
            "branch_total": branch_missed + branch_covered,
            "branch_pct": _percent(branch_covered, branch_missed),
            "method_missed": method_missed,
            "method_covered": method_covered,
            "method_pct": _percent(method_covered, method_missed),
            "class_missed": class_missed,
            "class_covered": class_covered,
            "class_pct": _percent(class_covered, class_missed),
        })
    return rows


def _gather_method_rows(root: ET.Element) -> list[dict[str, Any]]:
    """Flat list of every method with its line coverage. Useful for the AI
    agent to surface 'which specific methods are uncovered?' without parsing
    the full XML again."""
    rows: list[dict[str, Any]] = []
    for src in root.iter("sourcefile"):
        file_name = src.get("name") or ""
        for m in src.findall("method"):
            line_missed = line_covered = 0
            for c in m.findall("counter"):
                if c.get("type") == "LINE":
                    line_missed += int(c.get("missed", 0))
                    line_covered += int(c.get("covered", 0))
            total = line_missed + line_covered
            if total == 0:
                continue
            rows.append({
                "file": file_name,
                "method": m.get("name") or "",
                "line_missed": line_missed,
                "line_covered": line_covered,
                "line_total": total,
                "line_pct": _percent(line_covered, line_missed),
            })
    return rows


def _overall(rows: list[dict[str, Any]]) -> dict[str, Any]:
    lm = sum(r["line_missed"] for r in rows)
    lc = sum(r["line_covered"] for r in rows)
    bm = sum(r["branch_missed"] for r in rows)
    bc = sum(r["branch_covered"] for r in rows)
    mm = sum(r["method_missed"] for r in rows)
    mc = sum(r["method_covered"] for r in rows)
    return {
        "line_missed": lm,
        "line_covered": lc,
        "line_total": lm + lc,
        "line_pct": _percent(lc, lm),
        "branch_missed": bm,
        "branch_covered": bc,
        "branch_total": bm + bc,
        "branch_pct": _percent(bc, bm),
        "method_missed": mm,
        "method_covered": mc,
        "method_pct": _percent(mc, mm),
    }


def write_csv(rows: list[dict[str, Any]], out: Path) -> None:
    fieldnames = [
        "package", "line_missed", "line_covered", "line_total", "line_pct",
        "branch_missed", "branch_covered", "branch_total", "branch_pct",
    ]
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r[k] for k in fieldnames})


def write_markdown(
    overall: dict[str, Any],
    rows: list[dict[str, Any]],
    methods: list[dict[str, Any]],
    out: Path,
    min_pct: float,
) -> None:
    def status(pct: float) -> str:
        if pct >= min_pct:
            return "✅"
        if pct >= min_pct - 10:
            return "⚠️"
        return "❌"

    worst_pkgs = sorted(rows, key=lambda r: r["line_pct"])[:15]
    worst_methods = sorted(
        [m for m in methods if m["line_pct"] < min_pct],
        key=lambda m: (m["line_pct"], m["file"]),
    )[:20]

    lines: list[str] = [
        "# Test Coverage Report",
        "",
        f"**Overall line coverage:** {overall['line_pct']}% "
        f"({overall['line_covered']:,} of {overall['line_total']:,} lines)  ",
        f"**Threshold:** {min_pct}%  {status(overall['line_pct'])}",
        "",
        f"- Branch coverage: {overall['branch_pct']}% "
        f"({overall['branch_covered']:,}/{overall['branch_total']:,})",
        f"- Method coverage: {overall['method_pct']}% "
        f"({overall['method_covered']:,}/{overall['method_covered'] + overall['method_missed']:,})",
        "",
        "## Per-package line coverage (worst first)",
        "",
        "| Package | Line % | Covered | Missed | Total |",
        "|---|---:|---:|---:|---:|",
    ]
    for r in worst_pkgs:
        lines.append(
            f"| `{r['package']}` | {status(r['line_pct'])} {r['line_pct']}% "
            f"| {r['line_covered']:,} | {r['line_missed']:,} | {r['line_total']:,} |"
        )

    if worst_methods:
        lines.extend([
            "",
            f"## Uncovered / under-covered methods (below {min_pct}%)",
            "",
            "| File | Method | Line % | Covered | Missed |",
            "|---|---|---:|---:|---:|",
        ])
        for m in worst_methods:
            lines.append(
                f"| `{m['file']}` | `{m['method']}` | {m['line_pct']}% "
                f"| {m['line_covered']} | {m['line_missed']} |"
            )

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_json(
    overall: dict[str, Any],
    rows: list[dict[str, Any]],
    methods: list[dict[str, Any]],
    out: Path,
    min_pct: float,
) -> None:
    payload = {
        "threshold_pct": min_pct,
        "passes_threshold": overall["line_pct"] >= min_pct,
        "overall": overall,
        "packages": rows,
        "uncovered_methods": [
            m for m in methods if m["line_pct"] < min_pct
        ],
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--xml", type=Path, default=Path("target/site/jacoco/jacoco.xml"))
    p.add_argument("--output-dir", type=Path, default=Path("reports"))
    p.add_argument("--min-coverage", type=float, default=80.0,
                   help="Coverage threshold in percent (used for status icons).")
    args = p.parse_args()

    args.output_dir.mkdir(parents=True, exist_ok=True)

    if not args.xml.exists():
        # Write a structured "no data" payload so downstream consumers don't
        # break and the AI agent sees a clear signal.
        empty = {
            "threshold_pct": args.min_coverage,
            "passes_threshold": False,
            "error": f"jacoco.xml not found at {args.xml}",
            "overall": {
                "line_pct": 0.0, "line_missed": 0, "line_covered": 0, "line_total": 0,
                "branch_pct": 0.0, "branch_missed": 0, "branch_covered": 0, "branch_total": 0,
                "method_pct": 0.0, "method_missed": 0, "method_covered": 0,
            },
            "packages": [],
            "uncovered_methods": [],
        }
        (args.output_dir / "coverage-summary.json").write_text(
            json.dumps(empty, indent=2), encoding="utf-8"
        )
        # Also write a minimal CSV + MD so the upload step has files to find.
        (args.output_dir / "coverage-summary.csv").write_text(
            "package,line_missed,line_covered,line_total,line_pct,branch_missed,branch_covered,branch_total,branch_pct\n",
            encoding="utf-8",
        )
        (args.output_dir / "coverage-summary.md").write_text(
            f"# Test Coverage Report\n\n_No jacoco.xml at {args.xml}._\n",
            encoding="utf-8",
        )
        print(f"::warning::No jacoco.xml at {args.xml}; wrote empty summaries.")
        return 0

    root = ET.parse(args.xml).getroot()
    rows = _gather_package_rows(root)
    methods = _gather_method_rows(root)
    overall = _overall(rows)

    write_csv(rows, args.output_dir / "coverage-summary.csv")
    write_json(overall, rows, methods, args.output_dir / "coverage-summary.json", args.min_coverage)
    write_markdown(overall, rows, methods, args.output_dir / "coverage-summary.md", args.min_coverage)

    verdict = "PASS" if overall["line_pct"] >= args.min_coverage else "FAIL"
    print(
        f"Overall line coverage: {overall['line_pct']}% "
        f"(threshold {args.min_coverage}%) -> {verdict}"
    )
    if verdict == "FAIL":
        print(
            f"::warning::Coverage {overall['line_pct']}% is below threshold "
            f"{args.min_coverage}%. See coverage-summary.md for details.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
