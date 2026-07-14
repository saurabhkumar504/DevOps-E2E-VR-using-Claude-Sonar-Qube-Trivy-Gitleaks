#!/usr/bin/env python3
"""
check-deploy-gates.py

Validates the post-remediation state of the pipeline and writes a JSON
result file the deploy job consumes.

Required inputs (paths are configurable via flags):
  --coverage-summary    Path to JaCoCo coverage summary CSV (or jacoco.xml)
  --sonar-report        Path to sonar-report-after-fix.json
  --trivy-report        Path to trivy-report-after-fix.json
  --remediation-report  Path to remediation-report.json
  --rebuild-result      Path to a file whose presence indicates a successful
                        rebuild (e.g. target/.rebuild-ok)
  --codeql-sarif        Path to CodeQL SARIF (optional)
  --output              Where to write the gate result JSON

Required env (or defaults):
  MIN_COVERAGE                 int percent, default 70
  ALLOW_CRITICAL               bool, default False
  ALLOW_HIGH                   bool, default False
  REQUIRED_QUALITY_GATE        default "OK"

Exit code:
  0  = all gates passed
  1  = at least one gate failed (gates still written to --output)
"""
import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def _parse_jacoco_coverage(path: Path) -> float | None:
    """Return overall line coverage % from a JaCoCo XML or CSV summary."""
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
    # CSV: expect a row with header `LINE,%instructions,...` style — fall back
    # to a generic regex for any "XX%" pattern on a "Total" line.
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001
        return None
    m = re.search(r"Total.*?(\d{1,3}(?:\.\d+)?)\s*%", text, re.IGNORECASE | re.DOTALL)
    if m:
        return float(m.group(1))
    return None


def _parse_codeql_sarif(path: Path) -> tuple[int, int]:
    """Return (critical, high) alert counts parsed from a CodeQL SARIF file.

    Each <result> element is classified by:
      - properties["security-severity"] score (0.0 - 10.0), preferred
      - falling back to the SARIF level attribute ("error"|"warning"|"note")
    Score >= 9.0 -> Critical, 7.0-8.9 -> High, < 7.0 ignored.
    Missing/invalid file -> (0, 0) (graceful degradation).

    SARIF is JSON. CodeQL's emitter puts the score on the result's
    `properties` property bag (e.g. result["properties"]["security-severity"]
    = "9.5") and also on the tool rule definition as a fallback.
    """
    if not path.exists():
        return 0, 0
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        sarif = json.loads(text)
    except Exception:  # noqa: BLE001
        return 0, 0

    critical = 0
    high = 0

    def _coerce_score(v) -> float | None:
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    # Index rules by ruleId so result.properties.security-severity can
    # fall back to rule.properties.security-severity when the result omits it.
    rule_severity: dict[str, float] = {}
    for run in sarif.get("runs", []) or []:
        tool = run.get("tool") or {}
        # SARIF puts rules under tool.driver.rules (or tool.extensions[*].rules).
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
            if score is not None:
                if score >= 9.0:
                    critical += 1
                elif score >= 7.0:
                    high += 1
                continue
            # Last-resort: SARIF level attribute.
            level = (result.get("level") or "").lower()
            if level == "error":
                critical += 1
            elif level == "warning":
                high += 1
    return critical, high


def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--coverage-summary", type=Path, default=Path("reports/coverage-summary.csv"))
    p.add_argument("--sonar-report", type=Path, default=Path("reports/sonar-report-after-fix.json"))
    p.add_argument("--trivy-report", type=Path, default=Path("reports/trivy-report-after-fix.json"))
    p.add_argument("--remediation-report", type=Path, default=Path("reports/remediation-report.json"))
    p.add_argument("--rebuild-result", type=Path, default=Path("target/.rebuild-ok"))
    p.add_argument("--codeql-sarif", type=Path, default=Path("reports/codeql-results.sarif"))
    p.add_argument("--output", type=Path, default=Path("reports/deploy-gates.json"))
    args = p.parse_args()

    min_coverage = int(os.environ.get("MIN_COVERAGE", "70"))
    allow_critical = os.environ.get("ALLOW_CRITICAL", "false").lower() == "true"
    allow_high = os.environ.get("ALLOW_HIGH", "false").lower() == "true"
    required_qg = os.environ.get("REQUIRED_QUALITY_GATE", "OK")

    gates: list[dict] = []

    # 1) Build success
    build_ok = args.rebuild_result.exists()
    gates.append({
        "name": "build_succeeded",
        "expected": True,
        "actual": build_ok,
        "passed": build_ok,
    })

    # 2) Coverage threshold
    coverage_pct = _parse_jacoco_coverage(args.coverage_summary)
    coverage_ok = coverage_pct is not None and coverage_pct >= min_coverage
    gates.append({
        "name": "coverage_threshold",
        "expected": f">= {min_coverage}%",
        "actual": coverage_pct,
        "passed": coverage_ok,
    })

    # 3) SonarCloud quality gate
    sonar = _load_json(args.sonar_report)
    qg = sonar.get("qualityGate", "UNKNOWN")
    sonar_ok = qg == required_qg
    gates.append({
        "name": "sonar_quality_gate",
        "expected": required_qg,
        "actual": qg,
        "passed": sonar_ok,
    })

    # 4) SonarCloud no new vulnerabilities introduced (re-scan should not have
    #    more vulnerabilities than the pre-fix scan; we don't have the pre-fix
    #    in the gate step, so we just check that the current scan has zero).
    # Read from the new flat schema first; fall back to the old nested
    # `metrics.vulnerabilities` path so older reports keep working.
    if "vulnerabilities" in sonar:
        new_vulns = sonar.get("vulnerabilities", 0)
    else:
        new_vulns = sonar.get("metrics", {}).get("vulnerabilities", 0)
    try:
        new_vulns_n = int(new_vulns)
    except (TypeError, ValueError):
        new_vulns_n = -1
    vulns_ok = new_vulns_n == 0
    gates.append({
        "name": "no_remaining_vulnerabilities",
        "expected": 0,
        "actual": new_vulns_n,
        "passed": vulns_ok,
    })

    # 5) Trivy severity
    trivy = _load_json(args.trivy_report)
    findings = trivy if isinstance(trivy, list) else trivy.get("findings", [])
    critical = sum(1 for f in findings if (f.get("severity") or "").upper() == "CRITICAL")
    high = sum(1 for f in findings if (f.get("severity") or "").upper() == "HIGH")

    critical_ok = (critical == 0) or allow_critical
    high_ok = (high == 0) or allow_high

    gates.append({
        "name": "no_critical_trivy",
        "expected": "0 (allow_critical=%s)" % allow_critical,
        "actual": critical,
        "passed": critical_ok,
    })
    gates.append({
        "name": "no_high_trivy",
        "expected": "0 (allow_high=%s)" % allow_high,
        "actual": high,
        "passed": high_ok,
    })

    # 6) CodeQL static analysis (Critical / High alert counts)
    codeql_critical, codeql_high = _parse_codeql_sarif(args.codeql_sarif)
    codeql_critical_ok = (codeql_critical == 0) or allow_critical
    codeql_high_ok = (codeql_high == 0) or allow_high
    gates.append({
        "name": "no_critical_codeql",
        "expected": "0 (allow_critical=%s)" % allow_critical,
        "actual": codeql_critical,
        "passed": codeql_critical_ok,
    })
    gates.append({
        "name": "no_high_codeql",
        "expected": "0 (allow_high=%s)" % allow_high,
        "actual": codeql_high,
        "passed": codeql_high_ok,
    })

    # 7) AI remediation completed
    remediation = _load_json(args.remediation_report)
    remediation_ok = bool(remediation.get("fixes")) or remediation.get("status") in {"OK", "SKIPPED"}
    gates.append({
        "name": "ai_remediation_completed",
        "expected": True,
        "actual": remediation.get("status", "MISSING"),
        "passed": remediation_ok,
    })

    all_passed = all(g["passed"] for g in gates)
    result = {
        "all_passed": all_passed,
        "deploy_recommended": all_passed,
        "gates": gates,
        "environment": os.environ.get("DEPLOY_ENV", "dev"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")

    print(json.dumps(result, indent=2))
    if not all_passed:
        failed = [g["name"] for g in gates if not g["passed"]]
        print(f"\n::error::Deploy gate(s) FAILED: {', '.join(failed)}", file=sys.stderr)
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
