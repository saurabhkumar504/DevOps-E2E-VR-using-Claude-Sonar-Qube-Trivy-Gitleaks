#!/usr/bin/env python3
"""
parse-sarif.py

Normalises a Trivy SARIF v2.1.0 file (or a generic SARIF that follows
the Trivy schema) into a flat list of findings on stdout as JSON.

Usage:
  python scripts/parse-sarif.py <sarif-file> [--tool trivy|generic]

Output (JSON array to stdout):
  [
    {
      "tool": "trivy",
      "ruleId": "...",
      "level": "ERROR|WARNING|NOTE",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN",
      "cve": "CVE-...",
      "pkgName": "...",
      "installedVersion": "...",
      "fixedVersion": "...",
      "description": "...",
      "file": "...",
      "line": null,
      "recommendation": "...",
      "category": "vulnerability|secret|misconfig|license|..."
    },
    ...
  ]
"""

import argparse
import json
import re
import sys
from pathlib import Path

SEVERITY_BY_LEVEL = {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW", "NONE": "INFO"}

# Trivy injects these as lines in res.message.text. We split them out into
# structured fields so the AI agents and diff scripts can compare findings.
_TRIVY_FIELD_PATTERNS = [
    ("pkgName", re.compile(r"^Package:\s*(.+)$", re.MULTILINE)),
    ("installedVersion", re.compile(r"^Installed Version:\s*(.+)$", re.MULTILINE)),
    ("fixedVersion", re.compile(r"^Fixed Version:\s*(.+)$", re.MULTILINE)),
    ("cve", re.compile(r"^Vulnerability\s+(CVE-\S+)", re.MULTILINE)),
    ("cve", re.compile(r"(CVE-\d{4}-\d{4,7})")),
    ("severity", re.compile(r"^Severity:\s*(\S+)", re.MULTILINE)),
]


def _extract_message_fields(message_text: str) -> dict:
    """Best-effort extraction of structured fields from a Trivy message body."""
    out: dict = {}
    if not message_text:
        return out

    for key, pattern in _TRIVY_FIELD_PATTERNS:
        m = pattern.search(message_text)
        if m and key not in out:
            out[key] = m.group(1).strip()

    # Description = the first non-trivial line that isn't a known field
    description = None
    for raw in message_text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("Package:", "Installed Version:", "Fixed Version:",
                            "Severity:", "Vulnerability", "Link:", "Target:",
                            "PkgType:", "PkgPath:", "Layer:", "Class:", "Type:")):
            continue
        description = line
        break
    if description:
        out["description"] = description
    return out


def _coerce_severity(level: str, message_severity: str | None) -> str:
    if message_severity:
        sev = message_severity.strip().upper()
        if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return sev
    return SEVERITY_BY_LEVEL.get((level or "WARNING").upper(), "MEDIUM")


def _category_for(result: dict, props: dict) -> str:
    """Trivy uses security-severity Score and a 'Category' tag. Fall back to
    tags from the rule definition when present."""
    tags = (result.get("properties", {}).get("tags") or []) + (props.get("tags") or [])
    for t in tags:
        t_low = t.lower()
        if "secret" in t_low:
            return "secret"
        if "misconfig" in t_low or "config" in t_low:
            return "misconfig"
        if "license" in t_low:
            return "license"
        if "vulnerab" in t_low:
            return "vulnerability"
    return "vulnerability"


def parse(sarif_path: Path) -> list:
    try:
        doc = json.loads(sarif_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"WARN: failed to parse {sarif_path}: {exc}", file=sys.stderr)
        return []

    findings = []
    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {}) or {}
        tool_name = (driver.get("name") or "").lower() or "trivy"
        rules_index = {r.get("id"): r for r in (driver.get("rules") or []) if r.get("id")}

        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId")
            rule_def = rules_index.get(rule_id, {}) if rule_id else {}
            rule_props = rule_def.get("properties", {}) or {}
            result_props = result.get("properties", {}) or {}

            message = (result.get("message") or {}).get("text", "")
            extracted = _extract_message_fields(message)

            loc = (result.get("locations") or [{}])[0].get("physicalLocation") or {}
            uri = (loc.get("artifactLocation") or {}).get("uri")
            line = (loc.get("region") or {}).get("startLine")

            # Trivy also exposes security-severity Score on properties — prefer that
            # for the final severity when present.
            sev_score = result_props.get("security-severity") or rule_props.get("security-severity")
            if sev_score:
                try:
                    score = float(sev_score)
                    if score >= 9.0:
                        severity = "CRITICAL"
                    elif score >= 7.0:
                        severity = "HIGH"
                    elif score >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                except ValueError:
                    severity = _coerce_severity(result.get("level"), extracted.get("severity"))
            else:
                severity = _coerce_severity(result.get("level"), extracted.get("severity"))

            fixed_version = extracted.get("fixedVersion")
            pkg_name = extracted.get("pkgName")

            findings.append({
                "tool": tool_name,
                "ruleId": rule_id,
                "level": result.get("level", "WARNING"),
                "severity": severity,
                "cve": extracted.get("cve"),
                "pkgName": pkg_name,
                "installedVersion": extracted.get("installedVersion"),
                "fixedVersion": fixed_version,
                "description": extracted.get("description"),
                "file": uri,
                "line": line,
                "recommendation": (
                    f"Upgrade {pkg_name} to {fixed_version}"
                    if pkg_name and fixed_version and fixed_version != "not fixed"
                    else None
                ),
                "category": _category_for(result, rule_props),
            })
    return findings


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("sarif", type=Path)
    p.add_argument("--tool", default="trivy")
    args = p.parse_args()

    findings = parse(args.sarif)
    # Tag the tool consistently
    for f in findings:
        if not f.get("tool"):
            f["tool"] = args.tool
    json.dump(findings, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
