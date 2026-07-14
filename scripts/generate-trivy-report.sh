#!/usr/bin/env bash
#
# generate-trivy-report.sh
#
# Thin wrapper around the `trivy` CLI that produces the files the pipeline
# expects from a security scan. Always emits:
#
#   <out-dir>/trivy-fs.sarif           - SARIF, filesystem scan
#   <out-dir>/trivy-fs.sarif.txt       - text summary of the FS SARIF
#   <out-dir>/trivy-fs.raw.json        - Trivy's native JSON, FS scan
#   <out-dir>/trivy-image.sarif        - SARIF, image scan (placeholder if no image)
#   <out-dir>/trivy-image.sarif.txt    - text summary of the image SARIF
#   <out-dir>/trivy-image.raw.json     - Trivy's native JSON, image scan
#   <out-dir>/trivy-report.json        - merged normalised findings (FS + image)
#   <out-dir>/trivy-report.txt         - merged human-readable summary
#
# Modes (env-driven):
#   TRIVY_IMAGE   if set, also runs `trivy image <TRIVY_IMAGE>`.
#                 The CI pipeline sets this after `docker build`.
#                 When unset, image-scan files are placeholders with zero
#                 findings and the merged report is the FS scan only.
#
# Usage:
#   generate-trivy-report.sh <out-dir> [<scan-path>]
#
# Env (optional):
#   TRIVY_SEVERITY  - default: CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN
#   TRIVY_VERSION   - default: 0.72.0
#   TRIVY_IMAGE     - default: unset (skip image scan)
#   SKIP_INSTALL    - if set, do not attempt to install the Trivy CLI
#
# Exit code: 0 always — Trivy findings are informational, not gating
# (matches the policy used elsewhere in the pipeline).
set -euo pipefail

OUT_DIR="${1:-reports}"
SCAN_PATH="${2:-.}"
SEVERITY="${TRIVY_SEVERITY:-CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN}"
TRIVY_VERSION="${TRIVY_VERSION:-0.72.0}"
TRIVY_IMAGE="${TRIVY_IMAGE:-}"
export OUT_DIR SCAN_PATH SEVERITY

mkdir -p "$OUT_DIR"

# ---------------------------------------------------------------------
# Install Trivy if not present.
#
# Primary: download the Linux-64bit tarball from the GitHub release and
# verify its SHA-256 against the published checksums.txt.
# Fallback: Trivy's upstream install.sh (which fetches from get.trivy.dev).
# ---------------------------------------------------------------------
if ! command -v trivy >/dev/null 2>&1; then
  if [ -n "${SKIP_INSTALL:-}" ]; then
    echo "::error::Trivy not on PATH and SKIP_INSTALL is set; cannot scan."
    exit 1
  fi

  echo "Installing trivy ${TRIVY_VERSION}..."
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  installed=0

  base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
  asset="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
  if curl -fsSL -o "${tmpdir}/trivy.tar.gz" "${base}/${asset}" \
     && curl -fsSL -o "${tmpdir}/trivy_checksums.txt" "${base}/trivy_${TRIVY_VERSION}_checksums.txt"; then
    expected="$(awk -v a="${asset}" '$2 == a || $2 == "./"a {print $1; exit}' "${tmpdir}/trivy_checksums.txt" || true)"
    if [ -n "${expected:-}" ]; then
      actual="$(sha256sum "${tmpdir}/trivy.tar.gz" | awk '{print $1}')"
      if [ "${expected}" = "${actual}" ]; then
        tar -xz -C /usr/local/bin trivy -f "${tmpdir}/trivy.tar.gz"
        installed=1
        echo "  installed from ${asset} (sha256 verified)"
      else
        echo "::warning::sha256 mismatch for ${asset} (expected=${expected:0:12}.. actual=${actual:0:12}..)"
      fi
    else
      echo "::warning::No checksum entry for ${asset} in checksums.txt; skipping verification."
      tar -xz -C /usr/local/bin trivy -f "${tmpdir}/trivy.tar.gz"
      installed=1
      echo "  installed from ${asset} (checksum unavailable)"
    fi
  else
    echo "::warning::Direct download of ${asset} failed."
  fi

  if [ "${installed}" -eq 0 ]; then
    echo "::warning::Direct install failed; trying upstream install.sh..."
    if curl -fsSL "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh" \
         | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"; then
      installed=1
    else
      echo "::warning::Upstream install.sh also failed."
    fi
  fi

  if [ "${installed}" -eq 0 ] || ! command -v trivy >/dev/null 2>&1; then
    echo "::error::Failed to install trivy ${TRIVY_VERSION}. Try pinning a different TRIVY_VERSION, or pre-install trivy in the runner image and set SKIP_INSTALL=1."
    exit 1
  fi
  trivy --version
fi

# ---------------------------------------------------------------------
# Helper: write a minimal valid SARIF 2.1.0 placeholder.
# Used when a Trivy invocation fails so downstream tooling (Security tab
# upload, SARIF-aware linters) still has something well-formed to parse.
# ---------------------------------------------------------------------
write_empty_sarif() {
  local out="$1" label="$2"
  cat > "${out}" <<EOF
{
  "\$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "trivy",
          "version": "$(trivy --version 2>/dev/null | awk '{print $NF}' | head -n1 || echo unknown)",
          "informationUri": "https://github.com/aquasecurity/trivy"
        }
      },
      "invocations": [
        {
          "executionSuccessful": false,
          "properties": { "placeholder": "${label}" }
        }
      ],
      "results": []
    }
  ]
}
EOF
}

# ---------------------------------------------------------------------
# Helper: run a single `trivy` scan, write SARIF + raw JSON, fall back to
# placeholders on failure.
#
# Usage: run_scan <kind> <sarif-out> <raw-json-out> [extra trivy args...]
#   kind: "fs" or "image"
# ---------------------------------------------------------------------
run_scan() {
  local kind="$1"
  local sarif_out="$2"
  local raw_out="$3"
  shift 3

  local scan_label
  case "${kind}" in
    fs)    scan_label="filesystem scan of ${SCAN_PATH}" ;;
    image) scan_label="image scan of ${TRIVY_IMAGE}" ;;
  esac

  echo "::group::Trivy ${kind} scan: ${scan_label}"

  local sarif_ok=0 raw_ok=0

  if trivy "$@" --format sarif --output "${sarif_out}" --severity "${SEVERITY}" --no-progress 2>>"${OUT_DIR}/trivy-${kind}.log"; then
    sarif_ok=1
  else
    echo "::warning::Trivy ${kind} SARIF scan failed; writing empty SARIF placeholder. See trivy-${kind}.log."
    write_empty_sarif "${sarif_out}" "${scan_label}"
  fi

  if trivy "$@" --format json --output "${raw_out}" --severity "${SEVERITY}" --no-progress 2>>"${OUT_DIR}/trivy-${kind}.log"; then
    raw_ok=1
  else
    echo "::warning::Trivy ${kind} JSON scan failed; writing empty raw JSON placeholder. See trivy-${kind}.log."
    echo '{"Results":[]}' > "${raw_out}"
  fi

  echo "::endgroup::"
  if [ "${sarif_ok}" -eq 1 ] && [ "${raw_ok}" -eq 1 ]; then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------
# 1. Filesystem scan — always runs.
# ---------------------------------------------------------------------
run_scan fs "${OUT_DIR}/trivy-fs.sarif" "${OUT_DIR}/trivy-fs.raw.json" \
  fs --quiet "${SCAN_PATH}" \
  || echo "::warning::One or more filesystem scan outputs are placeholders."

# ---------------------------------------------------------------------
# 2. Image scan — only when TRIVY_IMAGE is set and the image exists locally.
# ---------------------------------------------------------------------
if [ -n "${TRIVY_IMAGE}" ]; then
  if command -v docker >/dev/null 2>&1 && docker image inspect "${TRIVY_IMAGE}" >/dev/null 2>&1; then
    # Trivy image pulls DB updates by default; we pass --skip-db-update on the
    # assumption that DB updates are handled centrally (e.g. by caching the
    # .trivy/ dir in CI). Set TRIVY_SKIP_DB_UPDATE=0 to opt in.
    if [ "${TRIVY_SKIP_DB_UPDATE:-1}" = "1" ]; then
      run_scan image "${OUT_DIR}/trivy-image.sarif" "${OUT_DIR}/trivy-image.raw.json" \
        image --skip-db-update --quiet "${TRIVY_IMAGE}" \
        || echo "::warning::One or more image-scan outputs are placeholders."
    else
      run_scan image "${OUT_DIR}/trivy-image.sarif" "${OUT_DIR}/trivy-image.raw.json" \
        image --quiet "${TRIVY_IMAGE}" \
        || echo "::warning::One or more image-scan outputs are placeholders."
    fi
  else
    echo "::warning::TRIVY_IMAGE='${TRIVY_IMAGE}' is set but the image is not present locally. Writing empty image-scan placeholders."
    write_empty_sarif "${OUT_DIR}/trivy-image.sarif" "image not built"
    echo '{"Results":[]}' > "${OUT_DIR}/trivy-image.raw.json"
  fi
else
  echo "::notice::TRIVY_IMAGE not set; skipping image scan (placeholders will be written)."
  write_empty_sarif "${OUT_DIR}/trivy-image.sarif" "TRIVY_IMAGE not set"
  echo '{"Results":[]}' > "${OUT_DIR}/trivy-image.raw.json"
fi

# ---------------------------------------------------------------------
# 3. Normalise the SARIFs into a single flat findings list
#    (used by the AI agents and the diff script).
# ---------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Per-scan normalised outputs. These are what the agent / diff script see.
for kind in fs image; do
  sarif_in="${OUT_DIR}/trivy-${kind}.sarif"
  json_out="${OUT_DIR}/trivy-${kind}.sarif.json"
  if [ -f "${sarif_in}" ] && command -v python3 >/dev/null 2>&1; then
    if ! python3 "${SCRIPT_DIR}/parse-sarif.py" "${sarif_in}" --tool trivy \
         > "${json_out}" 2>>"${OUT_DIR}/trivy-${kind}.log"; then
      echo "::warning::parse-sarif.py failed for ${kind}; writing empty ${json_out}."
      echo "[]" > "${json_out}"
    fi
  else
    echo "[]" > "${json_out}"
  fi
done

# Merged list. trivy-report.json is what every downstream consumer reads.
if command -v python3 >/dev/null 2>&1; then
  if ! python3 - "${OUT_DIR}" <<'PYEOF'
import json, sys
from pathlib import Path

out_dir = Path(sys.argv[1])
merged: list[dict] = []
for kind in ("fs", "image"):
    p = out_dir / f"trivy-{kind}.sarif.json"
    if not p.exists():
        continue
    try:
        arr = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        continue
    for finding in arr:
        # Tag the source so the AI agent and the human reader know where
        # the finding came from (filesystem vs image).
        f = dict(finding)
        f.setdefault("scanner", kind)
        if kind == "image" and not f.get("file"):
            f["file"] = f.get("Target") or f.get("pkgName") or f.get("ruleId") or "(image)"
        merged.append(f)

(out_dir / "trivy-report.json").write_text(json.dumps(merged, indent=2), encoding="utf-8")
print(f"Merged trivy-report.json: {len(merged)} findings (fs+image).")
PYEOF
  then
    echo "::warning::Failed to merge trivy findings; writing empty trivy-report.json."
    echo "[]" > "${OUT_DIR}/trivy-report.json"
  fi
else
  echo "[]" > "${OUT_DIR}/trivy-report.json"
fi

# ---------------------------------------------------------------------
# 4. Plain-text summary for the artifact — merged FS + image.
# ---------------------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
  if ! python3 - "${OUT_DIR}" <<'PYEOF' 2>>"${OUT_DIR}/trivy-summary.log"
import json, sys
from collections import Counter
from pathlib import Path

out_dir = Path(sys.argv[1])
src = out_dir / "trivy-report.json"
dst = out_dir / "trivy-report.txt"

try:
    findings = json.loads(src.read_text(encoding="utf-8"))
except Exception:
    findings = []

sev_counts = Counter(f.get("severity", "UNKNOWN") for f in findings)
scanner_counts = Counter(f.get("scanner", "fs") for f in findings)
cat_counts = Counter(f.get("category", "vulnerability") for f in findings)

lines = [
    "Trivy Scan Summary (filesystem + image)",
    "========================================",
    "",
    f"Total findings: {len(findings)}",
    "",
    "By severity:",
]
for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
    lines.append(f"  {sev:9s} {sev_counts.get(sev, 0)}")
lines.append("")
lines.append("By scanner:")
for scanner in ("fs", "image"):
    lines.append(f"  {scanner:9s} {scanner_counts.get(scanner, 0)}")
lines.append("")
lines.append("By category:")
for cat, n in cat_counts.most_common():
    lines.append(f"  {cat:15s} {n}")
lines.append("")
lines.append("Top 30 findings (sorted by severity, then by file):")
lines.append("-------------------------------------------------")
rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
for f in sorted(
    findings,
    key=lambda x: (-rank.get(x.get("severity", "UNKNOWN"), 0), x.get("file", "")),
)[:30]:
    where = f.get("file") or "(no file)"
    if f.get("line"):
        where = f"{where}:{f['line']}"
    sev = f.get("severity", "UNKNOWN")
    cat = f.get("category", "vuln")
    scanner = f.get("scanner", "fs")
    cve = f.get("cve") or ""
    pkg = f.get("pkgName") or f.get("ruleId") or ""
    inst = f.get("installedVersion")
    fix = f.get("fixedVersion")
    line = f"[{sev:8s}] {scanner:5s} {cat:10s} {cve:18s} {pkg}"
    if inst:
        line += f"@{inst}"
    if fix:
        line += f" -> {fix}"
    line += f"  -- {where}"
    lines.append(line)
if len(findings) > 30:
    lines.append("")
    lines.append(f"... and {len(findings) - 30} more (see trivy-report.json)")

dst.write_text("\n".join(lines) + "\n", encoding="utf-8")
PYEOF
  then
    echo "::warning::Failed to render trivy-report.txt; writing placeholder."
    cat > "${OUT_DIR}/trivy-report.txt" <<'TXT'
Trivy Scan Summary
==================

Total findings: 0
(summary rendering failed — see trivy-summary.log)
TXT
  fi
else
  echo "Trivy scan produced no output (python3 not available)" > "${OUT_DIR}/trivy-report.txt"
fi

# ---------------------------------------------------------------------
# 5. Always print a short summary to the run log.
# ---------------------------------------------------------------------
echo "Trivy scan complete."
if [ -f "${OUT_DIR}/trivy-report.json" ]; then
  python3 - <<'PYEOF' 2>/dev/null || true
import json
from pathlib import Path
import os
out_dir = Path(os.environ.get("OUT_DIR", "reports"))
data = json.loads((out_dir / "trivy-report.json").read_text(encoding="utf-8"))
sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
sc = {"fs": 0, "image": 0}
for f in data:
    sev[f.get("severity", "UNKNOWN")] = sev.get(f.get("severity", "UNKNOWN"), 0) + 1
    sc[f.get("scanner", "fs")] = sc.get(f.get("scanner", "fs"), 0) + 1
print(
    f"  CRITICAL={sev['CRITICAL']} HIGH={sev['HIGH']} MEDIUM={sev['MEDIUM']} "
    f"LOW={sev['LOW']} UNKNOWN={sev['UNKNOWN']} TOTAL={len(data)} "
    f"(fs={sc['fs']}, image={sc['image']})"
)
PYEOF
fi

# ---------------------------------------------------------------------
# 6. Final safety net: assert all expected output files exist.
# ---------------------------------------------------------------------
expected=(
  trivy-fs.sarif
  trivy-fs.raw.json
  trivy-image.sarif
  trivy-image.raw.json
  trivy-fs.sarif.json
  trivy-image.sarif.json
  trivy-report.json
  trivy-report.txt
)
for f in "${expected[@]}"; do
  if [ ! -s "${OUT_DIR}/${f}" ]; then
    echo "::warning::${f} missing or empty; writing placeholder."
    case "${f}" in
      *.sarif)        write_empty_sarif "${OUT_DIR}/${f}" "post-run safety net" ;;
      *.sarif.json)   echo "[]" > "${OUT_DIR}/${f}" ;;
      *.json)         echo "[]" > "${OUT_DIR}/${f}" ;;
      *.txt)          echo "Trivy scan produced no output (${f} is a placeholder)." > "${OUT_DIR}/${f}" ;;
    esac
  fi
done

# Maintain backward-compat alias: older consumers expect trivy-fs.sarif.txt
# and trivy-report.raw.json. trivy-fs.raw.json is the actual raw output.
[ -f "${OUT_DIR}/trivy-fs.raw.json" ] && cp "${OUT_DIR}/trivy-fs.raw.json" "${OUT_DIR}/trivy-report.raw.json" || true
[ -f "${OUT_DIR}/trivy-fs.sarif.json" ] && cp "${OUT_DIR}/trivy-fs.sarif.json" "${OUT_DIR}/trivy-fs.sarif.txt" 2>/dev/null || true

echo "Trivy outputs in ${OUT_DIR}:"
ls -la "${OUT_DIR}/trivy-"* 2>/dev/null || true
