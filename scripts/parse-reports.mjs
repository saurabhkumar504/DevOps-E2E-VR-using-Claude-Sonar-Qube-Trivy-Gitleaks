#!/usr/bin/env node
/**
 * parse-reports.mjs
 *
 * Discovers and parses SonarQube / Trivy reports under a directory and
 * emits a normalized JSON list of findings to stdout. Used by the
 * sonar-trivy-remediator agent to load reports in a single step.
 *
 * Usage:
 *   node scripts/parse-reports.mjs [--root <dir>] [--format json]
 *
 * Output (JSON to stdout):
 *   {
 *     "reports": [{ "path": "...", "type": "sarif|sonar-json|sonar-xml|sonar-html|trivy-json|trivy-sarif", "tool": "trivy|sonar", "findingCount": N }],
 *     "findings": [
 *       { "source": "trivy-fs", "tool": "trivy", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "pkgName": "...", "installedVersion": "...", "fixedVersion": "...", "cve": "...", "description": "...", "file": "...", "line": null, "recommendation": "..." },
 *       { "source": "sonar",    "tool": "sonar","severity": "BLOCKER|CRITICAL|MAJOR|MINOR|INFO", "ruleId": "...", "file": "...", "line": 0, "message": "...", "type": "..." }
 *     ]
 *   }
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, basename, extname } from "node:path";

const REPORT_NAMES = [
  "sonar-report.json",
  "sonar-report.xml",
  "sonar-report.txt",
  "sonar-report.html",
  "sonarqube-report.json",
  "trivy-report.json",
  "trivy-results.json",
  "trivy-report.sarif",
  "trivy.sarif",
  "trivy-fs.json",
  "trivy-image.json",
  "filesystem-report.json",
  "image-report.json",
  "trivy-fs.sarif",
  "trivy-image.sarif",
];

const SEARCH_DIRS = [
  "reports",
  "artifacts",
  "build",
  "target",
  "output",
  "scan",
  "security",
  ".github",
  "workspace",
  ".",
];

const SEVERITY_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0, BLOCKER: 5, MAJOR: 3, MINOR: 2 };

function parseArgs(argv) {
  const args = { root: process.cwd(), format: "json" };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--root") args.root = argv[++i];
    else if (argv[i] === "--format") args.format = argv[++i];
  }
  return args;
}

async function walk(dir, depth = 0) {
  if (depth > 4) return [];
  let out = [];
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === "node_modules" || e.name === ".git") continue;
      out = out.concat(await walk(p, depth + 1));
    } else if (e.isFile()) {
      out.push(p);
    }
  }
  return out;
}

function detectFormat(file) {
  const name = basename(file).toLowerCase();
  if (name.endsWith(".sarif")) return "sarif";
  if (name.endsWith(".json")) return "json";
  if (name.endsWith(".xml")) return "xml";
  if (name.endsWith(".html") || name.endsWith(".htm")) return "html";
  if (name.endsWith(".txt")) return "txt";
  return "unknown";
}

function detectTool(file) {
  const name = basename(file).toLowerCase();
  if (name.includes("trivy") || name.includes("filesystem") || name.includes("image")) return "trivy";
  if (name.includes("sonar")) return "sonar";
  return null;
}

function parseMessageLines(text) {
  const m = {
    pkgName: null,
    installedVersion: null,
    fixedVersion: null,
    severity: null,
    cve: null,
    description: null,
  };
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (/^Package:/.test(t)) m.pkgName = t.replace(/^Package:\s*/, "");
    else if (/^Installed Version:/.test(t)) m.installedVersion = t.replace(/^Installed Version:\s*/, "");
    else if (/^Fixed Version:/.test(t)) m.fixedVersion = t.replace(/^Fixed Version:\s*/, "");
    else if (/^Severity:/.test(t)) m.severity = t.replace(/^Severity:\s*/, "").toUpperCase();
    else if (/^Vulnerability/.test(t)) {
      const mm = t.match(/Vulnerability\s+(CVE-\S+)/);
      if (mm) m.cve = mm[1];
    } else if (/^Link:/.test(t)) continue;
    else if (m.description == null && t.length > 0 && !/^Target:/.test(t) && !/^PkgType:/.test(t) && !/^PkgPath:/.test(t) && !/^Layer:/.test(t)) {
      m.description = t;
    }
  }
  return m;
}

function parseSarif(text, file) {
  let sarif;
  try {
    sarif = JSON.parse(text);
  } catch {
    return [];
  }
  const findings = [];
  for (const run of sarif.runs || []) {
    const driver = run.tool?.driver || {};
    const toolName = driver.name || detectTool(file) || "unknown";
    for (const res of run.results || []) {
      const ruleId = res.ruleId || res.rule?.id || null;
      const level = (res.level || "").toUpperCase() || "WARNING";
      const msgText = res.message?.text || "";
      const loc = res.locations?.[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri || null;
      const line = loc?.region?.startLine || null;
      const meta = parseMessageLines(msgText);
      const severity = meta.severity || (level === "ERROR" ? "HIGH" : level === "WARNING" ? "MEDIUM" : "LOW");
      findings.push({
        source: basename(file),
        tool: toolName.toLowerCase(),
        severity,
        ruleId,
        cve: meta.cve,
        pkgName: meta.pkgName,
        installedVersion: meta.installedVersion,
        fixedVersion: meta.fixedVersion,
        description: meta.description,
        file: uri,
        line,
        recommendation: meta.fixedVersion ? `Upgrade ${meta.pkgName} to ${meta.fixedVersion}` : null,
      });
    }
  }
  return findings;
}

function parseSonarJson(text, file) {
  let j;
  try {
    j = JSON.parse(text);
  } catch {
    return [];
  }
  const issues = j.issues || [];
  return issues.map((it) => {
    const component = it.component || "";
    const filePath = component.includes(":") ? component.split(":").slice(1).join(":") : component;
    return {
      source: basename(file),
      tool: "sonar",
      severity: (it.severity || "INFO").toUpperCase(),
      ruleId: it.rule,
      cve: null,
      pkgName: null,
      installedVersion: null,
      fixedVersion: null,
      description: it.message || "",
      file: filePath,
      line: it.line || null,
      type: it.type || null,
      recommendation: null,
    };
  });
}

async function discover(root) {
  const seen = new Set();
  for (const d of SEARCH_DIRS) {
    const dir = join(root, d);
    try {
      await stat(dir);
    } catch {
      continue;
    }
    const files = await walk(dir);
    for (const f of files) {
      const base = basename(f).toLowerCase();
      if (REPORT_NAMES.some((n) => n.toLowerCase() === base)) seen.add(f);
    }
  }
  return [...seen];
}

async function parseReport(file) {
  const text = await readFile(file, "utf-8");
  const fmt = detectFormat(file);
  const tool = detectTool(file);
  if (fmt === "sarif") return parseSarif(text, file);
  if (fmt === "json" && tool === "sonar") return parseSonarJson(text, file);
  if (fmt === "json" && tool === "trivy") return parseSarif(text, file); // trivy can also emit JSON
  if (fmt === "json") return parseSonarJson(text, file) || parseSarif(text, file);
  return [];
}

(async () => {
  const args = parseArgs(process.argv.slice(2));
  const files = await discover(args.root);
  const allFindings = [];
  const reportSummaries = [];
  for (const f of files) {
    try {
      const findings = await parseReport(f);
      reportSummaries.push({
        path: f,
        type: detectFormat(f),
        tool: detectTool(f),
        findingCount: findings.length,
      });
      allFindings.push(...findings);
    } catch (e) {
      process.stderr.write(`WARN: failed to parse ${f}: ${e.message}\n`);
    }
  }
  allFindings.sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0));
  const out = { reports: reportSummaries, findings: allFindings };
  process.stdout.write(JSON.stringify(out, null, 2));
})();
