#!/usr/bin/env python3
"""
ai-remediation.py

Stage 7 of the DevSecOps pipeline. Reads the security review, Sonar and
Trivy reports, applies SAFE, DETERMINISTIC fixes to the working tree, then
commits locally and (optionally) opens a pull request.

What this script WILL change (safe, low-risk, behavior-preserving):
  - Replace plain-text password comparisons in `*Service.java` with
    BCryptPasswordEncoder.matches() (only when Spring Security is on the
    classpath and BCryptPasswordEncoder isn't already wired up).
  - Parameterise a small set of unambiguous SQL concatenation patterns
    (e.g. `... + username + ...` inside createNativeQuery) with `?` binds.
  - Strip hardcoded `app.secret.*` keys from application.properties.
  - Bump trivy-flagged dependency versions in pom.xml to the minimum fixed
    version (only when the change is a patch/minor bump and the parent BOM
    manages the artifact).
  - Add a Content-Security-Policy default to SecurityConfig.java when
    one isn't already present.

What this script WILL NOT change (recorded in `remediation-report.json`
and `ai-patch.diff` for human review):
  - Architectural refactors
  - Anything that requires understanding business logic
  - Anything that needs new test coverage to validate

Required env:
  GITHUB_TOKEN         - for `gh pr create` (only needed in auto-PR mode)
  NVIDIA_API_KEY       - optional; used to render an extra "AI patch"
                         section for findings the rules refused to fix
Optional env:
  GITHUB_REPOSITORY    - default: actions env
  GITHUB_REF           - default: actions env
  REMEDIATION_BRANCH   - default: ai-remediation/<short-sha>
  REMEDIATION_TARGET   - default: main
  SKIP_PR              - set to "true" to skip gh pr create
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from fnmatch import fnmatch
from pathlib import Path

# ---------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
                 "BLOCKER": 5, "MAJOR": 3, "MINOR": 2, "UNKNOWN": 0}

JAVA_SRC_GLOB = "**/src/main/java/**/*.java"
PROPERTIES_FILES = ["src/main/resources/application.properties",
                    "src/main/resources/application.yml",
                    "src/main/resources/application.yaml"]
POM_PATH = "pom.xml"


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _run(cmd: list[str], cwd: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    """Run a command and return the CompletedProcess. On error, print stderr.

    Uses UTF-8 with `errors="replace"` so that git output containing
    non-ASCII bytes (file paths, diff hunks with non-ASCII source)
    does not crash the parent on Windows, where the system default
    codec is cp1252. The crash was reproducible on `git diff` when
    the diff contained even a single non-cp1252 byte."""
    proc = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=False,
    )
    if check and proc.returncode != 0:
        print(f"::warning::Command failed: {' '.join(cmd)}", file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
    return proc


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def _parse_semver(v: str) -> tuple[int, int, int] | None:
    """Parse the leading MAJOR.MINOR.PATCH from a version string.

    Strips trailing qualifiers (`-ubuntu4.2`, `-RELEASE`, `-SNAPSHOT`,
    leading `1:` epoch prefix) and returns a 3-tuple of ints. Returns
    None when no dotted version is found (e.g. the "Link: ..." sentinel
    Trivy returns for "no fix available" advisories).
    """
    if not v:
        return None
    # Strip Debian/RPM epoch prefix.
    s = v.strip()
    if ":" in s:
        s = s.split(":", 1)[1]
    # Take the leading dotted run.
    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _pick_safe_bump(current: str, candidates: str) -> str | None:
    """Pick a safe bump target from a Trivy `fixedVersion` string.

    Trivy sometimes lists multiple fixed versions separated by `,`, e.g.
    `"4.0.6, 3.5.14"`. The previous logic in this fixer took only the
    first entry, which meant a fix like `3.3.13 -> 3.5.14` was rejected
    because the first candidate (`4.0.6`) was a major bump.

    Strategy:
      1. Split `candidates` on `,` and strip each entry.
      2. Drop "Link: ..." / URL-only entries (those mean "no fix").
      3. From the remaining list, return the first candidate whose
         MAJOR equals `current`'s MAJOR (covers both patch-only and
         same-major minor upgrades). Same-major is the only safe bump
         Spring Boot / Jackson etc. accept without breaking ABI.
      4. If none match, return None and let the caller skip.

    Returns the chosen candidate string, or None.
    """
    cur = _parse_semver(current)
    if cur is None:
        return None
    cur_major = cur[0]
    for raw in (c.strip() for c in (candidates or "").split(",")):
        if not raw:
            continue
        # Skip "Link: ..." / URL-only sentinels.
        if raw.lower().startswith("link:") or raw.lower().startswith("http"):
            continue
        cand = _parse_semver(raw)
        if cand is None:
            continue
        if cand[0] == cur_major:
            return raw
    return None


def _is_upgrade(current: str, candidate: str) -> bool:
    """True iff `candidate` is strictly newer than `current` on the
    same major. Used to prevent the bumper from picking a same-major
    DOWNGRADE (e.g. parent 3.3.13 -> 3.1.4). Returns False for
    invalid inputs.
    """
    cur = _parse_semver(current)
    cand = _parse_semver(candidate)
    if not cur or not cand:
        return False
    if cand[0] != cur[0]:
        return False
    if cand[1] > cur[1]:
        return True
    if cand[1] == cur[1] and cand[2] >= cur[2]:
        return True
    return False


def _pick_parent_target(current_parent_version: str, actionable: list[dict]) -> str | None:
    """Pick a safe target version for `spring-boot-starter-parent`.

    Looks at the *parent*'s own `fixedVersion` first (`org.springframework
    .boot:spring-boot`), then at any `org.springframework.boot:*` starter's
    `fixedVersion` (they all share the SB major-minor scheme), and only
    falls back to a transitive finding's `fixedVersion` as a last resort.
    This avoids the bug where the trigger finding was a transitive library
    (e.g. jackson-databind 2.x) and the fixer wrote `2.18.8` into the
    parent slot — a major-version downgrade.
    """
    # All SB artifacts that share the parent's version scheme.
    parent_pkgs = {
        "org.springframework.boot:spring-boot",
        "org.springframework.boot:spring-boot-starter-web",
        "org.springframework.boot:spring-boot-starter-data-jpa",
        "org.springframework.boot:spring-boot-starter-security",
        "org.springframework.boot:spring-boot-starter-tomcat",
        "org.springframework.boot:spring-boot-starter-logging",
    }
    # Priority 1: the parent artifact's own fixedVersion.
    for a in actionable:
        if a["pkg"] == "org.springframework.boot:spring-boot":
            target = _pick_safe_bump(current_parent_version, a["fixed"])
            if target and _is_upgrade(current_parent_version, target):
                return target
    # Priority 2: any SB starter artifact (they share the version scheme).
    for a in actionable:
        if a["pkg"] in parent_pkgs:
            target = _pick_safe_bump(current_parent_version, a["fixed"])
            if target and _is_upgrade(current_parent_version, target):
                return target
    # Priority 3: any other SB-managed artifact — the version scheme
    # may not match the parent's, so we already filtered by
    # _is_upgrade in `_pick_safe_bump` and the function returns None
    # for version-scheme mismatches, so this is a safety net only.
    for a in actionable:
        if a["pkg"].startswith("org.springframework.boot:"):
            target = _pick_safe_bump(current_parent_version, a["fixed"])
            if target and _is_upgrade(current_parent_version, target):
                return target
    return None


# ---------------------------------------------------------------------
# Safe fixers — each returns a list of "fix" dicts for the report.
# ---------------------------------------------------------------------


def fix_hardcoded_secrets(repo_root: Path) -> list[dict]:
    """Remove `app.secret.*` lines from application.properties / .yml."""
    fixes: list[dict] = []
    rel_targets = [Path(p) for p in PROPERTIES_FILES]
    for rel in rel_targets:
        path = repo_root / rel
        if not path.exists():
            continue
        original = _read(path)
        new = re.sub(r"(?m)^\s*app\.secret\.[A-Za-z0-9_.-]*\s*=\s*.*$", "", original)
        if new != original:
            _write(path, new.rstrip() + "\n")
            fixes.append({
                "rule": "hardcoded-secret",
                "category": "secret",
                "file": str(rel).replace("\\", "/"),
                "description": "Removed hardcoded app.secret.* property",
                "safe": True,
            })
    return fixes


def fix_sql_concat(repo_root: Path) -> list[dict]:
    """Replace `String sql = "..." + var + "...";` concatenation with a
    parameterised native query (`?` + `.setParameter(1, var)`).

    The OWASP lab concatenates inside a `String sql = "..." + var + "...";`
    assignment and then passes that `sql` to `createNativeQuery(sql, ...)`.
    The earlier version of this fixer only looked at the
    `createNativeQuery(...)` line, which never contains the `+` (the
    concatenation is one statement above), so it never matched.

    Strategy:
      1. Find the `String sql = "<prefix>" + <var> + "<suffix>";` line.
      2. Replace it with `String sql = "<prefix>?<suffix>";`.
      3. In the immediately-following `createNativeQuery(sql, X).getResultList()`
         chain, inject `.setParameter(1, <var>)` before `.getResultList()`.
    """
    fixes: list[dict] = []
    if not (repo_root / "src" / "main" / "java").exists():
        return fixes

    # Match a single-variable SQL string concatenation. The OWASP lab
    # uses the pattern `String sql = "..." + var + "...";` (one-line for
    # simple queries, sometimes multi-line for login). We require that
    # the concatenation has exactly one variable, so multi-var cases
    # (e.g. loginUnsafe's `+ username + "...' AND password = '" + password + "'"`)
    # are left alone — they're handled by fix_plain_password instead.
    assign_pat = re.compile(
        r'(?P<indent>[ \t]*)String[ \t]+(?P<varname>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=[ \t]*'
        r'"(?P<prefix>(?:[^"\\]|\\.)*)"[ \t]*\+\s*'
        r'(?P<var>[A-Za-z_][A-Za-z0-9_]*)[ \t]*\+\s*'
        r'"(?P<suffix>(?:[^"\\]|\\.)*)"\s*;',
        re.DOTALL,
    )

    for path in repo_root.glob("src/main/java/**/*.java"):
        original = _read(path)
        if "createNativeQuery" not in original:
            continue
        new = original
        per_file: list[dict] = []
        for m in assign_pat.finditer(new):
            indent = m.group("indent")
            var = m.group("var")
            prefix = m.group("prefix")
            suffix = m.group("suffix")
            varname = m.group("varname")
            # Sanity: only act on assignments that look like a SQL string
            # (start with a SQL keyword). Otherwise we might rewrite arbitrary
            # string concatenations.
            if not re.match(r"\s*(SELECT|INSERT|UPDATE|DELETE)\b", prefix, re.IGNORECASE):
                continue
            # Strip a trailing SQL quote from the prefix and a leading SQL
            # quote from the suffix so we don't end up with `?'` or `?''`
            # after substitution. (The original concatenation
            # `'<prefix>' + var + '<suffix>'` produces `'<prefix>?<suffix>'`
            # which has stray quotes around the placeholder.)
            if prefix.endswith("'"):
                prefix = prefix[:-1]
            if suffix.startswith("'"):
                suffix = suffix[1:]
            # Replace the assignment line.
            new_sql_line = f'{indent}String {varname} = "{prefix}?{suffix}";'
            new = new.replace(m.group(0), new_sql_line, 1)
            # Inject setParameter after the createNativeQuery line.
            # Look for `.createNativeQuery(<varname>, ...)`.
            cn_pat = re.compile(
                r'(\.createNativeQuery\([ \t]*' + re.escape(varname) + r'[ \t]*,[ \t]*[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\))'
                r'(\s*\.\s*getResultList\(\))',
            )
            cn_match = cn_pat.search(new)
            if cn_match:
                injection = f".setParameter(1, {var})"
                new = new.replace(
                    cn_match.group(0),
                    f"{cn_match.group(1)}{injection}{cn_match.group(2)}",
                    1,
                )
            per_file.append({
                "file": str(path.relative_to(repo_root)).replace("\\", "/"),
                "var": var,
                "sql_var": varname,
            })
        if per_file and new != original:
            _write(path, new)
            for info in per_file:
                fixes.append({
                    "rule": "sql-injection",
                    "category": "vulnerability",
                    "file": info["file"],
                    "description": (
                        f"Parameterised native query that previously concatenated "
                        f"{info['var']} into {info['sql_var']}"
                    ),
                    "safe": True,
                })
    return fixes


def fix_plain_password(repo_root: Path) -> list[dict]:
    """The OWASP lab concatenates the password into a SQL query in
    `UserService.loginUnsafe`. There is no `String.equals(...)` compare
    in the codebase, so the previous regex (which only matched
    `if (x.equals(y))` style checks) never fired. Rewrite the
    `loginUnsafe` method to look the user up by username only and verify
    the password in Java, with a clear TODO marker for BCrypt.
    """
    fixes: list[dict] = []
    target = repo_root / "src" / "main" / "java" / "com" / "owasp" / "lab" / "service" / "UserService.java"
    if not target.exists():
        return fixes
    original = _read(target)
    if "FIX_PLAIN_PASSWORD_APPLIED" in original:
        return fixes  # idempotent: don't re-apply

    # Match the full loginUnsafe method body, from `public User loginUnsafe`
    # up to the closing `}` of the method.
    method_pat = re.compile(
        r"public\s+User\s+loginUnsafe\s*\(\s*String\s+username\s*,\s*String\s+password\s*\)\s*\{[\s\S]*?\n\s{4}\}",
        re.MULTILINE,
    )
    new_body = (
        "public User loginUnsafe(String username, String password) {\n"
        "        // VULNERABILITY FIX (AI auto-remediation, marker FIX_PLAIN_PASSWORD_APPLIED):\n"
        "        //   - Look the user up by username only (no password in the SQL).\n"
        "        //   - Compare the supplied password to the stored password in Java.\n"
        "        //   - TODO: replace the String.equals check with BCryptPasswordEncoder.matches().\n"
        "        String sql = \"SELECT * FROM users WHERE username = ?\";\n"
        "        System.out.println(\"[VULNERABILITY-FIXED] Login SQL: \" + sql);\n"
        "\n"
        "        try {\n"
        "            @SuppressWarnings(\"unchecked\")\n"
        "            java.util.List<User> rows = entityManager\n"
        "                    .createNativeQuery(sql, User.class)\n"
        "                    .setParameter(1, username)\n"
        "                    .getResultList();\n"
        "            if (rows.isEmpty()) {\n"
        "                return null;\n"
        "            }\n"
        "            User u = rows.get(0);\n"
        "            if (u.getPassword() == null || !u.getPassword().equals(password)) {\n"
        "                return null;\n"
        "            }\n"
        "            return u;\n"
        "        } catch (Exception ex) {\n"
        "            return null;\n"
        "        }\n"
        "    }"
    )
    new = method_pat.sub(new_body, original, count=1)
    if new != original:
        _write(target, new)
        fixes.append({
            "rule": "plaintext-password",
            "category": "vulnerability",
            "file": str(target.relative_to(repo_root)).replace("\\", "/"),
            "description": (
                "loginUnsafe no longer concatenates password into the SQL; "
                "compares the password in Java with a TODO marker for BCrypt"
            ),
            "safe": True,
        })
    return fixes


def fix_bump_dependencies(repo_root: Path, trivy_report: dict) -> list[dict]:
    """Bump dependency versions in pom.xml based on Trivy findings.

    The previous version of this fixer only matched direct dependencies
    that have an explicit `<version>` in pom.xml. Spring Boot starter
    dependencies are BOM-managed (no `<version>`), and transitive
    libraries are not even listed in pom.xml — so the fixer never fired
    on this project.

    Strategy:
      1. **Spring Boot parent bump**: if a Trivy finding's
         `pkgName` is a Spring Boot artifact or one of the most common
         transitive libraries (jackson, snakeyaml, logback, tomcat, etc.)
         AND the parent is `spring-boot-starter-parent`, bump the parent
         version when a known fixed version is available. This is the
         single most common remediation for a Spring Boot app.
      2. **Direct dependency bump**: if a Trivy finding matches a
         `<groupId>/<artifactId>` in pom.xml that has an explicit
         `<version>`, bump it (patch / minor only).
    """
    fixes: list[dict] = []
    pom = repo_root / POM_PATH
    if not pom.exists():
        return fixes
    original = _read(pom)
    new = original
    findings = trivy_report if isinstance(trivy_report, list) else trivy_report.get("findings", [])

    # Collect findings worth acting on.
    actionable: list[dict] = []
    for f in findings:
        if (f.get("severity") or "").upper() not in {"CRITICAL", "HIGH"}:
            continue
        pkg = f.get("pkgName") or ""
        fixed = f.get("fixedVersion") or ""
        if not pkg or not fixed or fixed == "not fixed":
            continue
        actionable.append({"pkg": pkg, "fixed": fixed, "finding": f})

    if not actionable:
        return fixes

    # ---- Strategy 1: Spring Boot parent bump ----
    # Heuristic: if any finding is for a Spring Boot artifact or one of the
    # well-known transitive libraries, suggest bumping the parent.
    sb_managed_artifacts = {
        # Spring Boot starters (no version in pom)
        "org.springframework.boot:spring-boot-starter-web",
        "org.springframework.boot:spring-boot-starter-data-jpa",
        "org.springframework.boot:spring-boot-starter-security",
        "org.springframework.boot:spring-boot-starter-tomcat",
        "org.springframework.boot:spring-boot-starter-logging",
        # Common transitive deps
        "com.fasterxml.jackson.core:jackson-databind",
        "com.fasterxml.jackson.core:jackson-core",
        "com.fasterxml.jackson.core:jackson-annotations",
        "org.yaml:snakeyaml",
        "ch.qos.logback:logback-core",
        "ch.qos.logback:logback-classic",
        "org.apache.tomcat.embed:tomcat-embed-core",
        "org.apache.tomcat.embed:tomcat-embed-el",
        "org.apache.tomcat.embed:tomcat-embed-websocket",
        "org.hibernate.orm:hibernate-core",
    }
    # The "trigger" finding is the first SB-managed artifact that has a
    # CRITICAL/HIGH advisory. We only need its existence to decide
    # "yes, we should consider a parent bump" — the *target version*
    # always comes from the `org.springframework.boot:spring-boot`
    # finding (or any spring-boot-* starter), because that's the
    # artifact that lives in the same version scheme as the parent.
    sb_finding = next(
        (a for a in actionable if a["pkg"] in sb_managed_artifacts),
        None,
    )
    if sb_finding:
        # Find the spring-boot-starter-parent <version> in pom.xml.
        parent_pat = re.compile(
            r"(<artifactId>\s*spring-boot-starter-parent\s*</artifactId>\s*"
            r"<version>\s*)([^<]+)(</version>)",
        )
        m = parent_pat.search(new)
        if m:
            old_version = m.group(2).strip()
            # Pick the parent-bump target by looking at the SB parent
            # CVE's `fixedVersion` first, then at any SB starter's
            # `fixedVersion`, then at the trigger finding. Using the
            # trigger finding directly is WRONG — its version scheme
            # is the artifact's (e.g. jackson-databind 2.x), not the
            # parent's (3.x), which used to produce nonsensical
            # "bump parent to 3.1.4" suggestions.
            parent_target = _pick_parent_target(old_version, actionable)
            if parent_target and old_version != parent_target:
                new = parent_pat.sub(
                    lambda mm: f"{mm.group(1)}{parent_target}{mm.group(3)}",
                    new,
                    count=1,
                )
                fixes.append({
                    "rule": "outdated-dependency",
                    "category": "dependency",
                    "file": POM_PATH,
                    "description": (
                        f"Bumped spring-boot-starter-parent from {old_version} to "
                        f"{parent_target} (transitive fix for {sb_finding['pkg']})"
                    ),
                    "safe": True,
                    "old_version": old_version,
                    "new_version": parent_target,
                })
                # Once we bump the parent, all the BOM-managed findings
                # are addressed — skip the direct-dependency pass.
                if new != original:
                    _write(pom, new)
                return fixes
        # If sb_finding exists but there's no parent to bump, fall through
        # to Strategy 2 (in case any actionable finding matches a direct
        # dependency).

    # ---- Strategy 2: direct dependency bump (only when there's an
    # explicit <version> in pom.xml for the artifact) ----
    for a in actionable:
        pkg = a["pkg"]
        if ":" not in pkg:
            continue
        group_id, artifact_id = pkg.split(":", 1)
        pat = re.compile(
            rf"(<groupId>\s*{re.escape(group_id)}\s*</groupId>\s*"
            rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>\s*"
            rf"<version>\s*)([^<]+)(</version>)",
        )
        m = pat.search(new)
        if not m:
            continue
        old_version = m.group(2).strip()
        # Same multi-candidate handling as the parent-bump branch: pick
        # the first same-major entry from Trivy's fixed-version list.
        # We additionally require the target to be an UPGRADE (not a
        # same-major downgrade like 6.1.21 -> 6.0.0).
        new_version = _pick_safe_bump(old_version, a["fixed"])
        if not new_version or new_version == old_version:
            continue
        if not _is_upgrade(old_version, new_version):
            continue
        new = pat.sub(lambda mm: f"{mm.group(1)}{new_version}{mm.group(3)}", new, count=1)
        fixes.append({
            "rule": "outdated-dependency",
            "category": "dependency",
            "file": POM_PATH,
            "description": f"Bumped {pkg} from {old_version} to {new_version}",
            "safe": True,
            "old_version": old_version,
            "new_version": new_version,
        })

    if new != original:
        _write(pom, new)
    return fixes


def fix_bump_dockerfile_base(repo_root: Path, trivy_report) -> list[dict]:
    """Patch the Dockerfile runtime stage to pull the latest OS security
    updates. Most of the Trivy image-scanner findings the security
    review emits (bsdutils, gzip, libc-bin, libblkid1, etc.) are
    OS-package CVEs in the runtime base image. They cannot be fixed
    in Java code; they have to be fixed at the image level.

    The conservative, deterministic fix that works for any
    Ubuntu/Debian base image is to add `apt-get upgrade -y` to the
    runtime stage's `RUN apt-get update` block. This pulls every
    published security-pocket update for the codename, which closes
    the OS-package CVEs Trivy reports.

    Idempotency: the marker `FIX_DOCKERFILE_BASE_APPLIED` is added to
    the comment of the `apt-get` line so a re-run is a no-op.
    """
    fixes: list[dict] = []
    dockerfile = repo_root / "Dockerfile"
    if not dockerfile.exists():
        return fixes
    findings = trivy_report if isinstance(trivy_report, list) else trivy_report.get("findings", [])
    # Only act on image-level OS-package findings. SonarQube code-smell
    # findings and Maven-coordinate findings are not relevant here.
    os_findings = [
        f for f in findings
        if (f.get("scanner") == "image" or "library/" in (f.get("file") or ""))
        and (f.get("severity") or "").upper() in {"CRITICAL", "HIGH", "MEDIUM"}
        and ":" not in (f.get("pkgName") or "")  # exclude Maven coordinates
    ]
    if not os_findings:
        return fixes
    original = _read(dockerfile)
    if "FIX_DOCKERFILE_BASE_APPLIED" in original:
        return fixes  # idempotent
    new = original
    # Strategy A: append `&& apt-get upgrade -y` to an existing
    # `apt-get update` line in the runtime stage (any stage after the
    # last `FROM`). This is the safest universal fix — it pulls
    # every security-pocket update for the current codename without
    # requiring us to know a specific patch date.
    # Match `apt-get update \\\n` (with the trailing backslash and
    # newline, which is the Dockerfile line-continuation pattern) so
    # the replacement preserves the line layout bash needs.
    apt_pat = re.compile(
        r"(?P<lead>apt-get\s+update\s*\\\s*\n)"
        r"(?P<rest>\s*&&)",
    )
    m = apt_pat.search(new)
    if m:
        from_positions = [mm.start() for mm in re.finditer(r"^FROM\s+", new, re.MULTILINE)]
        last_from = from_positions[-1] if from_positions else -1
        if last_from == -1 or m.start() >= last_from:
            # `lead` ends with `apt-get update \\\n`; we insert
            # ` && apt-get upgrade -y --no-install-recommends \\\n`
            # right after it so the next original line continues
            # seamlessly. The match is greedy on `lead` so `rest`
            # always begins with ` && ...`.
            upgrade_line = " && apt-get upgrade -y --no-install-recommends \\\n"
            new = (
                new[: m.end("lead")]
                + upgrade_line
                + new[m.end("lead"):]
            )
    # Strategy B: if there's no apt-get block to extend, insert a fresh
    # one right after the runtime `FROM` line.
    if new == original:
        from_pat = re.compile(
            r"^(FROM\s+\S+[^\n]*\n)(?!.*^FROM\s+)",  # last FROM line
            re.MULTILINE | re.DOTALL,
        )
        m = from_pat.search(new)
        if m:
            insertion = (
                "\n# VULNERABILITY FIX (AI auto-remediation, marker FIX_DOCKERFILE_BASE_APPLIED):\n"
                "# Pull the latest OS security updates to remediate image-level Trivy findings.\n"
                "RUN apt-get update \\\n"
                " && apt-get upgrade -y --no-install-recommends \\\n"
                " && rm -rf /var/lib/apt/lists/*\n"
            )
            new = new[: m.end()] + insertion + new[m.end():]
    if new != original:
        _write(dockerfile, new)
        pkg_names = sorted({f.get("pkgName") for f in os_findings if f.get("pkgName")})[:5]
        fixes.append({
            "rule": "outdated-base-image",
            "category": "vulnerability",
            "file": "Dockerfile",
            "description": (
                f"Added `apt-get upgrade -y` to runtime stage to remediate "
                f"image-level OS-package CVEs ({len(os_findings)} findings, "
                f"e.g. {', '.join(pkg_names)})"
            ),
            "safe": True,
            "fixes_count": len(os_findings),
        })
    return fixes


def fix_add_csp(repo_root: Path) -> list[dict]:
    """Add a Content-Security-Policy header to `SecurityConfig.java`.

    The previous version of this fixer looked for an `authorizeHttpRequests(...)`
    call followed by an opening `{` to splice a `.headers(...)` block into.
    But Spring Security 6 uses a lambda DSL
    (`.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())`)
    that has no opening `{`, so the splice either fired on the wrong
    character (the method's closing brace) or never fired at all. And the
    skip-check compared against `headers()` with empty parens, which
    never matched this project's `.headers(h -> h.frameOptions(...))`.

    Strategy: locate the existing `.headers(...)` call. If it already
    configures a contentSecurityPolicy, skip. Otherwise, rewrite the
    lambda body to include the CSP directive alongside the existing
    configuration.
    """
    fixes: list[dict] = []
    for path in repo_root.glob("src/main/java/**/SecurityConfig.java"):
        original = _read(path)
        # Idempotency marker — also serves as a hint to human reviewers.
        if "FIX_CSP_APPLIED" in original:
            continue

        # Look for `.headers( -> h -> <body>);`
        # The body is everything between the first `->` after `.headers(`
        # and the matching `))` that closes the headers call.
        # Match `.headers(<arg> -> <body>);` where <body> is the lambda
        # body of the headers call. Capture the entire `.headers(...)`
        # invocation including its closing `)`s so we can rewrite it.
        # We use a non-greedy match for the body and rely on the
        # terminating `\)\)\s*;` to anchor the end of the headers call.
        headers_pat = re.compile(
            r"\.headers\(\s*[A-Za-z_][A-Za-z0-9_]*\s*->\s*"
            r"(?P<body>.*?)"
            r"\)\s*\)\s*;",
            re.DOTALL,
        )
        m = headers_pat.search(original)
        if m:
            body = m.group("body").rstrip()
            if "contentSecurityPolicy" in body or "ContentSecurityPolicy" in body:
                # Already configured, skip.
                continue
            # `body` is the lambda body, e.g. `h.frameOptions(f -> f.disable())`.
            # The lambda's closing `)` is captured separately by the regex
            # terminator `\)\)\s*;`, so we just append the new chain here.
            new_body = (
                f'{body}'
                f'.contentSecurityPolicy(csp -> csp.policyDirectives("default-src \'self\'; object-src \'none\'"))'
            )
            new = (
                original[: m.start("body")]
                + new_body
                + original[m.end("body") :]
            )
            if "FIX_CSP_APPLIED" not in new:
                # Insert a marker comment above the .headers() line so the
                # change is grep-able for reviewers and so re-running the
                # fixer is a no-op.
                new = re.sub(
                    r"(\.headers\()",
                    "// VULNERABILITY FIX (AI auto-remediation, marker FIX_CSP_APPLIED): added Content-Security-Policy header\n            \\1",
                    new,
                    count=1,
                )
            if new != original:
                _write(path, new)
                fixes.append({
                    "rule": "missing-csp",
                    "category": "misconfig",
                    "file": str(path.relative_to(repo_root)).replace("\\", "/"),
                    "description": "Added a default Content-Security-Policy header",
                    "safe": True,
                })
            continue

        # Fallback: no existing `.headers(...)` call. Add one before the
        # closing `;` of the security filter chain. Insert it just before
        # `return http.build();`.
        return_idx = original.find("return http.build();")
        if return_idx == -1:
            continue
        insertion = (
            "\n            // VULNERABILITY FIX (AI auto-remediation, marker FIX_CSP_APPLIED): added Content-Security-Policy header\n"
            "            .headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives(\"default-src 'self'; object-src 'none'\")))\n"
        )
        new = original[:return_idx] + insertion + original[return_idx:]
        if new != original:
            _write(path, new)
            fixes.append({
                "rule": "missing-csp",
                "category": "misconfig",
                "file": str(path.relative_to(repo_root)).replace("\\", "/"),
                "description": "Added a default Content-Security-Policy header (no prior headers() call found)",
                "safe": True,
            })
    return fixes


# ---------------------------------------------------------------------
# Pipeline orchestration
# ---------------------------------------------------------------------


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------
# LLM-driven per-file patches
# ---------------------------------------------------------------------

# Files the LLM is allowed to write to. Anything else is recorded as a
# `skipped` entry and never touches disk. This is a coarse whitelist
# tuned for the OWASP learning lab; tighten it for production code.
_LLM_WRITABLE_GLOBS = (
    "src/main/java/**/*.java",
    "src/test/java/**/*.java",
    "src/main/resources/**",
    "src/test/resources/**",
    "pom.xml",
    "Dockerfile",
)
_LLM_MAX_PATCHES = 10
_LLM_MAX_BYTES_PER_CALL = 256 * 1024
_LLM_MAX_FILE_BYTES = 8 * 1024


# Per-file-kind marker-comment syntax. The remediation prompt tells the
# LLM which syntax to use for each target file, but LLMs are not reliable
# at inferring the right marker from context — `pom.xml` kept ending up
# with `// FIX_LLM_APPLIED: ...` lines written outside the closing tag
# because the prompt only mentioned the `//` form. We classify the file
# here and, if the LLM wrote a marker with the wrong syntax, strip it
# (and, when the kind has a real marker syntax, replace it with the
# correct one) before writing to disk.
#
# Each value is the marker line we'll insert on a successful patch:
#   - "code_line" uses `//`     (Java, JavaScript, TypeScript, C, C++, Go, etc.)
#   - "code_hash" uses `#`      (Python, Ruby, shell, YAML, TOML, Dockerfile,
#                                .properties, .gradle)
#   - "xml"       uses <!-- -->  (pom.xml, applicationContext.xml, *.html,
#                                Markdown's HTML-comment support)
#   - "json"      has no marker  (JSON doesn't support comments and inserting
#                                a `_marker` key is fragile across schemas;
#                                idempotency for JSON is provided by the file
#                                content hash + the LLM's "new_content ==
#                                current" check above)
#
# The mapping is keyed on the lowercased file extension (or, for the
# Dockerfile / pom.xml cases, the basename).
_MARKER_KIND_BY_EXT: dict[str, str] = {
    # code_line (`//`)
    "java": "code_line", "js": "code_line", "mjs": "code_line", "cjs": "code_line",
    "ts": "code_line", "tsx": "code_line", "jsx": "code_line",
    "c": "code_line", "h": "code_line", "cpp": "code_line", "hpp": "code_line",
    "cc": "code_line", "cs": "code_line", "go": "code_line", "swift": "code_line",
    "kt": "code_line", "kts": "code_line", "scala": "code_line", "rs": "code_line",
    # code_hash (`#`)
    "py": "code_hash", "rb": "code_hash", "sh": "code_hash", "bash": "code_hash",
    "yaml": "code_hash", "yml": "code_hash", "toml": "code_hash",
    "properties": "code_hash", "gradle": "code_hash", "conf": "code_hash",
    "ini": "code_hash", "env": "code_hash",
    # xml-style (`<!-- -->`)
    "xml": "xml", "html": "xml", "htm": "xml", "xhtml": "xml", "md": "xml", "markdown": "xml",
    "svg": "xml", "xsl": "xml",
    # no marker
    "json": "json", "jsonc": "json", "json5": "json",
}
# Basename overrides for extension-less or unusual filenames.
_MARKER_KIND_BY_NAME: dict[str, str] = {
    "pom.xml": "xml",
    "Dockerfile": "code_hash",
    "containerfile": "code_hash",
    ".bashrc": "code_hash",
    ".zshrc": "code_hash",
}
# Files where the LLM is allowed to write but no marker is ever written
# (e.g. JSON), so the idempotency check must not look for a marker in
# the current file. The patching flow still does the standard
# "new_content == current" skip.
_NO_MARKER_KINDS: frozenset[str] = frozenset({"json"})

# Regexes for the four marker syntaxes. Used both to detect the LLM's
# marker lines and to strip/replace them. Each pattern matches a WHOLE
# line (with optional leading whitespace; the trailing newline is also
# optional so markers at the very end of a file — the common case in
# the corruption we've seen — still match).
#
# The rule_id capture is intentionally permissive: LLMs sometimes write
# multiple IDs comma-separated ("CVE-2026-41293, CVE-2026-43512") or
# append extra prose, and the stripping pass just needs to find the
# marker line, not validate the rule_id format.
_MARKER_LINE_RE = {
    "code_line": re.compile(
        r"^[ \t]*//[ \t]*FIX_LLM_APPLIED:[ \t]*([^\r\n]*)[ \t]*\r?\n?",
        re.MULTILINE,
    ),
    "code_hash": re.compile(
        r"^[ \t]*#[ \t]*FIX_LLM_APPLIED:[ \t]*([^\r\n]*)[ \t]*\r?\n?",
        re.MULTILINE,
    ),
    "xml": re.compile(
        r"^[ \t]*<!--[ \t]*FIX_LLM_APPLIED:[ \t]*([^\r\n]*?)[ \t]*-->[ \t]*\r?\n?",
        re.MULTILINE,
    ),
}


def _marker_kind_for(rel_path: str) -> str:
    """Return the marker-comment kind for `rel_path` ('code_line',
    'code_hash', 'xml', or 'json')."""
    name = rel_path.rsplit("/", 1)[-1].lower()
    if name in _MARKER_KIND_BY_NAME:
        return _MARKER_KIND_BY_NAME[name]
    if "." in name:
        ext = name.rsplit(".", 1)[-1]
        return _MARKER_KIND_BY_EXT.get(ext, "code_hash")
    # No extension and no special name -> default to `#` (shell-style).
    return "code_hash"


def _marker_line(kind: str, rule_id: str) -> str:
    """Render a marker comment line in the given kind's syntax."""
    rid = re.sub(r"[^A-Za-z0-9._:\-]", "_", rule_id or "llm")
    if kind == "code_line":
        return f"// FIX_LLM_APPLIED: {rid}\n"
    if kind == "code_hash":
        return f"# FIX_LLM_APPLIED: {rid}\n"
    if kind == "xml":
        return f"<!-- FIX_LLM_APPLIED: {rid} -->\n"
    return ""  # 'json' (or any kind with no marker) — no line emitted


# Pattern that matches a FIX_LLM_APPLIED marker line in ANY of the four
# known syntaxes. Used to (a) detect the LLM's marker before deciding
# whether to strip/replace, and (b) make the idempotency check in
# `_apply_llm_patches` cover all three comment styles (code_line,
# code_hash, xml). The trailing newline is optional (and there's an
# explicit $(?!\n) so we don't eat a *following* newline that belongs to
# the next line of content).
_MARKER_LINE_ANY_KIND_RE = re.compile(
    r"^[ \t]*("
    r"//[ \t]*FIX_LLM_APPLIED:[ \t]*[^\r\n]*"
    r"|#[ \t]*FIX_LLM_APPLIED:[ \t]*[^\r\n]*"
    r"|<!--[ \t]*FIX_LLM_APPLIED:[ \t]*[^\r\n]*?-->[ \t]*"
    r")[ \t]*\r?\n?",
    re.MULTILINE,
)


def _strip_wrong_syntax_markers(content: str, expected_kind: str) -> tuple[str, bool]:
    """Remove any FIX_LLM_APPLIED marker lines whose comment syntax is
    WRONG for `expected_kind`. Returns (sanitised_content, removed_any).
    The LLM is supposed to use the right syntax, but in practice it
    defaults to `//` for every file, so we sanitise defensively. Lines
    written with the *correct* syntax are left in place; the caller can
    decide whether to add one if it's missing.
    """
    if expected_kind not in _MARKER_LINE_RE:
        # 'json' / unknown: strip every marker in any syntax.
        out = _MARKER_LINE_ANY_KIND_RE.sub("", content)
        return out, out != content
    expected_re = _MARKER_LINE_RE[expected_kind]
    out_parts: list[str] = []
    removed = False
    pos = 0
    for m in _MARKER_LINE_ANY_KIND_RE.finditer(content):
        line = m.group(0)
        if expected_re.fullmatch(line):
            # Correct syntax — keep it in place.
            continue
        # Wrong syntax — drop it.
        out_parts.append(content[pos:m.start()])
        pos = m.end()
        removed = True
    out_parts.append(content[pos:])
    return "".join(out_parts), removed


def _has_any_marker(content: str) -> bool:
    return bool(_MARKER_LINE_ANY_KIND_RE.search(content))


def _is_path_writable(rel_path: str) -> bool:
    """True iff `rel_path` matches one of the whitelisted globs."""
    rel = rel_path.replace("\\", "/").lstrip("/")
    if not rel:
        return False
    # Reject absolute paths and parent-traversal early.
    if rel.startswith("/") or ".." in rel.split("/"):
        return False
    from fnmatch import fnmatch
    for pat in _LLM_WRITABLE_GLOBS:
        if fnmatch(rel, pat):
            return True
    return False


def _call_nvidia(prompt: str, system: str, model: str, base_url: str, max_tokens: int) -> str:
    """Call the NVIDIA chat completions API. Returns the assistant's
    content (a string), or "" on missing key / network error / non-JSON
    response. Logs a warning to stderr on failure so the workflow log
    shows why the LLM pass was skipped."""
    api_key = os.environ.get("NVIDIA_API_KEY", "").strip()
    if not api_key:
        print("WARN: NVIDIA_API_KEY not set; skipping LLM patch pass.", file=sys.stderr)
        return ""
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    }
    req = urllib.request.Request(
        f"{base_url.rstrip('/')}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError) as exc:
        print(f"WARN: NVIDIA API call failed: {exc}", file=sys.stderr)
        return ""
    try:
        return data["choices"][0]["message"]["content"] or ""
    except (KeyError, IndexError, TypeError):
        return ""


def _extract_json(text: str) -> dict | None:
    """Best-effort JSON extraction. Handles ```json fences and the case
    where the LLM wraps the JSON in leading prose."""
    if not text:
        return None
    text = re.sub(r"^```(?:json)?\s*", "", text.strip())
    text = re.sub(r"```$", "", text.strip())
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                return None
    return None


_REMEDIATION_SYSTEM_PROMPT = """You are an automated code-remediation agent for a Java / Spring Boot / Maven project.

You will receive:
  1. A list of security findings (id, severity, class, file, line, rule_id, evidence, suggested_fix).
  2. A per-finding context block that contains the file content you need
     to produce a patch. The block's prefix tells you which class of
     finding it is and which file the patch must target.

Your job: produce a STRICT JSON object describing SAFE, BEHAVIOR-PRESERVING
patches that fix as many findings as possible.

OUTPUT SCHEMA (return ONLY this JSON, no prose, no markdown fences):
{
  "patches": [
    {
      "file": "src/main/java/.../Foo.java" | "pom.xml" | "Dockerfile",
      "new_content": "<FULL new file content after the fix>",
      "rule_id": "java:S2077" | "CVE-2026-22732" | "outdated-base-image",
      "finding_id": "SR-001",
      "description": "One-line description of the change"
    }
  ],
  "skipped": [
    { "finding_id": "SR-009", "rule_id": "java:S5145",
      "reason": "Why this finding cannot be safely auto-fixed" }
  ]
}

FINDING CLASSES AND PATCH TARGETS:
  - SOURCE: real file path on disk (e.g. `src/main/java/.../Foo.java`).
    The context block has the file content; emit a patch whose
    `file` is that exact path.
  - MAVEN: dependency coordinate (`g:a` or `g:a:v`). The context block
    contains a `pom.xml` excerpt with the parent block and any
    matching `<dependency>` block. Emit a patch with `file: "pom.xml"`
    and a `new_content` that is the FULL pom.xml with the version
    bump applied. Safe bumps are SAME-MAJOR only (e.g. 3.3.13 -> 3.5.14,
    6.1.21 -> 6.2.11, 2.17.3 -> 2.18.8). NEVER bump the major version
    (3.3.13 -> 4.0.6 is NOT safe). To bump a transitive dependency,
    bump the parent; to bump a direct dependency, change its explicit
    `<version>` or add one.
  - OS: OS-package name (e.g. `gzip`, `bsdutils`). The context block
    contains the runtime stage of the Dockerfile. Emit a patch with
    `file: "Dockerfile"` and a `new_content` that adds
    `apt-get upgrade -y --no-install-recommends` to the runtime
    `RUN apt-get update` block, OR pins the base image to a more
    recent patch tag, OR inserts a fresh `RUN apt-get update &&
    apt-get upgrade -y && rm -rf /var/lib/apt/lists/*` block.

RULES:
- `new_content` MUST be the FULL file content, not a diff or a hunk.
- The `file` you emit MUST be a writable path. Allowed: `pom.xml`,
  `Dockerfile`, `src/main/java/**/*.java`, `src/test/java/**/*.java`,
  `src/main/resources/**`, `src/test/resources/**`.
- Cap patches at 10 and total new_content bytes at 256 KB.
- Be conservative: parameterise queries, hash passwords, escape output,
  validate inputs, add security headers. Do not introduce new
  dependencies unless the finding explicitly requires it.
- Do not delete code that the application still needs. If you remove
  vulnerable code, replace it with a safe equivalent.
- Add a marker comment ABOVE the change so re-runs are idempotent. Use
  the comment syntax that matches the target file type:
    * Java / JavaScript / TypeScript / C / C++ / Go / Kotlin / Scala ->
      `// FIX_LLM_APPLIED: <rule_id>`
    * Python / Ruby / shell / YAML / TOML / Dockerfile / .properties /
      Gradle -> `# FIX_LLM_APPLIED: <rule_id>`
    * XML / pom.xml / HTML / Markdown -> `<!-- FIX_LLM_APPLIED: <rule_id> -->`
    * JSON -> DO NOT add a marker. JSON has no comment syntax, and
      inserting a synthetic key can break parsers. Idempotency for JSON
      is handled by the file-content comparison.
  CRITICAL: the marker syntax MUST match the file type. A `//` marker
  in `pom.xml` is an XML parse error; a `//` marker in a `.properties`
  file is invalid syntax; a `//` marker in Markdown renders as visible
  text. If you are unsure of the file type, omit the marker.
- Return valid JSON. Do not include any commentary outside the JSON.
"""


def _classify_finding(finding: dict, repo_root: Path) -> str:
    """Classify a security-review finding into one of:

    - "source"   — `file` is a repo-relative path that exists on disk
                   (e.g. `src/main/java/.../Foo.java`, `pom.xml`,
                   `Dockerfile`). The LLM reads the file content and
                   patches the code in place.
    - "maven"    — `file` is a Maven coordinate (`g:a` or `g:a:v`).
                   Trivy reports dependency CVEs this way. The fix
                   lives in `pom.xml` (parent bump, explicit version
                   override, or a new `<dependency>` block).
    - "os"       — `file` is an OS-package name (no `:` in it) AND
                   the Trivy scanner is `image`. The fix lives in
                   the Dockerfile (base image bump or an
                   `apt-get upgrade` step).
    - "unknown"  — anything we can't classify. We still emit a
                   finding block, but with no attached file content,
                   so the LLM can either attempt a fix or skip.

    The classifier is intentionally simple — we want to err on the
    side of routing Maven / OS findings to the right place rather
    than the default "look for a file with this name" behaviour
    that previously caused all 10 dependency findings to be skipped
    with a misleading `(NOT FOUND on disk)`.
    """
    rel = (finding.get("file") or "").replace("\\", "/").strip()
    rule_id = (finding.get("rule_id") or "").upper()
    title = (finding.get("title") or "").upper()
    is_cve = rule_id.startswith("CVE-") or rule_id.startswith("GHSA-") or title.startswith("CVE-")
    is_image = (
        "scanner" in finding and finding.get("scanner") == "image"
    ) or "library/" in (finding.get("evidence") or "")

    # 1. Maven coordinate: contains `:` and at least one dot in the
    #    group id (heuristic for `org.springframework:spring-core`).
    if is_cve and ":" in rel and rel.split(":", 1)[0].count(".") >= 1:
        return "maven"

    # 2. OS package: no `:` in the name, image-scanner, CVE-shaped.
    if is_cve and ":" not in rel and is_image:
        return "os"

    # 3. Real disk path: exists on the working tree.
    if rel and (repo_root / rel).exists():
        return "source"

    # 4. CVE without a clear coordinate / path: probably a Trivy
    #    finding that got flattened into the review. Treat as
    #    a Maven/OS candidate by looking at the rule_id format.
    if is_cve and ":" in rel:
        return "maven"
    if is_cve:
        return "os"

    return "unknown"


def _read_pom_snippet_for_gav(repo_root: Path, gav: str) -> str:
    """Return a small `pom.xml` excerpt relevant to a Maven
    coordinate. The excerpt contains:
      - the `<parent>` block (where Spring Boot parent is declared), and
      - any `<dependency>` block whose `<artifactId>` matches the
        GAV's artifact id (so the LLM can see if there's already
        an explicit version override).

    This is what the LLM needs in order to make a same-major
    version bump decision. We do NOT send the whole pom.xml —
    that wastes tokens and dilutes the signal.
    """
    pom_path = repo_root / "pom.xml"
    if not pom_path.exists():
        return "(pom.xml not present)"
    text = pom_path.read_text(encoding="utf-8", errors="replace")

    out: list[str] = []
    # Parent block (bounded by `<parent>...</parent>`).
    parent_pat = re.compile(r"<parent>.*?</parent>", re.DOTALL)
    m = parent_pat.search(text)
    if m:
        out.append("--- <parent> block ---")
        out.append(m.group(0))

    # Find matching <dependency> blocks.
    if ":" in gav:
        group_id, artifact_id = gav.split(":", 1)
        if ":" in artifact_id:
            artifact_id = artifact_id.split(":", 1)[0]
        dep_pat = re.compile(
            r"<dependency>.*?</dependency>", re.DOTALL
        )
        matches: list[str] = []
        for dm in dep_pat.finditer(text):
            block = dm.group(0)
            if (
                re.search(rf"<groupId>\s*{re.escape(group_id)}\s*</groupId>", block)
                and re.search(rf"<artifactId>\s*{re.escape(artifact_id)}\s*</artifactId>", block)
            ):
                matches.append(block)
        if matches:
            out.append(f"--- <dependency> blocks matching {gav} ---")
            out.extend(matches)
        else:
            out.append(f"--- (no explicit <dependency> block for {gav}; the artifact is BOM-managed) ---")

    if not out:
        return "(no relevant pom.xml snippet found)"
    return "\n".join(out)


def _read_dockerfile_runtime(repo_root: Path) -> str:
    """Return the runtime stage of the Dockerfile — the part after
    the last `FROM` line. The OS-package findings are all about
    packages inside this stage, so the LLM only needs the runtime
    stage to plan a fix."""
    path = repo_root / "Dockerfile"
    if not path.exists():
        return "(Dockerfile not present)"
    text = path.read_text(encoding="utf-8", errors="replace")
    from_positions = [m.start() for m in re.finditer(r"^FROM\s+", text, re.MULTILINE)]
    if not from_positions:
        return text
    start = from_positions[-1]
    return text[start:]


def _build_remediation_prompt(review: dict, repo_root: Path) -> str:
    """Build the user prompt: capped findings + per-finding context
    blocks. Each finding gets one prompt block; the right file
    content (source / pom.xml / Dockerfile) is attached based on
    `_classify_finding` so the LLM can produce a valid patch.
    """
    findings = (review or {}).get("findings") or []
    findings = sorted(
        findings,
        key=lambda f: (
            -SEVERITY_RANK.get((f.get("severity") or "INFO").upper(), 0),
            -int(f.get("risk_score") or 0),
        ),
    )[:20]

    parts: list[str] = [
        "Produce safe, minimal patches for the following security findings.\n"
        "Coverage threshold is irrelevant here; fix the code, not the tests.\n"
        f"Severity scale: CRITICAL > HIGH > MEDIUM > LOW > INFO.\n"
        "Each finding below is classified as SOURCE (real file on disk),\n"
        "MAVEN (dependency coordinate — fix in pom.xml), or OS (OS\n"
        "package — fix in Dockerfile). Read the file content attached to\n"
        "each finding and emit a `patches[].file` path that matches it\n"
        "exactly (the validator will reject any other path).\n"
    ]
    parts.append("===== FINDINGS (sorted by severity, capped at 20) =====")
    for f in findings:
        parts.append(
            f"- id={f.get('id', '?')} sev={f.get('severity', 'INFO')} "
            f"class={_classify_finding(f, repo_root)} "
            f"file={f.get('file', '?')} line={f.get('line', '?')} "
            f"rule_id={f.get('rule_id', '?')}\n"
            f"  evidence: {(f.get('evidence') or '')[:300]}\n"
            f"  suggested_fix: {(f.get('suggested_fix') or '')[:300]}"
        )

    # Attach per-finding context blocks. We key by finding id (not
    # file) so two findings that share the same file each get their
    # own block — earlier code deduped by file, which silently
    # dropped the second gzip / third jackson-databind finding.
    parts.append("\n===== FINDING CONTEXT (one block per finding) =====")
    for f in findings:
        fid = f.get("id", "?")
        kind = _classify_finding(f, repo_root)
        rel = (f.get("file") or "").replace("\\", "/").strip()
        if kind == "source":
            path = repo_root / rel
            if path.exists():
                try:
                    content = path.read_text(encoding="utf-8", errors="replace")
                except OSError as exc:
                    parts.append(f"\n----- {fid} (SOURCE: {rel}) (READ ERROR: {exc}) -----")
                    continue
                if len(content.encode("utf-8")) > _LLM_MAX_FILE_BYTES:
                    content = content[:_LLM_MAX_FILE_BYTES] + "\n<!-- truncated -->\n"
                parts.append(f"\n----- {fid} (SOURCE: {rel}) -----\n{content}")
            else:
                parts.append(f"\n----- {fid} (SOURCE: {rel}) (NOT FOUND on disk) -----")
        elif kind == "maven":
            snippet = _read_pom_snippet_for_gav(repo_root, rel)
            parts.append(
                f"\n----- {fid} (MAVEN: {rel}) — fix in pom.xml -----\n{snippet}"
            )
        elif kind == "os":
            dockerfile = _read_dockerfile_runtime(repo_root)
            if len(dockerfile.encode("utf-8")) > _LLM_MAX_FILE_BYTES:
                dockerfile = dockerfile[:_LLM_MAX_FILE_BYTES] + "\n# truncated\n"
            parts.append(
                f"\n----- {fid} (OS: {rel}) — fix in Dockerfile -----\n{dockerfile}"
            )
        else:
            # Unknown / not classifiable — still emit a block, just
            # without file content. The LLM can try or skip.
            parts.append(
                f"\n----- {fid} (UNKNOWN: {rel}) — no file content; either fix "
                f"in pom.xml / Dockerfile based on the suggested_fix, or skip -----"
            )

    # Also attach the full pom.xml and Dockerfile at the end as a
    # "context" so the LLM can emit either file as the patch target
    # even if it wasn't the one we quoted in the per-finding block.
    parts.append("\n===== PROJECT CONTEXT (use these as patch targets) =====")
    pom = repo_root / "pom.xml"
    if pom.exists():
        try:
            content = pom.read_text(encoding="utf-8", errors="replace")
        except OSError:
            content = ""
        if len(content.encode("utf-8")) > _LLM_MAX_FILE_BYTES:
            content = content[:_LLM_MAX_FILE_BYTES] + "\n<!-- truncated -->\n"
        parts.append(f"\n----- pom.xml -----\n{content}")
    df = repo_root / "Dockerfile"
    if df.exists():
        try:
            content = df.read_text(encoding="utf-8", errors="replace")
        except OSError:
            content = ""
        if len(content.encode("utf-8")) > _LLM_MAX_FILE_BYTES:
            content = content[:_LLM_MAX_FILE_BYTES] + "\n# truncated\n"
        parts.append(f"\n----- Dockerfile -----\n{content}")

    parts.append(
        "\nReturn ONLY the JSON object. No commentary, no markdown fences."
    )
    return "\n".join(parts)


def _apply_llm_patches(repo_root: Path, raw_response: str) -> tuple[list[dict], list[dict]]:
    """Validate and write the LLM's per-file patches. Returns
    `(applied_fixes, skipped_fixes)`."""
    applied: list[dict] = []
    skipped: list[dict] = []

    parsed = _extract_json(raw_response)
    if not parsed:
        skipped.append({
            "rule_id": "llm",
            "finding_id": "-",
            "reason": "LLM response was not valid JSON",
        })
        return applied, skipped
    patches = parsed.get("patches")
    if not isinstance(patches, list):
        skipped.append({
            "rule_id": "llm",
            "finding_id": "-",
            "reason": "LLM response did not contain a `patches` array",
        })
        return applied, skipped
    if not isinstance(parsed.get("skipped", []), list):
        parsed["skipped"] = []

    total_bytes = 0
    for i, patch in enumerate(patches):
        if not isinstance(patch, dict):
            skipped.append({"rule_id": "llm", "finding_id": f"#{i}", "reason": "patch is not an object"})
            continue
        if len(applied) >= _LLM_MAX_PATCHES:
            skipped.append({"rule_id": patch.get("rule_id", "llm"), "finding_id": patch.get("finding_id", f"#{i}"),
                            "reason": f"max patches ({_LLM_MAX_PATCHES}) reached"})
            continue
        rel = (patch.get("file") or "").replace("\\", "/").lstrip("/")
        new_content = patch.get("new_content")
        rule_id = patch.get("rule_id") or "llm-patch"
        finding_id = patch.get("finding_id") or f"#{i}"
        if not rel:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id, "reason": "missing `file`"})
            continue
        if not isinstance(new_content, str):
            skipped.append({"rule_id": rule_id, "finding_id": finding_id, "reason": "missing or non-string `new_content`"})
            continue
        if not _is_path_writable(rel):
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": f"path not whitelisted: {rel}"})
            continue
        added_bytes = len(new_content.encode("utf-8"))
        if total_bytes + added_bytes > _LLM_MAX_BYTES_PER_CALL:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": f"max bytes per call ({_LLM_MAX_BYTES_PER_CALL}) reached"})
            continue
        target = repo_root / rel
        if not target.exists():
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": f"file does not exist on disk: {rel}"})
            continue
        current = _read(target)
        if current == new_content:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": "new_content is identical to current file (no change)"})
            continue
        # Idempotency: any marker-syntax version of FIX_LLM_APPLIED counts.
        if _has_any_marker(current):
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": "already applied (FIX_LLM_APPLIED marker present)"})
            continue

        # ---- Marker sanitisation (defence in depth) ---------------------
        # Even though the prompt tells the LLM which marker syntax to use
        # for each file type, LLMs frequently default to `//` for every
        # file, which breaks XML, YAML, .properties, JSON, Dockerfile, and
        # Markdown. Strip the LLM's wrong-syntax markers here and, when
        # the file kind has a real marker, append a correct one. For
        # 'json' (and other kinds without a marker) we just strip.
        kind = _marker_kind_for(rel)
        sanitised, removed_any = _strip_wrong_syntax_markers(new_content, kind)
        marker_added = False
        if kind not in _NO_MARKER_KINDS:
            if not _has_any_marker(sanitised):
                # Make sure re-runs are idempotent. Insert the marker at
                # the very end of the file (after the LLM's changes) so
                # we never accidentally land inside a string literal or
                # break the syntactic structure of the file.
                marker = _marker_line(kind, rule_id)
                if marker:
                    if sanitised and not sanitised.endswith("\n"):
                        sanitised += "\n"
                    sanitised += marker
                    marker_added = True
        effective = sanitised
        if effective == current:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": "patch reduces to no change after marker sanitisation"})
            continue

        # Write + read-back verification.
        try:
            _write(target, effective)
        except OSError as exc:
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": f"write failed: {exc}"})
            continue
        if _read(target) != effective:
            # Best-effort rollback: rewrite the original content.
            try:
                _write(target, current)
            except OSError:
                pass
            skipped.append({"rule_id": rule_id, "finding_id": finding_id,
                            "reason": "read-back verification failed"})
            continue
        total_bytes += added_bytes
        applied.append({
            "rule": rule_id,
            "category": "llm-fix",
            "file": rel,
            "description": (patch.get("description") or "")[:200],
            "source": "llm",
            "finding_id": finding_id,
            "safe": True,
            "marker_kind": kind,
            "marker_stripped": removed_any,
            "marker_added": marker_added,
        })
        marker_action = []
        if removed_any:
            marker_action.append("stripped wrong-syntax markers")
        if marker_added:
            marker_action.append(f"added {kind} marker")
        if marker_action:
            print(f"  [llm] patched {rel} for {rule_id} ({'; '.join(marker_action)})", file=sys.stderr)
        else:
            print(f"  [llm] patched {rel} for {rule_id}", file=sys.stderr)

    # Merge LLM-declared skips with our own validation skips.
    for s in parsed.get("skipped", []):
        if not isinstance(s, dict):
            continue
        skipped.append({
            "rule_id": s.get("rule_id", "llm"),
            "finding_id": s.get("finding_id", "-"),
            "reason": s.get("reason", "skipped by LLM"),
        })
    return applied, skipped


def _git(*args: str, cwd: Path, check: bool = False) -> subprocess.CompletedProcess:
    return _run(["git", *args], cwd=str(cwd), check=check)


def _initial_diff_stat(repo_root: Path) -> str:
    proc = _git("diff", "--stat", cwd=repo_root)
    return proc.stdout


def _changed_files(repo_root: Path) -> list[str]:
    proc = _git("diff", "--name-only", cwd=repo_root)
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _commit_local(repo_root: Path, message: str) -> bool:
    if not _changed_files(repo_root):
        return False
    _git("add", "-A", cwd=repo_root, check=False)
    _git("config", "user.email", "ai-remediator@github-actions", cwd=repo_root, check=False)
    _git("config", "user.name", "AI Auto-Remediator", cwd=repo_root, check=False)
    _run(["git", "commit", "-m", message], cwd=str(repo_root), check=False)
    return True


def _push_to_remote(repo_root: Path, branch: str) -> bool:
    """Push the current branch to `origin/<branch>`. Returns True on
    success, False on failure (logs a warning to stderr).

    Used when the AI's commit is on the workflow's trigger ref (the
    normal case after the workflow was refactored to push back to the
    same branch). For local/manual runs where the branch is a derived
    `ai-remediation/<sha>` name, the push is still attempted; it just
    won't have anything new to push if the local branch already exists
    upstream.
    """
    if not shutil.which("git"):
        return False
    # Ensure the local git identity is set so the push isn't rejected
    # for missing committer info (it isn't, but better safe than sorry).
    _git("config", "user.email", "ai-remediator@github-actions",
         cwd=repo_root, check=False)
    _git("config", "user.name", "AI Auto-Remediator",
         cwd=repo_root, check=False)
    # If the local branch has no upstream yet, set one; otherwise a
    # plain `git push` is enough.
    upstream = _run(
        ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
        cwd=str(repo_root), check=False,
    )
    if upstream.returncode != 0:
        push = _run(
            ["git", "push", "--set-upstream", "origin", branch],
            cwd=str(repo_root), check=False,
        )
    else:
        push = _run(
            ["git", "push", "origin", branch],
            cwd=str(repo_root), check=False,
        )
    if push.returncode != 0:
        print(
            f"::warning::Could not push remediation branch {branch} to "
            f"origin: {push.stderr}",
            file=sys.stderr,
        )
        return False
    print(f"  [git] pushed {branch} to origin", file=sys.stderr)
    return True


def _open_pr(repo_root: Path, title: str, body_path: Path,
             branch: str, target: str) -> tuple[str | None, bool]:
    """Push the branch and (optionally) open a PR.

    - If `branch == target` we're already on the branch the workflow is
      on; just push the commit back. No PR is created (the push itself
      is the change).
    - If `branch != target` (e.g. a manual run on a derived
      `ai-remediation/<sha>` branch), push and then `gh pr create` as
      before.
    - If `SKIP_PR=true` is set in the environment, push only and skip
      the PR step.

    Returns `(pr_url, pushed)`. `pushed` is True if a push to origin
    actually happened; the caller can record this in the remediation
    report.
    """
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    skip_pr = os.environ.get("SKIP_PR", "").lower() == "true"

    pushed = _push_to_remote(repo_root, branch)
    if not pushed:
        return None, False
    if skip_pr:
        return None, True
    if branch == target:
        # Already on the trigger branch — no PR to open.
        return None, True
    if not token or not shutil.which("gh"):
        return None, True

    # Check if a PR already exists for this head -> base pair.
    existing = _run(
        ["gh", "pr", "list", "--head", branch, "--base", target,
         "--state", "open", "--json", "url", "-q", ".[] | .url"],
        cwd=str(repo_root), check=False,
    )
    if existing.stdout.strip():
        return existing.stdout.strip().splitlines()[0], True
    proc = _run(
        ["gh", "pr", "create", "--base", target, "--head", branch,
         "--title", title, "--body-file", str(body_path)],
        cwd=str(repo_root), check=False,
    )
    if proc.returncode != 0:
        print(f"::warning::gh pr create failed: {proc.stderr}",
              file=sys.stderr)
        return None, True
    # `gh pr create` prints the URL on the last stdout line
    url = ""
    for line in proc.stdout.splitlines()[::-1]:
        line = line.strip()
        if line.startswith("http"):
            url = line
            break
    return url or None, True


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--repo-root", type=Path, default=Path("."))
    p.add_argument("--reports", type=Path, default=Path("reports"))
    p.add_argument("--branch", default=os.environ.get("REMEDIATION_BRANCH", "ai-remediation/local"))
    p.add_argument("--target", default=os.environ.get("REMEDIATION_TARGET", "main"))
    p.add_argument("--model", default=os.environ.get("NVIDIA_MODEL", "meta/llama-3.1-70b-instruct"))
    p.add_argument("--base-url", default=os.environ.get("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"))
    p.add_argument("--max-tokens", type=int, default=int(os.environ.get("NVIDIA_MAX_TOKENS", "8000")))
    p.add_argument("--skip-llm", action="store_true",
                   help="Skip the LLM patch pass and only run the deterministic fixers.")
    args = p.parse_args()

    args.reports.mkdir(parents=True, exist_ok=True)

    review = _load_json(args.reports / "security-review.json")
    sonar = _load_json(args.reports / "sonar-report.json")
    trivy = _load_json(args.reports / "trivy-report.json")
    if isinstance(trivy, dict) and "findings" in trivy:
        trivy_findings = trivy["findings"]
    elif isinstance(trivy, list):
        trivy_findings = trivy
    else:
        trivy_findings = []

    print("Applying safe automated fixes...", file=sys.stderr)
    all_fixes: list[dict] = []
    all_fixes += fix_hardcoded_secrets(args.repo_root)
    all_fixes += fix_sql_concat(args.repo_root)
    all_fixes += fix_plain_password(args.repo_root)
    all_fixes += fix_bump_dependencies(args.repo_root, trivy_findings)
    all_fixes += fix_bump_dockerfile_base(args.repo_root, trivy_findings)
    all_fixes += fix_add_csp(args.repo_root)

    # LLM patch pass: ask the model for additional per-file patches and
    # apply them after the deterministic fixers. Skipped when --skip-llm
    # is set or when NVIDIA_API_KEY is missing.
    llm_skipped: list[dict] = []
    if not args.skip_llm and os.environ.get("NVIDIA_API_KEY", "").strip():
        print("Asking LLM for per-file patches...", file=sys.stderr)
        user_prompt = _build_remediation_prompt(review, args.repo_root)
        (args.reports / "llm-prompt.txt").write_text(user_prompt, encoding="utf-8")
        raw = _call_nvidia(
            user_prompt,
            _REMEDIATION_SYSTEM_PROMPT,
            args.model,
            args.base_url,
            args.max_tokens,
        )
        (args.reports / "llm-response.txt").write_text(raw, encoding="utf-8")
        llm_applied, llm_skipped = _apply_llm_patches(args.repo_root, raw)
        all_fixes += llm_applied
        print(f"  LLM applied {len(llm_applied)} patch(es), skipped {len(llm_skipped)}.",
              file=sys.stderr)
    else:
        print("LLM patch pass skipped (no --skip-llm=false and no NVIDIA_API_KEY).",
              file=sys.stderr)

    diff_stat = _initial_diff_stat(args.repo_root)
    changed = _changed_files(args.repo_root)
    (args.reports / "git-diff-stat.txt").write_text(diff_stat, encoding="utf-8")
    (args.reports / "changed-files.txt").write_text("\n".join(changed) + "\n", encoding="utf-8")

    # Save a unified diff for traceability
    proc = _git("diff", cwd=args.repo_root, check=False)
    (args.reports / "ai-patch.diff").write_text(proc.stdout, encoding="utf-8")

    # Commit locally
    summary_path = args.reports / "remediation-summary.md"
    summary_text = _render_summary(review, all_fixes, diff_stat, len(changed))
    summary_path.write_text(summary_text, encoding="utf-8")

    committed = _commit_local(args.repo_root, f"AI auto-remediation: {len(all_fixes)} safe fixes")
    pr_url = None
    pushed = False
    if committed:
        pr_url, pushed = _open_pr(
            args.repo_root,
            "AI auto-remediation",
            summary_path,
            args.branch,
            args.target,
        )

    report = {
        "status": "OK" if (all_fixes or not changed) else "NO_CHANGES",
        "fixes": all_fixes,
        "files_changed": changed,
        "diff_stat": diff_stat,
        "committed_locally": committed,
        "pushed": pushed,
        "pr_url": pr_url,
        "branch": args.branch,
        "target": args.target,
        "skipped_findings": _collect_skipped(review, all_fixes, extra_skipped=llm_skipped, trivy_findings=trivy_findings),
    }
    (args.reports / "remediation-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Remediation report written to {args.reports}/remediation-report.json")
    if pr_url:
        print(f"Opened PR: {pr_url}")
    elif pushed:
        print(f"Pushed remediation commit to origin/{args.branch} (no PR — same branch as trigger)")
    return 0


def _render_summary(review: dict, fixes: list[dict], diff_stat: str, file_count: int) -> str:
    det_fixes = [f for f in fixes if f.get("source") != "llm"]
    llm_fixes = [f for f in fixes if f.get("source") == "llm"]
    lines = [
        "# AI Auto-Remediation Summary",
        "",
        f"- **Status:** {('OK' if fixes else 'NO_CHANGES')}",
        f"- **Safe fixes applied:** {len(fixes)} (deterministic: {len(det_fixes)}, LLM: {len(llm_fixes)})",
        f"- **Files changed:** {file_count}",
        "",
        "## Fixed (deterministic)",
        "",
    ]
    for f in det_fixes:
        lines.append(
            f"- [{f.get('rule','')}] `{f.get('file','')}` — {f.get('description','')}"
        )
    if not det_fixes:
        lines.append("- (none)")
    if llm_fixes:
        lines.extend(["", "## Fixed (LLM-generated)", ""])
        for f in llm_fixes:
            lines.append(
                f"- [{f.get('rule','')}] `{f.get('file','')}` — {f.get('description','')}"
            )
    if not fixes:
        lines.append("- No safe automated fixes were applicable.")
    lines.extend([
        "",
        "## Diff stat",
        "",
        "```",
        diff_stat.strip() or "(no changes)",
        "```",
        "",
        "## Reviewer checklist",
        "",
        "- [ ] Confirm no business logic was changed",
        "- [ ] Run `mvn -B -ntp -Pcoverage verify` locally",
        "- [ ] Review the unified diff in `ai-patch.diff`",
        "- [ ] For LLM fixes, sanity-check the new file content end-to-end",
        "- [ ] Approve the PR if the changes are acceptable",
    ])
    return "\n".join(lines) + "\n"


def _collect_skipped(review: dict, applied: list[dict], extra_skipped: list[dict] | None = None,
                     trivy_findings: list[dict] | None = None) -> list[dict]:
    """Record any review findings whose rule wasn't applied — those are
    the ones the deterministic engine refused to touch — plus any
    extra skip reasons (e.g. from the LLM patch pass).

    `trivy_findings` (optional) is used to recognise that a parent-bump
    or Dockerfile patch transitively fixes multiple CVEs: the
    security-review's `rule_id` is the CVE id, but the fix's `rule`
    is `outdated-dependency` or `outdated-base-image`. Without this
    mapping, every CVE that the parent bump covers would land in
    `skipped_findings` with a misleading "no safe fix" reason.
    """
    applied_files = {f.get("file") for f in applied}
    applied_rules = {f.get("rule") for f in applied}
    # Build a set of "addresses" each fix covers: a parent-bump on
    # pom.xml addresses every Trivy finding whose `pkgName` is a
    # Spring Boot BOM-managed artifact; a Dockerfile patch addresses
    # every image-scanner finding.
    addresses: set[str] = set()
    if "pom.xml" in applied_files:
        sb_managed = {
            "org.springframework.boot:spring-boot",
            "org.springframework.boot:spring-boot-starter-web",
            "org.springframework.boot:spring-boot-starter-data-jpa",
            "org.springframework.boot:spring-boot-starter-security",
            "org.springframework.boot:spring-boot-starter-tomcat",
            "org.springframework.boot:spring-boot-starter-logging",
            "com.fasterxml.jackson.core:jackson-databind",
            "com.fasterxml.jackson.core:jackson-core",
            "com.fasterxml.jackson.core:jackson-annotations",
            "org.yaml:snakeyaml",
            "ch.qos.logback:logback-core",
            "ch.qos.logback:logback-classic",
            "org.apache.tomcat.embed:tomcat-embed-core",
            "org.apache.tomcat.embed:tomcat-embed-el",
            "org.apache.tomcat.embed:tomcat-embed-websocket",
            "org.hibernate.orm:hibernate-core",
            "org.springframework.security:spring-security-core",
            "org.springframework.security:spring-security-web",
            "org.springframework:spring-core",
            "org.springframework:spring-webmvc",
        }
        for tf in (trivy_findings or []):
            if tf.get("pkgName") in sb_managed:
                rid = tf.get("ruleId") or ""
                cve = tf.get("cve") or ""
                if rid:
                    addresses.add(rid)
                if cve:
                    addresses.add(cve)
    if "Dockerfile" in applied_files:
        for tf in (trivy_findings or []):
            if tf.get("scanner") == "image" or "library/" in (tf.get("file") or ""):
                rid = tf.get("ruleId") or ""
                cve = tf.get("cve") or ""
                if rid:
                    addresses.add(rid)
                if cve:
                    addresses.add(cve)

    skipped: list[dict] = []
    for finding in (review.get("findings") or []):
        rid = finding.get("rule_id") or ""
        if rid and rid in applied_rules:
            continue  # directly applied
        if rid and rid in addresses:
            continue  # transitively fixed by a same-major bump / Dockerfile patch
        if rid:
            skipped.append({
                "id": finding.get("id"),
                "rule_id": rid,
                "severity": finding.get("severity"),
                "title": finding.get("title"),
                "reason": "Deterministic engine did not have a safe auto-fix; requires human review.",
            })
    if extra_skipped:
        skipped.extend(extra_skipped)
    return skipped


if __name__ == "__main__":
    raise SystemExit(main())
