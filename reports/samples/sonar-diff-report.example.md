# SonarCloud Re-Scan Diff Report

> Note: the initial SonarCloud scan was skipped (missing token). Only the post-fix scan was available; the diff below is informational.

- Before: reports/sonar-report.json (Quality Gate: UNKNOWN)
- After:  reports/sonar-report-after-fix.json (Quality Gate: OK)

## Severity counts

| Severity | Before | After | Δ |
| --- | --- | --- | --- |
| BLOCKER | 0 | 0 | 0 |
| CRITICAL | 2 | 0 | -2 |
| MAJOR | 7 | 3 | -4 |
| MINOR | 4 | 2 | -2 |
| INFO | 1 | 0 | -1 |

## Totals

- Total issues before: 14
- Total issues after:  5
- **Fixed:**  9
- **Remaining (still present after re-scan):**  5
- **New (introduced by remediation):**  0

## Fixed issues

- [CRITICAL] VULNERABILITY **java:S2077** — `src/main/java/com/owasp/lab/service/UserService.java:39` — User input concatenated into a native SQL query (SQL injection)
- [CRITICAL] VULNERABILITY **java:S6418** — `src/main/resources/application.properties:27` — Hardcoded JWT signing key
- [HIGH] VULNERABILITY **java:S6437** — `src/main/java/com/owasp/lab/service/UserService.java:60` — Plaintext password comparison
- [HIGH] VULNERABILITY **java:S5131** — `src/main/java/com/owasp/lab/controller/CommentController.java:27` — Reflected XSS in /api/comment/greet
- [MEDIUM] CODE_SMELL **java:S3776** — `src/main/java/com/owasp/lab/controller/AuthController.java:48` — Cognitive Complexity too high
- [MEDIUM] CODE_SMELL **java:S1192** — `src/main/java/com/owasp/lab/service/UserService.java:39` — String literal duplicated
- [MINOR] CODE_SMELL **java:S1481** — `src/main/java/com/owasp/lab/service/ProductService.java:12` — Unused local variable
- [MINOR] CODE_SMELL **java:S1854** — `src/main/java/com/owasp/lab/controller/UserController.java:55` — Dead store
- [INFO] CODE_SMELL **java:S106** — `src/main/java/com/owasp/lab/service/UserService.java:40` — Use of System.out.println

## Remaining issues

- [HIGH] VULNERABILITY **java:S5135** — `src/main/java/com/owasp/lab/controller/InsecureDeserializationController.java:24` — Unsafe Java native deserialisation
- [MEDIUM] VULNERABILITY **java:S4502** — `src/main/java/com/owasp/lab/config/SecurityConfig.java:18` — CSRF protection disabled globally
- [MEDIUM] CODE_SMELL **java:S3776** — `src/main/java/com/owasp/lab/controller/AuthController.java:48` — Cognitive Complexity too high
- [MAJOR] BUG **java:S2259** — `src/main/java/com/owasp/lab/service/UserService.java:43` — NullPointerException could be thrown
- [MINOR] CODE_SMELL **java:S1481** — `src/main/java/com/owasp/lab/service/ProductService.java:12` — Unused local variable

## Newly introduced issues

- None 🎉
