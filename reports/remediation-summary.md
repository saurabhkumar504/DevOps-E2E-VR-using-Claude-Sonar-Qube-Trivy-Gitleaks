# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 3 (deterministic: 3, LLM: 0)
- **Files changed:** 10

## Fixed (deterministic)

- [sql-injection] `src/main/java/com/owasp/lab/service/UserService.java` — Parameterised native query that previously concatenated username into sql
- [plaintext-password] `src/main/java/com/owasp/lab/service/UserService.java` — loginUnsafe no longer concatenates password into the SQL; compares the password in Java with a TODO marker for BCrypt
- [outdated-base-image] `Dockerfile` — Added `apt-get upgrade -y` to runtime stage to remediate image-level OS-package CVEs (22 findings, e.g. bsdutils, libblkid1, libc-bin, libc6, libexpat1)

## Diff stat

```
Dockerfile                                         |   1 +
 reports/SONAR_REPORT.md                            |  14 +-
 reports/llm-prompt.txt                             |   9 +
 reports/sonar-report.json                          |   8 +-
 reports/sonar-report.txt                           |   2 +-
 reports/trivy-image.raw.json                       | 364 ++++++++++-----------
 reports/trivy-image.sarif                          |  12 +-
 reports/trivy-image.sarif.json                     |   4 +-
 reports/trivy-report.json                          |   4 +-
 .../java/com/owasp/lab/service/UserService.java    |  27 +-
 10 files changed, 230 insertions(+), 215 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] For LLM fixes, sanity-check the new file content end-to-end
- [ ] Approve the PR if the changes are acceptable
