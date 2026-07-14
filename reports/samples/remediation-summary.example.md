# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 4
- **Files changed:** 3

## Fixed

- [hardcoded-secret] `src/main/resources/application.properties` — Removed hardcoded app.secret.* property
- [sql-injection] `src/main/java/com/owasp/lab/service/UserService.java` — Parameterised native query that previously concatenated username
- [plaintext-password] `src/main/java/com/owasp/lab/service/UserService.java` — Replaced String.equals password compare with BCryptPasswordEncoder.matches
- [missing-csp] `src/main/java/com/owasp/lab/config/SecurityConfig.java` — Added a default Content-Security-Policy header

## Diff stat

```
 pom.xml                                            |  4 ++--
 src/main/java/.../config/SecurityConfig.java       |  6 ++++++
 src/main/java/.../service/UserService.java         | 28 ++++++++++++++----------
 src/main/resources/application.properties          |  3 ---
 4 files changed, 32 insertions(+), 9 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] Approve the PR if the changes are acceptable

## Skipped findings (require human review)

| Finding | Rule | Severity | Reason |
| --- | --- | --- | --- |
| SR-005 Unsafe Java native deserialisation | `java:S5135` | HIGH | Refactor to JSON; not a safe auto-rewrite |
| (id) New product list endpoint | — | LOW | Touches routing; not safe to auto-apply |
