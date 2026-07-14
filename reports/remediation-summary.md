# AI Auto-Remediation Summary

- **Status:** OK
- **Safe fixes applied:** 1 (deterministic: 1, LLM: 0)
- **Files changed:** 7

## Fixed (deterministic)

- [outdated-base-image] `Dockerfile` — Added `apt-get upgrade -y` to runtime stage to remediate image-level OS-package CVEs (26 findings, e.g. bsdutils, libblkid1, libc-bin, libc6, libexpat1)

## Diff stat

```
Dockerfile                   |   1 +
 reports/SONAR_REPORT.md      |  16 +-
 reports/llm-prompt.txt       |   9 ++
 reports/sonar-report.json    |  20 +--
 reports/sonar-report.txt     |   2 +-
 reports/trivy-image.raw.json | 360 +++++++++++++++++++++----------------------
 reports/trivy-image.sarif    |   6 +-
 7 files changed, 209 insertions(+), 205 deletions(-)
```

## Reviewer checklist

- [ ] Confirm no business logic was changed
- [ ] Run `mvn -B -ntp -Pcoverage verify` locally
- [ ] Review the unified diff in `ai-patch.diff`
- [ ] For LLM fixes, sanity-check the new file content end-to-end
- [ ] Approve the PR if the changes are acceptable
