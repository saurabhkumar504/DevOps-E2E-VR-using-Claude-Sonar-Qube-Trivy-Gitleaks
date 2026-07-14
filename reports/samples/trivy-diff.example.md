# Trivy Re-Scan Diff

- Before: reports/trivy-report.json (12 findings)
- After:  reports/trivy-report-after-fix.json (4 findings)

## Severity counts

| Severity | Before | After | Δ |
| --- | --- | --- | --- |
| CRITICAL | 1 | 0 | -1 |
| HIGH | 3 | 1 | -2 |
| MEDIUM | 5 | 2 | -3 |
| LOW | 3 | 1 | -2 |
| UNKNOWN | 0 | 0 | 0 |

## Totals

- **Fixed:**  8
- **Remaining:**  4
- **New:**  0

## Fixed vulnerabilities

- [CRITICAL] CVE-2024-22243 org.springframework:spring-web@6.1.14 → 6.1.15
- [HIGH] CVE-2024-22259 org.springframework:spring-web@6.1.14 → 6.1.15
- [HIGH] CVE-2023-46589 org.apache.tomcat.embed:tomcat-embed-core@10.1.30 → 10.1.31
- [MEDIUM] CVE-2024-23672 com.h2database:h2@2.2.224 → 2.2.226
- [MEDIUM] CVE-2024-22233 org.springframework:spring-beans@6.1.14 → 6.1.15
- [LOW] CVE-2023-4586 org.apache.tomcat.embed:tomcat-embed-core@10.1.30 → 10.1.31
- [LOW] CVE-2023-46589 org.apache.tomcat.embed:tomcat-embed-core@10.1.30 → 10.1.31
- [LOW] (DS027) Hardcoded secret in application.properties (removed by AI remediator)

## Remaining vulnerabilities

- [HIGH] CVE-2024-26308 ch.qos.logback:logback-classic@1.5.6 → 1.5.7 — `pom.xml`
- [MEDIUM] CVE-2024-30171 ch.qos.logback:logback-classic@1.5.6 → 1.5.7 — `pom.xml`
- [MEDIUM] (MISCONF) Running as root in Dockerfile — `Dockerfile`
- [LOW] (LICENSE) GPL-2.0 dependency detected — `pom.xml`

## Newly introduced findings

- None 🎉
