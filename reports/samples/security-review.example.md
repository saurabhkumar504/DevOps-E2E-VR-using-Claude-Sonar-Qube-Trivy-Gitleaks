# Security Review

**Status:** `OK`  
**Overall Risk Score:** 86  
**Overall Priority:** P0  

## Executive Summary

SonarCloud reports 14 issues including 2 critical (raw SQL concatenation, hardcoded JWT signing key), 5 high (plaintext passwords, XSS sinks, unsafe deserialisation), 5 medium (code smells) and 2 low (duplication). Quality gate is currently FAIL — primarily due to the critical security findings. Two new vulnerabilities were introduced this iteration (a missing CSRF token check in AuthController and a new SQL query in ProductService).

## Findings

### SR-001 — [CRITICAL] User input concatenated into a native SQL query (SQL injection)

- **Priority:** P0
- **Category:** vulnerability
- **CWE:** CWE-89
- **OWASP:** A03:2021-Injection
- **Location:** `src/main/java/com/owasp/lab/service/UserService.java:39`
- **Rule:** `java:S2077`
- **Root cause:** UserService.findByUsernameUnsafe concatenates the request parameter directly into a native SQL string, allowing arbitrary query fragments.
- **Evidence:** `String sql = "SELECT * FROM users WHERE username = '" + username + "'";`
- **Suggested fix:** Use a parameterised query or a JPA derived method: `userRepository.findByUsername(String)`.
- **Risk score:** 95/100

### SR-002 — [CRITICAL] Hardcoded JWT signing key

- **Priority:** P0
- **Category:** secret
- **CWE:** CWE-798
- **OWASP:** A07:2021-Identification and Authentication Failures
- **Location:** `src/main/resources/application.properties:27`
- **Rule:** `java:S6418`
- **Evidence:** `app.secret.jwt.signing.key=this-is-a-hardcoded-jwt-signing-key-for-demo-only`
- **Suggested fix:** Move the key to a secret manager or environment variable; load it via @Value("${app.secret.jwt.signing.key:#{null}}") and fail fast on startup if absent.
- **Risk score:** 90/100

### SR-003 — [HIGH] Plaintext password comparison

- **Priority:** P1
- **Category:** vulnerability
- **CWE:** CWE-256
- **OWASP:** A02:2021-Cryptographic Failures
- **Location:** `src/main/java/com/owasp/lab/service/UserService.java:60`
- **Rule:** `java:S6437`
- **Evidence:** `String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";`
- **Suggested fix:** Hash the stored password with BCryptPasswordEncoder and call matches(rawPassword, hashed) at login time.
- **Risk score:** 80/100

### SR-004 — [HIGH] Reflected XSS in /api/comment/greet

- **Priority:** P1
- **Category:** vulnerability
- **CWE:** CWE-79
- **OWASP:** A03:2021-Injection
- **Location:** `src/main/java/com/owasp/lab/controller/CommentController.java:27`
- **Rule:** `java:S5131`
- **Evidence:** `@GetMapping("/greet") public String greet(@RequestParam String name) { return "Hello " + name; }`
- **Suggested fix:** Use the OWASP Java Encoder (Encode.forHtml(name)) or Thymeleaf with auto-escaping enabled.
- **Risk score:** 75/100

### SR-005 — [HIGH] Unsafe Java native deserialisation

- **Priority:** P1
- **Category:** vulnerability
- **CWE:** CWE-502
- **OWASP:** A08:2021-Software and Data Integrity Failures
- **Location:** `src/main/java/com/owasp/lab/controller/InsecureDeserializationController.java:24`
- **Rule:** `java:S5135`
- **Evidence:** `ObjectInputStream ois = new ObjectInputStream(bais); return ois.readObject();`
- **Suggested fix:** Replace with JSON (Jackson) and validate the shape; if Java serialisation is required, use a Look-ahead ObjectInputStream with an allowlist filter.
- **Risk score:** 80/100

### SR-006 — [MEDIUM] CSRF protection disabled globally

- **Priority:** P2
- **Category:** misconfig
- **CWE:** CWE-352
- **OWASP:** A05:2021-Security Misconfiguration
- **Location:** `src/main/java/com/owasp/lab/config/SecurityConfig.java:18`
- **Rule:** `java:S4502`
- **Evidence:** `http.csrf(csrf -> csrf.disable())`
- **Suggested fix:** Remove the disable() call. Use CookieCsrfTokenRepository.withHttpOnlyFalse() for SPA frontends.
- **Risk score:** 55/100
