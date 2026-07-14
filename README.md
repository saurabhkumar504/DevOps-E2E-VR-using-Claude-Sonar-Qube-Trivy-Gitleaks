# OWASP Vulnerability Learning Lab (Spring Boot 3)

## ⚠️ WARNING — EDUCATIONAL USE ONLY ⚠️

**DO NOT deploy this application to any public server, container image registry, or shared network.** Every endpoint in this project is **intentionally insecure**. The goal is to demonstrate — in a local, isolated sandbox — how the OWASP Top 10 (2021) issues look in a real Spring Boot codebase, so that defenders can recognise, exploit (legally) and ultimately fix them.

> "Anyone who has never made a mistake has never tried anything new." — Einstein
> Just don't deploy this on the open internet.

---

## Project purpose

This is an **OWASP Top 10 (2021) learning lab**. It bundles a single Spring Boot 3 / Java 17 application whose every controller and service exhibits at least one well-known security flaw, with `// VULNERABILITY:` comments pointing to the exact line and the relevant OWASP category.

The application runs against an in-memory H2 database, pre-seeded with sample users, products and comments.

---

## Build & run

```bash
mvn clean package
mvn spring-boot:run
```

Application starts on `http://localhost:8080`.
H2 console: `http://localhost:8080/h2-console` (JDBC URL `jdbc:h2:mem:owaspdb`, user `sa`, empty password).

---

## Sample data (seeded on startup)

| Username | Password (plain text!) | Role  | Balance |
|----------|------------------------|-------|---------|
| alice    | alice123               | USER  | 1000.0  |
| bob      | bob123                 | USER  |  500.0  |
| admin    | admin123               | ADMIN | 9999.0  |

---

## Vulnerabilities implemented (OWASP Top 10 — 2021)

| #  | OWASP category                                  | Where                                                                                |
|----|--------------------------------------------------|--------------------------------------------------------------------------------------|
| A01 | Broken Access Control (IDOR)                     | `GET /api/profile/{id}`, `GET /api/users`, `POST /api/transfer`                      |
| A02 | Cryptographic Failures (plain-text passwords)    | `User.password` field, `UserService.loginUnsafe`, hardcoded secrets in `application.properties` |
| A03 | Injection (SQLi + XSS)                           | `GET /api/search`, `POST /api/login`, `GET /api/comment/greet`, `GET /comments` (stored XSS) |
| A04 | Insecure Design                                  | No rate-limiting, no security headers, transfer endpoint accepts arbitrary `fromId`   |
| A05 | Security Misconfiguration                        | `SecurityConfig` — CSRF disabled, `permitAll` everywhere, frame options disabled     |
| A07 | Identification & Authentication Failures         | Plain-text password compare, login returns password in response                      |
| A08 | Software & Data Integrity Failures               | `POST /api/deserialize` — unsafe Java native deserialisation                         |
| A09 | Security Logging & Monitoring Failures           | No audit logging, no alerting on SQL injection attempts                              |
| A10 | Server-Side Request Forgery (SSRF)               | Not implemented here, but the codebase has no allowlist for outbound HTTP calls     |

---

## Vulnerable endpoints — quick reference

| Method | URL                            | Vulnerability demo                                          |
|--------|--------------------------------|-------------------------------------------------------------|
| GET    | `/vulnerabilities`             | Renders the index page (also leaks hardcoded secrets)       |
| GET    | `/api/users`                   | Lists every user (no auth) — A01                            |
| GET    | `/api/profile/{id}`            | IDOR — read any user by numeric id                          |
| GET    | `/api/search?q=' OR '1'='1`    | **SQL injection** — concatenates `q` into the SQL string    |
| POST   | `/api/login`                   | **SQL injection** + plain-text password compare             |
| POST   | `/api/register`                | Stores plain-text password                                  |
| POST   | `/api/transfer`                | Unauthenticated transfer, CSRF disabled globally            |
| GET    | `/api/comment/greet?name=<script>alert(1)</script>` | **Reflected XSS**                  |
| POST   | `/api/comment`                 | **Stored XSS** — submit, then visit `/comments`             |
| GET    | `/comments`                    | Renders stored comments as raw HTML (XSS sink)              |
| POST   | `/api/deserialize`             | **Unsafe Java deserialisation** — base64 body, `readObject`|

### Try SQL injection

```bash
# Login bypass
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"\" OR \"1\"=\"1","password":"anything"}'

# Search dump
curl "http://localhost:8080/api/search?q=' OR '1'='1"
```

### Try reflected XSS

```
http://localhost:8080/api/comment/greet?name=<script>alert('XSS')</script>
```

### Try stored XSS

```bash
# 1. Submit a malicious comment
curl -X POST http://localhost:8080/api/comment \
  -H "Content-Type: application/json" \
  -d '{"author":"attacker","body":"<script>alert(document.cookie)</script>"}'

# 2. Visit the HTML page that renders it
http://localhost:8080/comments
```

### Try unsafe deserialisation (advanced)

Generate a payload with ysoserial and base64 it, then POST to `/api/deserialize`:

```bash
java -jar ysoserial.jar CommonsCollections6 "calc.exe" | base64 | \
  curl -X POST --data-binary @- http://localhost:8080/api/deserialize
```

---

## How to fix each issue (for study)

| Vulnerability           | Fix                                                                              |
|-------------------------|----------------------------------------------------------------------------------|
| SQL injection           | Use JPA / JdbcTemplate with `?` placeholders. Validate input.                   |
| XSS (reflected/stored)  | Encode output, set `Content-Security-Policy`, sanitise with OWASP Java Encoder.  |
| CSRF                    | Leave Spring Security's CSRF protection **enabled** for browser clients.         |
| Plain-text passwords    | Hash with bcrypt / argon2 (e.g. `BCryptPasswordEncoder`).                        |
| Hardcoded secrets       | Use environment variables or a secrets manager; never commit `.properties`.     |
| IDOR                    | Authorise every request — check `principal.id == resource.ownerId`.             |
| Insecure deserialisation| Use JSON / Protobuf, or `ObjectInputStream` with a strict allowlist filter.     |
| Missing rate-limit      | Use Bucket4j / Spring Cloud Gateway limits / fail2ban.                           |
| Missing logging         | Log auth events to a SIEM; alert on repeated SQL errors.                         |

---

## File map

```
src/main/java/com/owasp/lab
├── VulnerableSpringAppApplication.java   # Spring Boot main
├── config/
│   ├── SecurityConfig.java               # CSRF off, permitAll
│   ├── SecretConfig.java                 # Hardcoded secrets injected
│   └── DataSeeder.java                   # Seeds sample data
├── controller/
│   ├── AuthController.java               # /api/login, /api/register, /api/transfer
│   ├── UserController.java               # /api/users, /api/profile/{id}, /api/search
│   ├── ProductController.java            # /api/products
│   ├── CommentController.java            # /api/comment + reflected XSS
│   ├── CommentViewController.java        # /comments (stored XSS)
│   ├── InsecureDeserializationController.java
│   └── VulnerabilityController.java      # /vulnerabilities index
├── model/
│   ├── User.java                         # Plain-text password field
│   ├── Product.java
│   └── Comment.java
├── repository/
│   ├── UserRepository.java
│   ├── ProductRepository.java
│   └── CommentRepository.java
└── service/
    ├── UserService.java                  # Unsafe SQL + unsafe login
    ├── ProductService.java
    └── CommentService.java

src/main/resources/
└── application.properties               # Hardcoded secrets (A02 / A05)
```

---

## Final reminder

> This codebase is a **controlled, classroom weapon**. Keep it on your laptop, in a VM, or behind a firewall that only you can reach. Run, observe, patch, repeat.
