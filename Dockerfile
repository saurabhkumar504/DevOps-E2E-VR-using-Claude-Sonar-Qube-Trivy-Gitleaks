# syntax=docker/dockerfile:1.6
#
# Multi-stage build for the OWASP vulnerability learning lab.
# Builder:  compiles the Spring Boot fat JAR with Maven.
# Runtime: minimal JRE 21 image that runs the JAR as a non-root user.
#
# Build:  docker build -t vulnerable-spring-app:ci .
# Run:    docker run --rm -p 8080:8080 vulnerable-spring-app:ci
#
# Image-scan target (used by the CI pipeline): the resulting image is fed
# to `trivy image` so OS-level CVEs and library-level CVEs inside the
# fat JAR are both reported.

# ---------- Builder ----------
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /build

# Cache dependencies first to speed up rebuilds.
COPY pom.xml ./
RUN mvn -B -ntp dependency:go-offline

# Copy the source and build the fat JAR (skip tests — the CI unit-test
# job runs them separately via `mvn test`).
COPY src ./src
RUN mvn -B -ntp -DskipTests package \
 && cp target/vulnerable-spring-app-*.jar /build/app.jar

# ---------- Runtime ----------
# eclipse-temurin:21-jre-jammy is a small Ubuntu-based JRE 21 image.
# `jammy` (= Ubuntu 22.04) is a long-term support release so security
# updates keep flowing.
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app

# OS-level hygiene: keep the image small, then create an unprivileged user
# and switch to it. The OWSAP lab exercises SQLi / XSS / SSRF etc. in the
# application, so isolating the runtime from root is a useful baseline.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get upgrade -y --no-install-recommends \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1001 app \
 && useradd  --system --uid 1001 --gid app --home /app --shell /usr/sbin/nologin app

COPY --from=builder /build/app.jar /app/app.jar
RUN chown -R app:app /app

USER app

# tini reaps zombie processes and forwards signals cleanly; without it
# `docker stop` doesn't get a chance to flush the JVM.
ENTRYPOINT ["/usr/bin/tini", "--", "java", "-jar", "/app/app.jar"]

EXPOSE 8080

# TCP liveness probe — confirms the JVM is listening on the application
# port. (An HTTP probe to /actuator/health would be nicer, but this
# project does not include spring-boot-starter-actuator, and a curl
# against / would hit the security chain and return a non-2xx. A raw
# TCP open is the right primitive for "is the JVM up?".)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8080' || exit 1
