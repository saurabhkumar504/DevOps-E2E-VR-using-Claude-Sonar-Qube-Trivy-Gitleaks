package com.owasp.lab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;

/**
 * Loads hardcoded "secrets" from application.properties into the Spring
 * context so we can demonstrate A02:2021 (Cryptographic Failures).
 *
 * VULNERABILITY (OWASP A02:2021 - Cryptographic Failures /
 *                OWASP A05:2021 - Security Misconfiguration):
 *  - Secrets are stored in plaintext in application.properties.
 *  - They are exposed in source control.
 *  - They are injected into beans and could be leaked via /env or
 *    /actuator endpoints (which we deliberately also expose in the demo).
 */
@Configuration
public class SecretConfig {

    @Value("${app.secret.api.key}")
    private String apiKey;

    @Value("${app.secret.db.password}")
    private String dbPassword;

    @Value("${app.secret.jwt.signing.key}")
    private String jwtSigningKey;

    @Bean(name = "apiKey")
    public String apiKey() {
        return apiKey;
    }

    @Bean(name = "dbPassword")
    public String dbPassword() {
        return dbPassword;
    }

    @Bean(name = "jwtSigningKey")
    public String jwtSigningKey() {
        return jwtSigningKey;
    }
}
