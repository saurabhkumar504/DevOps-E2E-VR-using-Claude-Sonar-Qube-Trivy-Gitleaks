package com.owasp.lab.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration.
 *
 * VULNERABILITY (OWASP A01:2021 - Broken Access Control /
 *                OWASP A05:2021 - Security Misconfiguration):
 *  - CSRF is DISABLED for state-changing endpoints (POST/PUT/DELETE).
 *  - All endpoints are permitted without authentication.
 *  - No authorization checks anywhere.
 *
 * This is INTENTIONALLY INSECURE. Do NOT copy this configuration.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain insecureFilterChain(HttpSecurity http) throws Exception {
        http
            // VULNERABILITY (A05:2021): disable CSRF protection entirely.
            .csrf(csrf -> csrf.disable())

            // VULNERABILITY (A01:2021): allow every request without auth.
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())

            // VULNERABILITY (A05:2021): keep no server-side session state
            // (acceptable) but also no logout / no auth headers, which
            // removes defence-in-depth.
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // VULNERABILITY (A05:2021): disable frame options on H2 console
            // (acceptable for local lab) - but combined with no auth, also bad.
            // VULNERABILITY FIX (AI auto-remediation, marker FIX_CSP_APPLIED): added Content-Security-Policy header
            .headers(h -> h.frameOptions(f -> f.disable().contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'self'; object-src 'none'"))));

        return http.build();
    }
}
