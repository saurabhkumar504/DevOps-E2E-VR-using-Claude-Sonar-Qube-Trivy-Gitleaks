package com.owasp.lab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * OWASP VULNERABILITY LEARNING LAB.
 *
 * This application is INTENTIONALLY INSECURE.
 * Do NOT deploy it to any public environment.
 */
@SpringBootApplication
public class VulnerableSpringAppApplication {

    public static void main(String[] args) {
        SpringApplication.run(VulnerableSpringAppApplication.class, args);
    }
}
