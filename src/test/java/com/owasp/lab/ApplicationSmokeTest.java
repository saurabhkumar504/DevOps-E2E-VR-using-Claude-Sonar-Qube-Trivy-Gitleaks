package com.owasp.lab;

import org.junit.jupiter.api.Test;

/**
 * Minimal smoke test used by the DevSecOps pipeline.
 *
 * <p>The pipeline relies on Surefire reports (junit.xml) and JaCoCo coverage
 * (target/site/jacoco/jacoco.xml) being produced and uploaded as artifacts.
 * Without at least one test under src/test, Surefire creates no surefire-reports
 * directory and JaCoCo's {@code report} goal (bound to the {@code verify}
 * phase) has nothing to report on, so downstream download-artifact steps fail.
 *
 * <p>This test is intentionally trivial: it does not load the full Spring
 * context (some beans in this OWASP lab are deliberately misconfigured) — it
 * simply guarantees at least one passing test, so the pipeline's test and
 * coverage jobs produce the artifacts they need.
 */
class ApplicationSmokeTest {

    @Test
    void pipeline_has_at_least_one_test() {
        // Intentional no-op: the value of this test is that it RUNS,
        // producing surefire-reports and a JaCoCo coverage entry.
    }
}
