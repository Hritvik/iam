# Distracted Identity Platform

Central identity and authorization platform for Dutch, Midas, Jarvis, and future first-party applications.

The canonical requirements and design are in the [Identity Platform Wayfinder](docs/identity-platform/wayfinder/map.md). Start with the [Identity Platform context](docs/identity-platform/IAM-CONTEXT.md) and the [implementation plan](docs/identity-platform/wayfinder/feature-implementation-plan.md).

## Foundation status

Work Unit 1 establishes a Java 25, Spring Boot 4.1.1, Gradle 9.8.2, PostgreSQL/Flyway foundation. It contains package-boundary enforcement, safe correlation/error primitives, production-like cryptographic capability validation, a PostgreSQL Testcontainers harness, and local quality gates.

This foundation does **not** yet implement registration, authentication, OAuth endpoints, token issuance, app activation, or production signing. Those behaviors belong to later work units and must remain fail-closed until their complete contracts and tests exist.

## Verification

Requirements:

- Java 25
- Docker available through the active Docker CLI context

Run all current foundation gates:

```bash
./gradlew clean test integrationTest check
```

The build enforces at least 80% line and branch coverage. It also runs Checkstyle, rejects dynamic or snapshot production dependencies, creates a CycloneDX-compatible component inventory at `build/reports/sbom/iam.cdx.json`, and scans owned source/configuration for common hardcoded-secret assignments.

Production-like profiles (`production`, `staging`, or `production-like`) require exactly one healthy typed capability bean plus an explicit matching external reference for:

- signing provider, key ID, and algorithm;
- identifier-encryption key;
- blind-index key.

The application never generates fallback production keys.

The Gradle distribution is checksum-pinned, dependency versions are locked in `gradle.lockfile`, and dependency artifact checksums are recorded in `gradle/verification-metadata.xml`.

