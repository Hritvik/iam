# DEP-1 evidence — runnable IAM runtime

Date: 2026-11-05
Host: macOS, Docker 29.5.2, Compose v2
Image: `iam:local` built from this tree
Database: `postgres:18-alpine`

## What was exercised

A clean checkout with no database volume:

```bash
./deploy/generate-local-secrets.sh
docker compose up --build --detach
```

The container image builds the jar from source, runs as a non-root user, and starts the application
with the `development` profile. PostgreSQL provisions the four IAM roles before Flyway runs.

## Observed results

| Check | Result |
|---|---|
| Compose services | `postgres` healthy, `iam` healthy |
| Flyway | `Successfully applied 13 migrations to schema "public", now at version v13` |
| Startup | `Started IamApplication in 2.15 seconds` |
| Registration | `Pinned registration created; appRegistrationId=dutch-development; manifestVersion=1` |
| Readiness probe | `{"status":"UP"}` |
| Liveness probe | `{"status":"UP"}` |
| Discovery | `/.well-known/oauth-protected-resource` returns the Dutch resource, issuer and scopes |
| Registration row | `dutch-development / development / dutch-mobile / eb19d5cd14c2…` |
| Migration history | 13 applied, 0 failed |
| Roles | `iam_migrator, iam_registration_reconciler, iam_relay, iam_runtime` |
| Schema ownership | `app_registration` owned by `iam_migrator` |
| Runtime authority | member of `iam_runtime`, not of `iam_registration_reconciler` |
| Reconciler authority | member of `iam_registration_reconciler`, not of `iam_runtime` |

Actuator exposure:

| Path | Status |
|---|---|
| `/actuator/health` | 200 |
| `/actuator/health/readiness` | 200 |
| `/actuator/health/liveness` | 200 |
| `/actuator/info` | 401 |
| `/actuator/env` | 401 |

## Build and test gate

```text
unit tests           374 passed
integration tests    319 passed
contract tests         8 passed
checkstyle            passed
secret scan           passed
dependency policy     passed
coverage              line and branch thresholds met
```

## Deliberate gaps

- The local keyring is bound to the `development` profile. Staging and production still fail closed
  until DEP-4 supplies real key custody.
- The advertised issuer is `https://iam.localhost`; there is no local TLS listener.
- Identity fixtures stay off because the deterministic fixture runner is a test surface.
- Outbox delivery, workload identity, backups, alerts and SLOs belong to DEP-2, DEP-3 and DEP-6.

## 2026-11-08 review follow-up

The independent review reproduced readiness staying UP after PostgreSQL stopped. The development
profile now includes database health in readiness and bounds the local connection and validation
timeouts. Liveness remains independent of PostgreSQL. The isolated Compose smoke using the
fresh Dockerfile build passed:

| Step | Readiness | Liveness |
|---|---|---|
| Fresh PostgreSQL volume, 13 migrations, Dutch development registration | 200 UP | 200 UP |
| PostgreSQL stopped | 503 DOWN | 200 UP |
| PostgreSQL restarted | 200 UP | 200 UP |

The rendered Compose configuration keeps PostgreSQL off host ports, publishes IAM on IPv4 loopback,
checks PostgreSQL initialization over TCP, and excludes the database superuser and relay passwords
from the IAM process. The mixed-profile regression cases now exclude the local signer whenever
staging, production, or production-like is active. The signer rejects secp256k1 at construction.

The Docker build passed with the digest-pinned Gradle 9.8.2 builder and strict dependency
verification. The clean build exposed missing metadata checksums that the host cache had masked.
Each SHA-256 pin was computed from Maven Central bytes checked against its published digest.
The tested image manifest digest was
`sha256:4065617bbd9754d6cccdb084ff12b201fa2379c9cb17ad59c76f02fcf80b4706`.

`PORT=0 ./gradlew --offline --dependency-verification=strict check jacocoTestReport bootJar`
passed 380 unit, 319 integration, and 8 contract tests, plus Checkstyle, dependency policy,
secret scan, and the coverage gate (92.47% line and 80.26% branch). The ephemeral test port
avoided an existing local listener.
