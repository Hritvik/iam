# IAM implementation onboarding

This is the durable entrypoint for an agent continuing the IAM-to-Dutch onboarding effort. Repository artifacts are authoritative; chat history and optional memory are discovery aids only.

## Read in this order

1. [Scope boundary](../artifacts/scope-boundary.md)
2. [Implementation plan](../feature-implementation-plan.md)
3. [Program work items](../work-items.md)
4. The active board named below, its packet, and referenced decision artifact
5. Current source and tests for the packet's owned paths

The work remains a development proving milestone. Cloud selection and production capability provisioning are separate efforts. Do not commit or push unless the user explicitly asks.

## Program status

| Work item | State | Accepted evidence |
|---|---|---|
| W-1 protected identifiers | Accepted | 71 unit, 37 PostgreSQL integration, 8 contract tests; [evidence](../artifacts/work-unit-04-red-green.md) |
| W-2 deterministic gated identity | Accepted | 139 unit, 47 PostgreSQL integration, 8 contract tests; [evidence](../artifacts/work-item-02-red-green.md) |
| W-3 pinned Dutch registration | Accepted | 190 unit, 174 PostgreSQL integration, 8 contract tests; [evidence](../artifacts/work-item-03-red-green.md) |
| W-4 single-use authorization code | Accepted | 239 unit, 243 PostgreSQL integration, 8 contract tests; 93.93% line / 80.54% branch; [evidence](../artifacts/work-item-04-red-green.md) |
| W-5 app-isolated subjects | Accepted | 247 unit, 267 PostgreSQL integration, 8 contract tests; 93.92% line / 80.90% branch; [evidence](../artifacts/work-item-05-red-green.md) |
| W-6 closed signed access token/JWKS | Accepted | 278 unit, 270 PostgreSQL integration, 8 contract tests; 94.17% line / 81.06% branch; [evidence](../artifacts/work-item-06-red-green.md) |
| W-7 native DPoP and replay protection | Accepted | 329 unit, 289 PostgreSQL integration, 8 contract; 92.93% line / 80.12% branch; [W-7 evidence](w07/evidence/W07-F.md) |
| W-8 strict Dutch activation | Accepted | 347 unit, 309 PostgreSQL integration, 8 contract; 92.71% line / 80.10% branch; [W-8 evidence](w08/evidence/W08-F.md) |
| W-9 onboarding relay + snapshot | Accepted | 360 unit, 319 PostgreSQL integration, 8 contract; 92.48% line / 80.16% branch; [W-9 evidence](w09/evidence/W09-F.md) |
| W-10 Dutch mapping/profile contracts | Accepted | 0 validation issues, 10/10 contract tests; [Dutch W-10 board](../../../../dutch/docs/wayfinder/w10/README.md) |
| W-11 UMS onboarding consumer | Accepted | 18 tests, 0 skipped (JDK 21, PostgreSQL 16); [Dutch W-11 board](../../../../dutch/docs/wayfinder/w11/README.md) |
| W-12 through W-14 | Planned | Decompose just in time from [work-items.md](../work-items.md) after dependencies are accepted |

All accepted items received independent correctness/database and security/privacy review with no unresolved critical, high, or medium findings. Their status in `work-items.md` is the program authority.

## Current resume point: W-12

W-11 is complete and accepted in the Dutch repository. UMS now consumes
`iam.app-subject.onboarding-ready.v1` idempotently in its own database: app-scoped profile, producer-keyed
inbox with fingerprint, durable `PAYLOAD_CONFLICT` quarantine, one Dutch mapping event per onboarding, and
a database-role negative proving it cannot reach IAM persistence. The UMS gate is 18 tests, 0 skipped.

Residual lows are recorded in `w11/README.md`: reorder/gap and checkpoint monotonicity (W-13), the
quarantine's second pooled connection, `dutch.environment` defaulting to development, and Testcontainers
skipping when Docker is absent.

**W-12** is next: serve honest profile-required/ready states — `GET /api/v1/me/profile-state`, the
`409 profile_required` split, `cor_` correlation and the IAM error envelope, with no identity leakage.

## Future sequence

After W-11 acceptance:

1. **W-12** serves honest profile-required/profile-ready states with standard errors and correlation IDs.
2. **W-13** proves duplicate delivery, downtime, lost acknowledgement, and snapshot repair end to end without cross-service database access.
3. **W-14** assembles the clean development-milestone evidence and independent reviews.

Create a work-packet sub-board for each item only when its dependencies are accepted. Contract ownership crosses into the versioned `contracts/**` artifacts at W-10. UMS implementation begins at W-11 in its own repository and database.

## Non-negotiable boundaries

- IAM owns identities, verified identifiers, OAuth/OIDC authority, sessions, refresh families, credentials, and PII.
- UMS owns Member Profiles and consumes only PII-free lifecycle data.
- Raw email/phone, credentials, authorization codes, access tokens, refresh tokens, proof material, and protected digests stay out of UMS, events, logs, metrics, traces, and API responses except where the OAuth wire protocol explicitly requires the token response.
- Services keep independent databases; no cross-service database access.
- Production-like profiles require external signing, digest protection, distributed limiting, and trusted origin/proxy capabilities and fail closed without them.
- Preserve existing work and contracts; use parameterized persistence; keep refresh, OIDC/ID tokens, and unrelated endpoints outside a packet unless its accepted authority explicitly includes them.

## Repository caveat

This checkout has previously lacked usable Git metadata, so `git diff/status` may be unavailable. File ownership, board revisions, evidence, conflict-marker scans, and clean gates are therefore especially important. Never infer that an untracked change is disposable, and do not revert another agent's work.
