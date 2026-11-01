# W-9 follow-up hardening — quarantine audit and snapshot cache headers

- Date: 2026-10-31
- Scope: IAM-only residual lows recorded by W09-RS/W09-RC. No UMS files touched.

## Changes

- `V13__relay_quarantine_audit.sql` grants `append_audit_fact` execution to `iam_relay`.
- `OnboardingRelay` now writes an immutable `OUTBOX_DELIVERY_QUARANTINED` audit fact (subject EVENT,
  outcome FAILED, fixed reason) after a successful quarantine, via the new repository method.
- The app-scoped snapshot returns `Cache-Control: no-store` and `Pragma: no-cache` on both success and
  error responses.

## Verification

`./gradlew clean test integrationTest contractTest check contractBundle` — BUILD SUCCESSFUL.
360 unit, 319 PostgreSQL integration, 8 contract tests.

New assertions: relay unit test observes the audit call; the PostgreSQL relay test reads the audit row
(fact type, outcome, reason, event id); the snapshot HTTP test asserts both cache headers on 200 and 404.

## Still open (deployment / later work)

- Relay scheduling and a production `OutboxTransport`.
- Production mTLS workload authenticator.
- Snapshot rate limiting (contract advertises 429/503).
- V12 app binding lives in the controller, not the database role.
