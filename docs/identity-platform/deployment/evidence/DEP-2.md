# DEP-2 evidence — production outbox transport and relay scheduler

Date: 2026-11-08
Environment: local development runtime and unit test JVM

## Implementation

| Element | Behaviour |
|---|---|
| `HttpOutboxTransport` | Posts the published event envelope over HTTPS with a workload bearer token |
| Endpoint safety | HTTPS required; plain HTTP only for loopback hosts |
| Headers | `Authorization: Bearer`, `Content-Type: application/json`, `Accept`, `Idempotency-Key` = event id, `X-Correlation-ID` |
| Success | Any 2xx is acknowledged |
| Retry | 401, 403, 404, 408, 429, 5xx, connection failure and timeout are retryable within the attempt budget |
| Quarantine | Any other 4xx is non-retryable and goes to quarantine |
| `SelfIssuedWorkloadTokenSupplier` | Mints a fresh `workload_access` token per delivery attempt; the event id stays the idempotency key |
| `RelayScheduler` | Fixed-delay drain with lease-safe concurrent replicas |
| Visibility | `iam.relay.deliveries{outcome=claimed, published, acknowledged, quarantined}` |

Wiring:

- `iam.messaging.relay.transport.mode=http` selects the transport.
- `iam.messaging.relay.transport.endpoint` is the consumer ingestion URL. The development defaults
  are the UMS-published values: issuer `https://iam.example.test`, endpoint
  `https://ums.example.test/internal/iam/events`, audience
  `https://ums.example.test/internal/iam/events`, scope `ums:onboarding:write`.
- The relay binding is minted once at startup; an unregistered workload, audience or scope fails
  startup with `relay_workload_binding_invalid`, and a later mint failure is a retryable transport
  failure rather than an uncaught exception.
- `iam.messaging.relay.schedule.enabled=true` starts the scheduler.
- The relay connects as `iam_relay`, never as the runtime or migration role.
- `compose.yaml` passes the relay and workload variables explicitly; the development runtime starts
  with `IAM_WORKLOAD_ENABLED=true` and `IAM_MESSAGING_ENABLED=true`.
- A missing issuer, endpoint, workload id, audience, scope or timeout fails startup; there is no
  test-only transport in the runtime path.

## Tests

```text
unit tests         411 passed
integration tests  319 passed
contract tests       8 passed
```

Focused coverage:

- The posted body is the published event envelope: `eventId`, `eventType`, `schemaVersion`,
  `occurredAt`, `producer`, `environment`, `aggregate`, `correlationId`, `causationId`,
  `destination.appRegistrationId`, and the parsed payload.
- `Authorization`, `Idempotency-Key` and `X-Correlation-ID` are exactly the expected values; the
  Bearer scheme is accepted case-insensitively.
- 200, 201, 202 and 204 are accepted; 400 and 422 are non-retryable; 401, 403, 404, 408, 429, 503
  and an unreachable consumer are retryable.
- An unregistered relay binding fails startup, and a mint failure during publish is a retryable
  transport failure, so claimed events do not stay leased forever.
- Missing, blank and malformed tokens are rejected before the request.
- Non-loopback plain HTTP, missing hosts, userinfo, query strings, fragments, and unbounded
  connect/request timeouts are refused.
- A fresh token is minted for every attempt: two attempts for the same event carry the same
  `Idempotency-Key` and different `jti` values.
- Scheduler counters reflect claimed, published, acknowledged and quarantined outcomes, and a
  repository failure does not escape the scheduled drain.

`RelayDeliveryScenarioTest` proves the consumer-facing sequence end to end with a real HTTP
consumer and the real relay:

- Two distinct events are posted and acknowledged.
- A 500 response to the third event is retried in a second drain with the same event id and
  `Idempotency-Key` but a new `jti`; it is acknowledged only after the 2xx.
- A duplicate delivery of the first event reaches the consumer with the same idempotency key.
- Acknowledgements are recorded after the successful post, never before it.

Limits: the lost-response case is a 500 before the consumer commits, so ambiguous acknowledgement
(a 2xx lost after commit) is not claimed here; durable claim/ack is covered by
`OutboxRelayPersistenceIntegrationTest`. Trust failures now exhaust the bounded attempt budget and
quarantine with an audit fact; an operator requeue path is not implemented.

## Deliberate gaps

- **No consumer endpoint exists yet.** UMS has no exposed IAM ingestion HTTP route, so the relay is
  disabled in the development runtime and the transport is proven against a local HTTP receiver.
- **One destination.** The endpoint is configured once; per-app destination routing is a later
  change.
- **No relay UI.** Retry and quarantine state is visible through the existing outbox tables, the
  quarantine audit fact, and the new counters.
- **Consumer acceptance.** UMS must accept the `workload_access` v1 profile before the push path can
  be switched on against a real endpoint.
