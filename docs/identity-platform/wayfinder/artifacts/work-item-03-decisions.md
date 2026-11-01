# W-3 Decisions — Pinned Dutch Registration and Metadata

Status: implementation-ready  
Work item: [W-3 — Load and expose the pinned Dutch registration](../work-items.md#w-3--load-and-expose-the-pinned-dutch-registration)  
Canonical inputs: [`app-registration.schema.json`](../../../../contracts/manifest/app-registration.schema.json), [`product-security-policy.schema.json`](../../../../contracts/manifest/product-security-policy.schema.json), [`dutch-development.app-registration.json`](../../../../contracts/manifest/dutch-development.app-registration.json), and [`semantic-requirements.yaml`](../../../../contracts/conformance/semantic-requirements.yaml)

## Scope and stopping boundary

W-3 adds a durable, locally queryable registration registry for the one published Dutch development manifest. It validates the bundled canonical manifest before reconciling it, persists its normalized app/client/resource/security-policy values, and exposes only the two already-published metadata representations. Authorization paths consume immutable registration application ports; they do not parse manifests or query registration tables directly.

This item stops before authorization requests, authorization codes, access or refresh tokens, DPoP proof processing/replay, App Subjects, activation, OIDC discovery, ID tokens, UserInfo, dynamic client registration, client credentials, key generation, or JWKS publication. W-4 owns requests/codes. W-7 owns signing, tokens, DPoP, and JWKS. The authorization-server metadata must contain the contracted future `jwks_uri`, but W-3 does not permit that URI through its security chain and does not synthesize a key.

No cloud registry, secret manager, production host, gateway route, or production manifest is selected here. The manifest is public policy configuration and contains no secret or private key.

## Canonical source and startup reconciliation

The versioned file under `contracts/manifest/dutch-development.app-registration.json` is the sole authoring source. The build includes that exact file plus its two schemas and semantic requirements as read-only classpath resources; source and packaged copies must have identical SHA-256 digests. Do not create a Java constant, SQL seed, YAML mirror, or second hand-written manifest.

Add a `PinnedRegistrationSource` application port and a classpath adapter. The adapter returns raw bytes and source identity, not a mutable object tree. A `RegistrationManifestValidator` performs, in order:

1. strict JSON parsing with duplicate keys rejected and bounded input size;
2. Draft 2020-12 validation against the bundled app-registration schema with format assertions enabled and the policy `$ref` resolved only from the bundled allowlist;
3. typed deserialization with unknown properties rejected into immutable values;
4. semantic validation of redirect safety from `semantic-requirements.yaml`; and
5. canonical JSON serialization plus lowercase SHA-256 content fingerprint.

Schema URLs are identifiers, never network locations. Validation performs no network fetch. The semantic validator implements the published rules rather than parsing English at runtime; a contract test keeps its cases aligned with the requirement file and canonical valid/invalid fixtures.

Reconciliation is an application startup runner enabled only when all of these are true:

- the active profile set is exclusively `development` and/or `test`;
- `iam.registration.dutch-development.enabled=true`; and
- `iam.environment` equals the manifest's `development` environment.

The opt-in defaults to false. Opt-in under no profile, any production-like profile (`staging`, `production`, or `production-like`), a mixed allowed/forbidden profile set, or a mismatched environment fails startup with a stable safe reason code. This prevents a development client from silently entering a normal or production registry. Integration tests activate `test`, opt in explicitly, and set `iam.environment=development`; no test bypass or alternate seed exists.

The runner validates before opening the reconciliation transaction. `RegistrationRegistry.reconcile(manifest, fingerprint)` executes one database transaction. An absent registration is inserted. A present registration with the same manifest version and fingerprint is an idempotent success. A present stable ID with any different fingerprint, child value, or environment is drift and fails startup; W-3 never mutates, deletes, or silently imports it. A restart therefore reads the same rows without producing duplicates or timestamps that imply a change. A later manifest evolution needs a new reviewed work item and explicit monotonic revision model; v1 has no generic update path.

Startup logs only a stable result (`created` or `unchanged`), app registration ID, manifest version, and abbreviated fingerprint. Validation and drift failures expose a safe code and JSON pointer/category, never the rejected value or full manifest.

## V5 relational model

Create `V5__pinned_app_registration.sql`. Use normalized constrained tables, not a JSONB policy cache:

### `app_registration`

- `app_registration_id text` primary key, contract pattern;
- `manifest_version smallint not null`, exactly `1`;
- `display_name text not null`, length `1..80`;
- `environment text not null`, allowed environment enum;
- `source_fingerprint char(64) not null`, lowercase hexadecimal;
- `created_at timestamptz not null default transaction_timestamp()`.

### `client_registration`

- `client_id text` primary key, contract pattern;
- `app_registration_id text not null` unique FK to app, `on delete restrict`;
- `client_type text not null`, exactly `NATIVE_PUBLIC`;
- `browser_mode text not null`, exactly `EXTERNAL`;
- `created_at timestamptz not null default transaction_timestamp()`.

W-3 supports one client for the pinned v1 app while retaining a separate table so later reviewed manifests can lift the unique-app constraint deliberately.

### `client_redirect_uri`

- `(client_id, redirect_uri)` primary key and restrictive FK;
- `redirect_uri text not null`, length bounded to the contract maximum.

The database stores the exact URI string. It does not normalize case, decode escapes, trim, use prefix matching, or use PostgreSQL URL interpretation. Application validation owns URI semantics; W-4 performs byte-for-byte equality against these rows.

### `client_grant_type` and `client_pkce_method`

- child key plus value composite primary key and restrictive client FK;
- grant constrained to `authorization_code`;
- PKCE method constrained to `S256`.

### `resource_registration`

- `resource_id text` primary key, contract pattern;
- `app_registration_id text not null` unique FK to app, `on delete restrict`;
- `audience text not null unique`, length `<=256`;
- `created_at timestamptz not null default transaction_timestamp()`.

### `resource_scope`

- `(resource_id, scope_name)` primary key and restrictive FK;
- `scope_name` constrained to the contract pattern and maximum length.

### `product_security_policy`

- `app_registration_id text` primary key and restrictive FK;
- `policy_version smallint not null`, exactly `1`;
- `require_dpop boolean not null`, required true;
- `required_pkce_method text not null`, exactly `S256`;
- `created_at timestamptz not null default transaction_timestamp()`.

### `policy_grant_type` and `policy_activation_evidence`

- app ID plus value composite primary keys and restrictive FKs;
- policy grant constrained to `authorization_code`;
- evidence constrained to `verified_identifier`, `usable_factor`, or `recovery_path`.

The reconciliation function verifies exactly one redirect, grant, PKCE method, resource, scope, policy grant, and all three distinct evidence values for the current pinned manifest before inserting. The schema additionally enforces value domains, uniqueness, FKs, lengths, and timestamps. Cross-row cardinality and equality between client and policy grant/PKCE sets remain application/reconciliation invariants because PostgreSQL `CHECK` constraints must not inspect other rows.

The exact persisted tuple is:

| Field | Value |
|---|---|
| app | `dutch-development` / `Dutch Development` / `development` / manifest v1 |
| client | `dutch-mobile` / `NATIVE_PUBLIC` / `EXTERNAL` |
| redirect | `dutch://oauth/callback` |
| client grant | `authorization_code` |
| client PKCE | `S256` |
| resource | `dutch-api` / `https://api.dutch.invalid` |
| scope | `member:read` |
| policy | v1 / DPoP required / `S256` / `authorization_code` |
| activation evidence | `verified_identifier`, `usable_factor`, `recovery_path` |

## Database authority and repository ports

### Corrected reconciliation authority

Reconciliation does **not** run with general `iam_runtime` authority. Deployment provisions the additional NOLOGIN role `iam_registration_reconciler` and a distinct login belonging only to that role. Runtime retains registration-table SELECT plus EXECUTE on the read-only canonical-graph verification function; it cannot execute reconciliation. The reconciler receives schema usage and reconciliation-function EXECUTE only, with no table SELECT or mutation grants.

When reconciliation is enabled, `iam.registration.reconciler.jdbc-url`, `.username`, and `.password` are mandatory typed properties with no defaults. They must differ from runtime credentials. Startup verifies actual PostgreSQL membership on both connections: runtime is `iam_runtime` but not reconciler; reconciliation is `iam_registration_reconciler` but not runtime. Missing, shared, unavailable, or miswired authority fails startup, and no runtime-datasource fallback exists.

V5 owns a private `pinned_registration_allowlist` row containing every reviewed Dutch scalar/set and the RFC 8785/SHA-256 manifest fingerprint. Reconciliation rejects any caller input that does not match it before mutation. Metadata lookup uses a separate read-only security-definer function and returns an app only when exactly one complete persisted graph—including fingerprint and every child set—matches the private allowlist. Absence, additions, deletions, scalar drift, ambiguity, or database failure therefore yields `metadata_unavailable`; drifted or partial metadata is never constructed.

V5 first asserts the existing `iam_migrator`, `iam_runtime`, and `iam_registration_reconciler` roles. Every new object is owned by `iam_migrator`; PUBLIC receives no table or function privileges. Runtime receives SELECT on the public registration tables and EXECUTE only on the read-only `canonical_registration()` security-definer function. The separate reconciler role receives EXECUTE only on `reconcile_pinned_registration(...)`. Reconciliation inputs are scalar parameters plus SQL arrays, never concatenated SQL or caller-provided JSON. Both functions fix `search_path` to `pg_catalog, public`; the mutation function validates the private allowlist, locks the app key, and returns `CREATED`, `UNCHANGED`, or `DRIFT`. Neither runtime nor reconciler receives direct INSERT, UPDATE, DELETE, TRUNCATE, sequence, or DDL authority.

The reconciler function atomically inserts the full graph or no rows. It compares all persisted scalar and child-set values plus the fingerprint when the app already exists. Failed validation, forced failure, contention, or drift leaves no partial app/client/resource/policy. Concurrent identical startup has one creator and one unchanged result. Non-allowlisted concurrent content is rejected before mutation. `DRIFT` means canonical input encountered an already persisted graph that differs from the allowlist; it never imports caller-supplied alternative content.

The registration module owns these ports and immutable values:

- `PinnedRegistrationSource` — canonical bytes/source identity;
- `RegistrationManifestValidator` — validated immutable manifest and fingerprint;
- `RegistrationRegistry` — reconcile and exact lookup by app, client, resource/audience;
- `RegistrationMetadata` — construct closed metadata values from the local registry and issuer configuration.

Place JDBC implementations under `registration.adapter.jdbc`. Other modules depend only on registration ports/value types. Web/protocol adapters depend on `RegistrationMetadata`, not JDBC or manifest parsing. Parameterized `JdbcTemplate` calls and typed row mapping are mandatory.

## Issuer and metadata HTTP surface

`iam.issuer` is external public configuration, not a secret. Accept one absolute HTTPS URI with no userinfo, query, or fragment and no trailing slash; parsing is strict. W-3 tests use the canonical contract value `https://iam.distracted.invalid`. A missing or invalid issuer while Dutch reconciliation/metadata is enabled fails startup safely.

Add a higher-priority security chain that permits unauthenticated, read-only `GET` and `HEAD` for exactly:

- `/.well-known/oauth-authorization-server`;
- `/.well-known/oauth-protected-resource`.

All other methods and paths remain handled by the foundation deny-all chain. Responses use `application/json`, `Cache-Control: public, max-age=300`, `X-Content-Type-Options: nosniff`, and the existing correlation header. They are raw standards metadata documents, not the platform `{data: ...}` envelope. No request parameter selects an app, issuer, resource, or arbitrary URI.

The authorization-server document is the closed object defined by [`authorization-server-metadata.schema.json`](../../../../contracts/oauth/authorization-server-metadata.schema.json): issuer plus issuer-relative `/oauth2/authorize`, `/oauth2/token`, and `/oauth2/jwks`; response `code`; grant `authorization_code`; PKCE `S256`; token authentication `none`; DPoP algorithm `ES256`. It advertises no refresh grant, implicit/password/client-credentials/token-exchange grant, OIDC scopes/claims, discovery, ID-token algorithm, UserInfo, introspection, revocation, dynamic registration, or client secret method. The endpoint does not activate the advertised protocol endpoints; their existing deny-all behavior remains until their owning work items.

The protected-resource document is the closed object defined by [`protected-resource-metadata.schema.json`](../../../../contracts/oauth/protected-resource-metadata.schema.json): the registered Dutch audience, the single configured issuer, the sorted registered scope set, header bearer method, and ES256. RFC 9728 deployment at the resource origin ultimately requires the Dutch resource/gateway to route or publish this representation; W-3 exposes the exact representation from IAM at the fixed well-known path for contract/integration use and makes no gateway change. With zero or more than one enabled resource, this endpoint fails closed rather than guessing.

Successful representations are computed from persisted registry rows after reconciliation, never copied from valid fixture JSON. Sorting is deterministic. A registry absence/drift/unavailable condition returns generic `503 metadata_unavailable` with `Retry-After` through the existing safe error envelope and correlation ID; database details and policy internals remain server-side and redacted. Unexpected failures use the existing generic 500 handling. Metadata contains no app subject, global identity ID, identifier, credential, client secret, token, code, session, private key, or unrestricted JSON policy.

## RED-to-GREEN verification matrix

Write the tests first and capture failing evidence before implementation.

### Unit and contract RED

1. Load the canonical manifest and prove the immutable typed tuple above; missing classpath resource, oversize JSON, duplicate JSON key, unknown field, unresolved/external `$ref`, or malformed JSON fails with a safe code.
2. Parameterize every registration fixture. Canonical valid manifests pass schema plus semantic validation; wildcard/prefix redirect, case/path variation, fragment, userinfo, unsafe scheme, non-loopback HTTP, hostname confusion, absent/zero/oversize port, invalid IPv4 octet, non-loopback IPv6, insecure audience, refresh grant, plain/missing PKCE, duplicate set member, undeclared field, and client/policy mismatch fail before persistence.
3. Add positive redirect semantic cases for the exact custom scheme, claimed HTTPS (using an explicit test ownership allowlist), IPv4 `127/8` with four bounded octets and explicit valid port, and IPv6 exactly `[::1]` with explicit valid port. The Dutch custom scheme ownership map is exactly `dutch-development -> dutch`; no suffix/prefix ownership inference exists.
4. Prove source-resource and packaged-resource digests match and contract fixtures/catalog still validate. Existing contract files remain unchanged unless a real contract defect is separately reviewed.
5. Validate generated authorization and protected-resource representations against their canonical schemas. Assert exact keys and values, stable ordering, no refresh/OIDC/ID-token fields, and recursive forbidden-name/value scans.
6. Prove registration value types contain no mutable collections and module rules prevent authorization/activation/web code from using registration JDBC packages.

### PostgreSQL 18 integration RED

1. Clean V1–V5 migration creates all constraints, ownership, revocations, grants, and security-definer search paths; migration under absent prerequisite roles fails.
2. Runtime direct insert/update/delete/truncate fails for every registration table; migrator authority works; PUBLIC has none.
3. First reconcile inserts the exact complete graph. Same-input sequential and concurrent reconcile yields one `CREATED`, remaining `UNCHANGED`, and one graph.
4. Same stable app ID with changed fingerprint or each scalar/child set in turn yields `DRIFT` and preserves the original graph byte-for-byte. Test transaction rollback with an injected mid-graph failure.
5. Database constraints reject every invalid ID/value/length, non-HTTPS audience, forbidden grant/PKCE/policy value, duplicate redirect/scope/evidence, broken FK, and attempted deletion of referenced parents.
6. A new application context against the same container reads the identical registration and metadata after restart. A clean new container converges to the same logical graph/fingerprint; timestamps need not match across databases.
7. Lookups by app, client, resource ID, and audience return only the registered immutable aggregate and use parameterized queries. Unknown values are empty and non-enumerating at HTTP boundaries.

### HTTP RED

1. GET and HEAD on each exact well-known path succeed only after reconciliation and conform to the canonical schema/content type/cache/security/correlation headers; HEAD has the GET status/headers and no body.
2. POST/PUT/PATCH/DELETE, path suffixes, query-driven app/resource selection, encoded path tricks, and all unrelated paths remain denied or not found under the existing safe envelope.
3. Missing/invalid issuer, no registered resource, multiple registered resources, database outage, and reconciliation drift never emit partial/stale metadata; return safe correlated errors with no SQL, manifest, policy, secret, identifier, or stack detail.
4. Captured responses and logs pass recursive canary scans for email, phone, credential, authorization code, access/refresh token, client secret, private key, global identity ID, and full policy JSON.

### Startup/profile RED

Test the full profile/opt-in matrix: development and test individually may opt in; no profile, staging, production, production-like, mixed allowed/forbidden profiles, false/absent opt-in, environment mismatch, invalid manifest, drift, invalid/missing issuer, and unavailable database all fail closed or leave the W-3 beans absent exactly as specified. No case installs an in-memory registry or default client.

## Completion gate

W-3 is complete only when `test`, PostgreSQL 18 `integrationTest`, `contractTest`, architecture checks, coverage gates, secret scan, migration checks, dependency verification, SBOM, and a clean restart pass; RED and GREEN evidence is recorded in a W-3 evidence artifact; and an independent correctness and security review has no unresolved critical/high finding. The contract bundle digest must remain unchanged unless an independently justified contract correction is approved.

The next item may rely on exact lookup ports and the persisted Dutch tuple. It may not bypass them, broaden redirect matching, or infer an authorization capability from unregistered input.
