# Work Unit 04 Decision Record: Protected Identifier and Verification Challenge

**Status:** accepted for implementation  
**Scope:** Slice A identity, identifier protection, and verification challenge only  
**Depends on:** Work Units 1–3 and decisions D-4 and D-11

## Boundary and invariant

Work Unit 4 adds the authoritative Human Identity aggregate, protected email/phone identifiers, and the challenge state machine. It does not add fixture loading, factor/recovery evidence, app registration, App Subject, activation, authorization, tokens, an HTTP registration surface, or any cross-service consumer. Work Unit 5 may call the application ports defined here; it may not insert these rows directly.

Raw or canonical email/phone and plaintext challenge codes exist only in short-lived application memory at the relevant port boundary. They are never persisted, returned from repositories, included in exceptions, logged, measured as labels, placed in audit facts, or written to the outbox. Database columns and indexes expose neither plaintext nor an unkeyed digest.

## V3 relational model

V3 extends the existing PostgreSQL 18/Flyway lineage. IDs are opaque CSPRNG-backed text values using `hid_`, `vid_`, and `vch_` prefixes followed by 22–128 URL-safe base64 characters. Timestamps are `timestamptz`; versions are positive `bigint`. Foreign keys use `RESTRICT`, never cascade. Runtime SQL is fixed and parameterized.

### `human_identity`

- `identity_id text primary key`, matching `^hid_[A-Za-z0-9_-]{22,128}$`;
- `state text not null`, closed to `ACTIVE|LOCKED|DISABLED` (WU4 creates only `ACTIVE`);
- `security_version bigint not null default 1 check (security_version >= 1)`;
- `version bigint not null default 1 check (version >= 1)`, the aggregate optimistic-lock version;
- `created_at timestamptz not null` and `updated_at timestamptz not null`.

Every mutation is `... where identity_id = ? and version = ?` and increments `version` exactly once. A security-relevant mutation increments `security_version` in the same statement. Challenge issue/resend/failure does not increment it; first successful identifier verification does. This leaves later factor, recovery, lock, and revocation work one explicit security invalidation mechanism without inventing those behaviors now.

### `verified_identifier`

- `identifier_id text primary key`, matching `^vid_[A-Za-z0-9_-]{22,128}$`;
- `identity_id text not null references human_identity(identity_id) on delete restrict`;
- `identifier_type text not null`, exactly `EMAIL|PHONE`;
- `normalization_version smallint not null`, exactly `1` in V3;
- canonical protected value: `canonical_ciphertext bytea`, `canonical_nonce bytea` (12 bytes), `canonical_tag bytea` (16 bytes);
- display protected value: `display_ciphertext bytea`, `display_nonce bytea` (12 bytes), `display_tag bytea` (16 bytes);
- `encryption_key_version smallint not null check (encryption_key_version >= 1)`;
- `verified_at timestamptz not null`;
- `version bigint not null default 1 check (version >= 1)`;
- `created_at` and `updated_at timestamptz not null`;
- unique `(identity_id, identifier_type)` for this milestone.

A row means verified: there is no pending/unverified state in this table. The candidate remains only as protected material on its challenge until consumption. Canonical and display values use independent nonces; all protected byte arrays must be nonempty. Display is the ASCII-trimmed submitted value and exists only for future IAM-owned presentation. It is never returned by the repository's ordinary lookup path.

### `verified_identifier_blind_index`

Rotation-safe lookup is normalized rather than adding versioned columns to `verified_identifier`:

- `identifier_id text not null references verified_identifier(identifier_id) on delete restrict`;
- `identifier_type text not null` and `normalization_version smallint not null`, copied and constraint-checked against the parent through the append function;
- `blind_index_key_version smallint not null check (blind_index_key_version >= 1)`;
- `blind_index bytea not null check (octet_length(blind_index) = 32)`;
- primary key `(identifier_id, blind_index_key_version)`;
- unique `(identifier_type, normalization_version, blind_index_key_version, blind_index)`.

V3 requires exactly one configured write key version and writes one blind-index row. A future rotation uses an additive migration/config rollout: make old and new versions readable, backfill a second child row for every identifier, verify completeness and collision-free uniqueness, switch the required write version, then retire old reads only after the maximum challenge lifetime plus operational rollback window. During overlap every create/consume checks all readable versions and writes every required write version in one transaction. No key version is silently inferred from deployment order.

### `verification_challenge`

- `challenge_id text primary key`, matching `^vch_[A-Za-z0-9_-]{22,128}$`;
- `identity_id text not null references human_identity(identity_id) on delete restrict`;
- `identifier_type text not null`, exactly `EMAIL|PHONE`;
- protected candidate canonical/display columns with the same ciphertext/nonce/tag/key-version/normalization constraints as `verified_identifier`;
- `candidate_blind_index_key_version smallint not null` and `candidate_blind_index bytea not null` (32 bytes), used only for duplicate detection and safe promotion;
- `challenge_digest bytea not null check (octet_length(challenge_digest) = 32)` and `digest_key_version smallint not null check (digest_key_version >= 1)`;
- `state text not null`, exactly `ISSUED|SUPERSEDED|CONSUMED|EXPIRED|LOCKED`;
- `attempt_count integer not null default 0 check (attempt_count >= 0)`;
- `max_attempts integer not null check (max_attempts between 1 and 20)`;
- `expires_at timestamptz not null`, `consumed_at timestamptz null`, `superseded_at timestamptz null`, `locked_at timestamptz null`;
- nullable `superseded_by_challenge_id text` referencing the same table with `RESTRICT`;
- `version bigint not null default 1 check (version >= 1)`;
- `created_at` and `updated_at timestamptz not null`.

State checks require only the timestamp/link belonging to the terminal state and forbid all terminal fields while `ISSUED`. A partial unique index on `(identity_id, identifier_type) where state = 'ISSUED'` permits one live challenge per identity/type. `expires_at > created_at`; configured TTL is bounded from 60 seconds through 24 hours. Challenge rows are retained security records in this milestone; no delete repository exists.

## Exact normalization version 1

Normalization is a pure value operation with explicit `EMAIL/v1` and `PHONE/v1` identifiers. It never depends on locale, database collation, or the machine's default Unicode settings.

### Email

1. Remove boundary characters only from the ASCII whitespace set HT, LF, VT, FF, CR, and SPACE (`U+0009`–`U+000D`, `U+0020`). Do not remove internal whitespace or any non-ASCII whitespace. Reject controls anywhere after this step.
2. Require exactly one `@`; a nonempty local part of at most 64 ASCII octets; and a nonempty domain. V1 accepts the conservative RFC 5322 dot-atom ASCII local form only: atoms contain `A-Z a-z 0-9 ! # $ % & ' * + - / = ? ^ _ ` { | } ~`, dots separate nonempty atoms, and quoted strings/comments/domain literals are rejected. Local-part case and plus tags are preserved exactly.
3. Process the domain with Unicode UTS #46 non-transitional mapping with STD3, Bidi, and ContextJ checks enabled; convert each label to its ASCII A-label, reject empty labels, a trailing dot, IP literals, and labels over 63 octets; then lowercase the ASCII domain with `Locale.ROOT`. The final canonical address must be at most 254 ASCII octets.
4. Canonical value is `<unchanged-local>@<lowercase-a-label-domain>`. Display value is only the boundary-trimmed submitted value. No dot removal, provider-specific rewriting, Unicode normalization of the local part, or full-address lowercasing occurs.

The implementation must use a pinned library that actually supplies the stated UTS #46 behavior; `java.net.IDN` is not an acceptable substitute because its algorithm/version contract is different.

### Phone

After the same ASCII-boundary trim, require the entire input to match `^\+[1-9][0-9]{1,14}$`. No spaces, punctuation, extension, national format, `00` prefix, Unicode digits, or inferred country code is accepted. Canonical and display values are identical. Region-aware parsing belongs in a future IAM-owned input adapter, not this canonical operation.

## Blind-index and encryption formats

For identifier type `email` or `phone`, blind-index input is UTF-8 bytes of exactly:

`iam|<environment>|identifier|<type>|norm-v<normalizationVersion>|<canonicalValue>`

`environment` is the closed runtime environment string; `type` is lower-case ASCII. The HMAC output is the full 32-byte HMAC-SHA-256 value, never hex/base64 in persistence. A configured numeric `blind_index_key_version` selects key material behind `BlindIndexCapability`; key references and secret bytes are not stored in rows. Comparisons are database unique-index comparisons or constant-time comparisons in application memory.

Canonical and display values are separately sealed with AES-256-GCM, a fresh 96-bit CSPRNG nonce per field/encryption, a 128-bit tag, and no nonce reuse for a key. AAD is UTF-8 text with length-delimited values (decimal byte length, colon, bytes) in this fixed order: protocol `iam-identifier-aad-v1`, environment, table (`verified_identifier` or `verification_challenge`), row ID, field (`canonical` or `display`), identifier type, normalization version, and encryption key version. Length delimiting, rather than a bare delimiter, prevents ambiguous binding. Decryption reconstructs AAD from immutable row metadata; moving ciphertext between rows, fields, types, environments, or versions fails authentication.

The identity adapter must receive a structured sealed value (`ciphertext`, `nonce`, `tag`, numeric key version) from a typed crypto/keyring adapter. If the existing foundation `IdentifierEncryptionCapability` remains an opaque byte-array boundary, the WU4 implementation must wrap/evolve it with tests rather than parsing provider-specific ciphertext. Production-like startup still requires an externally supplied, self-checked capability; tests may supply explicit non-production keys. There is no fallback key, hardcoded credential, deterministic nonce, or ephemeral production key.

Encryption rotation is read-old/write-new: deploy a keyring capable of decrypting every stored `encryption_key_version`, make the new version the sole writer, then re-encrypt rows with new random nonces using expected-version updates. Retirement occurs only after a completeness query proves no rows reference the old version and the rollback window closes. Re-encryption does not change the identifier, identity, verification timestamp, or security version.

## Challenge digest and state machine

Challenge codes are generated with a CSPRNG and have at least 128 bits of entropy; WU4 does not choose an email/SMS delivery UX or reduced-digit OTP. The stored digest is full HMAC-SHA-256 over UTF-8 bytes of:

`iam|<environment>|verification-challenge|digest-v1|<challengeId>|<code>`

using a purpose-separated challenge-digest key selected by `digest_key_version`. Reusing the identifier blind-index key is forbidden. Add a typed, self-checked challenge-digest capability/key reference; production-like startup fails when it is absent once the WU4 application is enabled. The plaintext code is returned only to the delivery port in memory and is never returned by persistence.

All issue, resend, verify, and expiry operations lock the `human_identity` row first and use expected-version updates on the challenge. The database clock (`transaction_timestamp()`) is the authoritative acceptance clock in PostgreSQL integration; unit tests use an injected clock.

- **Issue:** insert one `ISSUED` challenge with attempt `0`; reject an already verified `(identity,type)` without revealing whether it belongs elsewhere.
- **Resend:** in one transaction, lock the identity, change the current `ISSUED` row to `SUPERSEDED` with timestamp/link, and insert the replacement. The replacement has a new ID, code, nonce, digest, expiry, and attempt budget. The code is not reused. Concurrent resends serialize; the last committed replacement is the sole `ISSUED` row.
- **Verify, expired:** an `ISSUED` challenge at `now >= expires_at` is conditionally changed to `EXPIRED`; return the same public rejection class as any invalid code.
- **Verify, wrong code:** compare in constant time. Atomically increment attempts. When the new count is less than `max_attempts`, remain `ISSUED`; when it equals `max_attempts`, set `LOCKED` and `locked_at`. No comparison occurs after a terminal state.
- **Verify, correct code:** in one transaction conditionally change exactly one `ISSUED`, unexpired, under-budget row to `CONSUMED`; promote its protected candidate to one `verified_identifier`, insert required blind-index rows, increment Human Identity aggregate/security versions, and append the local audit facts. Any uniqueness conflict or injected failure rolls back the consumption and all effects. Retrying a consumed challenge returns an idempotent already-consumed result only to the same trusted command context; it never performs another effect.

Conditional updates include `challenge_id`, expected `version`, `state='ISSUED'`, `expires_at > now`, and `attempt_count < max_attempts`. Thus correct-code races, correct-versus-wrong races, and expiry races have exactly one state-transition winner. Repository results distinguish `APPLIED`, `ALREADY_TERMINAL`, `VERSION_CONFLICT`, and `IDENTIFIER_CONFLICT` internally; externally they map to bounded, non-enumerating errors.

## Lifecycle audit and D-11 resolution

The WU4 “PII-free lifecycle fact” is an IAM-internal immutable `audit_fact`, not an integration event. V3 extends the closed WU3 audit allowlists with only `IDENTITY_CREATED`, `IDENTIFIER_CHALLENGE_ISSUED`, `IDENTIFIER_CHALLENGE_SUPERSEDED`, `IDENTIFIER_CHALLENGE_LOCKED`, and `IDENTIFIER_VERIFIED`, plus bounded subject kinds `IDENTITY|VERIFICATION_CHALLENGE|VERIFIED_IDENTIFIER`. Subject IDs are the corresponding opaque IAM-internal IDs; outcomes and correlation/causation IDs use the established fields. There is no details JSON, identifier type/value, blind index, ciphertext, key version, code, delivery address, IP/user-agent, or exception text.

No WU4 operation writes `outbox_event` or `outbox_delivery`. In particular, there is no `iam.identity.verified.v1`, generic lifecycle event, or bridge publication. D-11 remains authoritative: the first and only cross-service identity-derived production fact in this milestone is the later app-scoped `iam.app-subject.onboarding-ready.v1`, after activation owns an App Subject.

## Application and repository ports

The identity module exposes commands/results rather than persistence entities:

- `CreateIdentity` creates the aggregate and allowlisted audit fact atomically;
- `IssueIdentifierChallenge` and `ResendIdentifierChallenge` normalize/protect the candidate, create/supersede challenge state, and hand the plaintext code only to a delivery port;
- `VerifyIdentifierChallenge` performs the bounded transition/promotion transaction;
- `FindIdentityByIdentifier` normalizes and derives all readable blind indexes, returning only an opaque identity reference or absence;
- `IdentityRepository`, `VerifiedIdentifierRepository`, and `VerificationChallengeRepository` expose fixed operations with expected versions and typed outcomes; no generic CRUD, delete, raw SQL fragment, decrypted entity, or “find all” API exists.

The transaction runner encloses aggregate, audit, challenge, identifier, and blind-index effects. Repositories translate constraint/serialization outcomes into safe domain result codes without embedding SQL messages or values. Application errors are stable codes such as `identifier_invalid`, `challenge_rejected`, and `conflict`; they do not distinguish unknown identity, duplicate identifier, expired, locked, wrong, or superseded challenge at an untrusted boundary. There is no WU4 HTTP controller, so transport mapping is tested at the application boundary only.

Safe logs contain event names, safe result codes, correlation ID, and optionally opaque challenge/identifier IDs when operationally necessary. They never contain method arguments, crypto buffers, JDBC parameters, exception messages from crypto/database providers, or object `toString()` output. Domain records holding protected bytes override/avoid generated `toString`; byte arrays are defensively copied on construction and access.

## Test matrix and RED/GREEN order

Tests use PostgreSQL 18 for persistence/concurrency and property/unit tests for pure transformations. They fail rather than skip when the container runtime is unavailable.

1. **RED normalization:** table/property cases for ASCII trim, preserved local case/plus/dots, UTS #46 A-label conversion, domain case, label/length/control/Bidi/ContextJ failures, quoted/local Unicode rejection, multiple `@`, Unicode whitespace, and exact E.164 accept/reject boundaries. Assert idempotence of canonicalization.
2. **RED crypto grammar:** fixed HMAC vectors for both types/environments/versions; a one-byte grammar/value change changes the digest. AES round trips; unique nonces; wrong AAD row/field/type/environment/version and tampered ciphertext/tag all fail without leaking provider errors. Assert database snapshots contain only ciphertext, nonce, tag, versions, and 32-byte HMACs—not seeded canaries.
3. **RED migration:** migrate empty V1→V2→V3 and the retained V2 snapshot; validate constraints, foreign keys, state/timestamp consistency, byte lengths, uniqueness, positive 64-bit versions, append-only audit changes, grants, and no-op re-run.
4. **RED duplicate registration:** sequential and concurrent consumption of challenges for the same canonical email/phone yields one verified identifier/identity association and one winner. Case-preserved local parts remain distinct; equivalent domains and equivalent IDNA forms collide. Verify another environment does not share a blind index.
5. **RED challenge transitions:** issue, resend, expiry boundary (`now == expires_at`), wrong attempts through lock, correct consume, reuse, superseded/locked/expired rejection, and injected failures at every effect. Assert replacement code/digest/nonce differs and only one row is `ISSUED`.
6. **RED concurrency:** concurrent issue/resend, correct/correct, correct/wrong, verify/expire, and max-attempt races have one legal winner, monotonic versions, no orphan identifier, and no partial audit effect. Restart preserves terminal state and budgets.
7. **RED privacy:** seed unique email, phone, challenge, credential-like, and token-like canaries; scan captured application logs, SQL error surfaces, audit/outbox/delivery rows, test reports, serialized results, and exception messages. Do not print a canary on assertion failure. Confirm WU4 produces zero outbox rows.
8. **GREEN/refactor gate:** run the narrow identity tests, then `./gradlew test integrationTest check`. Maintain at least 80% line and branch coverage globally and cover every state transition/typed repository outcome. Run contract validation, dependency/static/SBOM/secret scans through `check`; WU4 must not alter the published contract bundle.

Unit tests may fake clocks, IDs, CSPRNG outputs, and typed crypto/delivery capabilities. Integration tests use real PostgreSQL, real AES-256-GCM/HMAC-SHA-256 implementations with explicit non-production test key material, Flyway, Spring transactions, and concurrent connections. Neither H2 nor mocks are persistence evidence.

## Deferred and blockers

Delivery channel selection, OTP UX, rate limits across network/device dimensions, recovery/factor models, identifier removal/change, multiple identifiers of one type, Unicode/SMTPUTF8 local parts, production key custody/provider, retention/erasure, and an external identity API are deferred to their owning slices or a new decision. Their absence does not weaken the WU4 state and protection invariants above.

There is no design blocker to implementing Work Unit 4. The implementation must make one small foundation extension explicit: a purpose-separated challenge-digest capability and structured/version-addressable identifier crypto adapter. That extension must preserve the WU1 fail-closed production-like startup contract and cannot introduce key material or operational secrets in configuration defaults.
