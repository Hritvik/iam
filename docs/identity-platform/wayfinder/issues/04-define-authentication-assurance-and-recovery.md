Type: grilling
Status: resolved
Assignee: Codex
Parent: [Specify the shared first-party Identity Platform](../map.md)
Blocked by: 01, 02

# Define authentication, assurance, and recovery

## Question

Which Verified Identifier and Authentication Factor journeys, assurance levels, verification rules, step-up triggers, recovery evidence, enumeration protections, and factor lifecycle invariants meet the umbrella platform's security and usability needs?

## Answer

### Authentication portfolio and assurance

IAM creates a durable Human Identity only after a temporary, rate-limited verification attempt proves control of at least one permitted Verified Identifier. The initial platform supports passkeys as the preferred recurring factor, email verification links or one-time codes, E.164 phone one-time codes where app policy permits, and one-time recovery codes. Passwords, social federation, and enterprise federation are not part of the initial platform.

Synchronized passkeys are accepted for ordinary use. Product Security Policy may require a stronger device-bound or hardware-backed factor for a justified sensitive action when the platform can reliably enforce that property; attestation vendor identity is not universally trusted by default. WebAuthn Level 2 is the stable initial protocol baseline.

Authentication evidence is structured and PII-free: methods (`amr` semantics), authentication time, satisfied assurance policy (`acr` semantics), and necessary session/factor context. The platform defines:

1. **Baseline** — verified-channel authentication suitable for bootstrap and ordinary low-risk entry.
2. **Strong** — passkey or an approved multi-factor combination.
3. **Phishing-Resistant/Recent** — a phishing-resistant factor within the application-defined recent-authentication window.

Apps classify sensitive operations through Product Security Policy. A resource service signals insufficient strength or recentness through a structured step-up challenge; only IAM collects the additional factor and issues new app-bound credentials. Applications never collect IAM credentials or Authentication Factors.

Ordinary activation requires at least one Verified Identifier, one usable Authentication Factor, and a recovery path distinct from the current session. Bootstrap may create the Identity through an email/phone challenge and continue directly into passkey enrollment. Where policy permits skipping passkey enrollment, the session remains Baseline and sensitive actions remain unavailable until Strong enrollment.

### Recovery and factor lifecycle

Self-service recovery tries, in order: a currently authenticated device with recent Strong assurance, another registered passkey, a one-time recovery code, then a verified recovery email/phone challenge followed by mandatory factor establishment. Manual recovery is a governed last resort, never a direct support reset or impersonation path. It uses evidence collection, cooldown, dual approval for high-risk cases, immutable audit, generic communications, and an IAM-controlled Recovery Grant; operators receive no user credentials or tokens.

Adding/replacing/removing identifiers or factors after bootstrap requires recent Strong authentication. New identifiers are verified before attachment, checked for global uniqueness, announced to existing recovery channels, and prevented from becoming the sole recovery method until any applicable risk cooldown passes. The final usable factor or recovery method cannot be deleted without establishing a safe replacement in the same journey.

Successful recovery revokes Platform SSO Sessions, all app refresh families, outstanding authorization codes, old recovery grants, and pending factor/identifier changes. It produces a restricted Baseline recovery session, requires immediate factor confirmation/enrollment, and applies a cooldown to sensitive changes and operations. Prior assurance is never restored merely because recovery completed.

Recovery codes are displayed once, stored only as protected slow digests, consumed atomically, and replaced as a complete set only after recent Strong authentication. Regeneration or successful recovery invalidates the previous set.

If all self-service and governed manual evidence fails, the old Human Identity remains inaccessible. A new Human Identity may be created, but apps do not silently transfer profiles, history, or ownership; later linkage requires a separate explicit evidence-backed process.

### Challenges, abuse, and privacy

Email/SMS challenges are cryptographically random, short-lived, purpose- and identifier-bound, app/context-bound, attempt-limited, single-use, and stored only as protected digests. Successful use consumes a challenge atomically. One explicit resend policy invalidates or supersedes earlier challenges.

Login, verification, conflict, and recovery responses do not reveal whether an identifier or Identity exists. Rate limits and deterministic risk rules use network, device, protected identifier digest, Identity, app, failure history, recent changes, and action sensitivity without logging raw identifiers. The initial system uses explainable reason-coded rules rather than a black-box risk engine. Progressive throttling and temporary cooldown prevent an attacker from creating permanent denial of service; global lock requires credible compromise or governed operator action.

Security notifications cover factor/identifier changes, recovery start/completion, high-risk new devices, app/global logout, and security lock. They reveal no other app usage and link only to trusted IAM origins. Lifecycle events expose only opaque references, change class, state/version, time, correlation, and causation—never raw identifiers, challenges, factor secrets, tokens, recovery evidence, device fingerprints, or operator notes.

### Journey boundary

All authentication and recovery UI is centrally hosted by IAM in an external browser or secure system surface. Apps may contribute reviewed branding/context but never embed credential collection.

First registration binds exact client/redirect/resource, state, nonce, and S256 PKCE context; verifies an identifier; atomically creates the Human Identity and Verified Identifier; offers passkey enrollment; creates the App Subject and appropriate App Activation; issues credentials at the assurance actually achieved; and commits PII-free lifecycle facts through the same durable transaction boundary.

Deterministic test identities exist only in isolated development/test profiles. They exercise normal signed-token and validation paths, never mint unsigned credentials, use production identifiers, bypass production authentication, or load in normal/staging/production configuration.
