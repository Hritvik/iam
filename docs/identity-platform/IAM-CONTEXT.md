# Identity Platform

The Identity Platform centralizes identity and authentication for Dutch, Midas, Jarvis, and future first-party applications while leaving profiles and domain authorization with each application.

## Language

**Human Identity**:
A stable platform principal representing one person across all first-party applications. It is independent of any application's profile or authorization model.
_Avoid_: User account, Dutch Identity, Member

**App Activation**:
IAM's record governing whether a Human Identity may enter one first-party application. It is created idempotently, moves through Pending Prerequisites, Active, Suspended, or Departed, and is not a separate identity or application profile.
_Avoid_: Product account, duplicate identity, signup

**App Subject**:
A stable application-specific principal identifier mapped by IAM to one Human Identity. It prevents ordinary applications from correlating their data through a universally exposed platform identifier.
_Avoid_: Global user ID, Member ID, profile ID

**App Registration**:
The reviewed platform definition of a first-party application's clients, audiences, scopes, redirects, activation prerequisites, ownership, and security policy.
_Avoid_: OAuth client row, app config

**Verified Identifier**:
A typed, protected identifier whose control IAM has verified and may use for identity lookup or recovery according to policy. Email and E.164 phone are the initial types.
_Avoid_: Username, profile contact, plaintext identifier

**Authentication Factor**:
Evidence used to prove control of a Human Identity during authentication, such as a passkey or verified challenge. It is not itself an application profile or necessarily an identifier.
_Avoid_: Identifier, password field

**Platform SSO Session**:
IAM's central record of recent Human Identity authentication that may allow entry into another first-party application without repeating authentication, subject to that application's assurance policy.
_Avoid_: Access token, app session

**App Session**:
A client- and audience-bound authorization session for one application and device, with its own refresh-token family and revocation lifecycle.
_Avoid_: Global session, SSO cookie

**Workload Identity**:
A platform principal representing a service, job, or deployment workload rather than a person. It cannot implicitly stand in for a Human Identity.
_Avoid_: Service user, bot user, synthetic human

**Delegated Access**:
Short-lived, purpose-bound authority for a Workload Identity to perform a named action for a Human Identity while retaining both the human subject and workload actor in authorization and audit evidence.
_Avoid_: Impersonation, service login as user

**Product Security Policy**:
An application's reviewed requirements for assurance, factors, session lifetime, and reauthentication, constrained by platform minimums it cannot weaken.
_Avoid_: Per-app auth fork, optional baseline

**Authentication Assurance**:
PII-free evidence of how and when a Human Identity authenticated, classified as Baseline, Strong, or Phishing-Resistant/Recent for application policy decisions.
_Avoid_: Logged-in flag, user trust score

**Recovery Grant**:
A short-lived, restricted IAM authority issued after an approved recovery journey so the person can re-establish factors without automatically regaining prior assurance.
_Avoid_: Password reset token, full session, support override
