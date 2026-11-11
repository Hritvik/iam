# DEP-7 evidence — native sign-in and refresh (local milestone)

Date: 2026-11-11
Owner: IAM
Status: local milestone complete; staging acceptance remains blocked.

## Proven

- Public native client profile: external browser, authorization code, S256 PKCE, exact redirect,
  single audience, required DPoP, no client secret. Contract:
  `docs/identity-platform/deployment/native-sign-in.md`.
- DPoP-bound authorization-code flow with server nonce challenge and replay protection.
- Access token issuance with `cnf.jkt`, `security_version` and the closed claim set.
- DPoP-bound rotating refresh: one family per identity/app/client/device, single-use generations,
  reuse detection revokes the family, wrong-key and security-version revocation, 30-day absolute and
  7-day idle lifetimes.
- Wire contract bundle 1.2.0: optional `refresh_token` in the token response and the refresh grant in
  the authorization-server metadata.

End-to-end PostgreSQL test: `DpopTokenEndpointIntegrationTest` runs authorization code → nonce
challenge → token with access and refresh → refresh rotation → old-token reuse returns
`invalid_grant`, and the family is `REVOKED`. It also proves the revocation survives the rejected
request transaction.

## Not proven

- **Staging registration and real issuer.** DEP-7's acceptance requires an approved staging
  registration and a real authenticated principal. This needs `portfolio/INFRA-13` (issuer hostname,
  TLS, KMS bindings) and IAM DEP-4.
- **Issuer pin.** V6/V8 hardcode the authorization-server issuer to `https://iam.distracted.invalid`.
  A real issuer requires a migration; the local proof uses the pinned value.
- **Real login and device evidence.** The local proof uses the IAM test principal; the external
  browser login, sign-out wipe and Dutch device evidence belong to `dutch/NATIVE-AUTH`.
- **Compose sign-in.** The local runtime does not yet have development implementations of the
  authorization-code digest, DPoP state digest, access-token signer, a seeded app subject or a login
  surface. The end-to-end proof supplies those as test capabilities.

## Gate

```text
unit tests         422 passed
integration tests  326 passed
contract tests       8 passed
check              green
```

## References

- Decision: `capabilities/work/decisions/iam-native-refresh-001.yaml`
- Profile: `docs/identity-platform/deployment/native-sign-in.md`
- Contract bundle: `iam-contracts-1.2.0.zip`,
  sha256 `e93e102e0055908102d797eaad9b8dd33ca09139e8771909e4c09e4bbc267344`
- Staging gate: `portfolio/INFRA-13`, `iam/DEP-4`, `iam/DEP-5`
