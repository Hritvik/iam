package dev.distracted.iam.authorization;

import dev.distracted.iam.registration.RegistrationManifest;

public record ValidatedAuthorizationRequest(
        String issuer,
        RegistrationManifest registration,
        String redirectUri,
        String scope,
        String state,
        String nonce,
        byte[] codeChallenge) {
    public ValidatedAuthorizationRequest {
        codeChallenge = codeChallenge.clone();
    }

    @Override public byte[] codeChallenge() { return codeChallenge.clone(); }
}
