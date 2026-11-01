package dev.distracted.iam.authorization;

import java.time.Duration;

public record AuthorizationCodeIssue(
        String authorizationRequestId,
        String authorizationCodeId,
        String issuer,
        String appRegistrationId,
        String clientId,
        String resourceId,
        String resourceAudience,
        String humanIdentityId,
        String redirectUri,
        String scope,
        byte[] stateDigest,
        byte[] nonceDigest,
        byte[] codeChallenge,
        byte[] codeDigest,
        short digestKeyVersion,
        Duration lifetime,
        String correlationId) {
    public AuthorizationCodeIssue {
        stateDigest = stateDigest.clone();
        nonceDigest = nonceDigest.clone();
        codeChallenge = codeChallenge.clone();
        codeDigest = codeDigest.clone();
    }
    @Override public byte[] stateDigest() { return stateDigest.clone(); }
    @Override public byte[] nonceDigest() { return nonceDigest.clone(); }
    @Override public byte[] codeChallenge() { return codeChallenge.clone(); }
    @Override public byte[] codeDigest() { return codeDigest.clone(); }
    @Override public String toString() {
        return "AuthorizationCodeIssue[requestId=" + authorizationRequestId + ",codeId="
                + authorizationCodeId + ",clientId=" + clientId + ",protected]";
    }
}
