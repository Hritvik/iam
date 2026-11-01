package dev.distracted.iam.token;

import dev.distracted.iam.activation.AppSubject;
import java.time.Instant;

public record VerifiedHumanAccessToken(
        AppSubject subject, String appRegistrationId, String clientId, String audience,
        String scope, int securityVersion, DpopKeyThumbprint dpopKeyThumbprint,
        Instant issuedAt, Instant expiresAt) {
    @Override public String toString() {
        return "VerifiedHumanAccessToken[appRegistrationId=" + appRegistrationId + ",redacted]";
    }
}
