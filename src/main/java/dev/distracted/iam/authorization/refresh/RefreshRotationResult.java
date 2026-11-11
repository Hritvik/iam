package dev.distracted.iam.authorization.refresh;

import java.time.Instant;

public record RefreshRotationResult(
        RefreshRotationOutcome outcome,
        String familyId,
        String tokenId,
        Integer generation,
        Instant issuedAt,
        Instant expiresAt,
        String appRegistrationId,
        String clientId,
        String resourceId,
        String resourceAudience,
        String humanIdentityId,
        String scope,
        Instant absoluteExpiresAt) {
    public RefreshRotationResult {
        if (outcome == null) {
            throw new IllegalArgumentException("refresh_rotation_result_invalid");
        }
    }
}
