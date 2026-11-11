package dev.distracted.iam.authorization.refresh;

public record RefreshFamilyView(
        String familyId,
        String humanIdentityId,
        String appRegistrationId,
        String clientId,
        String resourceId,
        String resourceAudience,
        String scope,
        long securityVersion,
        String dpopJkt,
        String status) {
}
