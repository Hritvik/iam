package dev.distracted.iam.authorization.refresh;

import java.time.Duration;
import java.util.regex.Pattern;

public record RefreshFamilyIssue(
        String familyId,
        String tokenId,
        String humanIdentityId,
        String appRegistrationId,
        String clientId,
        String resourceId,
        String resourceAudience,
        String scope,
        String dpopJkt,
        long securityVersion,
        byte[] tokenDigest,
        Duration absoluteLifetime,
        Duration idleTimeout,
        String correlationId) {
    private static final Pattern FAMILY_ID = Pattern.compile("^rfm_[A-Za-z0-9_-]{22,128}$");
    private static final Pattern TOKEN_ID = Pattern.compile("^rft_[A-Za-z0-9_-]{22,128}$");
    private static final Pattern JKT = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final Pattern CORRELATION = Pattern.compile("^cor_[A-Za-z0-9_-]{16,128}$");
    private static final Duration MINIMUM_ABSOLUTE = Duration.ofDays(1);
    private static final Duration MAXIMUM_ABSOLUTE = Duration.ofDays(90);
    private static final Duration MINIMUM_IDLE = Duration.ofHours(1);
    private static final Duration MAXIMUM_IDLE = Duration.ofDays(30);

    public RefreshFamilyIssue {
        if (familyId == null || !FAMILY_ID.matcher(familyId).matches()
                || tokenId == null || !TOKEN_ID.matcher(tokenId).matches()
                || blank(humanIdentityId) || blank(appRegistrationId) || blank(clientId)
                || blank(resourceId) || blank(resourceAudience) || blank(scope)
                || dpopJkt == null || !JKT.matcher(dpopJkt).matches()
                || securityVersion < 1 || tokenDigest == null || tokenDigest.length != 32
                || absoluteLifetime == null || absoluteLifetime.compareTo(MINIMUM_ABSOLUTE) < 0
                || absoluteLifetime.compareTo(MAXIMUM_ABSOLUTE) > 0
                || idleTimeout == null || idleTimeout.compareTo(MINIMUM_IDLE) < 0
                || idleTimeout.compareTo(MAXIMUM_IDLE) > 0
                || correlationId == null || !CORRELATION.matcher(correlationId).matches()) {
            throw new IllegalArgumentException("refresh_issue_invalid");
        }
    }

    @Override
    public byte[] tokenDigest() {
        return tokenDigest.clone();
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }
}
