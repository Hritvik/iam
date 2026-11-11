package dev.distracted.iam.authorization.refresh;

import java.time.Duration;
import java.util.regex.Pattern;

public record RefreshRotationCommand(
        byte[] presentedDigest,
        byte[] newDigest,
        String dpopJkt,
        long securityVersion,
        String newTokenId,
        String correlationId,
        Duration idleTimeout) {
    private static final Pattern JKT = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final Pattern TOKEN_ID = Pattern.compile("^rft_[A-Za-z0-9_-]{22,128}$");
    private static final Pattern CORRELATION = Pattern.compile("^cor_[A-Za-z0-9_-]{16,128}$");
    private static final Duration MINIMUM_IDLE = Duration.ofHours(1);
    private static final Duration MAXIMUM_IDLE = Duration.ofDays(30);

    public RefreshRotationCommand {
        if (presentedDigest == null || presentedDigest.length != 32
                || newDigest == null || newDigest.length != 32
                || dpopJkt == null || !JKT.matcher(dpopJkt).matches()
                || securityVersion < 1
                || newTokenId == null || !TOKEN_ID.matcher(newTokenId).matches()
                || correlationId == null || !CORRELATION.matcher(correlationId).matches()
                || idleTimeout == null || idleTimeout.compareTo(MINIMUM_IDLE) < 0
                || idleTimeout.compareTo(MAXIMUM_IDLE) > 0) {
            throw new IllegalArgumentException("refresh_rotation_invalid");
        }
    }

    @Override
    public byte[] presentedDigest() {
        return presentedDigest.clone();
    }

    @Override
    public byte[] newDigest() {
        return newDigest.clone();
    }
}
