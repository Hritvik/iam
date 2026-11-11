package dev.distracted.iam.authorization.refresh;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public final class RefreshTokenDigest {
    private RefreshTokenDigest() {
    }

    public static byte[] of(String rawToken) {
        if (rawToken == null || !rawToken.matches("^[A-Za-z0-9_-]{43,128}$")) {
            throw new IllegalArgumentException("refresh_token_invalid");
        }
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(rawToken.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("refresh_digest_unavailable", exception);
        }
    }
}
