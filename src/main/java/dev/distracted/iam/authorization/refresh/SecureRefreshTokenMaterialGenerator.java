package dev.distracted.iam.authorization.refresh;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * Generates opaque 256-bit refresh tokens and their storage digests. The raw token is never stored;
 * the digest is an unkeyed SHA-256 of a high-entropy single-use value.
 */
public final class SecureRefreshTokenMaterialGenerator implements RefreshTokenMaterialGenerator {
    private static final int TOKEN_BYTES = 32;
    private static final int IDENTIFIER_BYTES = 18;

    private final SecureRandom random;

    public SecureRefreshTokenMaterialGenerator(SecureRandom random) {
        this.random = Objects.requireNonNull(random);
    }

    @Override
    public RefreshTokenMaterial newFamily() {
        return generate(newIdentifier("rfm_"));
    }

    @Override
    public RefreshTokenMaterial rotate(String familyId) {
        return generate(Objects.requireNonNull(familyId));
    }

    private RefreshTokenMaterial generate(String familyId) {
        var tokenBytes = new byte[TOKEN_BYTES];
        random.nextBytes(tokenBytes);
        var rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        return new RefreshTokenMaterial(familyId, newIdentifier("rft_"), rawToken,
                sha256(rawToken.getBytes(StandardCharsets.US_ASCII)));
    }

    private String newIdentifier(String prefix) {
        var bytes = new byte[IDENTIFIER_BYTES];
        random.nextBytes(bytes);
        return prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("refresh_digest_unavailable", exception);
        }
    }
}
