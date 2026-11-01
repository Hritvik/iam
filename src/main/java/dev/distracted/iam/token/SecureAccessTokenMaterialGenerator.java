package dev.distracted.iam.token;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

public final class SecureAccessTokenMaterialGenerator implements AccessTokenMaterialGenerator {
    private final SecureRandom random;

    public SecureAccessTokenMaterialGenerator(SecureRandom random) {
        this.random = Objects.requireNonNull(random);
    }

    @Override public String nextJti() {
        var bytes = new byte[18];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
