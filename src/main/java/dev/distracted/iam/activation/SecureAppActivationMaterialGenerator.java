package dev.distracted.iam.activation;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecureAppActivationMaterialGenerator implements AppActivationMaterialGenerator {
    private final SecureRandom random;

    public SecureAppActivationMaterialGenerator(SecureRandom random) {
        this.random = java.util.Objects.requireNonNull(random);
    }

    @Override public String nextActivationId() {
        var bytes = new byte[18];
        random.nextBytes(bytes);
        return "act_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
