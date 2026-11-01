package dev.distracted.iam.messaging;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecureOnboardingEventIdGenerator {
    private final SecureRandom random;

    public SecureOnboardingEventIdGenerator(SecureRandom random) {
        this.random = java.util.Objects.requireNonNull(random);
    }

    public String next() {
        var bytes = new byte[18];
        random.nextBytes(bytes);
        return "evt_" + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
