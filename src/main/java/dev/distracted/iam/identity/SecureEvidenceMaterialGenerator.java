package dev.distracted.iam.identity;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecureEvidenceMaterialGenerator implements EvidenceMaterialGenerator {
    private final SecureRandom random;

    public SecureEvidenceMaterialGenerator() {
        this(new SecureRandom());
    }

    SecureEvidenceMaterialGenerator(SecureRandom random) {
        this.random = java.util.Objects.requireNonNull(random, "random");
    }

    @Override
    public String factorId() {
        return opaque("fac_");
    }

    @Override
    public String recoveryMethodId() {
        return opaque("rcv_");
    }

    @Override
    public String auditId() {
        return opaque("aud_");
    }

    private String opaque(String prefix) {
        var bytes = new byte[18];
        random.nextBytes(bytes);
        return prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
