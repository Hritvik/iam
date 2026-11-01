package dev.distracted.iam.activation;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecureAppSubjectMaterialGenerator implements AppSubjectMaterialGenerator {
    private final SecureRandom random;

    public SecureAppSubjectMaterialGenerator() { this(new SecureRandom()); }

    SecureAppSubjectMaterialGenerator(SecureRandom random) { this.random = random; }

    @Override public AppSubject nextSubject() { return new AppSubject(opaque("aps_")); }

    @Override public String nextAuditId() { return opaque("aud_"); }

    private String opaque(String prefix) {
        var bytes = new byte[18];
        random.nextBytes(bytes);
        return prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
