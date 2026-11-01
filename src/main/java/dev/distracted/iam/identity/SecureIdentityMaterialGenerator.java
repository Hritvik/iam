package dev.distracted.iam.identity;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecureIdentityMaterialGenerator implements IdentityMaterialGenerator {
    private final SecureRandom random;
    public SecureIdentityMaterialGenerator() { this(new SecureRandom()); }
    SecureIdentityMaterialGenerator(SecureRandom random) { this.random = random; }
    @Override public String identityId() { return opaque("hid_", 18); }
    @Override public String identifierId() { return opaque("vid_", 18); }
    @Override public String challengeId() { return opaque("vch_", 18); }
    @Override public String auditId() { return opaque("aud_", 18); }
    @Override public String challengeCode() { return opaque("", 24); }
    private String opaque(String prefix, int bytes) {
        var value = new byte[bytes];
        random.nextBytes(value);
        return prefix + Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
