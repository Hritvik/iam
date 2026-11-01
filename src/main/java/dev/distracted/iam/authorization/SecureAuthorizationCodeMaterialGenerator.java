package dev.distracted.iam.authorization;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecureAuthorizationCodeMaterialGenerator implements AuthorizationCodeMaterialGenerator {
    private final SecureRandom random = new SecureRandom();

    @Override public AuthorizationCodeMaterial generate() {
        var id = new byte[17];
        var randomValue = new byte[32];
        random.nextBytes(id);
        random.nextBytes(randomValue);
        return new AuthorizationCodeMaterial("acd_" + encode(id), randomValue);
    }

    static String encode(byte[] value) { return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
}
