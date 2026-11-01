package dev.distracted.iam.dpop;

import java.security.SecureRandom;
import java.util.Base64;

public final class SecureDpopNonceGenerator {
    private final SecureRandom random;
    public SecureDpopNonceGenerator() { this(new SecureRandom()); }
    SecureDpopNonceGenerator(SecureRandom random) { this.random = java.util.Objects.requireNonNull(random); }
    public DpopNonceMaterial next() {
        var id = new byte[16];
        var nonce = new byte[32];
        random.nextBytes(id);
        random.nextBytes(nonce);
        var encoder = Base64.getUrlEncoder().withoutPadding();
        return new DpopNonceMaterial("dpn_" + encoder.encodeToString(id), encoder.encodeToString(nonce));
    }
}
