package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AuthorizationCodeRedemptionTest {
    @Test
    void validS256ProofConsumesThroughTheAtomicPort() {
        var digest = new HmacAuthorizationCodeDigestCapability("development", (short) 1,
                Map.of((short) 1, "authorization-code-test-key-00001".getBytes(StandardCharsets.US_ASCII)),
                Map.of((short) 1, "test://authorization-code/1"));
        var secret = new byte[32];
        var codeId = "acd_0123456789012345678901";
        var protection = digest.protect(codeId, secret);
        var consumed = new ConsumedAuthorization("arq_0123456789012345678901", "dutch-development",
                "dutch-mobile", "dutch-api", "https://api.dutch.invalid", "hid_0123456789012345678901",
                "member:read", new byte[32], new byte[32]);
        AuthorizationCodeConsumptionRepository repository = new AuthorizationCodeConsumptionRepository() {
            public Optional<AuthorizationCodeProtection> findProtection(String ignored) {
                return Optional.of(new AuthorizationCodeProtection(protection.keyVersion(), protection.digest(), 1L));
            }
            public Optional<ConsumedAuthorization> consume(AuthorizationCodeConsumption command) {
                return Optional.of(consumed);
            }
        };
        var service = new AuthorizationCodeRedemption(repository, digest, "https://iam.distracted.invalid");

        var result = service.redeem(new AuthorizationCodeRedemptionCommand(
                "authorization_code", codeId + "." + SecureAuthorizationCodeMaterialGenerator.encode(secret), "dutch-mobile",
                "dutch://oauth/callback", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "cor_0123456789012345"));

        assertThat(result).contains(consumed);
    }
}
