package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HmacAuthorizationCodeDigestCapabilityTest {
    @Test
    void digestIsBoundToEnvironmentCodeIdAndSecret() {
        var capability = new HmacAuthorizationCodeDigestCapability(
                "development", (short) 2,
                Map.of((short) 1, "old-key-material-old-key-material".getBytes(StandardCharsets.US_ASCII),
                        (short) 2, "new-key-material-new-key-material".getBytes(StandardCharsets.US_ASCII)),
                Map.of((short) 1, "kms://auth-code/1", (short) 2, "kms://auth-code/2"));
        var secret = new byte[32];

        var protectedCode = capability.protect("acd_0123456789012345678901", secret);

        assertThat(protectedCode.keyVersion()).isEqualTo((short) 2);
        assertThat(protectedCode.digest()).hasSize(32);
        assertThat(capability.matches("acd_0123456789012345678901", secret,
                protectedCode.keyVersion(), protectedCode.digest())).isTrue();
        assertThat(capability.matches("acd_1123456789012345678901", secret,
                protectedCode.keyVersion(), protectedCode.digest())).isFalse();
    }

    @Test
    void rotatedCapabilityReadsOldVersionAndMissingOldKeyFailsClosed() {
        var old = new HmacAuthorizationCodeDigestCapability("development", (short) 1,
                Map.of((short) 1, "old-key-material-old-key-material".getBytes(StandardCharsets.US_ASCII)),
                Map.of((short) 1, "kms://auth-code/1"));
        var secret = new byte[32];
        var protectedCode = old.protect("acd_0123456789012345678901", secret);
        var rotated = new HmacAuthorizationCodeDigestCapability("development", (short) 2,
                Map.of((short) 1, "old-key-material-old-key-material".getBytes(StandardCharsets.US_ASCII),
                        (short) 2, "new-key-material-new-key-material".getBytes(StandardCharsets.US_ASCII)),
                Map.of((short) 1, "kms://auth-code/1", (short) 2, "kms://auth-code/2"));
        var removed = new HmacAuthorizationCodeDigestCapability("development", (short) 2,
                Map.of((short) 2, "new-key-material-new-key-material".getBytes(StandardCharsets.US_ASCII)),
                Map.of((short) 2, "kms://auth-code/2"));

        assertThat(rotated.matches("acd_0123456789012345678901", secret,
                protectedCode.keyVersion(), protectedCode.digest())).isTrue();
        assertThat(removed.matches("acd_0123456789012345678901", secret,
                protectedCode.keyVersion(), protectedCode.digest())).isFalse();
    }
}
