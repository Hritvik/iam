package dev.distracted.iam.messaging;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class Rfc8785PayloadFingerprintTest {
    @Test
    void canonicalizesObjectOrderBeforeSha256() {
        var capability = new Rfc8785PayloadFingerprint();
        var payload = new OnboardingReadyPayload("dutch-development", "aps_abcdefghijklmnopqrstuv",
                "act_abcdefghijklmnop", 1, "FIRST_ACTIVATION", 1);

        assertThat(capability.fingerprint(payload)).hasSize(64);
        assertThat(capability.fingerprint(payload)).isEqualTo(capability.fingerprint(payload));
        assertThat(capability.fingerprint(payload)).isNotEqualTo(capability.fingerprint(
                new OnboardingReadyPayload("dutch-development", "aps_abcdefghijklmnopqrstuv",
                        "act_abcdefghijklmnop", 2, "FIRST_ACTIVATION", 1)));
    }
}
