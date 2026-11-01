package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HmacDpopStateDigestCapabilityTest {
    @Test
    void digestIsPurposeEnvironmentAndBindingSeparated() {
        var capability = capability((short) 2);

        var protectedValue = capability.protect(DpopStatePurpose.NONCE, "nonce_id_abcdefghijklmnop", value());

        assertThat(protectedValue.keyVersion()).isEqualTo((short) 2);
        assertThat(protectedValue.digest()).hasSize(32);
        assertThat(capability.matches(DpopStatePurpose.NONCE, "nonce_id_abcdefghijklmnop", value(),
                protectedValue.keyVersion(), protectedValue.digest())).isTrue();
        assertThat(capability.matches(DpopStatePurpose.REPLAY, "nonce_id_abcdefghijklmnop", value(),
                protectedValue.keyVersion(), protectedValue.digest())).isFalse();
        assertThat(capability.matches(DpopStatePurpose.NONCE, "nonce_id_xxxxxxxxxxxxxxxx", value(),
                protectedValue.keyVersion(), protectedValue.digest())).isFalse();
    }

    @Test
    void retainedKeyReadsOldDigestAndRemovedKeyFailsClosedWithoutThrowing() {
        var old = new HmacDpopStateDigestCapability("development", (short) 1,
                Map.of((short) 1, key("old")), Map.of((short) 1, "kms://dpop/1"));
        var protectedValue = old.protect(DpopStatePurpose.REPLAY, "proof_id_abcdefghijklmnop", value());
        var rotated = capability((short) 2);
        var removed = new HmacDpopStateDigestCapability("development", (short) 2,
                Map.of((short) 2, key("new")), Map.of((short) 2, "kms://dpop/2"));

        assertThat(rotated.matches(DpopStatePurpose.REPLAY, "proof_id_abcdefghijklmnop", value(),
                protectedValue.keyVersion(), protectedValue.digest())).isTrue();
        assertThat(rotated.protectReadable(DpopStatePurpose.REPLAY, "proof_id_abcdefghijklmnop", value())
                .values()).extracting(ProtectedDpopState::keyVersion).containsExactly((short) 1, (short) 2);
        assertThat(removed.matches(DpopStatePurpose.REPLAY, "proof_id_abcdefghijklmnop", value(),
                protectedValue.keyVersion(), protectedValue.digest())).isFalse();
    }

    @Test
    void configurationAndDiagnosticsFailClosed() {
        assertThatThrownBy(() -> new HmacDpopStateDigestCapability("development", (short) 1,
                Map.of((short) 1, new byte[8]), Map.of((short) 1, "kms://dpop/1")))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("dpop_state_digest_configuration_invalid");
        assertThat(capability((short) 2).toString()).doesNotContain("old-key", "new-key");
        assertThat(capability((short) 2).selfCheck().healthy()).isTrue();
    }

    @Test
    void rejectsEveryUnboundedOrMissingCapabilityInput() {
        assertThatThrownBy(() -> new HmacDpopStateDigestCapability(null, (short) 1,
                Map.of((short) 1, key("one")), Map.of((short) 1, "kms://dpop/1")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacDpopStateDigestCapability(" ", (short) 1,
                Map.of((short) 1, key("one")), Map.of((short) 1, "kms://dpop/1")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacDpopStateDigestCapability("x".repeat(65), (short) 1,
                Map.of((short) 1, key("one")), Map.of((short) 1, "kms://dpop/1")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacDpopStateDigestCapability("dev", (short) 1, null, Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacDpopStateDigestCapability("dev", (short) 1, Map.of(), Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacDpopStateDigestCapability("dev", (short) 2,
                Map.of((short) 1, key("one")), Map.of((short) 1, "kms://dpop/1")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacDpopStateDigestCapability("dev", (short) 1,
                Map.of((short) 1, key("one")), Map.of()))
                .isInstanceOf(IllegalArgumentException.class);
        var capability = capability((short) 2);
        assertThatThrownBy(() -> capability.protect(null, "binding_abcdefghijklmnop", value()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> capability.protect(DpopStatePurpose.NONCE, "", value()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> capability.protect(DpopStatePurpose.NONCE, "x".repeat(257), value()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> capability.protect(DpopStatePurpose.NONCE, "binding_abcdefghijklmnop", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> capability.protect(DpopStatePurpose.NONCE, "binding_abcdefghijklmnop", new byte[15]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> capability.protect(DpopStatePurpose.NONCE, "binding_abcdefghijklmnop", new byte[8193]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(capability.matches(DpopStatePurpose.NONCE, "binding_abcdefghijklmnop", value(),
                (short) 2, null)).isFalse();
        assertThat(capability.matches(DpopStatePurpose.NONCE, "binding_abcdefghijklmnop", value(),
                (short) 2, new byte[31])).isFalse();
    }

    private static HmacDpopStateDigestCapability capability(short version) {
        return new HmacDpopStateDigestCapability("development", version,
                Map.of((short) 1, key("old"), (short) 2, key("new")),
                Map.of((short) 1, "kms://dpop/1", (short) 2, "kms://dpop/2"));
    }

    private static byte[] key(String label) {
        return (label + "-key-material-for-dpop-state-000000").getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] value() { return "transient-dpop-material".getBytes(StandardCharsets.US_ASCII); }
}
