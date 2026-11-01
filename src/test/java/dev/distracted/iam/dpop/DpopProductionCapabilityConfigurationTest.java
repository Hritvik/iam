package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.authorization.AuthorizationCodeDigestCapability;
import dev.distracted.iam.authorization.ProtectedAuthorizationCode;
import dev.distracted.iam.platform.crypto.CapabilityMetadata;
import dev.distracted.iam.platform.crypto.CapabilityPurpose;
import dev.distracted.iam.platform.crypto.CapabilitySelfCheck;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DpopProductionCapabilityConfigurationTest {
    @Test
    void productionLikeRequiresExactlyOneHealthyExternalPurposeSeparatedCapability() {
        var properties = new DpopCapabilityProperties(true, "kms://dpop/2");

        assertThatThrownBy(() -> new DpopProductionCapabilityConfiguration(properties, List.of(), List.of(),
                List.of(), List.of(), List.of(), List.of()))
                .isInstanceOf(IllegalStateException.class).hasMessage("dpop_state_digest_capability_required");

        var reused = capability("kms://dpop/2");
        assertThatThrownBy(() -> new DpopProductionCapabilityConfiguration(properties,
                List.of(reused), List.of(reusedCodeDigest()), List.of(), List.of(), List.of(), List.of()))
                .isInstanceOf(IllegalStateException.class).hasMessage("dpop_state_digest_capability_invalid");
    }

    @Test
    void healthyCapabilityWithDedicatedReferenceIsAccepted() {
        new DpopProductionCapabilityConfiguration(new DpopCapabilityProperties(true, "kms://dpop/2"),
                List.of(capability("kms://dpop/2")), List.of(), List.of(), List.of(), List.of(), List.of());
    }

    private static DpopStateDigestCapability capability(String reference) {
        return new HmacDpopStateDigestCapability("production", (short) 2,
                Map.of((short) 2, "dedicated-dpop-state-key-material".getBytes(StandardCharsets.US_ASCII)),
                Map.of((short) 2, reference));
    }

    private static AuthorizationCodeDigestCapability reusedCodeDigest() {
        return new AuthorizationCodeDigestCapability() {
            @Override public ProtectedAuthorizationCode protect(String id, byte[] secret) { throw new UnsupportedOperationException(); }
            @Override public boolean matches(String id, byte[] secret, short version, byte[] digest) { return false; }
            @Override public short keyVersion() { return 1; }
            @Override public java.util.Set<Short> readableKeyVersions() { return java.util.Set.of((short) 1); }
            @Override public Map<Short, String> keyReferences() { return Map.of((short) 1, "kms://dpop/2"); }
            @Override public CapabilityMetadata metadata() { return new CapabilityMetadata(CapabilityPurpose.AUTHORIZATION_CODE_DIGEST, "external", "kms://dpop/2", "HMAC-SHA-256"); }
            @Override public CapabilitySelfCheck selfCheck() { return CapabilitySelfCheck.ready(); }
        };
    }
}
