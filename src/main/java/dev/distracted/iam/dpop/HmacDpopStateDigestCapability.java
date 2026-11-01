package dev.distracted.iam.dpop;

import dev.distracted.iam.platform.crypto.CapabilityMetadata;
import dev.distracted.iam.platform.crypto.CapabilityPurpose;
import dev.distracted.iam.platform.crypto.CapabilitySelfCheck;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class HmacDpopStateDigestCapability implements DpopStateDigestCapability {
    private final String environment;
    private final short writeVersion;
    private final Map<Short, byte[]> keys;
    private final Map<Short, String> references;

    public HmacDpopStateDigestCapability(String environment, short writeVersion,
                                         Map<Short, byte[]> keys, Map<Short, String> references) {
        this.environment = requireText(environment);
        this.writeVersion = writeVersion;
        this.keys = copyKeys(keys);
        this.references = references == null ? Map.of() : Map.copyOf(references);
        if (!this.keys.keySet().equals(this.references.keySet()) || !this.keys.containsKey(writeVersion)) {
            throw invalidConfiguration();
        }
    }

    @Override public ProtectedDpopState protect(DpopStatePurpose purpose, String bindingId, byte[] transientValue) {
        return new ProtectedDpopState(writeVersion, digest(purpose, bindingId, transientValue, writeVersion));
    }

    @Override public ProtectedDpopCandidates protectReadable(DpopStatePurpose purpose, String bindingId,
                                                              byte[] transientValue) {
        return new ProtectedDpopCandidates(keys.keySet().stream().sorted()
                .map(version -> new ProtectedDpopState(version, digest(purpose, bindingId, transientValue, version)))
                .toList());
    }

    @Override public boolean matches(DpopStatePurpose purpose, String bindingId, byte[] transientValue,
                                     short keyVersion, byte[] expectedDigest) {
        if (!keys.containsKey(keyVersion) || expectedDigest == null || expectedDigest.length != 32) return false;
        return MessageDigest.isEqual(digest(purpose, bindingId, transientValue, keyVersion), expectedDigest);
    }

    private byte[] digest(DpopStatePurpose purpose, String bindingId, byte[] transientValue, short version) {
        if (purpose == null || bindingId == null || bindingId.isBlank() || bindingId.length() > 256
                || transientValue == null || transientValue.length < 16 || transientValue.length > 8192) {
            throw new IllegalArgumentException("dpop_state_material_invalid");
        }
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keys.get(version), "HmacSHA256"));
            return mac.doFinal(encode("iam", environment, "dpop-state", "digest-v1",
                    purpose.name(), bindingId, transientValue));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("dpop_state_digest_unavailable");
        }
    }

    private static byte[] encode(String... text) {
        var values = java.util.Arrays.stream(text).map(value -> value.getBytes(StandardCharsets.UTF_8)).toList();
        var length = values.stream().mapToInt(value -> Integer.BYTES + value.length).sum();
        var buffer = ByteBuffer.allocate(length);
        values.forEach(value -> buffer.putInt(value.length).put(value));
        return buffer.array();
    }

    private static byte[] encode(String one, String two, String three, String four,
                                 String five, String six, byte[] value) {
        var prefix = encode(one, two, three, four, five, six);
        return ByteBuffer.allocate(prefix.length + Integer.BYTES + value.length)
                .put(prefix).putInt(value.length).put(value).array();
    }

    private static Map<Short, byte[]> copyKeys(Map<Short, byte[]> source) {
        if (source == null || source.isEmpty()) throw invalidConfiguration();
        var copy = new java.util.HashMap<Short, byte[]>();
        source.forEach((version, key) -> {
            if (version == null || version < 1 || key == null || key.length < 32) throw invalidConfiguration();
            copy.put(version, key.clone());
        });
        return Map.copyOf(copy);
    }

    private static String requireText(String value) {
        if (value == null || value.isBlank() || value.length() > 64) throw invalidConfiguration();
        return value;
    }

    private static IllegalArgumentException invalidConfiguration() {
        return new IllegalArgumentException("dpop_state_digest_configuration_invalid");
    }

    @Override public short keyVersion() { return writeVersion; }
    @Override public Set<Short> readableKeyVersions() { return keys.keySet(); }
    @Override public Map<Short, String> keyReferences() { return references; }
    @Override public CapabilityMetadata metadata() {
        return new CapabilityMetadata(CapabilityPurpose.DPOP_STATE_DIGEST,
                "external", references.get(writeVersion), "HMAC-SHA-256");
    }
    @Override public CapabilitySelfCheck selfCheck() {
        try {
            var value = new byte[32];
            var protectedValue = protect(DpopStatePurpose.NONCE, "dns_self_check_abcdefghijklmnop", value);
            return matches(DpopStatePurpose.NONCE, "dns_self_check_abcdefghijklmnop", value,
                    protectedValue.keyVersion(), protectedValue.digest())
                    ? CapabilitySelfCheck.ready() : CapabilitySelfCheck.unhealthy("dpop_state_digest_failed");
        } catch (RuntimeException exception) {
            return CapabilitySelfCheck.unhealthy("dpop_state_digest_failed");
        }
    }

    @Override public String toString() { return "HmacDpopStateDigestCapability[redacted]"; }
}
