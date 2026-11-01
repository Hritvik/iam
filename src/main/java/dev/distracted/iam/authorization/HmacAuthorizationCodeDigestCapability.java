package dev.distracted.iam.authorization;

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

public final class HmacAuthorizationCodeDigestCapability implements AuthorizationCodeDigestCapability {
    private final String environment;
    private final short writeVersion;
    private final Map<Short, byte[]> keys;
    private final Map<Short, String> references;

    public HmacAuthorizationCodeDigestCapability(String environment, short writeVersion,
            Map<Short, byte[]> keys, Map<Short, String> references) {
        this.environment = requireText(environment);
        this.writeVersion = writeVersion;
        this.keys = copyKeys(keys);
        this.references = Map.copyOf(references);
        if (!this.keys.keySet().equals(this.references.keySet()) || !this.keys.containsKey(writeVersion)) {
            throw new IllegalArgumentException("authorization_code_digest_configuration_invalid");
        }
    }

    @Override public ProtectedAuthorizationCode protect(String codeId, byte[] secret) {
        return new ProtectedAuthorizationCode(writeVersion, digest(codeId, secret, writeVersion));
    }

    @Override public boolean matches(String codeId, byte[] secret, short keyVersion, byte[] expectedDigest) {
        if (!keys.containsKey(keyVersion) || expectedDigest == null) return false;
        return MessageDigest.isEqual(digest(codeId, secret, keyVersion), expectedDigest);
    }

    private byte[] digest(String codeId, byte[] secret, short version) {
        if (codeId == null || secret == null || secret.length != 32) {
            throw new IllegalArgumentException("authorization_code_material_invalid");
        }
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keys.get(version), "HmacSHA256"));
            return mac.doFinal(encode("iam", environment, "authorization-code", "digest-v1", codeId, secret));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("authorization_code_digest_unavailable");
        }
    }

    private static byte[] encode(String first, String second, String third, String fourth,
            String fifth, byte[] secret) {
        var values = new byte[][] { bytes(first), bytes(second), bytes(third), bytes(fourth), bytes(fifth), secret };
        var length = java.util.Arrays.stream(values).mapToInt(value -> Integer.BYTES + value.length).sum();
        var buffer = ByteBuffer.allocate(length);
        for (var value : values) buffer.putInt(value.length).put(value);
        return buffer.array();
    }

    private static byte[] bytes(String value) { return requireText(value).getBytes(StandardCharsets.UTF_8); }
    private static String requireText(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("authorization_code_digest_configuration_invalid");
        return value;
    }
    private static Map<Short, byte[]> copyKeys(Map<Short, byte[]> source) {
        if (source == null || source.isEmpty()) throw new IllegalArgumentException("authorization_code_digest_configuration_invalid");
        var copy = new java.util.HashMap<Short, byte[]>();
        source.forEach((version, key) -> {
            if (version == null || version < 1 || key == null || key.length < 32) {
                throw new IllegalArgumentException("authorization_code_digest_configuration_invalid");
            }
            copy.put(version, key.clone());
        });
        return Map.copyOf(copy);
    }

    @Override public short keyVersion() { return writeVersion; }
    @Override public Set<Short> readableKeyVersions() { return keys.keySet(); }
    @Override public Map<Short, String> keyReferences() { return references; }
    @Override public CapabilityMetadata metadata() {
        return new CapabilityMetadata(CapabilityPurpose.AUTHORIZATION_CODE_DIGEST,
                "external", references.get(writeVersion), "HMAC-SHA-256");
    }
    @Override public CapabilitySelfCheck selfCheck() {
        try {
            var result = protect("acd_0123456789012345678901", new byte[32]);
            return matches("acd_0123456789012345678901", new byte[32], result.keyVersion(), result.digest())
                    ? CapabilitySelfCheck.ready() : CapabilitySelfCheck.unhealthy("authorization_code_digest_failed");
        } catch (RuntimeException exception) {
            return CapabilitySelfCheck.unhealthy("authorization_code_digest_failed");
        }
    }
}
