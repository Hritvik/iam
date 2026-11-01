package dev.distracted.iam.platform.crypto;

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public final class HmacChallengeDigestCapability implements ChallengeDigestCapability {
    private final Map<Short, String> keyReferences;
    private final short keyVersion;
    private final Map<Short, byte[]> keys;
    public HmacChallengeDigestCapability(String keyReference, short keyVersion, byte[] key) {
        this(Map.of(keyVersion, keyReference), keyVersion, singleton(keyVersion, key));
    }
    public HmacChallengeDigestCapability(Map<Short, String> references, short keyVersion, Map<Short, byte[]> material) {
        if (keyVersion < 1 || references == null || material == null || !references.keySet().equals(material.keySet())
                || !material.containsKey(keyVersion) || material.values().stream().anyMatch(key -> key.length < 32))
            throw new IllegalArgumentException("challenge_digest_keyring_invalid");
        this.keyReferences = Map.copyOf(references);
        this.keyVersion = keyVersion;
        var copy = new TreeMap<Short, byte[]>();
        material.forEach((version, key) -> copy.put(version, key.clone()));
        this.keys = Map.copyOf(copy);
    }
    @Override public byte[] digest(String environment, String challengeId, String code) {
        return digest(keyVersion, environment, challengeId, code);
    }
    @Override public byte[] digest(short version, String environment, String challengeId, String code) {
        if (!keys.containsKey(version)) throw new IllegalStateException("challenge_digest_failed");
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keys.get(version), "HmacSHA256"));
            return mac.doFinal(("iam|" + environment + "|verification-challenge|digest-v1|" + challengeId + "|" + code)
                    .getBytes(StandardCharsets.UTF_8));
        } catch (Exception exception) { throw new IllegalStateException("challenge_digest_failed"); }
    }
    @Override public short keyVersion() { return keyVersion; }
    @Override public Set<Short> readableKeyVersions() { return keys.keySet(); }
    @Override public Map<Short, String> keyReferences() { return keyReferences; }
    @Override public CapabilityMetadata metadata() { return new CapabilityMetadata(CapabilityPurpose.VERIFICATION_CHALLENGE_DIGEST, "local-jca", keyReferences.get(keyVersion), "HMAC-SHA-256"); }
    @Override public CapabilitySelfCheck selfCheck() { return CapabilitySelfCheck.ready(); }
    private static Map<Short, byte[]> singleton(short version, byte[] key) {
        if (key == null) throw new IllegalArgumentException("challenge_digest_keyring_invalid");
        return Map.of(version, key);
    }
}
