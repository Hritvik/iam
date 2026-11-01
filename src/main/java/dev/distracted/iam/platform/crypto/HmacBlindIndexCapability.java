package dev.distracted.iam.platform.crypto;

import dev.distracted.iam.identity.IdentifierType;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public final class HmacBlindIndexCapability implements BlindIndexCapability, VersionedBlindIndexCapability {
    private final Map<Short, String> keyReferences;
    private final short keyVersion;
    private final Map<Short, byte[]> keys;
    private final Set<Short> requiredWriteVersions;
    public HmacBlindIndexCapability(String keyReference, short keyVersion, byte[] key) {
        this(Map.of(keyVersion, keyReference), keyVersion, Set.of(keyVersion), singleton(keyVersion, key));
    }
    public HmacBlindIndexCapability(Map<Short, String> references, short keyVersion, Map<Short, byte[]> material) {
        this(references, keyVersion, Set.of(keyVersion), material);
    }
    public HmacBlindIndexCapability(Map<Short, String> references, short keyVersion,
            Set<Short> requiredWriteVersions, Map<Short, byte[]> material) {
        if (keyVersion < 1 || references == null || material == null || !references.keySet().equals(material.keySet())
                || !material.containsKey(keyVersion) || requiredWriteVersions == null || requiredWriteVersions.isEmpty()
                || !material.keySet().containsAll(requiredWriteVersions)
                || material.values().stream().anyMatch(key -> key.length < 32))
            throw new IllegalArgumentException("blind_index_keyring_invalid");
        this.keyReferences = Map.copyOf(references);
        this.keyVersion = keyVersion;
        var copy = new TreeMap<Short, byte[]>();
        material.forEach((version, key) -> copy.put(version, key.clone()));
        this.keys = Map.copyOf(copy);
        this.requiredWriteVersions = Set.copyOf(requiredWriteVersions);
    }
    @Override public byte[] deriveForVersion(short version, String environment, IdentifierType type,
            short normalizationVersion, String canonicalValue) {
        if (!keys.containsKey(version)) throw new IllegalStateException("blind_index_failed");
        return hmac(version, ("iam|" + environment + "|identifier|" + type.wireValue() + "|norm-v"
                + normalizationVersion + "|" + canonicalValue).getBytes(StandardCharsets.UTF_8));
    }
    public byte[] derive(String environment, IdentifierType type, short normalizationVersion, String canonicalValue) {
        return hmac(keyVersion, ("iam|" + environment + "|identifier|" + type.wireValue() + "|norm-v"
                + normalizationVersion + "|" + canonicalValue).getBytes(StandardCharsets.UTF_8));
    }
    @Override public Map<Short, byte[]> deriveReadable(String environment, IdentifierType type,
            short normalizationVersion, String canonicalValue) {
        var input = ("iam|" + environment + "|identifier|" + type.wireValue() + "|norm-v"
                + normalizationVersion + "|" + canonicalValue).getBytes(StandardCharsets.UTF_8);
        var values = new TreeMap<Short, byte[]>();
        keys.keySet().forEach(version -> values.put(version, hmac(version, input)));
        return Map.copyOf(values);
    }
    @Override public byte[] derive(byte[] canonicalValue) { return hmac(keyVersion, canonicalValue.clone()); }
    private byte[] hmac(short version, byte[] input) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keys.get(version), "HmacSHA256"));
            return mac.doFinal(input);
        }
        catch (Exception exception) { throw new IllegalStateException("blind_index_failed"); }
    }
    @Override public short keyVersion() { return keyVersion; }
    @Override public Set<Short> requiredWriteKeyVersions() { return requiredWriteVersions; }
    @Override public Set<Short> readableKeyVersions() { return keys.keySet(); }
    @Override public Map<Short, String> keyReferences() { return keyReferences; }
    @Override public CapabilityMetadata metadata() { return new CapabilityMetadata(CapabilityPurpose.IDENTIFIER_BLIND_INDEX, "local-jca", keyReferences.get(keyVersion), "HMAC-SHA-256"); }
    @Override public CapabilitySelfCheck selfCheck() { return CapabilitySelfCheck.ready(); }
    private static Map<Short, byte[]> singleton(short version, byte[] key) {
        if (key == null) throw new IllegalArgumentException("blind_index_keyring_invalid");
        return Map.of(version, key);
    }
}
