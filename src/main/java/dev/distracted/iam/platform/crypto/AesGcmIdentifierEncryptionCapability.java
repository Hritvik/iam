package dev.distracted.iam.platform.crypto;

import dev.distracted.iam.identity.IdentifierCryptoException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AesGcmIdentifierEncryptionCapability
        implements IdentifierEncryptionCapability, StructuredIdentifierEncryptionCapability {
    private static final int TAG_BYTES = 16;
    private final Map<Short, String> keyReferences;
    private final short keyVersion;
    private final Map<Short, SecretKeySpec> keys;
    private final SecureRandom random;

    public AesGcmIdentifierEncryptionCapability(String keyReference, short keyVersion, byte[] key) {
        this(Map.of(keyVersion, keyReference), keyVersion, singleton(keyVersion, key), new SecureRandom());
    }

    public AesGcmIdentifierEncryptionCapability(
            Map<Short, String> keyReferences, short keyVersion, Map<Short, byte[]> keys) {
        this(keyReferences, keyVersion, keys, new SecureRandom());
    }

    AesGcmIdentifierEncryptionCapability(Map<Short, String> references, short keyVersion,
            Map<Short, byte[]> material, SecureRandom random) {
        if (keyVersion < 1 || references == null || material == null || !references.keySet().equals(material.keySet())
                || !material.containsKey(keyVersion) || material.values().stream().anyMatch(key -> key.length != 32)) {
            throw new IllegalArgumentException("encryption_keyring_invalid");
        }
        this.keyReferences = Map.copyOf(references);
        this.keyVersion = keyVersion;
        var copied = new TreeMap<Short, SecretKeySpec>();
        material.forEach((version, key) -> copied.put(version, new SecretKeySpec(key.clone(), "AES")));
        this.keys = Map.copyOf(copied);
        this.random = random;
    }

    public SealedIdentifierValue seal(byte[] plaintext, byte[] associatedData) {
        try {
            var nonce = new byte[12];
            random.nextBytes(nonce);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keys.get(keyVersion), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(associatedData.clone());
            var combined = cipher.doFinal(plaintext.clone());
            return new SealedIdentifierValue(Arrays.copyOf(combined, combined.length - TAG_BYTES), nonce,
                    Arrays.copyOfRange(combined, combined.length - TAG_BYTES, combined.length), keyVersion);
        } catch (Exception exception) { throw new IdentifierCryptoException(); }
    }

    @Override public byte[] open(SealedIdentifierValue sealed, byte[] associatedData) {
        try {
            var readKey = keys.get(sealed.keyVersion());
            if (readKey == null) throw new IdentifierCryptoException();
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, readKey, new GCMParameterSpec(128, sealed.nonce()));
            cipher.updateAAD(associatedData.clone());
            var ciphertext = sealed.ciphertext();
            var tag = sealed.tag();
            var combined = Arrays.copyOf(ciphertext, ciphertext.length + tag.length);
            System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
            return cipher.doFinal(combined);
        } catch (Exception exception) { throw new IdentifierCryptoException(); }
    }

    @Override public byte[] encrypt(byte[] plaintext, byte[] associatedData) {
        var sealed = seal(plaintext, associatedData);
        var output = new byte[12 + sealed.ciphertext().length + 16];
        System.arraycopy(sealed.nonce(), 0, output, 0, 12);
        System.arraycopy(sealed.ciphertext(), 0, output, 12, sealed.ciphertext().length);
        System.arraycopy(sealed.tag(), 0, output, output.length - 16, 16);
        return output;
    }

    @Override public byte[] decrypt(byte[] ciphertext, byte[] associatedData) {
        if (ciphertext == null || ciphertext.length <= 28) throw new IdentifierCryptoException();
        var nonce = Arrays.copyOfRange(ciphertext, 0, 12);
        var encrypted = Arrays.copyOfRange(ciphertext, 12, ciphertext.length - 16);
        var tag = Arrays.copyOfRange(ciphertext, ciphertext.length - 16, ciphertext.length);
        return open(new SealedIdentifierValue(encrypted, nonce, tag, keyVersion), associatedData);
    }

    @Override public CapabilityMetadata metadata() { return new CapabilityMetadata(CapabilityPurpose.IDENTIFIER_ENCRYPTION, "local-jca", keyReferences.get(keyVersion), "AES-256-GCM"); }
    @Override public CapabilitySelfCheck selfCheck() { return CapabilitySelfCheck.ready(); }
    @Override public short keyVersion() { return keyVersion; }
    @Override public Set<Short> readableKeyVersions() { return keys.keySet(); }
    @Override public Map<Short, String> keyReferences() { return keyReferences; }
    private static Map<Short, byte[]> singleton(short version, byte[] key) {
        if (key == null) throw new IllegalArgumentException("encryption_keyring_invalid");
        return Map.of(version, key);
    }
}
