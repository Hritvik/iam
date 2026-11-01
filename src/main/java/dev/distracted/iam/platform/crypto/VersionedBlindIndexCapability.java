package dev.distracted.iam.platform.crypto;

import dev.distracted.iam.identity.IdentifierType;

public interface VersionedBlindIndexCapability extends BlindIndexCapability {
    byte[] derive(String environment, IdentifierType type, short normalizationVersion, String canonicalValue);
    byte[] deriveForVersion(short keyVersion, String environment, IdentifierType type,
            short normalizationVersion, String canonicalValue);
    java.util.Map<Short, byte[]> deriveReadable(
            String environment, IdentifierType type, short normalizationVersion, String canonicalValue);
    short keyVersion();
    java.util.Set<Short> requiredWriteKeyVersions();
    java.util.Set<Short> readableKeyVersions();
    java.util.Map<Short, String> keyReferences();
}
