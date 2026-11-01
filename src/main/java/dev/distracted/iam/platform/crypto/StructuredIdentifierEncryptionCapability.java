package dev.distracted.iam.platform.crypto;

public interface StructuredIdentifierEncryptionCapability extends IdentifierEncryptionCapability {
    SealedIdentifierValue seal(byte[] plaintext, byte[] associatedData);
    byte[] open(SealedIdentifierValue sealed, byte[] associatedData);
    short keyVersion();
    java.util.Set<Short> readableKeyVersions();
    java.util.Map<Short, String> keyReferences();
}
