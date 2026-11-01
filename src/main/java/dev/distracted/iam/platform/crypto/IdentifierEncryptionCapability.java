package dev.distracted.iam.platform.crypto;

public interface IdentifierEncryptionCapability extends StartupCheckedCapability {
    byte[] encrypt(byte[] plaintext, byte[] associatedData);

    byte[] decrypt(byte[] ciphertext, byte[] associatedData);
}

