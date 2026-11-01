package dev.distracted.iam.platform.crypto;

public interface TokenSignerCapability extends StartupCheckedCapability {
    byte[] sign(byte[] signingInput);
}

