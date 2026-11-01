package dev.distracted.iam.platform.crypto;

public interface BlindIndexCapability extends StartupCheckedCapability {
    byte[] derive(byte[] canonicalValue);
}

