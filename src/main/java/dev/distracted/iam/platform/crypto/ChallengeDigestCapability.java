package dev.distracted.iam.platform.crypto;

public interface ChallengeDigestCapability extends StartupCheckedCapability {
    byte[] digest(String environment, String challengeId, String code);
    byte[] digest(short keyVersion, String environment, String challengeId, String code);
    short keyVersion();
    java.util.Set<Short> readableKeyVersions();
    java.util.Map<Short, String> keyReferences();
}
