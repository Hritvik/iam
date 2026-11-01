package dev.distracted.iam.platform.crypto;

public interface StartupCheckedCapability {
    CapabilityMetadata metadata();

    CapabilitySelfCheck selfCheck();
}

