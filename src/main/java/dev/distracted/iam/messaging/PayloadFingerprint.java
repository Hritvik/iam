package dev.distracted.iam.messaging;

public interface PayloadFingerprint {
    String fingerprint(EventPayload payload);
}
