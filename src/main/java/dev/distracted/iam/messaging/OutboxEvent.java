package dev.distracted.iam.messaging;

import java.time.Instant;

public record OutboxEvent(String eventId, String eventType, long schemaVersion, Instant occurredAt,
        String producer, String environment, String aggregateType, String aggregateId,
        long aggregateVersion, CorrelationId correlationId, CausationId causationId,
        String destinationAppRegistrationId, OnboardingReadyPayload payload, String payloadFingerprint) {
    public OutboxEvent {
        if (!eventId.matches("^evt_[A-Za-z0-9_-]{16,128}$")
                || !"iam.app-subject.onboarding-ready.v1".equals(eventType)
                || schemaVersion != 1 || !"iam".equals(producer) || !"APP_ONBOARDING".equals(aggregateType)
                || occurredAt == null || !("development".equals(environment) || "test".equals(environment)
                        || "staging".equals(environment) || "production".equals(environment))
                || correlationId == null || !payloadFingerprint.matches("^[0-9a-f]{64}$")
                || !aggregateId.equals(payload.activationId())
                || aggregateVersion != payload.onboardingVersion()
                || !destinationAppRegistrationId.equals(payload.appRegistrationId())) {
            throw new IllegalArgumentException("event payload semantics are invalid");
        }
    }
}
