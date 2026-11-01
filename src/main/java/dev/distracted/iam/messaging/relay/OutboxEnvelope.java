package dev.distracted.iam.messaging.relay;

public record OutboxEnvelope(String eventId, String eventType, long schemaVersion, java.time.Instant occurredAt,
                             String producer, String environment, String aggregateType, String aggregateId,
                             long aggregateVersion, String correlationId, String causationId,
                             String destinationAppRegistrationId, String payloadJson, String payloadFingerprint) {
    public OutboxEnvelope {
        if (eventId == null || eventType == null || occurredAt == null || payloadJson == null
                || payloadFingerprint == null || destinationAppRegistrationId == null) {
            throw new IllegalArgumentException("outbox_envelope_invalid");
        }
    }

    @Override public String toString() { return "OutboxEnvelope[eventId=" + eventId + ",redacted]"; }
}
