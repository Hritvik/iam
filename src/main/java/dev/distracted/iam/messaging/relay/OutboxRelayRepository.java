package dev.distracted.iam.messaging.relay;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface OutboxRelayRepository {
    List<ClaimedDelivery> claim(String owner, Instant now, int leaseSeconds, int limit);
    Optional<OutboxEnvelope> event(String eventId);
    boolean acknowledge(String eventId, String destinationName, String owner, long expectedVersion, Instant now);
    boolean quarantine(String eventId, String destinationName, String owner, long expectedVersion,
                       String reasonCode, Instant now);
    void appendQuarantineAudit(String auditId, String eventId, String correlationId, String reasonCode,
                               Instant occurredAt);
}
