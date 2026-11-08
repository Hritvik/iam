package dev.distracted.iam.messaging.relay.transport;

import dev.distracted.iam.messaging.relay.OutboxEnvelope;
import dev.distracted.iam.messaging.relay.TransportException;
import java.util.LinkedHashMap;
import java.util.Map;
import tools.jackson.databind.ObjectMapper;

/** Serializes an outbox envelope into the published reusable event envelope. */
public final class OutboxEnvelopeJson {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private OutboxEnvelopeJson() {
    }

    public static byte[] toWire(OutboxEnvelope envelope) {
        var aggregate = new LinkedHashMap<String, Object>();
        aggregate.put("type", envelope.aggregateType());
        aggregate.put("id", envelope.aggregateId());
        aggregate.put("version", envelope.aggregateVersion());
        var destination = new LinkedHashMap<String, Object>();
        destination.put("appRegistrationId", envelope.destinationAppRegistrationId());
        var wire = new LinkedHashMap<String, Object>();
        wire.put("eventId", envelope.eventId());
        wire.put("eventType", envelope.eventType());
        wire.put("schemaVersion", envelope.schemaVersion());
        wire.put("occurredAt", envelope.occurredAt().toString());
        wire.put("producer", envelope.producer());
        wire.put("environment", envelope.environment());
        wire.put("aggregate", Map.copyOf(aggregate));
        wire.put("correlationId", envelope.correlationId());
        wire.put("causationId", envelope.causationId());
        wire.put("destination", Map.copyOf(destination));
        wire.put("payload", MAPPER.readTree(envelope.payloadJson()));
        try {
            return MAPPER.writeValueAsBytes(wire);
        } catch (RuntimeException exception) {
            throw new TransportException();
        }
    }
}
