package dev.distracted.iam.messaging.relay.adapter.jdbc;

import dev.distracted.iam.messaging.relay.ClaimedDelivery;
import dev.distracted.iam.messaging.relay.OutboxEnvelope;
import dev.distracted.iam.messaging.relay.OutboxRelayRepository;
import dev.distracted.iam.messaging.relay.RelayException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcOutboxRelayRepository implements OutboxRelayRepository {
    private final JdbcTemplate jdbc;

    public JdbcOutboxRelayRepository(JdbcTemplate jdbc) {
        this.jdbc = java.util.Objects.requireNonNull(jdbc);
    }

    @Override public List<ClaimedDelivery> claim(String owner, Instant now, int leaseSeconds, int limit) {
        try {
            return jdbc.query("select event_id,destination_name,attempt_count,version from claim_outbox_deliveries(?,?,?,?)",
                    (row, index) -> new ClaimedDelivery(row.getString("event_id"), row.getString("destination_name"),
                            row.getInt("attempt_count"), row.getLong("version")),
                    owner, java.sql.Timestamp.from(now), leaseSeconds, limit);
        } catch (DataAccessException exception) {
            throw new RelayException(exception);
        }
    }

    @Override public Optional<OutboxEnvelope> event(String eventId) {
        try {
            return jdbc.query("select event_id,event_type,schema_version,occurred_at,producer,environment,aggregate_type,"
                            + "aggregate_id,aggregate_version,correlation_id,causation_id,destination_app_registration_id,"
                            + "payload::text payload,payload_fingerprint fingerprint from outbox_event "
                            + "where event_id=?",
                    (row, index) -> new OutboxEnvelope(row.getString("event_id"), row.getString("event_type"),
                            row.getLong("schema_version"), row.getTimestamp("occurred_at").toInstant(),
                            row.getString("producer"), row.getString("environment"), row.getString("aggregate_type"),
                            row.getString("aggregate_id"), row.getLong("aggregate_version"),
                            row.getString("correlation_id"), row.getString("causation_id"),
                            row.getString("destination_app_registration_id"), row.getString("payload"),
                            row.getString("fingerprint")),
                    eventId).stream().findFirst();
        } catch (DataAccessException exception) {
            throw new RelayException(exception);
        }
    }

    @Override public boolean acknowledge(String eventId, String destinationName, String owner, long expectedVersion,
                                         Instant now) {
        try {
            return Boolean.TRUE.equals(jdbc.queryForObject("select acknowledge_outbox_delivery(?,?,?,?,?)",
                    Boolean.class, eventId, destinationName, owner, expectedVersion, java.sql.Timestamp.from(now)));
        } catch (DataAccessException exception) {
            throw new RelayException(exception);
        }
    }

    @Override public void appendQuarantineAudit(String auditId, String eventId, String correlationId,
                                                String reasonCode, Instant occurredAt) {
        try {
            jdbc.queryForObject("select append_audit_fact(?,?,?,?,?,?,?,?,?,?)", Integer.class,
                    auditId, "OUTBOX_DELIVERY_QUARANTINED", "EVENT", eventId, "FAILED", correlationId,
                    null, eventId, reasonCode, java.sql.Timestamp.from(occurredAt));
        } catch (DataAccessException exception) {
            throw new RelayException(exception);
        }
    }

    @Override public boolean quarantine(String eventId, String destinationName, String owner, long expectedVersion,
                                        String reasonCode, Instant now) {
        try {
            return Boolean.TRUE.equals(jdbc.queryForObject("select quarantine_outbox_delivery(?,?,?,?,?,?)",
                    Boolean.class, eventId, destinationName, owner, expectedVersion, reasonCode,
                    java.sql.Timestamp.from(now)));
        } catch (DataAccessException exception) {
            throw new RelayException(exception);
        }
    }
}
