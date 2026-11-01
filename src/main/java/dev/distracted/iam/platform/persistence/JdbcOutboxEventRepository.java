package dev.distracted.iam.platform.persistence;

import dev.distracted.iam.messaging.OutboxEvent;
import dev.distracted.iam.messaging.PayloadFingerprint;
import java.sql.Timestamp;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcOutboxEventRepository implements OutboxEventRepository {
    private final JdbcTemplate jdbc;
    private final PayloadFingerprint fingerprints;

    public JdbcOutboxEventRepository(JdbcTemplate jdbc, PayloadFingerprint fingerprints) {
        this.jdbc = jdbc;
        this.fingerprints = fingerprints;
    }

    @Override
    public AppendResult append(OutboxEvent event) {
        if (!fingerprints.fingerprint(event.payload()).equals(event.payloadFingerprint())) {
            throw new IllegalArgumentException("payload fingerprint mismatch");
        }
        try {
            var result = jdbc.queryForObject("select append_outbox_event(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    Integer.class, event.eventId(), event.eventType(), event.schemaVersion(),
                    Timestamp.from(event.occurredAt()),
                    event.producer(), event.environment(), event.aggregateType(), event.aggregateId(),
                    event.aggregateVersion(), event.correlationId().value(),
                    event.causationId() == null ? null : event.causationId().value(),
                    event.destinationAppRegistrationId(), event.payload().canonicalizationInput(),
                    event.payloadFingerprint());
            if (result != null && result == 1) {
                return AppendResult.INSERTED;
            }
            if (result != null && result == 0) {
                return AppendResult.ALREADY_EXISTS;
            }
            throw new IllegalArgumentException("outbox event conflicts with an existing fact");
        } catch (DataIntegrityViolationException exception) {
            throw new IllegalArgumentException("outbox event rejected");
        }
    }
}
