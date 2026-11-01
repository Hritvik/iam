package dev.distracted.iam.platform.persistence;

import dev.distracted.iam.messaging.AuditFact;
import java.sql.Timestamp;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcAuditFactRepository implements AuditFactRepository {
    private final JdbcTemplate jdbc;

    public JdbcAuditFactRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override
    public AppendResult append(AuditFact fact) {
        try {
            var result = jdbc.queryForObject("select append_audit_fact(?,?,?,?,?,?,?,?,?,?)", Integer.class,
                    fact.auditId(), fact.factType(), fact.subjectKind(), fact.subjectId(), fact.outcome(),
                    fact.correlationId().value(), fact.causationId() == null ? null : fact.causationId().value(),
                    fact.eventId(), fact.reasonCode(),
                    Timestamp.from(fact.occurredAt()));
            if (result != null && result == 1) {
                return AppendResult.INSERTED;
            }
            if (result != null && result == 0) {
                return AppendResult.ALREADY_EXISTS;
            }
            throw new IllegalArgumentException("audit fact conflicts with an existing fact");
        } catch (DataIntegrityViolationException exception) {
            throw new IllegalArgumentException("audit fact rejected");
        }
    }
}
