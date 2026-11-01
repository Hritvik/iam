package dev.distracted.iam.platform.persistence;

import dev.distracted.iam.messaging.Delivery;
import dev.distracted.iam.messaging.InitialDelivery;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

public final class JdbcDeliveryRepository implements DeliveryRepository {
    private final JdbcTemplate jdbc;

    public JdbcDeliveryRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override
    public AppendResult create(InitialDelivery delivery) {
        try {
            var result = jdbc.queryForObject("select append_initial_delivery(?,?)", Integer.class,
                    delivery.eventId(), Timestamp.from(delivery.availableAt()));
            if (result != null && result == 1) {
                return AppendResult.INSERTED;
            }
            if (result != null && result == 0) {
                return AppendResult.ALREADY_EXISTS;
            }
            throw new IllegalArgumentException("delivery conflicts with an existing intent");
        } catch (DataIntegrityViolationException exception) {
            throw new IllegalArgumentException("delivery rejected");
        }
    }

    @Override
    public List<Delivery> claim(String owner, Instant now, Duration leaseDuration, int limit) {
        var leaseSeconds = leaseDuration.toSeconds();
        if (owner == null || !owner.matches("^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
                || limit < 1 || limit > 1000 || leaseSeconds < 1 || leaseSeconds > 900
                || !leaseDuration.equals(Duration.ofSeconds(leaseSeconds))) {
            throw new IllegalArgumentException("unsafe claim policy");
        }
        return jdbc.query("select * from claim_outbox_deliveries(?,?,?,?)", (row, index) -> map(row), owner,
                Timestamp.from(now), (int) leaseSeconds, limit);
    }

    @Override
    public boolean acknowledge(
            String eventId, String destination, String leaseOwner, long expectedVersion, Instant now) {
        return Boolean.TRUE.equals(jdbc.queryForObject("select acknowledge_outbox_delivery(?,?,?,?,?)",
                Boolean.class, eventId, destination, leaseOwner, expectedVersion, Timestamp.from(now)));
    }

    @Override
    public boolean quarantine(String eventId, String destination, String leaseOwner, long expectedVersion,
            String reasonCode, Instant now) {
        if (!"RETRY_EXHAUSTED".equals(reasonCode) && !"NON_RETRYABLE_FAILURE".equals(reasonCode)) {
            throw new IllegalArgumentException("quarantine reason is not registered");
        }
        return Boolean.TRUE.equals(jdbc.queryForObject("select quarantine_outbox_delivery(?,?,?,?,?,?)",
                Boolean.class, eventId, destination, leaseOwner, expectedVersion, reasonCode, Timestamp.from(now)));
    }

    private static Delivery map(ResultSet row) throws SQLException {
        return new Delivery(row.getString("event_id"), row.getString("destination_name"), row.getString("state"),
                row.getInt("attempt_count"), row.getTimestamp("available_at").toInstant(),
                row.getString("lease_owner"), instant(row.getTimestamp("lease_expires_at")),
                instant(row.getTimestamp("acknowledged_at")), row.getString("last_failure_code"),
                row.getLong("version"));
    }

    private static Timestamp timestamp(Instant value) { return value == null ? null : Timestamp.from(value); }

    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }
}
