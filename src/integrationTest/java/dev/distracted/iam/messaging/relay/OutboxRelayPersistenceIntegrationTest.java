package dev.distracted.iam.messaging.relay;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.messaging.relay.adapter.jdbc.JdbcOutboxRelayRepository;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
class OutboxRelayPersistenceIntegrationTest {
    @Container static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RELAY_PASSWORD = UUID.randomUUID().toString();
    private static final String EVENT = "evt_012345678901234567";
    private static JdbcTemplate owner;
    private static JdbcTemplate relay;
    private static final Instant NOW = Instant.parse("2026-10-30T00:00:00Z");

    @BeforeAll
    static void migrate() throws Exception {
        try (var connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()); var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
            statement.execute("create role unrelated_service nologin");
            statement.execute("create role iam_relay_login login password '" + RELAY_PASSWORD + "' in role iam_relay");
            statement.execute("grant iam_migrator to " + POSTGRES.getUsername());
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate();
        owner = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()));
        relay = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_relay_login", RELAY_PASSWORD));
    }

    @BeforeEach
    void seed() {
        owner.execute("truncate audit_fact,outbox_delivery,outbox_event cascade");
        owner.update("insert into outbox_event(event_id,event_type,schema_version,occurred_at,producer,environment,"
                + "aggregate_type,aggregate_id,aggregate_version,correlation_id,destination_app_registration_id,"
                + "payload,payload_fingerprint) values(?,?,?,?,?,?,?,?,?,?,?,?::jsonb,?)",
                EVENT, "iam.app-subject.onboarding-ready.v1", 1, java.sql.Timestamp.from(NOW), "iam", "development",
                "APP_ONBOARDING", "act_012345678901234567", 1, "cor_0123456789012345", "dutch-development",
                "{\"appRegistrationId\":\"dutch-development\",\"appSubject\":\"aps_0123456789012345678901ab\","
                        + "\"activationId\":\"act_012345678901234567\",\"activationState\":\"ACTIVE\","
                        + "\"activationVersion\":2,\"onboardingReason\":\"FIRST_ACTIVATION\","
                        + "\"onboardingVersion\":1,\"requiredProfileState\":\"PROFILE_REQUIRED\"}",
                "a".repeat(64));
        owner.update("insert into outbox_delivery(event_id,destination_name,state,attempt_count,initial_available_at,"
                + "available_at) values(?,?,?,?,?,?)", EVENT, "dutch-ums-onboarding", "PENDING", 0,
                java.sql.Timestamp.from(NOW), java.sql.Timestamp.from(NOW));
    }

    private static JdbcOutboxRelayRepository repository() { return new JdbcOutboxRelayRepository(relay); }

    @Test
    void claimIsBoundedAndAcknowledgeCompletesTheDelivery() {
        var repo = repository();
        var claimed = repo.claim("relay-1", NOW, 30, 10);
        assertThat(claimed).singleElement().satisfies(d -> {
            assertThat(d.eventId()).isEqualTo(EVENT);
            assertThat(d.attemptCount()).isEqualTo(1);
        });
        assertThat(repo.event(EVENT).orElseThrow().payloadJson()).contains("aps_0123456789012345678901ab");
        assertThat(repo.acknowledge(EVENT, "dutch-ums-onboarding", "relay-1", claimed.getFirst().version(), NOW)).isTrue();
        assertThat(repo.claim("relay-2", NOW, 30, 10)).isEmpty();
    }

    @Test
    void anUnacknowledgedLeaseIsRedeliveredAfterExpiry() {
        var repo = repository();
        var first = repo.claim("relay-1", NOW, 30, 10);
        assertThat(first).hasSize(1);
        assertThat(repo.claim("relay-2", NOW.plusSeconds(10), 30, 10)).isEmpty();
        var recovered = repo.claim("relay-2", NOW.plusSeconds(31), 30, 10);
        assertThat(recovered).singleElement().satisfies(d -> assertThat(d.attemptCount()).isEqualTo(2));
    }

    @Test
    void quarantineIsTerminalAndConcurrentClaimsHaveOneWinner() throws Exception {
        var repo = repository();
        var claimed = repo.claim("relay-1", NOW, 30, 10);
        assertThat(repo.quarantine(EVENT, "dutch-ums-onboarding", "relay-1", claimed.getFirst().version(),
                "RETRY_EXHAUSTED", NOW)).isTrue();
        repo.appendQuarantineAudit("aud_012345678901234567", EVENT, "cor_0123456789012345",
                "RETRY_EXHAUSTED", NOW);
        var audit = owner.queryForMap("select fact_type, outcome, reason_code, event_id from audit_fact"
                + " where event_id=?", EVENT);
        assertThat(audit.get("fact_type")).isEqualTo("OUTBOX_DELIVERY_QUARANTINED");
        assertThat(audit.get("outcome")).isEqualTo("FAILED");
        assertThat(audit.get("reason_code")).isEqualTo("RETRY_EXHAUSTED");
        assertThat(repo.claim("relay-2", NOW.plusSeconds(60), 30, 10)).isEmpty();

        owner.update("update outbox_delivery set state='PENDING',lease_owner=null,lease_expires_at=null,"
                + "acknowledged_at=null,last_failure_code=null,version=version+1,available_at=? where event_id=?",
                java.sql.Timestamp.from(NOW), EVENT);
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> {
                barrier.await();
                return repository().claim("relay-a", NOW, 30, 10).size();
            });
            var second = executor.submit(() -> {
                barrier.await();
                return repository().claim("relay-b", NOW, 30, 10).size();
            });
            assertThat(first.get() + second.get()).isEqualTo(1);
        }
    }

    @Test
    void staleOrForeignWorkersCannotAcknowledgeOrQuarantine() {
        var repo = repository();
        var claimed = repo.claim("relay-1", NOW, 30, 10).getFirst();
        assertThat(repo.acknowledge(EVENT, "dutch-ums-onboarding", "relay-2", claimed.version(), NOW)).isFalse();
        assertThat(repo.acknowledge(EVENT, "dutch-ums-onboarding", "relay-1", claimed.version() + 1, NOW)).isFalse();
        assertThat(repo.quarantine(EVENT, "dutch-ums-onboarding", "relay-2", claimed.version(),
                "RETRY_EXHAUSTED", NOW)).isFalse();
        assertThat(owner.queryForObject("select state from outbox_delivery where event_id=?", String.class, EVENT))
                .isEqualTo("LEASED");
        assertThat(repo.acknowledge(EVENT, "dutch-ums-onboarding", "relay-1", claimed.version(), NOW)).isTrue();
    }

    @Test
    void onlyTheRelayRoleCanClaim() {
        assertThat(owner.queryForObject("select has_function_privilege('iam_relay',?,'EXECUTE')", Boolean.class,
                "public.claim_outbox_deliveries(text,timestamp with time zone,integer,integer)")).isTrue();
        assertThat(owner.queryForObject("select has_function_privilege('iam_runtime',?,'EXECUTE')", Boolean.class,
                "public.claim_outbox_deliveries(text,timestamp with time zone,integer,integer)")).isFalse();
        assertThat(owner.queryForObject("select has_table_privilege('iam_relay','public.outbox_event','SELECT')",
                Boolean.class)).isTrue();
    }
}
