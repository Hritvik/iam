package dev.distracted.iam.messaging;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.messaging.relay.ClaimedDelivery;
import dev.distracted.iam.messaging.relay.OnboardingRelay;
import dev.distracted.iam.messaging.relay.OutboxTransport;
import dev.distracted.iam.messaging.relay.RelayOutcome;
import dev.distracted.iam.messaging.relay.RelaySettings;
import dev.distracted.iam.messaging.relay.adapter.jdbc.JdbcOutboxRelayRepository;
import dev.distracted.iam.messaging.snapshot.adapter.jdbc.JdbcOnboardingSnapshotQuery;
import java.sql.DriverManager;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
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
class OnboardingProducerIntegrationTest {
    @Container static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final String RELAY_PASSWORD = UUID.randomUUID().toString();
    private static final String APP = "dutch-development";
    private static final String IDENTITY = "hid_0123456789012345678901";
    private static final String SUBJECT = "aps_0123456789012345678901ab";
    private static final String ACTIVATION = "act_012345678901234567";
    private static final String EVENT = "evt_012345678901234567";
    private static final Instant NOW = Instant.parse("2026-10-30T00:00:00Z");
    private static JdbcTemplate owner;
    private static JdbcTemplate runtime;
    private static JdbcTemplate relay;

    @BeforeAll
    static void migrate() throws Exception {
        try (var connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()); var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
            statement.execute("create role unrelated_service nologin");
            statement.execute("create role iam_runtime_login login password '" + RUNTIME_PASSWORD + "' in role iam_runtime");
            statement.execute("create role iam_relay_login login password '" + RELAY_PASSWORD + "' in role iam_relay");
            statement.execute("grant iam_migrator to " + POSTGRES.getUsername());
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate();
        owner = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()));
        runtime = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_runtime_login",
                RUNTIME_PASSWORD));
        relay = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_relay_login", RELAY_PASSWORD));
    }

    @BeforeEach
    void seed() {
        owner.execute("truncate app_activation,app_subject,human_identity,authentication_factor,recovery_method,"
                + "verified_identifier_blind_index,verified_identifier,audit_fact,outbox_delivery,outbox_event,"
                + "policy_activation_evidence,policy_grant_type,product_security_policy,resource_scope,"
                + "resource_registration,client_pkce_method,client_grant_type,client_redirect_uri,"
                + "client_registration,app_registration cascade");
        owner.queryForObject("select reconcile_pinned_registration(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                APP, (short) 1, "Dutch Development", "development",
                "eb19d5cd14c21e66c334bdd61afd8822da6b2a7d692384a4aa4a96f9f589bafc",
                "dutch-mobile", "NATIVE_PUBLIC", "EXTERNAL", new String[] {"dutch://oauth/callback"},
                new String[] {"authorization_code"}, new String[] {"S256"}, "dutch-api",
                "https://api.dutch.invalid", new String[] {"member:read"}, true, "S256",
                new String[] {"verified_identifier", "usable_factor", "recovery_path"});
        owner.update("insert into human_identity(identity_id,state) values(?,?)", IDENTITY, "ACTIVE");
        owner.update("insert into app_subject(app_registration_id,human_identity_id,app_subject) values(?,?,?)",
                APP, IDENTITY, SUBJECT);
        owner.update("insert into app_activation(activation_id,app_registration_id,human_identity_id,app_subject,"
                + "state,activation_version,onboarding_version,onboarding_reason) values(?,?,?,?,?,?,?,?)",
                ACTIVATION, APP, IDENTITY, SUBJECT, "ACTIVE", 2, 1, "FIRST_ACTIVATION");
        owner.update("insert into outbox_event(event_id,event_type,schema_version,occurred_at,producer,environment,"
                + "aggregate_type,aggregate_id,aggregate_version,correlation_id,destination_app_registration_id,"
                + "payload,payload_fingerprint) values(?,?,?,?,?,?,?,?,?,?,?,?::jsonb,?)",
                EVENT, "iam.app-subject.onboarding-ready.v1", 1, java.sql.Timestamp.from(NOW), "iam", "development",
                "APP_ONBOARDING", ACTIVATION, 1, "cor_0123456789012345", APP,
                "{\"appRegistrationId\":\"dutch-development\",\"appSubject\":\"" + SUBJECT + "\","
                        + "\"activationId\":\"" + ACTIVATION + "\",\"activationState\":\"ACTIVE\","
                        + "\"activationVersion\":2,\"onboardingReason\":\"FIRST_ACTIVATION\","
                        + "\"onboardingVersion\":1,\"requiredProfileState\":\"PROFILE_REQUIRED\"}",
                "a".repeat(64));
        owner.update("insert into outbox_delivery(event_id,destination_name,state,attempt_count,initial_available_at,"
                + "available_at) values(?,?,?,?,?,?)", EVENT, "dutch-ums-onboarding", "PENDING", 0,
                java.sql.Timestamp.from(NOW), java.sql.Timestamp.from(NOW));
    }

    @Test
    void publishThenCrashBeforeAckIsRedeliveredAndTheSnapshotStaysAppScoped() {
        var published = new ArrayList<String>();
        OutboxTransport transport = envelope -> published.add(envelope.eventId());
        var repository = new JdbcOutboxRelayRepository(relay);

        // Publish succeeded, then the worker died before acknowledging.
        List<ClaimedDelivery> claimed = repository.claim("relay-crashed", NOW, 30, 10);
        assertThat(claimed).hasSize(1);
        transport.publish(repository.event(EVENT).orElseThrow());
        assertThat(published).containsExactly(EVENT);

        // A restarted worker recovers the expired lease and republishes the same immutable event.
        var restarted = new OnboardingRelay(new JdbcOutboxRelayRepository(relay), transport,
                new RelaySettings("relay-restarted", 30, 10, 5), Clock.fixed(NOW.plusSeconds(31), ZoneOffset.UTC));
        RelayOutcome outcome = restarted.drainOnce();
        assertThat(outcome.published()).isEqualTo(1);
        assertThat(outcome.acknowledged()).isEqualTo(1);
        assertThat(published).containsExactly(EVENT, EVENT);
        assertThat(owner.queryForObject("select count(*) from outbox_event", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select state from outbox_delivery", String.class))
                .isEqualTo("ACKNOWLEDGED");

        // Snapshot: the bound app sees exactly the allowlisted row, another app sees nothing.
        var query = new JdbcOnboardingSnapshotQuery(runtime);
        var page = query.page(APP, null, 100);
        assertThat(page.items()).singleElement().satisfies(item -> {
            assertThat(item.appSubject()).isEqualTo(SUBJECT);
            assertThat(item.activationState()).isEqualTo("ACTIVE");
            assertThat(item.requiredProfileState()).isEqualTo("PROFILE_REQUIRED");
        });
        assertThat(query.page("dutch-staging", null, 100).items()).isEmpty();
    }
}
