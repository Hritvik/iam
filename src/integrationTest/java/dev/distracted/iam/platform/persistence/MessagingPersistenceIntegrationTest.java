package dev.distracted.iam.platform.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import dev.distracted.iam.messaging.AuditFact;
import dev.distracted.iam.messaging.CorrelationId;
import dev.distracted.iam.messaging.InitialDelivery;
import dev.distracted.iam.messaging.OutboxEvent;
import dev.distracted.iam.messaging.OnboardingReadyPayload;
import dev.distracted.iam.messaging.Rfc8785PayloadFingerprint;
import java.sql.DriverManager;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.slf4j.LoggerFactory;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
class MessagingPersistenceIntegrationTest {
    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.0-alpine");
    private static JdbcTemplate jdbc;
    private static JdbcTemplate migratorJdbc;
    private static JdbcOutboxEventRepository events;
    private static JdbcAuditFactRepository audits;
    private static JdbcDeliveryRepository deliveries;
    private static JdbcDeliveryRepository runtimeDeliveries;
    private static SpringTransactionRunner transactions;
    private static final Rfc8785PayloadFingerprint FINGERPRINTS = new Rfc8785PayloadFingerprint();
    private static final String MIGRATOR_PASSWORD = UUID.randomUUID().toString();
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final String RELAY_PASSWORD = UUID.randomUUID().toString();
    private static final String UNRELATED_PASSWORD = UUID.randomUUID().toString();

    @BeforeAll
    static void migrate() throws Exception {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
            statement.execute("create role unrelated_service nologin");
            statement.execute("create role iam_migrator_login login password '" + MIGRATOR_PASSWORD
                    + "' in role iam_migrator");
            statement.execute("create role iam_runtime_login login password '" + RUNTIME_PASSWORD
                    + "' in role iam_runtime");
            statement.execute("create role iam_relay_login login password '" + RELAY_PASSWORD
                    + "' in role iam_relay");
            statement.execute("create role unrelated_login login password '" + UNRELATED_PASSWORD
                    + "' in role unrelated_service");
            statement.execute("grant usage,create on schema public to iam_migrator");
            statement.execute("create schema unrelated authorization unrelated_service");
            statement.execute("set role unrelated_service");
            statement.execute("create table unrelated.private_marker(id bigint primary key)");
            statement.execute("reset role");
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), "iam_migrator_login", MIGRATOR_PASSWORD)
                .initSql("set role iam_migrator")
                .load().migrate();
        var runtimeDataSource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), "iam_runtime_login", RUNTIME_PASSWORD);
        var relayDataSource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), "iam_relay_login", RELAY_PASSWORD);
        var migratorDataSource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), "iam_migrator_login", MIGRATOR_PASSWORD);
        jdbc = new JdbcTemplate(runtimeDataSource);
        migratorJdbc = new JdbcTemplate(migratorDataSource);
        migratorJdbc.execute("set role iam_migrator");
        migratorJdbc.execute("create table test_aggregate(id text primary key, version bigint not null)");
        migratorJdbc.execute("grant select,insert on test_aggregate to iam_runtime");
        events = new JdbcOutboxEventRepository(jdbc, FINGERPRINTS);
        audits = new JdbcAuditFactRepository(jdbc);
        deliveries = new JdbcDeliveryRepository(new JdbcTemplate(relayDataSource));
        runtimeDeliveries = new JdbcDeliveryRepository(jdbc);
        transactions = new SpringTransactionRunner(
                new TransactionTemplate(new DataSourceTransactionManager(runtimeDataSource)));
    }

    @Test
    void appendsRoundTripsAndDeduplicatesLogicalEvents() {
        var event = event(1, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        assertThat(transactions.required(() -> java.util.List.of(
                events.append(event), events.append(event))))
                .containsExactly(AppendResult.INSERTED, AppendResult.ALREADY_EXISTS);
        var collisionSource = event(2, event.eventType(), event.destinationAppRegistrationId());
        assertThatThrownBy(() -> events.append(event(event.eventId(), collisionSource)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("outbox event conflicts with an existing fact");
        assertThat(jdbc.queryForObject(
                "select aggregate_version from outbox_event where event_id=?", Long.class, event.eventId()))
                .isEqualTo(1L);
    }

    @Test
    void rejectsFingerprintMismatchAndSqlInjectionAsData() {
        var event = event(2, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        var invalid = new OutboxEvent(event.eventId(), event.eventType(), event.schemaVersion(), event.occurredAt(),
                event.producer(), event.environment(), event.aggregateType(), event.aggregateId(),
                event.aggregateVersion(), event.correlationId(), event.causationId(),
                event.destinationAppRegistrationId(), event.payload(), "0".repeat(64));
        assertThatThrownBy(() -> events.append(invalid)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new OnboardingReadyPayload("x'); drop table outbox_event; --",
                "aps_abcdefghijklmnopqrstuv", "act_abcdefghijklmnop", 1, "FIRST_ACTIVATION", 1))
                .hasMessageNotContaining("drop table");
        assertThat(jdbc.queryForObject("select count(*) from outbox_event", Integer.class)).isNotNull();
    }

    @Test
    void transactionRollsBackAtEveryNamedSeam() {
        for (var seam = 0; seam <= 4; seam++) {
            var currentSeam = seam;
            var event = event(40 + seam, "iam.app-subject.onboarding-ready.v1", "dutch-development");
            assertThatThrownBy(() -> transactions.required(() -> {
                failAt(currentSeam, 0);
                jdbc.update("insert into test_aggregate(id,version) values (?,?)", event.aggregateId() + currentSeam, 1);
                failAt(currentSeam, 1);
                events.append(event);
                failAt(currentSeam, 2);
                audits.append(audit(event));
                failAt(currentSeam, 3);
                runtimeDeliveries.create(pending(event));
                failAt(currentSeam, 4);
                return true;
            })).isInstanceOf(IllegalStateException.class);
            assertThat(migratorJdbc.queryForObject(
                    "select count(*) from outbox_event where event_id=?", Integer.class, event.eventId())).isZero();
            assertThat(migratorJdbc.queryForObject(
                    "select count(*) from audit_fact where event_id=?", Integer.class, event.eventId())).isZero();
            assertThat(migratorJdbc.queryForObject(
                    "select count(*) from outbox_delivery where event_id=?", Integer.class, event.eventId())).isZero();
        }
    }

    @Test
    void immutableFactsRejectOwnerUpdateAndDelete() {
        var event = event(5, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        events.append(event);
        audits.append(audit(event));
        assertThatThrownBy(() -> migratorJdbc.update(
                "update outbox_event set producer=? where event_id=?", "changed", event.eventId()))
                .hasMessageContaining("immutable fact mutation denied");
        assertThatThrownBy(() -> migratorJdbc.update("delete from audit_fact where event_id=?", event.eventId()))
                .hasMessageContaining("immutable fact mutation denied");
    }

    @Test
    void claimVersionRaceLeaseRecoveryAndAcknowledgementAreDurable() throws Exception {
        var first = event(6, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        var second = event(7, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        events.append(first);
        events.append(second);
        runtimeDeliveries.create(pending(first));
        runtimeDeliveries.create(pending(second));
        var now = Instant.parse("2026-01-02T03:04:05Z");
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var one = executor.submit(() -> {
                start.await();
                return deliveries.claim("relay-a", now, Duration.ofSeconds(30), 1);
            });
            var two = executor.submit(() -> {
                start.await();
                return deliveries.claim("relay-b", now, Duration.ofSeconds(30), 1);
            });
            start.countDown();
            var claimed = new HashSet<String>();
            one.get().forEach(delivery -> claimed.add(delivery.eventId()));
            two.get().forEach(delivery -> claimed.add(delivery.eventId()));
            assertThat(claimed).containsExactlyInAnyOrder(first.eventId(), second.eventId());
        }
        assertThat(runtimeDeliveries.create(pending(first))).isEqualTo(AppendResult.ALREADY_EXISTS);
        var expired = migratorJdbc.queryForMap(
                "select lease_owner,version from outbox_delivery where event_id=?", first.eventId());
        assertThat(deliveries.acknowledge(first.eventId(), "dutch-ums-onboarding", (String) expired.get("lease_owner"),
                (Long) expired.get("version"), now.plusSeconds(31))).isFalse();
        assertThat(deliveries.quarantine(first.eventId(), "dutch-ums-onboarding", (String) expired.get("lease_owner"),
                (Long) expired.get("version"), "RETRY_EXHAUSTED", now.plusSeconds(31))).isFalse();
        var restartedRelay = new JdbcDeliveryRepository(new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), "iam_relay_login", RELAY_PASSWORD)));
        var reclaimed = restartedRelay.claim(
                "relay-after-restart", now.plusSeconds(31), Duration.ofSeconds(30), 2);
        assertThat(reclaimed).hasSize(2).allMatch(delivery -> delivery.version() == 3);
        var delivery = reclaimed.getFirst();
        assertThat(deliveries.acknowledge(delivery.eventId(), delivery.destinationName(), "wrong-owner",
                delivery.version(), now.plusSeconds(32))).isFalse();
        assertThat(deliveries.acknowledge(
                delivery.eventId(), delivery.destinationName(), delivery.leaseOwner(), delivery.version(),
                now.plusSeconds(32))).isTrue();
        assertThat(runtimeDeliveries.create(new InitialDelivery(
                delivery.eventId(), Instant.parse("2026-01-02T03:04:05Z"))))
                .isEqualTo(AppendResult.ALREADY_EXISTS);
        assertThat(deliveries.acknowledge(
                delivery.eventId(), delivery.destinationName(), delivery.leaseOwner(), delivery.version(),
                now.plusSeconds(32))).isFalse();
    }

    @Test
    void enforcesRuntimeRelayAndUnrelatedRoleBoundaries() throws Exception {
        assertAllowed("iam_runtime_login", RUNTIME_PASSWORD, "select count(*) from outbox_event");
        assertDenied("iam_runtime_login", RUNTIME_PASSWORD, "update outbox_event set producer='changed'");
        assertDenied("iam_runtime_login", RUNTIME_PASSWORD, "insert into outbox_event(event_id) values ('denied')");
        assertDenied("iam_runtime_login", RUNTIME_PASSWORD,
                "insert into outbox_delivery(event_id,destination_name,state,available_at) values ('x','x','PENDING',now())");
        assertAllowed("iam_relay_login", RELAY_PASSWORD, "select count(*) from outbox_event");
        assertDenied("iam_relay_login", RELAY_PASSWORD, "update outbox_delivery set version=version+1");
        assertDenied("iam_relay_login", RELAY_PASSWORD,
                "insert into outbox_delivery(event_id,destination_name,state,available_at) values ('x','x','PENDING',now())");
        assertDenied("iam_relay_login", RELAY_PASSWORD, "select count(*) from audit_fact");
        assertDenied("unrelated_login", UNRELATED_PASSWORD, "select count(*) from outbox_event");
        assertDenied("unrelated_login", UNRELATED_PASSWORD,
                "select * from claim_outbox_deliveries('worker',now(),30,1)");
        assertDenied("iam_runtime_login", RUNTIME_PASSWORD, "select count(*) from unrelated.private_marker");
        assertAllowed("unrelated_login", UNRELATED_PASSWORD, "select count(*) from unrelated.private_marker");
        assertAllowed("iam_migrator_login", MIGRATOR_PASSWORD,
                "set role iam_migrator; create table synthetic_next_migration(id bigint primary key)");
        assertThat(migratorJdbc.queryForObject("""
                select r.rolname from pg_class c join pg_roles r on r.oid=c.relowner
                where c.relname='outbox_event'
                """, String.class)).isEqualTo("iam_migrator");
        assertThat(migratorJdbc.queryForObject("""
                select has_function_privilege('public',
                  'claim_outbox_deliveries(text,timestamptz,integer,integer)','EXECUTE')
                """, Boolean.class)).isFalse();
    }

    @Test
    void rejectsUnsafeClaimPolicyAtTheBoundary() {
        var now = Instant.parse("2026-01-02T03:04:05Z");
        assertThatThrownBy(() -> deliveries.claim("relay", now, Duration.ofSeconds(1), 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> deliveries.claim("relay", now, Duration.ofSeconds(1), 1001))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> deliveries.claim("relay", now, Duration.ofSeconds(-1), 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> deliveries.claim("relay", now, Duration.ZERO, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> deliveries.claim(null, now, Duration.ofSeconds(1), 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> deliveries.claim("invalid owner", now, Duration.ofSeconds(1), 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> deliveries.claim("relay", now, Duration.ofSeconds(901), 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> deliveries.claim("relay", now, Duration.ofMillis(1500), 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(deliveries.quarantine("evt_abcdefghijklmnop", "dutch-ums-onboarding", "relay", 1,
                "NON_RETRYABLE_FAILURE", now)).isFalse();
    }

    @Test
    void concurrentLogicalEventRetryCreatesOneFact() throws Exception {
        var first = event(8, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        var start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var one = executor.submit(() -> {
                start.await();
                return events.append(first);
            });
            var two = executor.submit(() -> {
                start.await();
                return events.append(first);
            });
            start.countDown();
            assertThat(java.util.List.of(one.get(), two.get()))
                    .containsExactlyInAnyOrder(AppendResult.INSERTED, AppendResult.ALREADY_EXISTS);
        }
        assertThat(jdbc.queryForObject("""
                select count(*) from outbox_event where aggregate_id=? and aggregate_version=?
                """, Integer.class, first.aggregateId(), first.aggregateVersion())).isEqualTo(1);
    }

    @Test
    void auditAndDeliveryRetriesRequireExactImmutableContent() {
        var event = event(9, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        events.append(event);
        var audit = audit(event);
        assertThat(audits.append(audit)).isEqualTo(AppendResult.INSERTED);
        assertThat(audits.append(audit)).isEqualTo(AppendResult.ALREADY_EXISTS);
        var conflictingAudit = new AuditFact(audit.auditId(), audit.factType(), audit.subjectKind(), audit.subjectId(),
                audit.outcome(), new CorrelationId("cor_differentcorrelate"), audit.causationId(), audit.eventId(), audit.reasonCode(),
                audit.occurredAt());
        assertThatThrownBy(() -> audits.append(conflictingAudit))
                .hasMessage("audit fact conflicts with an existing fact");

        var delivery = pending(event);
        assertThat(runtimeDeliveries.create(delivery)).isEqualTo(AppendResult.INSERTED);
        assertThat(runtimeDeliveries.create(delivery)).isEqualTo(AppendResult.ALREADY_EXISTS);
        var conflictingDelivery = new InitialDelivery(
                delivery.eventId(), delivery.availableAt().plusSeconds(1));
        assertThatThrownBy(() -> runtimeDeliveries.create(conflictingDelivery))
                .hasMessage("delivery conflicts with an existing intent");
    }

    @Test
    void quarantineIsFencedByOwnerVersionAndAllowlistedReason() {
        var event = event(10, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        events.append(event);
        runtimeDeliveries.create(pending(event));
        var now = Instant.parse("2026-01-02T03:04:05Z");
        var claimed = deliveries.claim("relay-quarantine", now, Duration.ofSeconds(30), 10).stream()
                .filter(candidate -> candidate.eventId().equals(event.eventId())).findFirst().orElseThrow();
        assertThat(deliveries.quarantine(claimed.eventId(), claimed.destinationName(), "wrong-owner",
                claimed.version(), "RETRY_EXHAUSTED", now)).isFalse();
        assertThat(deliveries.quarantine(claimed.eventId(), claimed.destinationName(), claimed.leaseOwner(),
                claimed.version() + 1, "RETRY_EXHAUSTED", now)).isFalse();
        assertThatThrownBy(() -> deliveries.quarantine(claimed.eventId(), claimed.destinationName(),
                claimed.leaseOwner(), claimed.version(), "private failure detail", now))
                .hasMessageNotContaining("private failure detail");
        assertThat(deliveries.quarantine(claimed.eventId(), claimed.destinationName(), claimed.leaseOwner(),
                claimed.version(), "RETRY_EXHAUSTED", now)).isTrue();
        assertThat(runtimeDeliveries.create(pending(event))).isEqualTo(AppendResult.ALREADY_EXISTS);
        assertThatThrownBy(() -> runtimeDeliveries.create(
                new InitialDelivery(event.eventId(), pending(event).availableAt().plusSeconds(1))))
                .hasMessage("delivery conflicts with an existing intent");
    }

    @Test
    void preservesNullabilityInstantsAndVersionsBeyond32Bit() {
        var version = 3_000_000_000L;
        var event = event(version, "iam.app-subject.onboarding-ready.v1", "midas-development");
        events.append(event);
        var row = migratorJdbc.queryForMap("select * from outbox_event where event_id=?", event.eventId());
        assertThat(row.get("aggregate_version")).isEqualTo(version);
        assertThat(row.get("causation_id")).isNull();
        assertThat(((java.sql.Timestamp) row.get("occurred_at")).toInstant()).isEqualTo(event.occurredAt());

        var otherDestination = event(version, event.eventType(), "jarvis-development");
        assertThat(events.append(otherDestination)).isEqualTo(AppendResult.INSERTED);
    }

    @Test
    void databaseAppendFunctionsRejectUnregisteredConstantsAndCanariesWithoutEcho() {
        var payload = new OnboardingReadyPayload("dutch-development", "aps_abcdefghijklmnopqrstuv",
                "act_abcdefghijklmnop", 1, "FIRST_ACTIVATION", 1);
        var canonical = payload.canonicalizationInput();
        assertRawEventRejected("unregistered.event.v1", 1, "iam", "APP_ONBOARDING",
                "cor_abcdefghijklmnop", null, canonical, "unregistered.event.v1");
        assertRawEventRejected("iam.app-subject.onboarding-ready.v1", 2, "iam", "APP_ONBOARDING",
                "cor_abcdefghijklmnop", null, canonical, "schema-version-canary");
        assertRawEventRejected("iam.app-subject.onboarding-ready.v1", 1, "other", "APP_ONBOARDING",
                "cor_abcdefghijklmnop", null, canonical, "producer-canary");
        assertRawEventRejected("iam.app-subject.onboarding-ready.v1", 1, "iam", "OTHER_AGGREGATE",
                "cor_abcdefghijklmnop", null, canonical, "aggregate-canary");
        var privateCanary = "person@example.invalid";
        assertRawEventRejected("iam.app-subject.onboarding-ready.v1", 1, "iam", "APP_ONBOARDING",
                privateCanary, null, canonical, privateCanary);
        assertRawEventRejected("iam.app-subject.onboarding-ready.v1", 1, "iam", "APP_ONBOARDING",
                "cor_abcdefghijklmnop", privateCanary, canonical, privateCanary);
        assertRawEventRejected("iam.app-subject.onboarding-ready.v1", 1, "iam", "APP_ONBOARDING",
                "cor_abcdefghijklmnop", null,
                canonical.replace("aps_abcdefghijklmnopqrstuv", privateCanary), privateCanary);
        assertThatThrownBy(() -> jdbc.queryForObject("select append_audit_fact(?,?,?,?,?,?,?,?,?,?)",
                Integer.class, id("aud_"), "OUTBOX_EVENT_RECORDED", "EVENT", "evt_abcdefghijklmnop",
                "SUCCEEDED", privateCanary, null, "evt_abcdefghijklmnop", null,
                java.sql.Timestamp.from(Instant.EPOCH))).hasMessageNotContaining(privateCanary);
    }

    @Test
    void databaseConstraintsRejectMalformedDeliveryAndAuditStates() {
        var event = event(12, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        events.append(event);
        assertDirectSqlRejected("""
                insert into outbox_delivery(event_id,destination_name,state,attempt_count,initial_available_at,
                  available_at,version) values (?,'dutch-ums-onboarding','LEASED',0,now(),now(),1)
                """, event.eventId());
        assertDirectSqlRejected("""
                insert into outbox_delivery(event_id,destination_name,state,attempt_count,initial_available_at,
                  available_at,version) values (?,'dutch-ums-onboarding','PENDING',-1,now(),now(),1)
                """, event.eventId());
        assertDirectSqlRejected("""
                insert into outbox_delivery(event_id,destination_name,state,attempt_count,initial_available_at,
                  available_at,version) values (?,'dutch-ums-onboarding','PENDING',0,now(),now(),0)
                """, event.eventId());
        assertDirectSqlRejected("""
                insert into audit_fact(audit_id,fact_type,subject_kind,subject_id,outcome,correlation_id,
                  event_id,occurred_at) values (?,'OUTBOX_EVENT_RECORDED','SYSTEM',null,'FAILED',?,?,now())
                """, id("aud_"), "cor_abcdefghijklmnop", event.eventId());
    }

    @Test
    void derivesTheRegisteredRouteAndRejectsAnUnregisteredAppRoute() {
        var dutch = event(13, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        events.append(dutch);
        runtimeDeliveries.create(pending(dutch));
        assertThat(migratorJdbc.queryForObject(
                "select destination_name from outbox_delivery where event_id=?", String.class, dutch.eventId()))
                .isEqualTo("dutch-ums-onboarding");

        var midas = event(13, "iam.app-subject.onboarding-ready.v1", "midas-development");
        events.append(midas);
        assertThatThrownBy(() -> runtimeDeliveries.create(pending(midas)))
                .hasMessage("delivery rejected");
    }

    @Test
    void exactEventRetryComparesPayloadAsWellAsTheSuppliedFingerprint() {
        var original = event(14, "iam.app-subject.onboarding-ready.v1", "dutch-development");
        events.append(original);
        var changedPayload = new OnboardingReadyPayload("dutch-development", "aps_abcdefghijklmnopqrstuv",
                original.aggregateId(), 2, "RECONCILIATION", original.aggregateVersion());
        var forged = new OutboxEvent(original.eventId(), original.eventType(), original.schemaVersion(),
                original.occurredAt(), original.producer(), original.environment(), original.aggregateType(),
                original.aggregateId(), original.aggregateVersion(), original.correlationId(), original.causationId(),
                original.destinationAppRegistrationId(), changedPayload, original.payloadFingerprint());
        assertThatThrownBy(() -> events.append(forged)).hasMessage("payload fingerprint mismatch");
        assertThat(jdbc.queryForObject("select append_outbox_event(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", Integer.class,
                original.eventId(), original.eventType(), original.schemaVersion(),
                java.sql.Timestamp.from(original.occurredAt()), original.producer(), original.environment(),
                original.aggregateType(), original.aggregateId(), original.aggregateVersion(),
                original.correlationId().value(), null, original.destinationAppRegistrationId(),
                changedPayload.canonicalizationInput(), original.payloadFingerprint())).isEqualTo(-1);
    }

    @Test
    void sanitizesNullMalformedJsonAndCanariesFromErrorsAndCapturedLogs() {
        var canary = "private.person@example.invalid";
        var fingerprintCanary = "cafebabe".repeat(8);
        var logger = (Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME);
        var captured = new ListAppender<ILoggingEvent>();
        captured.start();
        logger.addAppender(captured);
        try {
            var valid = event(15, "iam.app-subject.onboarding-ready.v1", "dutch-development");
            var invalidRepositoryEvent = new OutboxEvent(valid.eventId(), valid.eventType(), valid.schemaVersion(),
                    valid.occurredAt(), valid.producer(), valid.environment(), valid.aggregateType(),
                    valid.aggregateId(), valid.aggregateVersion(), valid.correlationId(), valid.causationId(),
                    valid.destinationAppRegistrationId(), valid.payload(), fingerprintCanary);
            var repositoryError = catchThrowable(() -> events.append(invalidRepositoryEvent));
            assertErrorChainOmits(repositoryError, fingerprintCanary);
            var malformed = "{\"appSubject\":\"" + canary + "\"";
            var eventError = catchThrowable(() -> jdbc.queryForObject(
                    "select append_outbox_event(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", Integer.class, null,
                    "iam.app-subject.onboarding-ready.v1", 1L, java.sql.Timestamp.from(Instant.EPOCH), "iam", "test",
                    "APP_ONBOARDING", "act_abcdefghijklmnop", 1L, "cor_abcdefghijklmnop", null,
                    "dutch-development", malformed, "0".repeat(64)));
            assertErrorChainOmits(eventError, canary);
            var auditError = catchThrowable(() -> jdbc.queryForObject(
                    "select append_audit_fact(?,?,?,?,?,?,?,?,?,?)", Integer.class, null,
                    "OUTBOX_EVENT_RECORDED", "EVENT", "evt_abcdefghijklmnop", "SUCCEEDED",
                    "cor_abcdefghijklmnop", null, "evt_abcdefghijklmnop", null,
                    java.sql.Timestamp.from(Instant.EPOCH)));
            assertErrorChainOmits(auditError, canary);
            var deliveryError = catchThrowable(() -> jdbc.queryForObject(
                    "select append_initial_delivery(?,?)", Integer.class, null, null));
            assertErrorChainOmits(deliveryError, canary);
            var applicationLeak = captured.list.stream().map(ILoggingEvent::getFormattedMessage)
                    .anyMatch(message -> message.contains(canary) || message.contains(fingerprintCanary));
            if (applicationLeak) {
                throw new AssertionError("captured application logs contained a privacy canary");
            }
            var databaseLogs = POSTGRES.getLogs();
            if (databaseLogs.contains(canary) || databaseLogs.contains(fingerprintCanary)) {
                throw new AssertionError("PostgreSQL logs contained a privacy canary");
            }
        } finally {
            logger.detachAppender(captured);
            captured.stop();
        }
    }

    private static void assertAllowed(String role, String password, String query) throws Exception {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), role, password);
                var statement = connection.createStatement()) {
            statement.execute(query);
        }
    }

    private static void assertDenied(String role, String password, String query) throws Exception {
        assertThatThrownBy(() -> assertAllowed(role, password, query)).isInstanceOf(Exception.class);
    }

    private static OutboxEvent event(long version, String type, String destination) {
        var payload = new OnboardingReadyPayload(destination, "aps_abcdefghijklmnopqrstuv",
                "act_abcdefghijklmnop", version, "FIRST_ACTIVATION", version);
        return new OutboxEvent(id("evt_"), type, 1, Instant.parse("2026-01-02T03:04:05Z"), "iam",
                "test", "APP_ONBOARDING", "act_abcdefghijklmnop", version,
                new CorrelationId("cor_abcdefghijklmnop"), null, destination, payload,
                FINGERPRINTS.fingerprint(payload));
    }

    private static OutboxEvent event(String id, OutboxEvent source) {
        return new OutboxEvent(id, source.eventType(), source.schemaVersion(), source.occurredAt(), source.producer(),
                source.environment(), source.aggregateType(), source.aggregateId(), source.aggregateVersion(),
                source.correlationId(), source.causationId(), source.destinationAppRegistrationId(),
                source.payload(), source.payloadFingerprint());
    }

    private static AuditFact audit(OutboxEvent event) {
        return new AuditFact(id("aud_"), "OUTBOX_EVENT_RECORDED", "EVENT", event.eventId(), "SUCCEEDED",
                event.correlationId(), null, event.eventId(), null, event.occurredAt());
    }

    private static InitialDelivery pending(OutboxEvent event) {
        return new InitialDelivery(event.eventId(), Instant.parse("2026-01-02T03:04:05Z"));
    }

    private static String id(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "");
    }

    private static void failAt(int seam, int current) {
        if (seam == current) {
            throw new IllegalStateException("injected failure");
        }
    }

    private static void assertRawEventRejected(String eventType, long schemaVersion, String producer,
            String aggregateType, String correlationId, String causationId, String payload, String canary) {
        assertThatThrownBy(() -> jdbc.queryForObject("select append_outbox_event(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                Integer.class, id("evt_"), eventType, schemaVersion, java.sql.Timestamp.from(Instant.EPOCH),
                producer, "test", aggregateType, "act_abcdefghijklmnop", 1L, correlationId, causationId,
                "dutch-development", payload, "0".repeat(64))).hasMessageNotContaining(canary);
    }

    private static void assertDirectSqlRejected(String sql, Object... parameters) {
        assertThatThrownBy(() -> migratorJdbc.update(sql, parameters)).isInstanceOf(Exception.class);
    }

    private static void assertErrorChainOmits(Throwable error, String canary) {
        assertThat(error).isNotNull();
        var messages = new StringBuilder();
        for (var current = error; current != null; current = current.getCause()) {
            messages.append(current.getClass().getName()).append(':').append(current.getMessage()).append('\n');
        }
        assertThat(messages).doesNotContain(canary);
    }
}
