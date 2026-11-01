package dev.distracted.iam.activation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.activation.adapter.jdbc.JdbcAppActivationRepository;
import dev.distracted.iam.activation.adapter.jdbc.JdbcAppSubjectRepository;
import dev.distracted.iam.messaging.OnboardingEventFactory;
import dev.distracted.iam.messaging.OnboardingIntentException;
import dev.distracted.iam.messaging.SecureOnboardingEventIdGenerator;
import dev.distracted.iam.messaging.adapter.jdbc.JdbcOnboardingIntentWriter;
import dev.distracted.iam.platform.persistence.SpringTransactionRunner;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
class FirstActivationIntegrationTest {
    @Container static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final String APP = "dutch-development";
    private static final String IDENTITY = "hid_0123456789012345678901";
    private static final String CORRELATION = "cor_0123456789012345";
    private static JdbcTemplate owner;
    private static JdbcTemplate runtime;
    private static DriverManagerDataSource runtimeDataSource;

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
            statement.execute("grant iam_migrator to " + POSTGRES.getUsername());
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate();
        owner = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()));
        runtimeDataSource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_runtime_login", RUNTIME_PASSWORD);
        runtime = new JdbcTemplate(runtimeDataSource);
    }

    @BeforeEach
    void seed() {
        owner.execute("truncate app_activation,app_subject,human_identity,authentication_factor,recovery_method,"
                + "verified_identifier_blind_index,verified_identifier,verification_challenge,audit_fact,"
                + "outbox_delivery,outbox_event,policy_activation_evidence,policy_grant_type,"
                + "product_security_policy,resource_scope,resource_registration,client_pkce_method,"
                + "client_grant_type,client_redirect_uri,client_registration,app_registration cascade");
        owner.queryForObject("select reconcile_pinned_registration(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                APP, (short) 1, "Dutch Development", "development",
                "eb19d5cd14c21e66c334bdd61afd8822da6b2a7d692384a4aa4a96f9f589bafc",
                "dutch-mobile", "NATIVE_PUBLIC", "EXTERNAL", new String[] {"dutch://oauth/callback"},
                new String[] {"authorization_code"}, new String[] {"S256"}, "dutch-api",
                "https://api.dutch.invalid", new String[] {"member:read"}, true, "S256",
                new String[] {"verified_identifier", "usable_factor", "recovery_path"});
        owner.update("insert into human_identity(identity_id,state) values(?,?)", IDENTITY, "ACTIVE");
    }

    private static FirstActivationTransaction service(dev.distracted.iam.messaging.OnboardingIntentWriter intents) {
        var resolver = new AppSubjectResolver(new JdbcAppSubjectRepository(runtime),
                new SecureAppSubjectMaterialGenerator(), 3);
        var activations = new AppActivationService(new JdbcAppActivationRepository(runtime),
                new SecureAppActivationMaterialGenerator(new SecureRandom()), new ActivationPrerequisiteEvaluator());
        return new FirstActivationTransaction(resolver, activations, new OnboardingEventFactory(), intents,
                new SecureOnboardingEventIdGenerator(new SecureRandom()),
                new SpringTransactionRunner(new TransactionTemplate(
                        new DataSourceTransactionManager(runtimeDataSource))), "development");
    }

    private static void addEvidence() {
        owner.update("insert into verified_identifier(identifier_id,identity_id,identifier_type,"
                + "normalization_version,canonical_ciphertext,canonical_nonce,canonical_tag,display_ciphertext,"
                + "display_nonce,display_tag,encryption_key_version,verified_at) values(?,?,?,?,?,?,?,?,?,?,?,now())",
                "vid_0123456789012345678901", IDENTITY, "EMAIL", (short) 1, bytes(32), bytes(12), bytes(16),
                bytes(32), bytes(12), bytes(16), (short) 1);
        owner.update("insert into authentication_factor(factor_id,identity_id,verified_identifier_id,factor_type,state)"
                + " values(?,?,?,?,?)", "fac_0123456789012345678901", IDENTITY, "vid_0123456789012345678901",
                "EMAIL_OTP", "ACTIVE");
        owner.update("insert into recovery_method(recovery_method_id,identity_id,verified_identifier_id,"
                + "recovery_type,state) values(?,?,?,?,?)", "rcv_0123456789012345678901", IDENTITY,
                "vid_0123456789012345678901", "VERIFIED_EMAIL", "ACTIVE");
    }

    private static byte[] bytes(int length) {
        var value = new byte[length];
        java.util.Arrays.fill(value, (byte) 1);
        return value;
    }

    private static FirstActivationTransaction live() {
        return service(new JdbcOnboardingIntentWriter(runtime));
    }

    @Test
    void missingPrerequisitesLeaveActivationPendingAndCreateNoEvent() {
        var result = live().activate(APP, IDENTITY, CORRELATION);

        assertThat(result.activation().state()).isEqualTo(ActivationState.PENDING_PREREQUISITES);
        assertThat(result.onboardingIntent()).isEmpty();
        assertThat(count("outbox_event")).isZero();
        assertThat(count("outbox_delivery")).isZero();
    }

    @Test
    void completeEvidenceCreatesOneSubjectActivationAndOnboardingVersion() {
        addEvidence();
        var result = live().activate(APP, IDENTITY, CORRELATION);

        assertThat(result.activation().state()).isEqualTo(ActivationState.ACTIVE);
        assertThat(result.onboardingIntent()).isPresent();
        assertThat(result.activation().onboardingVersion()).isEqualTo(1);
        assertThat(count("app_subject")).isEqualTo(1);
        assertThat(count("app_activation")).isEqualTo(1);
        assertThat(count("outbox_event")).isEqualTo(1);
        assertThat(count("outbox_delivery")).isEqualTo(1);

        var retried = live().activate(APP, IDENTITY, CORRELATION);
        assertThat(retried.onboardingIntent().orElseThrow().eventId())
                .isEqualTo(result.onboardingIntent().orElseThrow().eventId());
        assertThat(count("app_subject")).isEqualTo(1);
        assertThat(count("app_activation")).isEqualTo(1);
        assertThat(count("outbox_event")).isEqualTo(1);
        assertThat(count("outbox_delivery")).isEqualTo(1);
    }

    @Test
    void aFailureAfterActivationRollsBackSubjectActivationAndIntentTogether() {
        addEvidence();
        var failing = service(command -> {
            throw new OnboardingIntentException();
        });

        assertThatThrownBy(() -> failing.activate(APP, IDENTITY, CORRELATION))
                .isInstanceOf(OnboardingIntentException.class);

        assertThat(count("app_subject")).isZero();
        assertThat(count("app_activation")).isZero();
        assertThat(count("outbox_event")).isZero();
        assertThat(count("outbox_delivery")).isZero();
    }

    @Test
    void aFailureAfterTheIntentIsAppendedRollsBackEveryEffectIncludingAudit() {
        addEvidence();
        var writer = new JdbcOnboardingIntentWriter(runtime);
        var failing = service(command -> {
            writer.append(command);
            throw new OnboardingIntentException();
        });

        assertThatThrownBy(() -> failing.activate(APP, IDENTITY, CORRELATION))
                .isInstanceOf(OnboardingIntentException.class);

        assertThat(count("app_subject")).isZero();
        assertThat(count("app_activation")).isZero();
        assertThat(count("outbox_event")).isZero();
        assertThat(count("outbox_delivery")).isZero();
        assertThat(count("audit_fact")).isZero();
    }

    @Test
    void concurrentFirstActivationHasExactlyOneWinner() throws Exception {
        addEvidence();
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> {
                barrier.await();
                return live().activate(APP, IDENTITY, CORRELATION);
            });
            var second = executor.submit(() -> {
                barrier.await();
                return live().activate(APP, IDENTITY, CORRELATION);
            });
            var one = first.get();
            var two = second.get();
            assertThat(one.activation().state()).isEqualTo(ActivationState.ACTIVE);
            assertThat(two.activation().state()).isEqualTo(ActivationState.ACTIVE);
            assertThat(count("app_subject")).isEqualTo(1);
            assertThat(count("app_activation")).isEqualTo(1);
            assertThat(count("outbox_event")).isEqualTo(1);
            assertThat(count("outbox_delivery")).isEqualTo(1);
        }
    }

    private static int count(String table) {
        return owner.queryForObject("select count(*) from " + table, Integer.class);
    }
}
