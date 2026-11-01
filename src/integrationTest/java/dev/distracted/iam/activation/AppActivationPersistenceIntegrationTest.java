package dev.distracted.iam.activation;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.activation.adapter.jdbc.JdbcAppActivationRepository;
import java.sql.DriverManager;
import java.util.Set;
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
class AppActivationPersistenceIntegrationTest {
    @Container static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final String APP = "dutch-development";
    private static final String IDENTITY = "hid_0123456789012345678901";
    private static final String SUBJECT = "aps_0123456789012345678901ab";
    private static JdbcTemplate owner;
    private static JdbcTemplate runtime;

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
        runtime = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_runtime_login",
                RUNTIME_PASSWORD));
    }

    @BeforeEach
    void seed() {
        owner.execute("truncate app_activation,app_subject,human_identity,authentication_factor,recovery_method,"
                + "verified_identifier_blind_index,verified_identifier,verification_challenge,"
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
    }

    private static AppActivationService service() {
        return new AppActivationService(new JdbcAppActivationRepository(runtime),
                new SecureAppActivationMaterialGenerator(new java.security.SecureRandom()),
                new ActivationPrerequisiteEvaluator());
    }

    private static void addEvidence() {
        owner.update("insert into verified_identifier(identifier_id,identity_id,identifier_type,"
                + "normalization_version,canonical_ciphertext,canonical_nonce,canonical_tag,display_ciphertext,"
                + "display_nonce,display_tag,encryption_key_version,verified_at) values(?,?,?,?,?,?,?,?,?,?,?,now())",
                "vid_0123456789012345678901", IDENTITY, "EMAIL", (short) 1, bytes(1), bytes(2), bytes(3),
                bytes(4), bytes(5), bytes(6), (short) 1);
        owner.update("insert into authentication_factor(factor_id,identity_id,verified_identifier_id,factor_type,state)"
                + " values(?,?,?,?,?)", "fac_0123456789012345678901", IDENTITY, "vid_0123456789012345678901",
                "EMAIL_OTP", "ACTIVE");
        owner.update("insert into recovery_method(recovery_method_id,identity_id,verified_identifier_id,"
                + "recovery_type,state) values(?,?,?,?,?)", "rcv_0123456789012345678901", IDENTITY,
                "vid_0123456789012345678901", "VERIFIED_EMAIL", "ACTIVE");
    }

    private static byte[] bytes(int seed) {
        var length = switch (seed) {
            case 1, 4 -> 32;
            case 2, 5 -> 12;
            default -> 16;
        };
        var value = new byte[length];
        java.util.Arrays.fill(value, (byte) seed);
        return value;
    }

    @Test
    void missingPrerequisitesPersistPendingAndCreateNoOnboardingVersion() {
        var activation = service().advance(APP, IDENTITY, SUBJECT, "cor_0123456789012345");

        assertThat(activation.state()).isEqualTo(ActivationState.PENDING_PREREQUISITES);
        assertThat(activation.activationVersion()).isEqualTo(1);
        assertThat(activation.onboardingVersion()).isZero();
        assertThat(service().prerequisites(APP, IDENTITY).missing())
                .containsExactlyInAnyOrder("verified_identifier", "usable_factor", "recovery_path");
    }

    @Test
    void completeEvidenceActivatesOnceAndRetriesAreIdempotent() {
        var service = service();
        assertThat(service.advance(APP, IDENTITY, SUBJECT, "cor_0123456789012345").state())
                .isEqualTo(ActivationState.PENDING_PREREQUISITES);
        addEvidence();

        var activated = service.advance(APP, IDENTITY, SUBJECT, "cor_1123456789012345");
        assertThat(activated.state()).isEqualTo(ActivationState.ACTIVE);
        assertThat(activated.activationVersion()).isEqualTo(2);
        assertThat(activated.onboardingVersion()).isEqualTo(1);
        assertThat(activated.onboardingReason()).isEqualTo("FIRST_ACTIVATION");

        var retried = service.advance(APP, IDENTITY, SUBJECT, "cor_2123456789012345");
        assertThat(retried.activationId()).isEqualTo(activated.activationId());
        assertThat(retried.activationVersion()).isEqualTo(2);
        assertThat(retried.onboardingVersion()).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from app_activation", Integer.class)).isEqualTo(1);
    }

    @Test
    void aStaleExpectedVersionIsAConflictAndDoesNotAdvance() {
        var repository = new JdbcAppActivationRepository(runtime);
        repository.transition(new ActivationCommand("act_012345678901234567", APP, IDENTITY, SUBJECT, 0,
                "cor_0123456789012345"));
        addEvidence();

        var stale = repository.transition(new ActivationCommand("act_012345678901234567", APP, IDENTITY, SUBJECT, 7,
                "cor_1123456789012345"));
        assertThat(stale.outcome()).isEqualTo(ActivationTransition.Outcome.CONFLICT);
        assertThat(owner.queryForObject("select state from app_activation", String.class))
                .isEqualTo("PENDING_PREREQUISITES");
    }

    @Test
    void concurrentActivationHasExactlyOneWinner() throws Exception {
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> {
                barrier.await();
                return service().advance(APP, IDENTITY, SUBJECT, "cor_0123456789012345");
            });
            var second = executor.submit(() -> {
                barrier.await();
                return service().advance(APP, IDENTITY, SUBJECT, "cor_1123456789012345");
            });
            var one = first.get();
            var two = second.get();
            assertThat(one.activationId()).isEqualTo(two.activationId());
            assertThat(one.onboardingVersion()).isEqualTo(two.onboardingVersion());
            assertThat(owner.queryForObject("select count(*) from app_activation", Integer.class)).isEqualTo(1);
            assertThat(owner.queryForObject("select count(*) from app_activation where onboarding_version>1",
                    Integer.class)).isZero();
        }
    }

    @Test
    void aSubjectThatIsNotTheAuthoritativeMappingIsRejected() {
        var outcome = new JdbcAppActivationRepository(runtime).transition(new ActivationCommand(
                "act_012345678901234567", APP, IDENTITY, "aps_ZZZZZZZZZZZZZZZZZZZZZZZZ", 0,
                "cor_0123456789012345"));
        assertThat(outcome.outcome()).isEqualTo(ActivationTransition.Outcome.REJECTED);
        assertThat(owner.queryForObject("select count(*) from app_activation", Integer.class)).isZero();
    }

    @Test
    void anAppWithNoRegisteredEvidenceReportsNotRegisteredInBothPaths() throws Exception {
        owner.update("delete from policy_activation_evidence where app_registration_id=?", APP);

        var prerequisites = service().prerequisites(APP, IDENTITY);
        assertThat(prerequisites.satisfied()).isFalse();
        assertThat(prerequisites.missing()).containsExactly("app_not_registered");
        var sql = owner.queryForMap("select * from evaluate_activation_prerequisites(?,?)", APP, IDENTITY);
        assertThat(sql.get("satisfied")).isEqualTo(false);
        assertThat(java.util.Arrays.asList((Object[]) ((java.sql.Array) sql.get("missing")).getArray()))
                .containsExactly("app_not_registered");
    }

    @Test
    void concurrentActivationToActiveHasExactlyOneWinner() throws Exception {
        addEvidence();
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> {
                barrier.await();
                return service().advance(APP, IDENTITY, SUBJECT, "cor_0123456789012345");
            });
            var second = executor.submit(() -> {
                barrier.await();
                return service().advance(APP, IDENTITY, SUBJECT, "cor_1123456789012345");
            });
            var one = first.get();
            var two = second.get();
            assertThat(one.state()).isEqualTo(ActivationState.ACTIVE);
            assertThat(two.state()).isEqualTo(ActivationState.ACTIVE);
            assertThat(one.onboardingVersion()).isEqualTo(1);
            assertThat(two.onboardingVersion()).isEqualTo(1);
            assertThat(owner.queryForObject("select count(*) from app_activation", Integer.class)).isEqualTo(1);
        }
    }

    @Test
    void anotherIdentitysSubjectCannotBeStoredForThisIdentity() {
        owner.update("insert into human_identity(identity_id,state) values(?,?)", "hid_1123456789012345678901", "ACTIVE");
        owner.update("insert into app_subject(app_registration_id,human_identity_id,app_subject) values(?,?,?)",
                APP, "hid_1123456789012345678901", "aps_1123456789012345678901ab");

        var outcome = new JdbcAppActivationRepository(runtime).transition(new ActivationCommand(
                "act_012345678901234567", APP, IDENTITY, "aps_1123456789012345678901ab", 0,
                "cor_0123456789012345"));
        assertThat(outcome.outcome()).isEqualTo(ActivationTransition.Outcome.REJECTED);
        assertThat(owner.queryForObject("select count(*) from app_activation", Integer.class)).isZero();
    }

    @Test
    void activationObjectsHaveLeastPrivilegeAuthority() {
        assertThat(owner.queryForObject("select tableowner from pg_tables where schemaname='public' and tablename=?",
                String.class, "app_activation")).isEqualTo("iam_migrator");
        for (var role : java.util.List.of("iam_runtime", "iam_relay", "iam_registration_reconciler",
                "unrelated_service", "public")) {
            assertThat(owner.queryForObject("select has_table_privilege(?,?,?)", Boolean.class, role,
                    "public.app_activation", "SELECT")).as(role).isFalse();
        }
        for (var function : java.util.List.of("evaluate_activation_prerequisites(text,text)",
                "read_activation_evidence(text,text)",
                "advance_app_activation(text,text,text,text,bigint,text)", "read_app_activation(text,text)")) {
            assertThat(owner.queryForObject("select has_function_privilege('iam_runtime',?,'EXECUTE')", Boolean.class,
                    "public." + function)).isTrue();
            assertThat(owner.queryForObject("select has_function_privilege('public',?,'EXECUTE')", Boolean.class,
                    "public." + function)).isFalse();
        }
        assertThat(Set.of("PENDING_PREREQUISITES", "ACTIVE", "SUSPENDED", "DEPARTED")).hasSize(4);
    }
}
