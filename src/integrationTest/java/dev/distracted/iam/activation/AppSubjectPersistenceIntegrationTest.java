package dev.distracted.iam.activation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.DriverManager;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import dev.distracted.iam.bootstrap.IamApplication;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import dev.distracted.iam.activation.adapter.jdbc.JdbcAppSubjectRepository;

@Testcontainers
class AppSubjectPersistenceIntegrationTest {
    @Container static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
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
            statement.execute("create role iam_runtime_login login password '" + RUNTIME_PASSWORD
                    + "' in role iam_runtime");
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
        owner.execute("truncate token_issuance_audit_fact,dpop_replay,dpop_nonce,app_subject,audit_fact,verified_identifier_blind_index,verified_identifier,"
                + "verification_challenge,human_identity,policy_activation_evidence,policy_grant_type,"
                + "product_security_policy,resource_scope,resource_registration,client_pkce_method,"
                + "client_grant_type,client_redirect_uri,client_registration,app_registration cascade");
        owner.queryForObject("select reconcile_pinned_registration(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                "dutch-development", (short) 1, "Dutch Development", "development",
                "eb19d5cd14c21e66c334bdd61afd8822da6b2a7d692384a4aa4a96f9f589bafc",
                "dutch-mobile", "NATIVE_PUBLIC", "EXTERNAL", new String[] {"dutch://oauth/callback"},
                new String[] {"authorization_code"}, new String[] {"S256"}, "dutch-api",
                "https://api.dutch.invalid", new String[] {"member:read"}, true, "S256",
                new String[] {"verified_identifier", "usable_factor", "recovery_path"});
        owner.update("insert into human_identity(identity_id,state) values(?,?)",
                "hid_0123456789012345678901", "ACTIVE");
    }

    @Test
    void resolvesOneStableSubjectAndOneAuditFact() {
        var first = resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aud_0123456789012345678901");
        var repeated = resolve("aps_BBBBBBBBBBBBBBBBBBBBBBBB", "aud_1123456789012345678901");

        assertThat(first.get("result")).isEqualTo("CREATED");
        assertThat(repeated.get("result")).isEqualTo("EXISTING");
        assertThat(repeated.get("app_subject")).isEqualTo(first.get("app_subject"));
        assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type='APP_SUBJECT_ALLOCATED'",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void runtimeCannotReadOrMutateMappingsDirectly() {
        resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aud_0123456789012345678901");

        assertThatThrownBy(() -> runtime.queryForObject("select count(*) from app_subject", Integer.class))
                .hasRootCauseMessage("ERROR: permission denied for table app_subject");
        assertThatThrownBy(() -> runtime.update("delete from app_subject"))
                .hasRootCauseMessage("ERROR: permission denied for table app_subject");
    }

    @Test
    void jdbcAdapterMapsTheClosedDatabaseOutcomes() {
        var repository = new JdbcAppSubjectRepository(runtime);

        var result = repository.resolve("dutch-development", "hid_0123456789012345678901",
                new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA"), "aud_0123456789012345678901",
                "cor_0123456789012345");

        assertThat(result.outcome()).isEqualTo(AppSubjectRepository.Outcome.CREATED);
        assertThat(result.appSubject()).isEqualTo(new AppSubject("aps_AAAAAAAAAAAAAAAAAAAAAAAA"));
    }

    @Test
    void concurrentFirstResolutionHasOneStableWinner() throws Exception {
        var ready = new CountDownLatch(8);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var attempts = java.util.stream.IntStream.range(0, 8).mapToObj(index -> executor.submit(() -> {
                ready.countDown();
                start.await(10, TimeUnit.SECONDS);
                return resolve("aps_" + String.valueOf((char) ('A' + index)).repeat(24),
                        "aud_" + index + "123456789012345678901").get("app_subject");
            })).toList();
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            assertThat(attempts.stream().map(future -> {
                try { return future.get(10, TimeUnit.SECONDS); }
                catch (Exception exception) { throw new AssertionError(exception); }
            }).distinct()).hasSize(1);
        }
        assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type='APP_SUBJECT_ALLOCATED'",
                Integer.class)).isEqualTo(1);
    }

    @Test
    void concurrentIdentityDisableCannotRaceAnAllocation() throws Exception {
        try (var mutation = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()); var statement = mutation.prepareStatement(
                        "update human_identity set state='DISABLED' where identity_id=?");
                var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            mutation.setAutoCommit(false);
            statement.setString(1, "hid_0123456789012345678901");
            statement.executeUpdate();
            var future = executor.submit(() -> resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA",
                    "aud_0123456789012345678901"));
            awaitBlockedResolution();
            mutation.commit();
            assertThat(future.get(10, TimeUnit.SECONDS).get("result")).isEqualTo("REJECTED");
        }
        assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isZero();
        assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type='APP_SUBJECT_ALLOCATED'",
                Integer.class)).isZero();
    }

    @Test
    void concurrentRegistrationMutationCannotRaceAnAllocation() throws Exception {
        try (var mutation = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword()); var statement = mutation.prepareStatement(
                        "delete from policy_activation_evidence where app_registration_id=?");
                var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            mutation.setAutoCommit(false);
            statement.setString(1, "dutch-development");
            statement.executeUpdate();
            var future = executor.submit(() -> resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA",
                    "aud_0123456789012345678901"));
            awaitBlockedResolution();
            mutation.commit();
            assertThat(future.get(10, TimeUnit.SECONDS).get("result")).isEqualTo("REJECTED");
        }
        assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isZero();
        assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type='APP_SUBJECT_ALLOCATED'",
                Integer.class)).isZero();
    }

    @Test
    void globalCollisionRetriesWithoutCreatingACrossAppLink() {
        owner.update("insert into human_identity(identity_id,state) values(?,?)",
                "hid_1123456789012345678901", "ACTIVE");
        seedSecondRegistration();
        resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aud_0123456789012345678901");

        var collision = runtime.queryForMap("select * from resolve_app_subject(?,?,?,?,?)", "test-portfolio-app",
                "hid_1123456789012345678901", "aps_AAAAAAAAAAAAAAAAAAAAAAAA",
                "aud_1123456789012345678901", "cor_1123456789012345");
        var fresh = runtime.queryForMap("select * from resolve_app_subject(?,?,?,?,?)", "test-portfolio-app",
                "hid_1123456789012345678901", "aps_BBBBBBBBBBBBBBBBBBBBBBBB",
                "aud_2123456789012345678901", "cor_1123456789012345");

        assertThat(collision.get("result")).isEqualTo("RETRY_COLLISION");
        assertThat(collision.get("app_subject")).isNull();
        assertThat(fresh.get("result")).isEqualTo("CREATED");
        assertThat(fresh.get("app_subject")).isNotEqualTo("aps_AAAAAAAAAAAAAAAAAAAAAAAA");
    }

    @Test
    void sameIdentityReceivesDifferentStableSubjectsAcrossCompleteApps() {
        seedSecondRegistration();

        var dutch = resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aud_0123456789012345678901");
        var other = runtime.queryForMap("select * from resolve_app_subject(?,?,?,?,?)", "test-portfolio-app",
                "hid_0123456789012345678901", "aps_BBBBBBBBBBBBBBBBBBBBBBBB",
                "aud_1123456789012345678901", "cor_1123456789012345");

        assertThat(other.get("result")).isEqualTo("CREATED");
        assertThat(other.get("app_subject")).isNotEqualTo(dutch.get("app_subject"));
    }

    @Test
    void bothAppsRemainStableAcrossRestartAndAllocateIndependently() throws Exception {
        seedSecondRegistration();
        AppSubject dutch;
        AppSubject other;
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var dutchFuture = executor.submit(() -> resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA",
                    "aud_0123456789012345678901"));
            var otherFuture = executor.submit(() -> runtime.queryForMap(
                    "select * from resolve_app_subject(?,?,?,?,?)", "test-portfolio-app",
                    "hid_0123456789012345678901", "aps_BBBBBBBBBBBBBBBBBBBBBBBB",
                    "aud_1123456789012345678901", "cor_1123456789012345"));
            dutch = new AppSubject(String.valueOf(dutchFuture.get(10, TimeUnit.SECONDS).get("app_subject")));
            other = new AppSubject(String.valueOf(otherFuture.get(10, TimeUnit.SECONDS).get("app_subject")));
        }
        assertThat(other).isNotEqualTo(dutch);
        try (var restarted = restartContext()) {
            var resolver = restarted.getBean(AppSubjectResolver.class);
            var identity = new dev.distracted.iam.identity.IdentityReference("hid_0123456789012345678901");
            assertThat(resolver.resolve(new AppSubjectResolutionCommand("dutch-development", identity,
                    new dev.distracted.iam.messaging.CorrelationId("cor_2123456789012345"))).appSubject())
                    .isEqualTo(dutch);
            assertThat(resolver.resolve(new AppSubjectResolutionCommand("test-portfolio-app", identity,
                    new dev.distracted.iam.messaging.CorrelationId("cor_3123456789012345"))).appSubject())
                    .isEqualTo(other);
        }
        assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isEqualTo(2);
        assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type='APP_SUBJECT_ALLOCATED'",
                Integer.class)).isEqualTo(2);
    }

    @Test
    void nullAndInactiveInputsFailClosedWithoutRows() {
        owner.update("update human_identity set state='DISABLED'");
        var inactive = resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aud_0123456789012345678901");
        var missingApp = runtime.queryForMap("select * from resolve_app_subject(?,?,?,?,?)", "missing-app",
                "hid_0123456789012345678901", "aps_AAAAAAAAAAAAAAAAAAAAAAAA",
                "aud_1123456789012345678901", "cor_1123456789012345");
        var nullInput = runtime.queryForMap("select * from resolve_app_subject(?,?,?,?,?)", null,
                "hid_0123456789012345678901", "aps_AAAAAAAAAAAAAAAAAAAAAAAA",
                "aud_2123456789012345678901", "cor_1123456789012345");

        assertThat(inactive.get("result")).isEqualTo("REJECTED");
        assertThat(missingApp.get("result")).isEqualTo("REJECTED");
        assertThat(nullInput.get("result")).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isZero();
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4})
    void everyNullFunctionArgumentFailsClosedWithoutRows(int nullArgument) {
        var arguments = new Object[] {"dutch-development", "hid_0123456789012345678901",
                "aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aud_0123456789012345678901",
                "cor_0123456789012345"};
        arguments[nullArgument] = null;

        var result = runtime.queryForMap("select * from resolve_app_subject(?,?,?,?,?)", arguments);

        assertThat(result.get("result")).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isZero();
        assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type='APP_SUBJECT_ALLOCATED'",
                Integer.class)).isZero();
    }

    @Test
    void incompleteRegistrationAndAuditFailureLeaveNoPartialMapping() {
        seedSecondRegistration();
        owner.update("delete from policy_activation_evidence where app_registration_id='test-portfolio-app'");
        var incomplete = runtime.queryForMap("select * from resolve_app_subject(?,?,?,?,?)", "test-portfolio-app",
                "hid_0123456789012345678901", "aps_AAAAAAAAAAAAAAAAAAAAAAAA",
                "aud_0123456789012345678901", "cor_0123456789012345");
        owner.update("insert into audit_fact(audit_id,fact_type,subject_kind,subject_id,outcome,correlation_id,"
                + "occurred_at) values(?,?,?,?,?,?,transaction_timestamp())", "aud_1123456789012345678901",
                "IDENTITY_CREATED", "IDENTITY", "hid_0123456789012345678901", "SUCCEEDED",
                "cor_1123456789012345");

        assertThat(incomplete.get("result")).isEqualTo("REJECTED");
        assertThatThrownBy(() -> runtime.queryForMap("select * from resolve_app_subject(?,?,?,?,?)",
                "dutch-development", "hid_0123456789012345678901", "aps_BBBBBBBBBBBBBBBBBBBBBBBB",
                "aud_1123456789012345678901", "cor_2123456789012345"))
                .hasStackTraceContaining("app_subject_resolution_rejected");
        assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isZero();
    }

    @Test
    void failuresBeforeMappingBetweenMappingAndAuditAndAfterAuditRollbackEverything() {
        assertInjectedRollback("before_mapping", "app_subject", "before");
        assertInjectedRollback("between_mapping_audit", "app_subject", "after");
        assertInjectedRollback("after_audit", "audit_fact", "after");
    }

    @Test
    void mappingAndAllocationAuditAreImmutable() {
        resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aud_0123456789012345678901");

        assertThatThrownBy(() -> owner.update("update app_subject set version=1"))
                .hasStackTraceContaining("immutable fact mutation denied");
        assertThatThrownBy(() -> owner.update("delete from app_subject"))
                .hasStackTraceContaining("immutable fact mutation denied");
        assertThatThrownBy(() -> owner.update("delete from audit_fact where fact_type='APP_SUBJECT_ALLOCATED'"))
                .hasStackTraceContaining("immutable fact mutation denied");
    }

    @Test
    void everyV7MappingConstraintAndRestrictiveForeignKeyRejectsInvalidState() {
        var valid = new Object[] {"dutch-development", "hid_0123456789012345678901",
                "aps_AAAAAAAAAAAAAAAAAAAAAAAA", 1L, new java.sql.Timestamp(System.currentTimeMillis())};
        for (int column = 0; column < valid.length; column++) {
            var values = valid.clone();
            values[column] = null;
            assertThatThrownBy(() -> owner.update("insert into app_subject values(?,?,?,?,?)", values))
                    .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        }
        assertThatThrownBy(() -> owner.update("insert into app_subject values(?,?,?,?,transaction_timestamp())",
                "dutch-development", "hid_0123456789012345678901", "aps_short", 1L))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThatThrownBy(() -> owner.update("insert into app_subject values(?,?,?,?,transaction_timestamp())",
                "dutch-development", "hid_0123456789012345678901",
                "aps_AAAAAAAAAAAAAAAAAAAAAAAA", 2L))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThatThrownBy(() -> owner.update("insert into app_subject values(?,?,?,?,transaction_timestamp())",
                "missing-app", "hid_0123456789012345678901", "aps_AAAAAAAAAAAAAAAAAAAAAAAA", 1L))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThatThrownBy(() -> owner.update("insert into app_subject values(?,?,?,?,transaction_timestamp())",
                "dutch-development", "hid_9999999999999999999999",
                "aps_AAAAAAAAAAAAAAAAAAAAAAAA", 1L))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);

        resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA", "aud_0123456789012345678901");
        owner.update("insert into human_identity(identity_id,state) values(?,?)",
                "hid_1123456789012345678901", "ACTIVE");
        assertThatThrownBy(() -> owner.update("insert into app_subject values(?,?,?,?,transaction_timestamp())",
                "dutch-development", "hid_0123456789012345678901",
                "aps_BBBBBBBBBBBBBBBBBBBBBBBB", 1L))
                .isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
        assertThatThrownBy(() -> owner.update("insert into app_subject values(?,?,?,?,transaction_timestamp())",
                "dutch-development", "hid_1123456789012345678901",
                "aps_AAAAAAAAAAAAAAAAAAAAAAAA", 1L))
                .isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
        assertThatThrownBy(() -> owner.update("insert into audit_fact(audit_id,fact_type,subject_kind,subject_id,"
                + "outcome,correlation_id,occurred_at) values(?,?,?,?,?,?,transaction_timestamp())",
                "aud_1123456789012345678901", "APP_SUBJECT_ALLOCATED", "APP_SUBJECT",
                "aps_AAAAAAAAAAAAAAAAAAAAAAAA", "SUCCEEDED", "cor_1123456789012345"))
                .isInstanceOf(org.springframework.dao.DuplicateKeyException.class);
        assertThatThrownBy(() -> owner.update("delete from app_registration where app_registration_id=?",
                "dutch-development")).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        assertThatThrownBy(() -> owner.update("delete from human_identity where identity_id=?",
                "hid_0123456789012345678901"))
                .isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }

    @Test
    void fullApplicationContextRestartReturnsThePersistedSubject() {
        AppSubject first;
        try (var before = restartContext()) {
            first = before.getBean(AppSubjectResolver.class).resolve(new AppSubjectResolutionCommand(
                    "dutch-development", new dev.distracted.iam.identity.IdentityReference(
                            "hid_0123456789012345678901"),
                    new dev.distracted.iam.messaging.CorrelationId("cor_0123456789012345"))).appSubject();
        }
        try (var after = restartContext()) {
            var repeated = after.getBean(AppSubjectResolver.class).resolve(new AppSubjectResolutionCommand(
                    "dutch-development", new dev.distracted.iam.identity.IdentityReference(
                            "hid_0123456789012345678901"),
                    new dev.distracted.iam.messaging.CorrelationId("cor_1123456789012345"))).appSubject();
            assertThat(repeated).isEqualTo(first);
        }
        assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isEqualTo(1);
    }

    @Test
    void resultsDiagnosticsAuditOutboxLogsAndMetricsDoNotLeakGlobalOrRawCanaries() {
        var identity = "hid_PRIVACY0123456789012345";
        owner.update("insert into human_identity(identity_id,state) values(?,?)", identity, "ACTIVE");
        var canaries = java.util.List.of(identity, "person@example.invalid", "+15555550123",
                "credential-canary", "authorization-code-canary", "access-token-canary", "refresh-token-canary");
        var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(
                org.slf4j.Logger.ROOT_LOGGER_NAME);
        var appender = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
        appender.start();
        logger.addAppender(appender);
        try (var context = restartContext()) {
            var result = context.getBean(AppSubjectResolver.class).resolve(new AppSubjectResolutionCommand(
                    "dutch-development", new dev.distracted.iam.identity.IdentityReference(identity),
                    new dev.distracted.iam.messaging.CorrelationId("cor_9123456789012345")));
            var visible = result.toString() + owner.queryForList("select * from audit_fact where "
                    + "fact_type='APP_SUBJECT_ALLOCATED'") + owner.queryForList("select * from outbox_event")
                    + appender.list.stream().map(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).toList();
            var registry = context.getBeanProvider(io.micrometer.core.instrument.MeterRegistry.class).getIfAvailable();
            if (registry != null) {
                visible += registry.getMeters().stream().map(meter -> meter.getId().toString()).toList();
            }
            assertThat(visible).doesNotContain(canaries.toArray(String[]::new));
            assertThat(result.toString()).doesNotContain(result.appSubject().value());
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void functionAndTablePrivilegesAreLeastAuthority() {
        assertThat(owner.queryForObject("select has_function_privilege('iam_runtime',"
                + "'resolve_app_subject(text,text,text,text,text)','EXECUTE')", Boolean.class)).isTrue();
        assertThat(owner.queryForObject("select has_function_privilege('iam_migrator',"
                + "'resolve_app_subject(text,text,text,text,text)','EXECUTE')", Boolean.class)).isTrue();
        assertThat(owner.queryForObject("select has_function_privilege('iam_relay',"
                + "'resolve_app_subject(text,text,text,text,text)','EXECUTE')", Boolean.class)).isFalse();
        assertThat(owner.queryForObject("select has_function_privilege('iam_registration_reconciler',"
                + "'resolve_app_subject(text,text,text,text,text)','EXECUTE')", Boolean.class)).isFalse();
        assertThat(owner.queryForObject("select has_function_privilege('unrelated_service',"
                + "'resolve_app_subject(text,text,text,text,text)','EXECUTE')", Boolean.class)).isFalse();
        assertThat(owner.queryForObject("select has_function_privilege('public',"
                + "'resolve_app_subject(text,text,text,text,text)','EXECUTE')", Boolean.class)).isFalse();
        assertThat(owner.queryForList("select coalesce(r.rolname,'PUBLIC') from pg_proc p "
                + "cross join lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a "
                + "left join pg_roles r on r.oid=a.grantee where p.oid="
                + "'resolve_app_subject(text,text,text,text,text)'::regprocedure "
                + "and a.privilege_type='EXECUTE' order by 1", String.class))
                .containsExactly("iam_migrator", "iam_runtime")
                .doesNotContain("PUBLIC", "iam_registration_reconciler", "iam_relay", "unrelated_service");
        assertThat(owner.queryForObject("select has_table_privilege('iam_runtime','app_subject','SELECT')",
                Boolean.class)).isFalse();
        var metadata = owner.queryForMap("select prosecdef,provolatile,proconfig from pg_proc "
                + "where oid='resolve_app_subject(text,text,text,text,text)'::regprocedure");
        assertThat(metadata.get("prosecdef")).isEqualTo(true);
        assertThat(metadata.get("provolatile")).isEqualTo("v");
        assertThat(String.valueOf(metadata.get("proconfig"))).contains("search_path=pg_catalog, public");
        assertThat(owner.queryForObject("select proowner=(select oid from pg_roles where rolname='iam_migrator') "
                + "from pg_proc where oid='resolve_app_subject(text,text,text,text,text)'::regprocedure",
                Boolean.class)).isTrue();
        assertThat(owner.queryForObject("select tableowner='iam_migrator' from pg_tables "
                + "where schemaname='public' and tablename='app_subject'", Boolean.class)).isTrue();
        for (var operation : java.util.List.of("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES",
                "TRIGGER")) {
            assertThat(owner.queryForObject("select has_table_privilege('iam_migrator','app_subject',?)",
                    Boolean.class, operation)).isTrue();
            for (var role : java.util.List.of("iam_runtime", "iam_registration_reconciler", "iam_relay",
                    "unrelated_service")) {
                assertThat(owner.queryForObject("select has_table_privilege(?,'app_subject',?)", Boolean.class,
                        role, operation)).isFalse();
            }
        }
        assertThat(owner.queryForObject("select not exists(select 1 from aclexplode(coalesce(c.relacl,"
                + "acldefault('r',c.relowner))) a where a.grantee=0) from pg_class c "
                + "where c.oid='app_subject'::regclass", Boolean.class)).isTrue();
    }

    @Test
    void cleanAndV6UpgradeProduceTheSameV7SchemaAndRerunIsNoOp() {
        owner.execute("create database app_subject_v7_clean");
        owner.execute("create database app_subject_v7_upgrade");
        var cleanUrl = databaseUrl("app_subject_v7_clean");
        var upgradeUrl = databaseUrl("app_subject_v7_upgrade");
        assertThat(Flyway.configure().dataSource(cleanUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate().migrationsExecuted).isEqualTo(14);
        assertThat(Flyway.configure().dataSource(upgradeUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .target("6").load().migrate().migrationsExecuted).isEqualTo(6);
        var upgradeJdbc = new JdbcTemplate(new DriverManagerDataSource(upgradeUrl, POSTGRES.getUsername(),
                POSTGRES.getPassword()));
        upgradeJdbc.update("insert into human_identity(identity_id,state) values(?,?)",
                "hid_7123456789012345678901", "ACTIVE");
        upgradeJdbc.update("insert into audit_fact(audit_id,fact_type,subject_kind,subject_id,outcome,correlation_id,"
                + "occurred_at) values(?,?,?,?,?,?,transaction_timestamp())", "aud_7123456789012345678901",
                "IDENTITY_CREATED", "IDENTITY", "hid_7123456789012345678901", "SUCCEEDED",
                "cor_7123456789012345");
        var upgraded = Flyway.configure().dataSource(upgradeUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .load();
        assertThat(upgraded.migrate().migrationsExecuted).isEqualTo(8);
        assertThat(upgraded.migrate().migrationsExecuted).isZero();
        assertThat(v7Snapshot(cleanUrl)).isEqualTo(v7Snapshot(upgradeUrl));
        assertThat(upgradeJdbc.queryForObject("select state from human_identity where identity_id=?", String.class,
                "hid_7123456789012345678901")).isEqualTo("ACTIVE");
        assertThat(upgradeJdbc.queryForObject("select count(*) from audit_fact where audit_id=?", Integer.class,
                "aud_7123456789012345678901")).isEqualTo(1);
    }

    @Test
    void v7MigrationFailsWhenAPrerequisiteRoleIsMissing() throws Exception {
        try (var isolated = new PostgreSQLContainer("postgres:18-alpine")) {
            isolated.start();
            try (var connection = DriverManager.getConnection(isolated.getJdbcUrl(), isolated.getUsername(),
                    isolated.getPassword()); var statement = connection.createStatement()) {
                statement.execute("create role iam_migrator nologin");
                statement.execute("create role iam_runtime nologin");
                statement.execute("create role iam_relay nologin");
                statement.execute("create role iam_registration_reconciler nologin");
                statement.execute("grant iam_migrator to " + isolated.getUsername());
            }
            Flyway.configure().dataSource(isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword())
                    .target("6").load().migrate();
            try (var connection = DriverManager.getConnection(isolated.getJdbcUrl(), isolated.getUsername(),
                    isolated.getPassword()); var statement = connection.createStatement()) {
                statement.execute("drop owned by iam_relay");
                statement.execute("drop role iam_relay");
            }
            assertThatThrownBy(() -> Flyway.configure()
                    .dataSource(isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword())
                    .load().migrate()).hasStackTraceContaining("required IAM privilege roles are not provisioned");
        }
    }

    private java.util.Map<String, Object> resolve(String subject, String auditId) {
        return runtime.queryForMap("select * from resolve_app_subject(?,?,?,?,?)", "dutch-development",
                "hid_0123456789012345678901", subject, auditId, "cor_0123456789012345");
    }

    private void seedSecondRegistration() {
        owner.update("insert into app_registration(app_registration_id,manifest_version,display_name,environment,"
                + "source_fingerprint) values(?,?,?,?,?)", "test-portfolio-app", (short) 1, "Test Portfolio App",
                "test", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        owner.update("insert into client_registration(client_id,app_registration_id,client_type,browser_mode) "
                + "values(?,?,?,?)", "test-portfolio-client", "test-portfolio-app", "NATIVE_PUBLIC", "EXTERNAL");
        owner.update("insert into client_redirect_uri values(?,?)", "test-portfolio-client", "test://callback");
        owner.update("insert into client_grant_type values(?,?)", "test-portfolio-client", "authorization_code");
        owner.update("insert into client_pkce_method values(?,?)", "test-portfolio-client", "S256");
        owner.update("insert into resource_registration(resource_id,app_registration_id,audience) values(?,?,?)",
                "test-portfolio-api", "test-portfolio-app", "https://api.test.invalid");
        owner.update("insert into resource_scope values(?,?)", "test-portfolio-api", "member:read");
        owner.update("insert into product_security_policy(app_registration_id,policy_version,require_dpop,"
                + "required_pkce_method) values(?,?,?,?)", "test-portfolio-app", (short) 1, true, "S256");
        owner.update("insert into policy_grant_type values(?,?)", "test-portfolio-app", "authorization_code");
        for (var evidence : new String[] {"verified_identifier", "usable_factor", "recovery_path"}) {
            owner.update("insert into policy_activation_evidence values(?,?)", "test-portfolio-app", evidence);
        }
    }

    private org.springframework.context.ConfigurableApplicationContext restartContext() {
        return new SpringApplicationBuilder(IamApplication.class)
                .web(WebApplicationType.SERVLET).profiles("test").properties(
                        "server.port=0", "spring.flyway.enabled=false",
                        "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "spring.datasource.username=iam_runtime_login",
                        "spring.datasource.password=" + RUNTIME_PASSWORD,
                        "iam.app-subject.enabled=true")
                .run();
    }

    private static String databaseUrl(String database) {
        return "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getFirstMappedPort() + "/" + database;
    }

    private static java.util.List<java.util.Map<String, Object>> v7Snapshot(String url) {
        var jdbc = new JdbcTemplate(new DriverManagerDataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword()));
        return jdbc.queryForList("select 'column' kind,table_name object,column_name detail,data_type value "
                + "from information_schema.columns where table_schema='public' and table_name='app_subject' "
                + "union all select 'constraint',c.relname,con.conname,pg_get_constraintdef(con.oid) "
                + "from pg_constraint con join pg_class c on c.oid=con.conrelid "
                + "where c.relnamespace='public'::regnamespace and c.relname in ('app_subject','audit_fact') "
                + "union all select 'function',p.proname,p.oid::regprocedure::text,"
                + "coalesce(array_to_string(p.proconfig,','),'') from pg_proc p "
                + "where p.pronamespace='public'::regnamespace and p.proname='resolve_app_subject' "
                + "order by 1,2,3,4");
    }

    private void awaitBlockedResolution() throws Exception {
        for (int attempt = 0; attempt < 250; attempt++) {
            var blocked = owner.queryForObject("select exists(select 1 from pg_stat_activity "
                    + "where query like 'select * from resolve_app_subject%' and wait_event_type='Lock')",
                    Boolean.class);
            if (Boolean.TRUE.equals(blocked)) {
                return;
            }
            Thread.sleep(20);
        }
        throw new AssertionError("resolution did not block on the eligibility mutation");
    }

    private void assertInjectedRollback(String name, String table, String timing) {
        var function = "test_fail_" + name;
        var trigger = "test_trigger_" + name;
        owner.execute("create function " + function + "() returns trigger language plpgsql as $$ "
                + "begin raise exception 'injected_failure'; end $$");
        var predicate = table.equals("audit_fact") ? " when (new.fact_type='APP_SUBJECT_ALLOCATED')" : "";
        owner.execute("create trigger " + trigger + " " + timing + " insert on " + table
                + " for each row" + predicate + " execute function " + function + "()");
        try {
            assertThatThrownBy(() -> resolve("aps_AAAAAAAAAAAAAAAAAAAAAAAA",
                    "aud_0123456789012345678901")).hasStackTraceContaining("injected_failure");
            assertThat(owner.queryForObject("select count(*) from app_subject", Integer.class)).isZero();
            assertThat(owner.queryForObject("select count(*) from audit_fact where fact_type='APP_SUBJECT_ALLOCATED'",
                    Integer.class)).isZero();
        } finally {
            owner.execute("drop trigger " + trigger + " on " + table);
            owner.execute("drop function " + function + "()");
        }
    }
}
