package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.DriverManager;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import dev.distracted.iam.authorization.adapter.jdbc.JdbcAuthorizationCodeConsumptionRepository;
import dev.distracted.iam.bootstrap.IamApplication;
import dev.distracted.iam.token.adapter.jdbc.JdbcAuthorizationServerIssuerAuthority;
import dev.distracted.iam.token.AuthorizationServerIssuerAuthority;
import dev.distracted.iam.token.AccessTokenSigningCapability;
import dev.distracted.iam.token.AccessTokenSigningSnapshot;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;

@Testcontainers
class AuthorizationCodePersistenceIntegrationTest {
    @Container static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final String RECONCILER_PASSWORD = UUID.randomUUID().toString();
    private static JdbcTemplate owner;
    private static JdbcTemplate runtime;

    @BeforeAll
    static void migrate() throws Exception {
        try (var connection = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
            statement.execute("create role unrelated_service nologin");
            statement.execute("create role iam_runtime_login login password '" + RUNTIME_PASSWORD + "' in role iam_runtime");
            statement.execute("create role iam_reconciler_login login password '" + RECONCILER_PASSWORD
                    + "' in role iam_registration_reconciler");
            statement.execute("grant iam_migrator to " + POSTGRES.getUsername());
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()).load().migrate();
        owner = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
        runtime = new JdbcTemplate(new DriverManagerDataSource(POSTGRES.getJdbcUrl(), "iam_runtime_login", RUNTIME_PASSWORD));
    }

    @BeforeEach
    void seed() {
        owner.execute("truncate token_issuance_audit_fact,dpop_replay,dpop_nonce,app_subject,authorization_audit_fact,authorization_code,authorization_request,verified_identifier_blind_index,"
                + "verified_identifier,verification_challenge,human_identity,policy_activation_evidence,policy_grant_type,"
                + "product_security_policy,resource_scope,resource_registration,client_pkce_method,client_grant_type,"
                + "client_redirect_uri,client_registration,app_registration cascade");
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
    void oneIssuedCodeCanBeConsumedExactlyOnce() {
        byte[] state = bytes(1);
        byte[] nonce = bytes(2);
        byte[] challenge = bytes(3);
        byte[] digest = bytes(4);
        runtime.queryForMap("select * from issue_authorization_code(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "arq_0123456789012345678901", "acd_0123456789012345678901", "https://iam.distracted.invalid",
                "dutch-development", "dutch-mobile", "dutch-api", "https://api.dutch.invalid",
                "hid_0123456789012345678901", "dutch://oauth/callback", "member:read", state, nonce,
                challenge, digest, (short) 1, 120, "cor_0123456789012345");

        var first = runtime.queryForMap("select * from consume_authorization_code(?,?,?,?,?,?,?,?,?)",
                "acd_0123456789012345678901", digest, (short) 1, "https://iam.distracted.invalid",
                "dutch-mobile", "dutch://oauth/callback", challenge, 1L, "cor_1123456789012345");
        var replay = runtime.queryForMap("select * from consume_authorization_code(?,?,?,?,?,?,?,?,?)",
                "acd_0123456789012345678901", digest, (short) 1, "https://iam.distracted.invalid",
                "dutch-mobile", "dutch://oauth/callback", challenge, 1L, "cor_2123456789012345");

        assertThat(first.get("result")).isEqualTo("CONSUMED");
        assertThat(replay.get("result")).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select count(*) from authorization_code where status='CONSUMED'", Integer.class))
                .isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from authorization_audit_fact", Integer.class)).isEqualTo(2);
    }

    @Test
    void migrationOwnedIssuerAuthorityIsCanonicalLeastPrivilegeAndStableAcrossRestart() {
        assertThat(new JdbcAuthorizationServerIssuerAuthority(runtime).pinnedIssuer())
                .isEqualTo("https://iam.distracted.invalid");
        assertThat(new JdbcAuthorizationServerIssuerAuthority(runtime).pinnedIssuer())
                .isEqualTo("https://iam.distracted.invalid");
        assertThat(owner.queryForObject("select has_function_privilege('iam_runtime',"
                + "'read_authorization_server_issuer()','EXECUTE')", Boolean.class)).isTrue();
        for (var role : List.of("iam_registration_reconciler", "iam_relay", "unrelated_service")) {
            assertThat(owner.queryForObject("select has_function_privilege(?,"
                    + "'read_authorization_server_issuer()','EXECUTE')", Boolean.class, role)).isFalse();
        }
        assertThat(owner.queryForObject("select not has_function_privilege('public',"
                + "'read_authorization_server_issuer()','EXECUTE')", Boolean.class)).isTrue();
        assertThat(owner.queryForObject("select not has_table_privilege('iam_runtime',"
                + "'authorization_server_issuer','SELECT')", Boolean.class)).isTrue();
        assertThat(owner.queryForObject("select prosecdef and proowner='iam_migrator'::regrole "
                + "and proconfig=array['search_path=pg_catalog, public'] from pg_proc "
                + "where oid='read_authorization_server_issuer()'::regprocedure", Boolean.class)).isTrue();
    }

    @Test
    void freshFullSpringContextsRehydrateProductionIssuerAuthorityAgainstSameDatabase() throws Exception {
        AuthorizationServerIssuerAuthority firstAuthority;
        try (var first = issuerAuthorityRestartContext()) {
            firstAuthority = first.getBean(AuthorizationServerIssuerAuthority.class);
            assertThat(firstAuthority).isInstanceOf(JdbcAuthorizationServerIssuerAuthority.class);
            assertThat(firstAuthority.pinnedIssuer()).isEqualTo("https://iam.distracted.invalid");
        }
        try (var restarted = issuerAuthorityRestartContext()) {
            var restartedAuthority = restarted.getBean(AuthorizationServerIssuerAuthority.class);
            assertThat(restartedAuthority).isInstanceOf(JdbcAuthorizationServerIssuerAuthority.class)
                    .isNotSameAs(firstAuthority);
            assertThat(restartedAuthority.pinnedIssuer()).isEqualTo("https://iam.distracted.invalid");
            assertThat(restarted.getEnvironment().getProperty("spring.datasource.url"))
                    .isEqualTo(POSTGRES.getJdbcUrl());
            assertThat(restarted.getEnvironment().getProperty("spring.datasource.username"))
                    .isEqualTo("iam_runtime_login");
        }
    }

    @Test
    void issuerAuthorityFailsSafelyForMissingDuplicateDriftAndDatabaseFailure() throws Exception {
        withOwnerTransaction(jdbc -> {
            jdbc.update("delete from authorization_server_issuer");
            assertThatThrownBy(() -> new JdbcAuthorizationServerIssuerAuthority(jdbc).pinnedIssuer())
                    .hasMessage("access token could not be issued");
        });
        withOwnerTransaction(jdbc -> {
            jdbc.execute("alter table authorization_server_issuer drop constraint authorization_server_issuer_format");
            jdbc.update("update authorization_server_issuer set issuer='https://attacker.example'");
            assertThatThrownBy(() -> new JdbcAuthorizationServerIssuerAuthority(jdbc).pinnedIssuer())
                    .hasMessage("access token could not be issued");
        });
        withOwnerTransaction(jdbc -> {
            jdbc.execute("alter table authorization_server_issuer drop constraint authorization_server_issuer_pkey");
            jdbc.execute("alter table authorization_server_issuer drop constraint authorization_server_issuer_issuer_key");
            jdbc.execute("alter table authorization_server_issuer drop constraint authorization_server_issuer_singleton");
            jdbc.execute("alter table authorization_server_issuer drop constraint authorization_server_issuer_format");
            jdbc.update("insert into authorization_server_issuer(singleton,issuer) values(false,?)",
                    "https://attacker.example");
            assertThatThrownBy(() -> new JdbcAuthorizationServerIssuerAuthority(jdbc).pinnedIssuer())
                    .hasMessage("access token could not be issued");
        });
        var unavailable = new JdbcTemplate(new DriverManagerDataSource("jdbc:postgresql://127.0.0.1:1/missing",
                "missing", "missing"));
        assertThatThrownBy(() -> new JdbcAuthorizationServerIssuerAuthority(unavailable).pinnedIssuer())
                .hasMessage("access token could not be issued")
                .hasMessageNotContaining("connection")
                .hasMessageNotContaining("password")
                .hasMessageNotContaining("127.0.0.1");
    }

    private static void withOwnerTransaction(java.util.function.Consumer<JdbcTemplate> action) throws Exception {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())) {
            connection.setAutoCommit(false);
            try {
                action.accept(new JdbcTemplate(new SingleConnectionDataSource(connection, true)));
            } finally {
                connection.rollback();
            }
        }
    }

    @Test
    void concurrentRedemptionHasExactlyOneWinner() throws Exception {
        byte[] challenge = bytes(3);
        byte[] digest = bytes(4);
        issue("1123456789012345678901", challenge, digest);
        var ready = new CountDownLatch(2);
        var start = new CountDownLatch(1);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var attempts = java.util.stream.IntStream.range(0, 2).mapToObj(index -> executor.submit(() -> {
                ready.countDown();
                start.await(10, TimeUnit.SECONDS);
                return runtime.queryForObject("select result from consume_authorization_code(?,?,?,?,?,?,?,?,?)",
                        String.class, "acd_1123456789012345678901", digest, (short) 1,
                        "https://iam.distracted.invalid", "dutch-mobile", "dutch://oauth/callback", challenge, 1L,
                        "cor_" + index + "123456789012345");
            })).toList();
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            assertThat(attempts.stream().map(future -> {
                try { return future.get(10, TimeUnit.SECONDS); }
                catch (Exception exception) { throw new AssertionError(exception); }
            }).filter("CONSUMED"::equals).count()).isEqualTo(1);
        }
    }

    @Test
    void runtimeUsesOnlyTheNarrowFunctionsAndProtectedRowsContainNoRawValues() {
        var challenge = bytes(3);
        var digest = bytes(4);
        issue("2123456789012345678901", challenge, digest);

        assertThatThrownBy(() -> runtime.queryForObject("select count(*) from authorization_code", Integer.class))
                .hasRootCauseMessage("ERROR: permission denied for table authorization_code");
        assertThatThrownBy(() -> runtime.update("delete from authorization_request"))
                .hasRootCauseMessage("ERROR: permission denied for table authorization_request");
        var persisted = owner.queryForMap("select encode(state_digest,'hex') state,encode(nonce_digest,'hex') nonce,"
                + "encode(code_digest,'hex') code from authorization_request join authorization_code using(authorization_request_id) "
                + "where authorization_code_id='acd_2123456789012345678901'").toString();
        assertThat(persisted).doesNotContain("raw-state-canary", "raw-nonce-canary", "raw-code-canary");
    }

    @Test
    void wrongProofDoesNotConsumeAndDatabaseExpiryTerminalizesTheCode() {
        var challenge = bytes(3);
        var digest = bytes(4);
        issue("3123456789012345678901", challenge, digest);
        var wrong = runtime.queryForObject("select result from consume_authorization_code(?,?,?,?,?,?,?,?,?)",
                String.class, "acd_3123456789012345678901", digest, (short) 1,
                "https://iam.distracted.invalid", "dutch-mobile", "dutch://oauth/callback", bytes(9), 1L,
                "cor_1123456789012345");
        assertThat(wrong).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select status from authorization_code where authorization_code_id=?",
                String.class, "acd_3123456789012345678901")).isEqualTo("ISSUED");

        owner.update("update authorization_code set issued_at=transaction_timestamp()-interval '2 minutes',"
                + "expires_at=transaction_timestamp()-interval '1 minute' "
                + "where authorization_code_id=?", "acd_3123456789012345678901");
        owner.update("update authorization_request set authorized_at=transaction_timestamp()-interval '2 minutes',"
                + "expires_at=transaction_timestamp()-interval '1 minute' where authorization_request_id=?",
                "arq_3123456789012345678901");
        var expired = runtime.queryForObject("select result from consume_authorization_code(?,?,?,?,?,?,?,?,?)",
                String.class, "acd_3123456789012345678901", digest, (short) 1,
                "https://iam.distracted.invalid", "dutch-mobile", "dutch://oauth/callback", challenge, 1L,
                "cor_2123456789012345");
        assertThat(expired).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select status from authorization_code where authorization_code_id=?",
                String.class, "acd_3123456789012345678901")).isEqualTo("EXPIRED");
    }

    @Test
    void issuanceFailsClosedWhenTheCanonicalRegistrationDrifts() {
        owner.update("update app_registration set display_name='Drifted'");
        assertThatThrownBy(() -> issue("4123456789012345678901", bytes(3), bytes(4)))
                .hasStackTraceContaining("authorization_issue_rejected");
        assertThat(owner.queryForObject("select count(*) from authorization_request", Integer.class)).isZero();
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8})
    void nullRedemptionBindingRejectsWithoutConsuming(int nullArgument) {
        var challenge = bytes(3);
        var digest = bytes(4);
        issue("5123456789012345678901", challenge, digest);
        var arguments = new Object[] {"acd_5123456789012345678901", digest, (short) 1,
                "https://iam.distracted.invalid", "dutch-mobile", "dutch://oauth/callback", challenge, 1L,
                "cor_5123456789012345"};
        arguments[nullArgument] = null;

        var result = runtime.queryForObject("select result from consume_authorization_code(?,?,?,?,?,?,?,?,?)",
                String.class, arguments);

        assertThat(result).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select status from authorization_code where authorization_code_id=?",
                String.class, "acd_5123456789012345678901")).isEqualTo("ISSUED");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
    void nullIssuanceBindingRollsBackWithoutRows(int nullArgument) {
        var arguments = new Object[] {"arq_6123456789012345678901", "acd_6123456789012345678901",
                "https://iam.distracted.invalid", "dutch-development", "dutch-mobile", "dutch-api",
                "https://api.dutch.invalid", "hid_0123456789012345678901", "dutch://oauth/callback",
                "member:read", bytes(1), bytes(2), bytes(3), bytes(4), (short) 1, 120,
                "cor_6123456789012345"};
        arguments[nullArgument] = null;

        assertThatThrownBy(() -> runtime.queryForMap(
                "select * from issue_authorization_code(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", arguments))
                .hasStackTraceContaining("authorization_issue_rejected");
        assertThat(owner.queryForObject("select count(*) from authorization_request", Integer.class)).isZero();
        assertThat(owner.queryForObject("select count(*) from authorization_code", Integer.class)).isZero();
    }

    @Test
    void consumedCodeRemainsRejectedAcrossFreshRepositoryBoundary() {
        var codeId = "acd_7123456789012345678901";
        var randomValue = new byte[32];
        var capability = new HmacAuthorizationCodeDigestCapability("development", (short) 1,
                Map.of((short) 1, "authorization-code-test-key-00001".getBytes(StandardCharsets.US_ASCII)),
                Map.of((short) 1, "test://authorization-code/1"));
        var protection = capability.protect(codeId, randomValue);
        var challenge = Base64.getUrlDecoder().decode("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        issue("7123456789012345678901", challenge, protection.digest());
        var wireCode = codeId + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(randomValue);
        var command = new AuthorizationCodeRedemptionCommand("authorization_code", wireCode, "dutch-mobile",
                "dutch://oauth/callback", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                "cor_7123456789012345");

        var beforeRestart = new AuthorizationCodeRedemption(
                new JdbcAuthorizationCodeConsumptionRepository(runtime), capability, "https://iam.distracted.invalid");
        assertThat(beforeRestart.redeem(command)).isPresent();
        var afterRestart = new AuthorizationCodeRedemption(
                new JdbcAuthorizationCodeConsumptionRepository(runtime), capability, "https://iam.distracted.invalid");
        assertThat(afterRestart.redeem(command)).isEmpty();
    }

    @Test
    void databaseRejectsUnapprovedIssuerAndRegistrationDriftAtRedemption() {
        var challenge = bytes(3);
        var digest = bytes(4);
        var invalidIssuer = new Object[] {"arq_8123456789012345678901", "acd_8123456789012345678901",
                "https://other-iam.distracted.invalid", "dutch-development", "dutch-mobile", "dutch-api",
                "https://api.dutch.invalid", "hid_0123456789012345678901", "dutch://oauth/callback",
                "member:read", bytes(1), bytes(2), challenge, digest, (short) 1, 120,
                "cor_8123456789012345"};
        assertThatThrownBy(() -> runtime.queryForMap(
                "select * from issue_authorization_code(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", invalidIssuer))
                .hasStackTraceContaining("authorization_issue_rejected");

        issue("8123456789012345678901", challenge, digest);
        owner.update("update app_registration set display_name='Drifted'");
        var result = runtime.queryForObject("select result from consume_authorization_code(?,?,?,?,?,?,?,?,?)",
                String.class, "acd_8123456789012345678901", digest, (short) 1,
                "https://iam.distracted.invalid", "dutch-mobile", "dutch://oauth/callback", challenge, 1L,
                "cor_8123456789012345");
        assertThat(result).isEqualTo("REJECTED");
        assertThat(owner.queryForObject("select status from authorization_code where authorization_code_id=?",
                String.class, "acd_8123456789012345678901")).isEqualTo("ISSUED");
    }

    @Test
    void v6FunctionsAndTablesHaveExactRuntimeAuthority() {
        var runtimeFunctions = List.of(
                "issue_authorization_code(text,text,text,text,text,text,text,text,text,text,bytea,bytea,bytea,bytea,smallint,integer,text)",
                "authorization_code_protection(text)",
                "consume_authorization_code(text,bytea,smallint,text,text,text,bytea,bigint,text)");
        for (var function : List.of(runtimeFunctions.get(0), runtimeFunctions.get(1), runtimeFunctions.get(2),
                "digest_equal(bytea,bytea)")) {
            assertThat(owner.queryForObject("select has_function_privilege('iam_runtime',?,'EXECUTE')",
                    Boolean.class, "public." + function)).isEqualTo(runtimeFunctions.contains(function));
            for (var role : List.of("iam_registration_reconciler", "iam_relay", "unrelated_service")) {
                assertThat(owner.queryForObject("select has_function_privilege(?,?,'EXECUTE')",
                        Boolean.class, role, "public." + function)).isFalse();
            }
            assertThat(owner.queryForObject("select not exists(select 1 from aclexplode(coalesce(p.proacl,"
                    + "acldefault('f',p.proowner))) a where a.grantee=0 and a.privilege_type='EXECUTE') "
                    + "from pg_proc p where p.oid=?::regprocedure", Boolean.class, "public." + function)).isTrue();
            assertThat(owner.queryForObject("select proowner=(select oid from pg_roles where rolname='iam_migrator') "
                    + "and prosecdef and coalesce(array_to_string(proconfig,','),'') like '%search_path=pg_catalog, public%' "
                    + "from pg_proc where oid=?::regprocedure", Boolean.class, "public." + function)).isTrue();
        }
        for (var table : List.of("authorization_server_issuer", "authorization_request", "authorization_code",
                "authorization_audit_fact")) {
            for (var operation : List.of("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")) {
                for (var role : List.of("iam_runtime", "iam_registration_reconciler", "iam_relay", "unrelated_service")) {
                    assertThat(owner.queryForObject("select has_table_privilege(?,?,?)", Boolean.class,
                            role, "public." + table, operation)).isFalse();
                }
                assertThat(owner.queryForObject("select has_table_privilege('iam_migrator',?,?)", Boolean.class,
                        "public." + table, operation)).isTrue();
            }
            assertThat(owner.queryForObject("select not exists(select 1 from pg_class c,"
                    + "lateral aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a "
                    + "where c.oid=?::regclass and a.grantee=0)", Boolean.class, "public." + table)).isTrue();
            assertThat(owner.queryForObject("select tableowner='iam_migrator' from pg_tables "
                    + "where schemaname='public' and tablename=?", Boolean.class, table)).isTrue();
        }
    }

    @Test
    void cleanAndV5UpgradeProduceTheSameV6AuthorizationSchema() {
        owner.execute("create database authorization_v6_clean");
        owner.execute("create database authorization_v6_upgrade");
        var cleanUrl = databaseUrl("authorization_v6_clean");
        var upgradeUrl = databaseUrl("authorization_v6_upgrade");
        assertThat(Flyway.configure().dataSource(cleanUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate().migrationsExecuted).isEqualTo(14);
        assertThat(Flyway.configure().dataSource(upgradeUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .target("5").load().migrate().migrationsExecuted).isEqualTo(5);
        assertThat(Flyway.configure().dataSource(upgradeUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate().migrationsExecuted).isEqualTo(9);

        assertThat(schemaSnapshot(cleanUrl)).isEqualTo(schemaSnapshot(upgradeUrl));
    }

    @Test
    void v6MigrationFailsWhenRuntimeRoleIsMissing() throws Exception {
        try (var isolated = new PostgreSQLContainer("postgres:18-alpine")) {
            isolated.start();
            try (var connection = DriverManager.getConnection(
                    isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword());
                    var statement = connection.createStatement()) {
                statement.execute("create role iam_migrator nologin");
                statement.execute("create role iam_runtime nologin");
                statement.execute("create role iam_relay nologin");
                statement.execute("create role iam_registration_reconciler nologin");
                statement.execute("grant iam_migrator to " + isolated.getUsername());
            }
            Flyway.configure().dataSource(isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword())
                    .target("5").load().migrate();
            try (var connection = DriverManager.getConnection(
                    isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword());
                    var statement = connection.createStatement()) {
                statement.execute("drop owned by iam_runtime");
                statement.execute("drop role iam_runtime");
            }
            assertThatThrownBy(() -> Flyway.configure()
                    .dataSource(isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword()).load().migrate())
                    .hasStackTraceContaining("required IAM privilege roles are not provisioned");
        }
    }

    @ParameterizedTest
    @MethodSource("invalidV6Mutations")
    void everyV6AuthorizationConstraintRejectsInvalidState(String mutation) {
        issue("9123456789012345678901", bytes(3), bytes(4));
        assertThatThrownBy(() -> owner.execute(mutation)).isInstanceOf(org.springframework.dao.DataAccessException.class);
    }

    @Test
    void v6NotNullMatrixIsLiteralAndComplete() {
        assertNotNullColumns("authorization_server_issuer", "issuer", "singleton");
        assertNotNullColumns("authorization_request", "app_registration_id", "authorization_request_id",
                "authorized_at", "client_id", "code_challenge", "code_challenge_method", "correlation_id",
                "expires_at", "human_identity_id", "issuer", "nonce_digest", "redirect_uri", "resource_audience",
                "resource_id", "scope", "state_digest", "status", "version");
        assertNotNullColumns("authorization_code", "authorization_code_id", "authorization_request_id",
                "code_digest", "digest_key_version", "expires_at", "issued_at", "status", "version");
        assertNotNullColumns("authorization_audit_fact", "app_registration_id", "audit_id",
                "authorization_code_id", "authorization_request_id", "client_id", "correlation_id", "fact_type",
                "occurred_at", "outcome");
    }

    @Test
    void v6ForeignKeyAndUniquenessMatrixIsLiteralAndComplete() {
        assertConstraintNames('f', List.of(
                "authorization_audit_fact_app_registration_id_fkey",
                "authorization_audit_fact_authorization_code_id_fkey",
                "authorization_audit_fact_authorization_request_id_fkey",
                "authorization_audit_fact_client_id_fkey",
                "authorization_code_authorization_request_id_fkey",
                "authorization_request_app_registration_id_fkey",
                "authorization_request_client_id_fkey",
                "authorization_request_human_identity_id_fkey",
                "authorization_request_registration_binding",
                "authorization_request_resource_binding",
                "authorization_request_resource_id_fkey"));
        assertConstraintNames('u', List.of(
                "authorization_audit_once", "authorization_code_authorization_request_id_key",
                "authorization_code_digest_unique", "authorization_server_issuer_issuer_key",
                "client_registration_app_client_unique", "resource_registration_app_resource_unique"));
        assertConstraintNames('p', List.of(
                "authorization_audit_fact_pkey", "authorization_code_pkey", "authorization_request_pkey",
                "authorization_server_issuer_pkey"));
    }

    @Test
    void v6AuditConstraintAndImmutabilityMatrixIsLiteralAndComplete() {
        assertThat(owner.queryForList("select conname from pg_constraint where conrelid="
                + "'authorization_audit_fact'::regclass and contype='c' order by conname", String.class))
                .containsExactly("authorization_audit_causation_format", "authorization_audit_correlation_format",
                        "authorization_audit_fact_type", "authorization_audit_id_format",
                        "authorization_audit_outcome");
        issue("A223456789012345678901", bytes(3), bytes(4));
        assertThatThrownBy(() -> owner.update("update authorization_audit_fact set outcome='FAILED'"))
                .hasStackTraceContaining("immutable");
        assertThatThrownBy(() -> owner.update("delete from authorization_audit_fact"))
                .hasStackTraceContaining("immutable");
    }

    private static void assertNotNullColumns(String table, String... expected) {
        assertThat(owner.queryForList("select column_name from information_schema.columns where table_schema='public' "
                + "and table_name=? and is_nullable='NO' order by column_name", String.class, table))
                .containsExactly(expected);
    }

    private static void assertConstraintNames(char type, List<String> expected) {
        assertThat(owner.queryForList("select conname from pg_constraint where contype=? and conrelid in "
                + "('authorization_server_issuer'::regclass,'authorization_request'::regclass,"
                + "'authorization_code'::regclass,'authorization_audit_fact'::regclass,"
                + "'client_registration'::regclass,'resource_registration'::regclass) "
                + "and (conname like 'authorization_%' or conname in "
                + "('client_registration_app_client_unique','resource_registration_app_resource_unique')) "
                + "order by conname", String.class, String.valueOf(type))).containsExactlyElementsOf(expected);
    }

    static Stream<String> invalidV6Mutations() {
        return Stream.of(
                "update authorization_server_issuer set singleton=false",
                "update authorization_server_issuer set issuer='https://other.invalid'",
                "update authorization_request set authorization_request_id='bad'",
                "update authorization_request set issuer='short'",
                "update authorization_request set resource_audience=repeat('x',257)",
                "update authorization_request set redirect_uri='short'",
                "update authorization_request set scope='member:read  member:write'",
                "update authorization_request set state_digest='x'::bytea",
                "update authorization_request set nonce_digest='x'::bytea",
                "update authorization_request set code_challenge='x'::bytea",
                "update authorization_request set code_challenge_method='plain'",
                "update authorization_request set status='PENDING'",
                "update authorization_request set expires_at=authorized_at",
                "update authorization_request set correlation_id='bad'",
                "update authorization_request set version=0",
                "update authorization_code set authorization_code_id='bad'",
                "update authorization_code set code_digest='x'::bytea",
                "update authorization_code set digest_key_version=0",
                "update authorization_code set status='PENDING'",
                "update authorization_code set expires_at=issued_at",
                "update authorization_code set status='CONSUMED'",
                "update authorization_code set consumed_at=transaction_timestamp()",
                "update authorization_code set consumed_correlation_id='bad'",
                "update authorization_code set version=0",
                "update authorization_audit_fact set outcome='FAILED'");
    }

    @ParameterizedTest
    @ValueSource(strings = {"authorization_code", "authorization_audit_fact"})
    void injectedFailureAfterRequestInsertRollsBackTheEntireIssue(String targetTable) {
        owner.execute("create function injected_authorization_failure() returns trigger language plpgsql as "
                + "$$ begin raise exception 'injected'; end $$");
        owner.execute("create trigger injected_authorization_failure before insert on " + targetTable
                + " for each row execute function injected_authorization_failure()");
        try {
            assertThatThrownBy(() -> issue("A123456789012345678901", bytes(3), bytes(4)))
                    .hasStackTraceContaining("injected");
            assertThat(owner.queryForObject("select count(*) from authorization_request", Integer.class)).isZero();
            assertThat(owner.queryForObject("select count(*) from authorization_code", Integer.class)).isZero();
            assertThat(owner.queryForObject("select count(*) from authorization_audit_fact", Integer.class)).isZero();
        } finally {
            owner.execute("drop trigger injected_authorization_failure on " + targetTable);
            owner.execute("drop function injected_authorization_failure()");
        }
    }

    @Test
    void consumedCodeRemainsRejectedAfterFullSpringContextRestart() {
        AuthorizationRedirectResult issued;
        var command = requestCommand();
        try (var first = restartContext()) {
            issued = first.getBean(AuthorizationRequestService.class).authorize(
                    new AuthenticatedIdentity(new dev.distracted.iam.identity.IdentityReference(
                            "hid_0123456789012345678901")), command, "cor_B123456789012345");
            assertThat(first.getBean(AuthorizationCodeRedemption.class).redeem(redemption(issued.code(),
                    "cor_C123456789012345"))).isPresent();
        }
        try (var restarted = restartContext()) {
            assertThat(restarted.getBean(AuthorizationCodeRedemption.class).redeem(redemption(issued.code(),
                    "cor_D123456789012345"))).isEmpty();
            assertThat(restarted.getBean(AuthorizationCodeRepository.class))
                    .isInstanceOf(dev.distracted.iam.authorization.adapter.jdbc.JdbcAuthorizationCodeRepository.class);
        }
    }

    @Test
    void persistedCodesHonorReadableKeyRotationAcrossFullApplicationRestarts() {
        AuthorizationRedirectResult redeemableV1;
        AuthorizationRedirectResult strandedV1;
        try (var v1 = restartContext((short) 1, Map.of((short) 1, key(1)))) {
            var service = v1.getBean(AuthorizationRequestService.class);
            var principal = new AuthenticatedIdentity(new dev.distracted.iam.identity.IdentityReference(
                    "hid_0123456789012345678901"));
            redeemableV1 = service.authorize(principal, requestCommand(), "cor_R123456789012345");
            strandedV1 = service.authorize(principal, requestCommand(), "cor_S123456789012345");
        }

        AuthorizationRedirectResult issuedV2;
        try (var rotating = restartContext((short) 2, Map.of((short) 1, key(1), (short) 2, key(2)))) {
            assertThat(rotating.getBean(AuthorizationCodeRedemption.class).redeem(
                    redemption(redeemableV1.code(), "cor_T123456789012345"))).isPresent();
            issuedV2 = rotating.getBean(AuthorizationRequestService.class).authorize(
                    new AuthenticatedIdentity(new dev.distracted.iam.identity.IdentityReference(
                            "hid_0123456789012345678901")), requestCommand(), "cor_U123456789012345");
        }
        assertThat(owner.queryForObject("select digest_key_version from authorization_code "
                + "where authorization_code_id=?", Short.class, codeId(issuedV2))).isEqualTo((short) 2);

        try (var v1Removed = restartContext((short) 2, Map.of((short) 2, key(2)))) {
            assertThat(v1Removed.getBean(AuthorizationCodeRedemption.class).redeem(
                    redemption(strandedV1.code(), "cor_V123456789012345"))).isEmpty();
        }
        assertThat(owner.queryForObject("select status from authorization_code where authorization_code_id=?",
                String.class, codeId(strandedV1))).isEqualTo("ISSUED");
    }

    private static org.springframework.context.ConfigurableApplicationContext restartContext() {
        return restartContext((short) 1, Map.of((short) 1, key(1)));
    }

    private static org.springframework.context.ConfigurableApplicationContext issuerAuthorityRestartContext()
            throws Exception {
        var key = new com.nimbusds.jose.jwk.gen.ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
                .keyID("restart01").keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .algorithm(com.nimbusds.jose.JWSAlgorithm.ES256).generate();
        AccessTokenSigningCapability capability = () -> new AccessTokenSigningSnapshot(
                "ACCESS_TOKEN_SIGNING", "ES256", key.getKeyID(), List.of(key.toPublicJWK()), true, input -> {
                    try {
                        return new com.nimbusds.jose.crypto.ECDSASigner(key).sign(
                                new com.nimbusds.jose.JWSHeader(com.nimbusds.jose.JWSAlgorithm.ES256), input).decode();
                    } catch (com.nimbusds.jose.JOSEException exception) {
                        throw new IllegalStateException(exception);
                    }
                });
        return new SpringApplicationBuilder(IamApplication.class)
                .initializers(context -> context.getBeanFactory().registerSingleton(
                        "restartAccessTokenSigningCapability", capability))
                .web(WebApplicationType.SERVLET).profiles("test").properties(
                        "server.port=0", "spring.flyway.enabled=false", "iam.token.enabled=true",
                        "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "spring.datasource.username=iam_runtime_login", "spring.datasource.password=" + RUNTIME_PASSWORD)
                .run();
    }

    private static org.springframework.context.ConfigurableApplicationContext restartContext(
            short writeVersion, Map<Short, byte[]> keys) {
        var references = keys.keySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                version -> version, version -> "test://authorization-code/" + version));
        var capability = new HmacAuthorizationCodeDigestCapability("development", writeVersion, keys, references);
        return new SpringApplicationBuilder(IamApplication.class)
                .initializers(context -> context.getBeanFactory().registerSingleton(
                        "authorizationCodeDigestCapability", capability))
                .web(WebApplicationType.SERVLET).profiles("test").properties(
                        "server.port=0", "spring.flyway.enabled=false",
                        "spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                        "spring.datasource.username=iam_runtime_login", "spring.datasource.password=" + RUNTIME_PASSWORD,
                        "iam.registration.dutch-development.enabled=true", "iam.environment=development",
                        "iam.registration.reconciler.jdbc-url=" + POSTGRES.getJdbcUrl(),
                        "iam.registration.reconciler.username=iam_reconciler_login",
                        "iam.registration.reconciler.password=" + RECONCILER_PASSWORD,
                        "iam.authorization.enabled=true", "iam.issuer=https://iam.distracted.invalid")
                .run();
    }

    private static byte[] key(int version) {
        return ("authorization-code-test-key-0000" + version).getBytes(StandardCharsets.US_ASCII);
    }

    private static String codeId(AuthorizationRedirectResult result) {
        return result.code().substring(0, result.code().indexOf('.'));
    }

    private static AuthorizationRequestCommand requestCommand() {
        return new AuthorizationRequestCommand("dutch-mobile", "code", "dutch://oauth/callback", "member:read",
                "https://api.dutch.invalid", "state_0123456789", "nonce_0123456789",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256");
    }

    private static AuthorizationCodeRedemptionCommand redemption(String code, String correlation) {
        return new AuthorizationCodeRedemptionCommand("authorization_code", code, "dutch-mobile",
                "dutch://oauth/callback", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", correlation);
    }

    private static String databaseUrl(String database) {
        return "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getFirstMappedPort() + "/" + database;
    }

    private static List<Map<String, Object>> schemaSnapshot(String url) {
        var jdbc = new JdbcTemplate(new DriverManagerDataSource(url, POSTGRES.getUsername(), POSTGRES.getPassword()));
        return jdbc.queryForList("select 'column' kind,table_name object,column_name detail,data_type value "
                + "from information_schema.columns where table_schema='public' and table_name like 'authorization_%' "
                + "union all select 'constraint',c.relname,con.conname,pg_get_constraintdef(con.oid) "
                + "from pg_constraint con join pg_class c on c.oid=con.conrelid "
                + "where c.relnamespace='public'::regnamespace and c.relname like 'authorization_%' "
                + "union all select 'function',p.proname,p.oid::regprocedure::text,"
                + "coalesce(array_to_string(p.proconfig,','),'') from pg_proc p "
                + "where p.pronamespace='public'::regnamespace and p.proname like '%authorization_code%' "
                + "order by 1,2,3,4");
    }

    private static void issue(String suffix, byte[] challenge, byte[] digest) {
        runtime.queryForMap("select * from issue_authorization_code(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                "arq_" + suffix, "acd_" + suffix, "https://iam.distracted.invalid", "dutch-development",
                "dutch-mobile", "dutch-api", "https://api.dutch.invalid", "hid_0123456789012345678901",
                "dutch://oauth/callback", "member:read", bytes(1), bytes(2), challenge, digest, (short) 1, 120,
                "cor_0123456789012345");
    }

    private static byte[] bytes(int value) {
        var result = new byte[32];
        java.util.Arrays.fill(result, (byte) value);
        return result;
    }
}
