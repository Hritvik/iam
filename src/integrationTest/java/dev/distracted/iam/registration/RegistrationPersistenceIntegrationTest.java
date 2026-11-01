package dev.distracted.iam.registration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.DriverManager;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import dev.distracted.iam.registration.adapter.jdbc.JdbcRegistrationRegistry;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
class RegistrationPersistenceIntegrationTest {
    @Container
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RUNTIME_PASSWORD = "runtime-test-placeholder";
    private static final String RECONCILER_PASSWORD = "reconciler-test-placeholder";
    private static JdbcTemplate runtime;
    private static JdbcTemplate reconciler;
    private static JdbcTemplate owner;

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
        reconciler = new JdbcTemplate(new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), "iam_reconciler_login", RECONCILER_PASSWORD));
    }

    @BeforeEach
    void clearRegistrationGraph() {
        owner.execute("truncate app_activation,token_issuance_audit_fact,dpop_replay,dpop_nonce,app_subject,authorization_audit_fact,authorization_code,authorization_request,policy_activation_evidence,policy_grant_type,product_security_policy,resource_scope,"
                + "resource_registration,client_pkce_method,client_grant_type,client_redirect_uri,client_registration,"
                + "app_registration");
    }

    @Test
    void runtimeCanOnlyReconcileThroughTheFunctionAndThenReadExactGraph() {
        var registry = new JdbcRegistrationRegistry(reconciler);
        var lookup = new JdbcRegistrationRegistry(runtime);
        var validated = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());

        assertThat(owner.queryForObject("select has_function_privilege('iam_registration_reconciler',"
                + "'public.reconcile_pinned_registration(text,smallint,text,text,text,text,text,text,text[],text[],text[],"
                + "text,text,text[],boolean,text,text[])','EXECUTE')", Boolean.class)).isTrue();
        assertThat(registry.reconcile(validated)).isEqualTo(ReconciliationResult.CREATED);
        assertThat(registry.reconcile(validated)).isEqualTo(ReconciliationResult.UNCHANGED);
        assertThat(lookup.findByAppId("dutch-development")).get().isEqualTo(validated.manifest());
        assertThat(lookup.findByClientId("dutch-mobile")).contains(validated.manifest());
        assertThat(lookup.findByResourceId("dutch-api")).contains(validated.manifest());
        assertThat(lookup.findByAudience("https://api.dutch.invalid")).contains(validated.manifest());
        assertThat(lookup.findByAppId("unknown-app")).isEmpty();
        assertThat(lookup.findByClientId("unknown-client")).isEmpty();
        assertThat(owner.queryForObject("select count(*) from app_registration", Integer.class)).isOne();
        assertThatThrownBy(() -> runtime.update("delete from app_registration"))
                .rootCause()
                .hasMessageContaining("permission denied");
        assertThatThrownBy(() -> new JdbcRegistrationRegistry(runtime).reconcile(validated))
                .rootCause().hasMessageContaining("permission denied");
    }

    @Test
    void persistedGraphDriftIsDetectedAndUnallowlistedFingerprintIsRejected() {
        var registry = new JdbcRegistrationRegistry(reconciler);
        var validated = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());
        registry.reconcile(validated);

        assertThatThrownBy(() -> registry.reconcile(new ValidatedRegistration(validated.manifest(), "a".repeat(64))))
                .rootCause().hasMessageContaining("registration_reconcile_not_allowlisted");
        owner.update("update app_registration set display_name=? where app_registration_id=?",
                "Drifted", "dutch-development");
        assertThat(registry.reconcile(validated)).isEqualTo(ReconciliationResult.DRIFT);
        owner.update("update app_registration set display_name=? where app_registration_id=?",
                "Dutch Development", "dutch-development");
    }

    @Test
    void reconcilerCannotCreateAnUnpublishedTuple() {
        var canonical = new StrictRegistrationManifestValidator()
                .validate(new ClasspathPinnedRegistrationSource().load());
        var value = canonical.manifest();
        var arbitrary = new RegistrationManifest(value.manifestVersion(), "rogue-development", value.displayName(),
                value.environment(), value.client(), value.resource(), value.securityPolicy());

        assertThatThrownBy(() -> new JdbcRegistrationRegistry(reconciler)
                .reconcile(new ValidatedRegistration(arbitrary, canonical.fingerprint())))
                .rootCause().hasMessageContaining("registration_reconcile_not_allowlisted");
        assertThat(owner.queryForObject("select count(*) from app_registration where app_registration_id=?",
                Integer.class, "rogue-development")).isZero();
    }

    @Test
    void concurrentIdenticalStartupCreatesOneCanonicalGraph() throws Exception {
        var validated = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var one = executor.submit(() -> new JdbcRegistrationRegistry(reconciler).reconcile(validated));
            var two = executor.submit(() -> new JdbcRegistrationRegistry(reconciler).reconcile(validated));
            assertThat(Stream.of(one.get(), two.get()).filter(result -> result == ReconciliationResult.CREATED).count())
                    .isOne();
            assertThat(Stream.of(one.get(), two.get()).filter(result -> result == ReconciliationResult.UNCHANGED).count())
                    .isOne();
        }
        assertThat(owner.queryForObject("select count(*) from app_registration", Integer.class)).isOne();
    }

    @Test
    void concurrentMigratorMutationNeverEscapesTheAtomicCanonicalSnapshot() throws Exception {
        var canonical = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());
        new JdbcRegistrationRegistry(reconciler).reconcile(canonical);
        var lookup = new JdbcRegistrationRegistry(runtime);
        var mutationIsUncommitted = new CountDownLatch(1);
        var canonicalReadCompleted = new CountDownLatch(1);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var writer = executor.submit(() -> {
                try (var connection = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                     var statement = connection.createStatement()) {
                    connection.setAutoCommit(false);
                    statement.executeUpdate("update app_registration set display_name='Changed' "
                            + "where app_registration_id='dutch-development'");
                    mutationIsUncommitted.countDown();
                    assertThat(canonicalReadCompleted.await(10, TimeUnit.SECONDS)).isTrue();
                    connection.commit();
                }
                return null;
            });
            var reader = executor.submit(() -> {
                assertThat(mutationIsUncommitted.await(10, TimeUnit.SECONDS)).isTrue();
                assertThat(lookup.findByAppId("dutch-development")).contains(canonical.manifest());
                canonicalReadCompleted.countDown();
                return null;
            });
            writer.get();
            reader.get();
        }
        assertThat(lookup.findByAppId("dutch-development")).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("persistedDriftMutations")
    void detectsEveryPersistedScalarAndChildSetDrift(String mutation) {
        var validated = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());
        var registry = new JdbcRegistrationRegistry(reconciler);
        registry.reconcile(validated);
        owner.execute(mutation);
        assertThat(registry.reconcile(validated)).isEqualTo(ReconciliationResult.DRIFT);
    }

    static Stream<String> persistedDriftMutations() {
        return Stream.of(
                "update app_registration set display_name='Changed'",
                "update app_registration set environment='test'",
                "update app_registration set source_fingerprint='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'",
                "delete from client_redirect_uri; delete from client_grant_type; delete from client_pkce_method; "
                        + "update client_registration set client_id='changed-mobile'",
                "delete from resource_scope; update resource_registration set resource_id='changed-api'",
                "update resource_registration set audience='https://changed.invalid'",
                "delete from client_redirect_uri",
                "delete from client_grant_type",
                "delete from client_pkce_method",
                "delete from resource_scope",
                "delete from policy_grant_type",
                "delete from policy_activation_evidence where evidence_type='recovery_path'");
    }

    @ParameterizedTest
    @MethodSource("invalidV5Statements")
    void everyV5ConstraintRejectsInvalidOrConflictingData(String statement) {
        var canonical = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());
        new JdbcRegistrationRegistry(reconciler).reconcile(canonical);
        assertThatThrownBy(() -> owner.execute(statement)).rootCause();
    }

    static Stream<String> invalidV5Statements() {
        return Stream.of(
                "update app_registration set app_registration_id='BAD'",
                "update app_registration set app_registration_id='ab'",
                "update app_registration set app_registration_id='a'||repeat('b',64)",
                "update app_registration set manifest_version=2",
                "update app_registration set display_name=''",
                "update app_registration set display_name=repeat('x',81)",
                "update app_registration set environment='invalid'",
                "update app_registration set source_fingerprint='ABC'",
                "update client_registration set client_id='BAD'",
                "update client_registration set client_id='ab'",
                "update client_registration set client_id='a'||repeat('b',64)",
                "update client_registration set client_type='CONFIDENTIAL'",
                "update client_registration set browser_mode='EMBEDDED'",
                "insert into client_registration values('other-client','missing-app','NATIVE_PUBLIC','EXTERNAL')",
                "insert into client_redirect_uri values('missing-client','dutch://oauth/callback')",
                "insert into client_redirect_uri values('dutch-mobile','short')",
                "insert into client_redirect_uri values('dutch-mobile',repeat('x',513))",
                "insert into client_redirect_uri values('dutch-mobile','dutch://oauth/callback')",
                "insert into client_grant_type values('missing-client','authorization_code')",
                "insert into client_grant_type values('dutch-mobile','refresh_token')",
                "insert into client_grant_type values('dutch-mobile','authorization_code')",
                "insert into client_pkce_method values('missing-client','S256')",
                "insert into client_pkce_method values('dutch-mobile','plain')",
                "insert into client_pkce_method values('dutch-mobile','S256')",
                "update resource_registration set resource_id='BAD'",
                "update resource_registration set resource_id='ab'",
                "update resource_registration set resource_id='a'||repeat('b',64)",
                "insert into resource_registration(resource_id,app_registration_id,audience) "
                        + "values('other-api','missing-app','https://other.invalid')",
                "update resource_registration set audience='http://api.invalid'",
                "update resource_registration set audience='https://'||repeat('x',250)",
                "insert into resource_scope values('missing-api','member:read')",
                "insert into resource_scope values('dutch-api','INVALID')",
                "insert into resource_scope values('dutch-api','a'||repeat('x',64))",
                "insert into resource_scope values('dutch-api','member:read')",
                "insert into product_security_policy values('missing-app',1,true,'S256')",
                "update product_security_policy set policy_version=2",
                "update product_security_policy set require_dpop=false",
                "update product_security_policy set required_pkce_method='plain'",
                "insert into policy_grant_type values('missing-app','authorization_code')",
                "insert into policy_grant_type values('dutch-development','refresh_token')",
                "insert into policy_grant_type values('dutch-development','authorization_code')",
                "insert into policy_activation_evidence values('missing-app','verified_identifier')",
                "insert into policy_activation_evidence values('dutch-development','invalid')",
                "insert into policy_activation_evidence values('dutch-development','verified_identifier')",
                "delete from app_registration",
                "delete from client_registration",
                "delete from resource_registration",
                "delete from product_security_policy");
    }

    @ParameterizedTest
    @MethodSource("everyPublicRegistrationGraphNotNullColumn")
    void everyPublicRegistrationGraphNotNullConstraintRejectsNull(String qualifiedColumn) {
        var canonical = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());
        new JdbcRegistrationRegistry(reconciler).reconcile(canonical);
        var separator = qualifiedColumn.indexOf('.');
        var table = qualifiedColumn.substring(0, separator);
        var column = qualifiedColumn.substring(separator + 1);
        assertThatThrownBy(() -> owner.execute("update " + table + " set " + column + "=null"))
                .rootCause().hasMessageContaining("null value");
    }

    static Stream<String> everyPublicRegistrationGraphNotNullColumn() {
        return Stream.of(
                "app_registration.app_registration_id", "app_registration.manifest_version",
                "app_registration.display_name", "app_registration.environment",
                "app_registration.source_fingerprint", "app_registration.created_at",
                "client_registration.client_id", "client_registration.app_registration_id",
                "client_registration.client_type", "client_registration.browser_mode",
                "client_registration.created_at", "client_redirect_uri.client_id",
                "client_redirect_uri.redirect_uri", "client_grant_type.client_id",
                "client_grant_type.grant_type", "client_pkce_method.client_id",
                "client_pkce_method.pkce_method", "resource_registration.resource_id",
                "resource_registration.app_registration_id", "resource_registration.audience",
                "resource_registration.created_at", "resource_scope.resource_id",
                "resource_scope.scope_name", "product_security_policy.app_registration_id",
                "product_security_policy.policy_version", "product_security_policy.require_dpop",
                "product_security_policy.required_pkce_method", "product_security_policy.created_at",
                "policy_grant_type.app_registration_id", "policy_grant_type.grant_type",
                "policy_activation_evidence.app_registration_id", "policy_activation_evidence.evidence_type");
    }

    @ParameterizedTest
    @MethodSource("everyV5ParentAndBusinessUniquenessConflict")
    void everyV5ParentAndBusinessUniquenessConstraintRejectsConflict(String statement) {
        var canonical = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());
        new JdbcRegistrationRegistry(reconciler).reconcile(canonical);
        assertThatThrownBy(() -> owner.execute(statement)).rootCause().hasMessageContaining("duplicate key");
    }

    static Stream<String> everyV5ParentAndBusinessUniquenessConflict() {
        var secondApp = "insert into app_registration values('other-development',1,'Other','development',"
                + "'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',transaction_timestamp());";
        return Stream.of(
                "insert into app_registration select * from app_registration",
                "insert into client_registration select * from client_registration",
                "insert into resource_registration select * from resource_registration",
                "insert into product_security_policy select * from product_security_policy",
                secondApp + "insert into client_registration(client_id,app_registration_id,client_type,browser_mode) "
                        + "values('other-client','dutch-development','NATIVE_PUBLIC','EXTERNAL')",
                secondApp + "insert into resource_registration(resource_id,app_registration_id,audience) "
                        + "values('other-api','dutch-development','https://other.invalid')",
                secondApp + "insert into resource_registration(resource_id,app_registration_id,audience) "
                        + "values('other-api','other-development','https://api.dutch.invalid')");
    }

    @Test
    void constraintFailureRollsBackTheEntireGraph() {
        owner.update("update pinned_registration_allowlist set client_id=? where app_registration_id=?",
                "INVALID_CLIENT", "dutch-development");
        var canonical = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());
        var changed = new RegistrationManifest(canonical.manifest().manifestVersion(), canonical.manifest().appRegistrationId(),
                canonical.manifest().displayName(), canonical.manifest().environment(),
                new RegistrationManifest.Client("INVALID_CLIENT", canonical.manifest().client().clientType(),
                        canonical.manifest().client().redirectUris(), canonical.manifest().client().grantTypes(),
                        canonical.manifest().client().pkceMethods(), canonical.manifest().client().browserMode()),
                canonical.manifest().resource(), canonical.manifest().securityPolicy());
        assertThatThrownBy(() -> new JdbcRegistrationRegistry(reconciler)
                .reconcile(new ValidatedRegistration(changed, canonical.fingerprint())))
                .rootCause().hasMessageContaining("registration_reconcile_invalid");
        assertThat(owner.queryForObject("select count(*) from app_registration", Integer.class)).isZero();
        owner.update("update pinned_registration_allowlist set client_id=? where app_registration_id=?",
                "dutch-mobile", "dutch-development");
    }

    @Test
    void migrationFailsWhenTheExternallyProvisionedReconcilerRoleIsAbsent() throws Exception {
        try (var isolated = new PostgreSQLContainer("postgres:18-alpine")) {
            isolated.start();
            try (var connection = DriverManager.getConnection(
                    isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword());
                 var statement = connection.createStatement()) {
                statement.execute("create role iam_migrator nologin");
                statement.execute("create role iam_runtime nologin");
                statement.execute("create role iam_relay nologin");
            }
            assertThatThrownBy(() -> Flyway.configure().dataSource(
                            isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword()).load().migrate())
                    .rootCause().hasMessageContaining("required IAM privilege roles are not provisioned");
        }
    }

    @Test
    void cleanSecondDatabaseConvergesToTheSameLogicalGraphAndFingerprint() throws Exception {
        var canonical = new StrictRegistrationManifestValidator().validate(new ClasspathPinnedRegistrationSource().load());
        new JdbcRegistrationRegistry(reconciler).reconcile(canonical);
        try (var isolated = new PostgreSQLContainer("postgres:18-alpine")) {
            isolated.start();
            try (var connection = DriverManager.getConnection(
                    isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword());
                 var statement = connection.createStatement()) {
                statement.execute("create role iam_migrator nologin");
                statement.execute("create role iam_runtime nologin");
                statement.execute("create role iam_relay nologin");
                statement.execute("create role iam_registration_reconciler nologin");
                statement.execute("create role isolated_reconciler login password 'isolated-reconciler-placeholder' "
                        + "in role iam_registration_reconciler");
                statement.execute("create role isolated_runtime login password 'isolated-runtime-placeholder' "
                        + "in role iam_runtime");
                statement.execute("grant iam_migrator to " + isolated.getUsername());
            }
            Flyway.configure().dataSource(isolated.getJdbcUrl(), isolated.getUsername(), isolated.getPassword())
                    .load().migrate();
            var isolatedReconciler = new JdbcTemplate(new DriverManagerDataSource(
                    isolated.getJdbcUrl(), "isolated_reconciler", "isolated-reconciler-placeholder"));
            var isolatedRuntime = new JdbcTemplate(new DriverManagerDataSource(
                    isolated.getJdbcUrl(), "isolated_runtime", "isolated-runtime-placeholder"));
            assertThat(new JdbcRegistrationRegistry(isolatedReconciler).reconcile(canonical))
                    .isEqualTo(ReconciliationResult.CREATED);
            assertThat(new JdbcRegistrationRegistry(isolatedRuntime).findSoleRegistration())
                    .contains(canonical.manifest());
            assertThat(new JdbcTemplate(new DriverManagerDataSource(isolated.getJdbcUrl(), isolated.getUsername(),
                    isolated.getPassword())).queryForObject(
                            "select source_fingerprint from app_registration", String.class))
                    .isEqualTo(canonical.fingerprint());
        }
    }

    @Test
    void privilegeMatrixSeparatesLookupReconciliationAndMigrationAuthority() {
        var tables = Stream.of("app_registration", "client_registration", "client_redirect_uri",
                "client_grant_type", "client_pkce_method", "resource_registration", "resource_scope",
                "product_security_policy", "policy_grant_type", "policy_activation_evidence").toList();
        var operations = java.util.List.of("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE");
        for (var table : tables) {
            for (var operation : operations) {
                assertThat(privilege("iam_runtime", table, operation)).isEqualTo(operation.equals("SELECT"));
                assertThat(privilege("iam_registration_reconciler", table, operation)).isFalse();
                assertThat(privilege("iam_relay", table, operation)).isFalse();
                assertThat(privilege("unrelated_service", table, operation)).isFalse();
                assertThat(privilege("iam_migrator", table, operation)).isTrue();
                assertThat(publicTablePrivilege(table, operation)).isFalse();
            }
            assertThat(owner.queryForObject("select count(*) from information_schema.role_table_grants "
                    + "where grantee='PUBLIC' and table_name=?", Integer.class, table)).isZero();
            var column = owner.queryForObject("select column_name from information_schema.columns "
                    + "where table_schema='public' and table_name=? order by ordinal_position limit 1",
                    String.class, table);
            assertDenied(() -> runtime.update("update " + table + " set " + column + "=" + column));
            assertDenied(() -> runtime.update("delete from " + table));
            assertDenied(() -> runtime.execute("truncate " + table));
            assertDenied(() -> reconciler.queryForObject("select count(*) from " + table, Integer.class));
            assertThat(owner.queryForObject("select tableowner from pg_tables where schemaname='public' and tablename=?",
                    String.class, table)).isEqualTo("iam_migrator");
        }
        for (var role : java.util.List.of("iam_runtime", "iam_registration_reconciler", "iam_relay",
                "unrelated_service")) {
            for (var operation : operations) {
                assertThat(privilege(role, "pinned_registration_allowlist", operation)).isFalse();
            }
        }
        assertThat(owner.queryForObject("select count(*) from information_schema.role_table_grants "
                + "where grantee='PUBLIC' and table_name='pinned_registration_allowlist'", Integer.class)).isZero();
        assertThat(owner.queryForObject("select tableowner from pg_tables where schemaname='public' "
                + "and tablename='pinned_registration_allowlist'", String.class)).isEqualTo("iam_migrator");
        for (var operation : operations) {
            assertThat(privilege("iam_migrator", "pinned_registration_allowlist", operation)).isTrue();
            assertThat(publicTablePrivilege("pinned_registration_allowlist", operation)).isFalse();
        }
        var signature = "public.reconcile_pinned_registration(text,smallint,text,text,text,text,text,text,text[],"
                + "text[],text[],text,text,text[],boolean,text,text[])";
        assertThat(functionPrivilege("iam_registration_reconciler", signature)).isTrue();
        assertThat(functionPrivilege("iam_runtime", signature)).isFalse();
        assertThat(functionPrivilege("iam_relay", signature)).isFalse();
        assertThat(functionPrivilege("unrelated_service", signature)).isFalse();
        assertThat(publicFunctionExecute("reconcile_pinned_registration")).isFalse();
        var canonicalSignature = "public.canonical_registration()";
        assertThat(functionPrivilege("iam_runtime", canonicalSignature)).isTrue();
        assertThat(functionPrivilege("iam_registration_reconciler", canonicalSignature)).isFalse();
        assertThat(functionPrivilege("iam_relay", canonicalSignature)).isFalse();
        assertThat(functionPrivilege("unrelated_service", canonicalSignature)).isFalse();
        assertThat(publicFunctionExecute("canonical_registration")).isFalse();
        assertThat(owner.queryForObject("select has_schema_privilege('iam_registration_reconciler','public','USAGE')",
                Boolean.class)).isTrue();
        assertThat(owner.queryForObject("select has_schema_privilege('iam_registration_reconciler','public','CREATE')",
                Boolean.class)).isFalse();
        for (var function : java.util.List.of("reconcile_pinned_registration", "canonical_registration")) {
            assertThat(owner.queryForObject("select p.prosecdef from pg_proc p join pg_namespace n on n.oid=p.pronamespace "
                    + "where n.nspname='public' and p.proname=?", Boolean.class, function)).isTrue();
            assertThat(owner.queryForObject("select pg_get_userbyid(p.proowner) from pg_proc p join pg_namespace n "
                    + "on n.oid=p.pronamespace where n.nspname='public' and p.proname=?",
                    String.class, function)).isEqualTo("iam_migrator");
            assertThat(owner.queryForObject("select array_to_string(p.proconfig,',') from pg_proc p join pg_namespace n "
                    + "on n.oid=p.pronamespace where n.nspname='public' and p.proname=?",
                    String.class, function)).contains("search_path=pg_catalog, public");
        }
    }

    private static Boolean privilege(String role, String table, String privilege) {
        return owner.queryForObject("select has_table_privilege(?,?,?)", Boolean.class, role, table, privilege);
    }

    private static Boolean functionPrivilege(String role, String signature) {
        return owner.queryForObject("select has_function_privilege(?,?,?)", Boolean.class,
                role, signature, "EXECUTE");
    }

    private static Boolean publicTablePrivilege(String table, String operation) {
        return owner.queryForObject("select exists(select 1 from pg_class c join pg_namespace n on n.oid=c.relnamespace, "
                + "lateral aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a "
                + "where n.nspname='public' and c.relname=? and a.grantee=0 and a.privilege_type=?)",
                Boolean.class, table, operation);
    }

    private static Boolean publicFunctionExecute(String function) {
        return owner.queryForObject("select exists(select 1 from pg_proc p, "
                + "lateral aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a "
                + "where p.proname=? and a.grantee=0 and a.privilege_type='EXECUTE')", Boolean.class, function);
    }

    private static void assertDenied(org.assertj.core.api.ThrowableAssert.ThrowingCallable action) {
        assertThatThrownBy(action).rootCause().hasMessageContaining("permission denied");
    }
}
