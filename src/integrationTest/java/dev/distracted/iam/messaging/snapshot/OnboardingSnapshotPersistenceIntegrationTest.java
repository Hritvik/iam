package dev.distracted.iam.messaging.snapshot;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.messaging.snapshot.adapter.jdbc.JdbcOnboardingSnapshotQuery;
import java.sql.DriverManager;
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
class OnboardingSnapshotPersistenceIntegrationTest {
    @Container static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final String APP = "dutch-development";
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
        owner.execute("truncate app_activation,app_subject,human_identity,policy_activation_evidence,"
                + "policy_grant_type,product_security_policy,resource_scope,resource_registration,"
                + "client_pkce_method,client_grant_type,client_redirect_uri,client_registration,app_registration cascade");
        owner.queryForObject("select reconcile_pinned_registration(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", String.class,
                APP, (short) 1, "Dutch Development", "development",
                "eb19d5cd14c21e66c334bdd61afd8822da6b2a7d692384a4aa4a96f9f589bafc",
                "dutch-mobile", "NATIVE_PUBLIC", "EXTERNAL", new String[] {"dutch://oauth/callback"},
                new String[] {"authorization_code"}, new String[] {"S256"}, "dutch-api",
                "https://api.dutch.invalid", new String[] {"member:read"}, true, "S256",
                new String[] {"verified_identifier", "usable_factor", "recovery_path"});
        for (int index = 0; index < 3; index++) {
            var identity = "hid_012345678901234567890" + index;
            var subject = "aps_0123456789012345678901a" + index;
            owner.update("insert into human_identity(identity_id,state) values(?,?)", identity, "ACTIVE");
            owner.update("insert into app_subject(app_registration_id,human_identity_id,app_subject) values(?,?,?)",
                    APP, identity, subject);
            owner.update("insert into app_activation(activation_id,app_registration_id,human_identity_id,app_subject,"
                    + "state,activation_version,onboarding_version,onboarding_reason) values(?,?,?,?,?,?,?,?)",
                    "act_01234567890123456" + index, APP, identity, subject,
                    index == 2 ? "PENDING_PREREQUISITES" : "ACTIVE", 2, index == 2 ? 0 : 1,
                    index == 2 ? null : "FIRST_ACTIVATION");
        }
    }

    @Test
    void returnsOnlyActiveRowsForTheAppInStableCursorOrder() {
        var query = new JdbcOnboardingSnapshotQuery(runtime);
        var first = query.page(APP, null, 1);
        assertThat(first.items()).hasSize(1);
        assertThat(first.hasMore()).isTrue();
        assertThat(first.nextCursor()).isNotBlank();

        var second = query.page(APP, first.nextCursor(), 10);
        assertThat(second.items()).hasSize(1);
        assertThat(second.hasMore()).isFalse();
        assertThat(second.nextCursor()).isNull();
        assertThat(second.items().getFirst().appSubject()).isGreaterThan(first.items().getFirst().appSubject());

        var all = query.page(APP, null, 10);
        assertThat(all.items()).extracting(OnboardingSnapshotItem::activationState).containsOnly("ACTIVE");
        assertThat(all.items()).extracting(OnboardingSnapshotItem::requiredProfileState)
                .containsOnly("PROFILE_REQUIRED");
    }

    @Test
    void theContractMaximumLimitReturnsRowsRatherThanAnEmptyProbe() {
        var query = new JdbcOnboardingSnapshotQuery(runtime);
        var page = query.page(APP, null, 200);
        assertThat(page.items()).hasSize(2);
        assertThat(page.hasMore()).isFalse();
    }

    @Test
    void anotherAppAndMalformedCursorsAreNonEnumeratingOrRejected() {
        var query = new JdbcOnboardingSnapshotQuery(runtime);
        assertThat(query.page("dutch-staging", null, 10).items()).isEmpty();
        assertThat(query.page("dutch-staging", null, 10).hasMore()).isFalse();
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> query.page(APP, "bad!", 10))
                .isInstanceOf(IllegalArgumentException.class);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> query.page(APP, null, 201))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void snapshotFunctionIsRuntimeExecutableAndNotPublic() {
        assertThat(owner.queryForObject("select has_function_privilege('iam_runtime',?,'EXECUTE')", Boolean.class,
                "public.read_onboarding_snapshot(text,text,integer)")).isTrue();
        assertThat(owner.queryForObject("select has_function_privilege('public',?,'EXECUTE')", Boolean.class,
                "public.read_onboarding_snapshot(text,text,integer)")).isFalse();
        assertThat(owner.queryForObject("select has_table_privilege('iam_runtime','public.app_activation','SELECT')",
                Boolean.class)).isFalse();
    }
}
