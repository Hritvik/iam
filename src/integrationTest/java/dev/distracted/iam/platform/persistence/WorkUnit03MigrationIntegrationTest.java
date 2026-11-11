package dev.distracted.iam.platform.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.DriverManager;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

@Testcontainers
class WorkUnit03MigrationIntegrationTest {
    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.0-alpine");

    @BeforeAll
    static void provisionPrivilegeRoles() throws Exception {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
        }
    }

    @Test
    void installsImmutableOutboxDeliveryAndAuditPrimitives() throws Exception {
        var flyway = Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load();
        assertThat(flyway.migrate().success).isTrue();
        assertThat(flyway.validateWithResult().validationSuccessful).isTrue();
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.prepareStatement(
                        "select count(*) from information_schema.tables where table_name in ('outbox_event',"
                                + "'outbox_delivery','audit_fact','human_identity','verified_identifier',"
                                + "'verified_identifier_blind_index','verification_challenge')");
                var rows = statement.executeQuery()) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getInt(1)).isEqualTo(7);
        }
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.prepareStatement(
                        "select count(*) from pg_constraint where conrelid in "
                                + "('verified_identifier'::regclass,'verified_identifier_blind_index'::regclass,"
                                + "'verification_challenge'::regclass) and contype='f'");
                var rows = statement.executeQuery()) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getInt(1)).isEqualTo(4);
        }
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.prepareStatement(
                        "select count(*) from information_schema.role_table_grants where grantee='iam_runtime' "
                                + "and table_name in ('human_identity','verified_identifier',"
                                + "'verified_identifier_blind_index','verification_challenge') "
                                + "and privilege_type='UPDATE'");
                var rows = statement.executeQuery()) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getInt(1)).isZero();
        }
    }

    @Test
    void upgradesADataBearingV1DatabaseAndRerunIsNoOp() throws Exception {
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.createStatement()) {
            statement.execute("create database retained_v1");
        }
        var retainedUrl = "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getFirstMappedPort()
                + "/retained_v1";
        var v1 = Flyway.configure()
                .dataSource(retainedUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .target(MigrationVersion.fromVersion("1"))
                .load();
        v1.migrate();
        try (var connection = DriverManager.getConnection(
                retainedUrl, POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.prepareStatement(
                        "update iam_schema_marker set description=? where singleton=true")) {
            statement.setString(1, "retained foundation data");
            statement.executeUpdate();
        }
        var latest = Flyway.configure()
                .dataSource(retainedUrl, POSTGRES.getUsername(), POSTGRES.getPassword())
                .load();
        // V2 through additive V9 must upgrade a retained V1 database without rewriting it.
        assertThat(latest.migrate().migrationsExecuted).isEqualTo(13);
        assertThat(latest.migrate().migrationsExecuted).isZero();
        try (var connection = DriverManager.getConnection(
                retainedUrl, POSTGRES.getUsername(), POSTGRES.getPassword());
                var statement = connection.prepareStatement(
                        "select description from iam_schema_marker where singleton=true");
                var rows = statement.executeQuery()) {
            assertThat(rows.next()).isTrue();
            assertThat(rows.getString(1)).isEqualTo("retained foundation data");
        }
    }
}
