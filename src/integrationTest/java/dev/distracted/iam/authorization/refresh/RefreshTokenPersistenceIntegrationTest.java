package dev.distracted.iam.authorization.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.authorization.adapter.jdbc.JdbcRefreshTokenRepository;
import java.security.SecureRandom;
import java.sql.DriverManager;
import java.time.Duration;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

class RefreshTokenPersistenceIntegrationTest {
    private static final String IDENTITY = "hid_refreshtest000000000001";
    private static final String JKT = "a".repeat(43);
    private static final String OTHER_JKT = "b".repeat(43);
    private static final String CORRELATION = "cor_0123456789abcdef";
    private static final String APP = "dutch-development";
    private static final String CLIENT = "dutch-mobile";
    private static final String RESOURCE = "dutch-api";
    private static final String AUDIENCE = "https://api.dutch.invalid";
    private static final String SCOPE = "member:read";
    private static final Duration ABSOLUTE = Duration.ofDays(30);
    private static final Duration IDLE = Duration.ofDays(7);
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");

    static {
        POSTGRES.start();
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {
            statement.execute("create role iam_migrator nologin");
            statement.execute("create role iam_runtime nologin");
            statement.execute("create role iam_relay nologin");
            statement.execute("create role iam_registration_reconciler nologin");
            statement.execute("create role iam_runtime_login login password '" + RUNTIME_PASSWORD
                    + "' in role iam_runtime");
            statement.execute("grant iam_migrator to " + POSTGRES.getUsername());
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate();
        try (var connection = DriverManager.getConnection(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
             var statement = connection.createStatement()) {
            statement.execute("select reconcile_pinned_registration('dutch-development',1::smallint,'Dutch Development',"
                    + "'development','eb19d5cd14c21e66c334bdd61afd8822da6b2a7d692384a4aa4a96f9f589bafc',"
                    + "'dutch-mobile','NATIVE_PUBLIC','EXTERNAL',array['dutch://oauth/callback'],"
                    + "array['authorization_code'],array['S256'],'dutch-api','https://api.dutch.invalid',"
                    + "array['member:read'],true,'S256',"
                    + "array['verified_identifier','usable_factor','recovery_path'])");
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
    }

    private final JdbcTemplate admin = new JdbcTemplate(new DriverManagerDataSource(
            POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword()));
    private final JdbcTemplate runtime = new JdbcTemplate(new DriverManagerDataSource(
            POSTGRES.getJdbcUrl(), "iam_runtime_login", RUNTIME_PASSWORD));
    private final RefreshTokenMaterialGenerator generator =
            new SecureRefreshTokenMaterialGenerator(new SecureRandom());
    private final RefreshTokenRepository repository = new JdbcRefreshTokenRepository(runtime);

    @BeforeEach
    void reset() {
        admin.update("insert into human_identity(identity_id,state,security_version,version) "
                + "values(?, 'ACTIVE', 1, 1) on conflict (identity_id) do update "
                + "set state='ACTIVE', security_version=1, version=human_identity.version+1", IDENTITY);
    }

    @Test
    void rotatesOnceAndRevokesTheFamilyOnReuse() {
        var first = generator.newFamily();
        assertThat(repository.issue(issue(first, JKT)).version()).isEqualTo(1);
        var view = repository.findByTokenDigest(first.digest()).orElseThrow();
        assertThat(view.familyId()).isEqualTo(first.familyId());
        assertThat(view.securityVersion()).isEqualTo(1);
        assertThat(view.status()).isEqualTo("ACTIVE");
        assertThat(repository.findByTokenDigest(new byte[32])).isEmpty();

        var second = generator.rotate(first.familyId());
        var rotated = repository.rotate(command(first, second, JKT, 1));
        assertThat(rotated.outcome()).isEqualTo(RefreshRotationOutcome.ROTATED);
        assertThat(rotated.familyId()).isEqualTo(first.familyId());
        assertThat(rotated.generation()).isEqualTo(2);

        var third = generator.rotate(first.familyId());
        var reuse = repository.rotate(command(first, third, JKT, 1));
        assertThat(reuse.outcome()).isEqualTo(RefreshRotationOutcome.REUSE);
        assertThat(admin.queryForObject("select status from refresh_family where family_id=?",
                String.class, first.familyId())).isEqualTo("REVOKED");
        assertThat(admin.queryForObject("select revocation_reason from refresh_family where family_id=?",
                String.class, first.familyId())).isEqualTo("REUSE");
        assertThat(admin.queryForObject("select status from refresh_token where refresh_token_id=?",
                String.class, second.tokenId())).isEqualTo("REVOKED");
    }

    @Test
    void wrongDeviceKeyRevokesTheFamily() {
        var first = generator.newFamily();
        repository.issue(issue(first, JKT));
        var second = generator.rotate(first.familyId());

        var result = repository.rotate(command(first, second, OTHER_JKT, 1));

        assertThat(result.outcome()).isEqualTo(RefreshRotationOutcome.WRONG_KEY);
        assertThat(admin.queryForObject("select revocation_reason from refresh_family where family_id=?",
                String.class, first.familyId())).isEqualTo("WRONG_KEY");
    }

    @Test
    void aSecurityVersionAdvanceRevokesTheFamily() {
        var first = generator.newFamily();
        repository.issue(issue(first, JKT));
        admin.update("update human_identity set security_version=2 where identity_id=?", IDENTITY);
        var second = generator.rotate(first.familyId());

        var result = repository.rotate(command(first, second, JKT, 1));

        assertThat(result.outcome()).isEqualTo(RefreshRotationOutcome.SECURITY_VERSION);
        assertThat(admin.queryForObject("select status from refresh_family where family_id=?",
                String.class, first.familyId())).isEqualTo("REVOKED");
    }

    @Test
    void anIdleFamilyExpiresInsteadOfRotating() {
        var first = generator.newFamily();
        repository.issue(issue(first, JKT));
        admin.update("update refresh_token set issued_at=transaction_timestamp()-interval '10 minutes', "
                + "expires_at=transaction_timestamp()-interval '1 minute' where refresh_token_id=?",
                first.tokenId());
        var second = generator.rotate(first.familyId());

        var result = repository.rotate(command(first, second, JKT, 1));

        assertThat(result.outcome()).isEqualTo(RefreshRotationOutcome.EXPIRED);
        assertThat(admin.queryForObject("select status from refresh_family where family_id=?",
                String.class, first.familyId())).isEqualTo("EXPIRED");
    }

    @Test
    void operatorRevocationEndsTheFamilyAndIsIdempotent() {
        var first = generator.newFamily();
        repository.issue(issue(first, JKT));

        assertThat(repository.revokeFamily(first.familyId(), "OPERATOR", CORRELATION)).isTrue();
        assertThat(repository.revokeFamily(first.familyId(), "OPERATOR", CORRELATION)).isFalse();
        var second = generator.rotate(first.familyId());
        assertThat(repository.rotate(command(first, second, JKT, 1)).outcome())
                .isEqualTo(RefreshRotationOutcome.REVOKED);
    }

    @Test
    void issueRejectsAnUnknownIdentity() {
        var first = generator.newFamily();
        assertThatThrownBy(() -> repository.issue(new RefreshFamilyIssue(
                first.familyId(), first.tokenId(), "hid_unknown0000000000000001", APP, CLIENT, RESOURCE,
                AUDIENCE, SCOPE, JKT, 1, first.digest(), ABSOLUTE, IDLE, CORRELATION)))
                .isInstanceOf(RefreshTokenException.class)
                .hasMessageContaining("refresh_issue_rejected");
    }

    private RefreshFamilyIssue issue(RefreshTokenMaterial material, String jkt) {
        return new RefreshFamilyIssue(material.familyId(), material.tokenId(), IDENTITY, APP, CLIENT,
                RESOURCE, AUDIENCE, SCOPE, jkt, 1, material.digest(), ABSOLUTE, IDLE, CORRELATION);
    }

    private RefreshRotationCommand command(
            RefreshTokenMaterial presented, RefreshTokenMaterial next, String jkt, long securityVersion) {
        return new RefreshRotationCommand(presented.digest(), next.digest(), jkt, securityVersion,
                next.tokenId(), CORRELATION, IDLE);
    }
}
