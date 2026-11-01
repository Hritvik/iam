package dev.distracted.iam.messaging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.activation.ActivationState;
import dev.distracted.iam.activation.AppActivation;
import dev.distracted.iam.messaging.adapter.jdbc.JdbcOnboardingIntentWriter;
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
class OnboardingIntentPersistenceIntegrationTest {
    @Container static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18-alpine");
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final String APP = "dutch-development";
    private static final String IDENTITY = "hid_0123456789012345678901";
    private static final String SUBJECT = "aps_0123456789012345678901ab";
    private static final String ACTIVATION = "act_012345678901234567";
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
        owner.execute("truncate app_activation,app_subject,human_identity,audit_fact,outbox_delivery,outbox_event,"
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
    }

    @Test
    void appendsOneEventAndDeliveryPerActivationVersionAndRetriesAreIdempotent() {
        var factory = new OnboardingEventFactory();
        var payload = factory.create(APP, SUBJECT, ACTIVATION, 2, 1, "FIRST_ACTIVATION");
        var writer = new JdbcOnboardingIntentWriter(runtime);

        var created = writer.append(command("evt_012345678901234567", payload));
        assertThat(created.created()).isTrue();
        var existing = writer.append(command("evt_112345678901234567", payload));
        assertThat(existing.created()).isFalse();
        assertThat(existing.eventId()).isEqualTo(created.eventId());

        assertThat(owner.queryForObject("select count(*) from outbox_event", Integer.class)).isEqualTo(1);
        assertThat(owner.queryForObject("select count(*) from outbox_delivery", Integer.class)).isEqualTo(1);
        var stored = new tools.jackson.databind.ObjectMapper().readValue(
                owner.queryForObject("select payload::text from outbox_event", String.class), java.util.Map.class);
        var expected = new tools.jackson.databind.ObjectMapper().readValue(payload.json(), java.util.Map.class);
        assertThat(stored).isEqualTo(expected);
        assertThat(owner.queryForObject("select destination_app_registration_id from outbox_event", String.class))
                .isEqualTo(APP);
        assertThat(owner.queryForObject("select aggregate_type from outbox_event", String.class))
                .isEqualTo("APP_ONBOARDING");
    }

    @Test void rejectsAnActivationThatDoesNotMatchTheIntent() {
        var factory = new OnboardingEventFactory();
        var payload = factory.create(APP, SUBJECT, ACTIVATION, 2, 1, "FIRST_ACTIVATION");
        var writer = new JdbcOnboardingIntentWriter(runtime);

        assertThatThrownBy(() -> writer.append(new OnboardingIntentCommand("evt_212345678901234567", ACTIVATION,
                APP, SUBJECT, 7, 1, "FIRST_ACTIVATION", "development", "cor_0123456789012345",
                payload.json(), payload.fingerprint()))).isInstanceOf(OnboardingIntentException.class);
    }

    @Test void rejectsAForgedPayloadEnvironmentOrDivergentDuplicate() {
        var factory = new OnboardingEventFactory();
        var payload = factory.create(APP, SUBJECT, ACTIVATION, 2, 1, "FIRST_ACTIVATION");
        var writer = new JdbcOnboardingIntentWriter(runtime);

        assertThatThrownBy(() -> writer.append(new OnboardingIntentCommand("evt_312345678901234567", ACTIVATION,
                APP, SUBJECT, 2, 1, "FIRST_ACTIVATION", "production", "cor_0123456789012345",
                payload.json(), payload.fingerprint()))).isInstanceOf(OnboardingIntentException.class);

        var forged = payload.json().replace(SUBJECT, "aps_FORGEDFORGEDFORGEDFORGED");
        assertThatThrownBy(() -> writer.append(new OnboardingIntentCommand("evt_412345678901234567", ACTIVATION,
                APP, SUBJECT, 2, 1, "FIRST_ACTIVATION", "development", "cor_0123456789012345",
                forged, payload.fingerprint()))).isInstanceOf(OnboardingIntentException.class);

        writer.append(command("evt_512345678901234567", payload));
        assertThatThrownBy(() -> writer.append(new OnboardingIntentCommand("evt_612345678901234567", ACTIVATION,
                APP, SUBJECT, 2, 1, "FIRST_ACTIVATION", "development", "cor_0123456789012345",
                payload.json(), "a".repeat(64)))).isInstanceOf(OnboardingIntentException.class);
        assertThat(owner.queryForObject("select count(*) from outbox_event", Integer.class)).isEqualTo(1);
    }

    @Test void aFingerprintThatDoesNotMatchTheCanonicalPayloadIsRejected() {
        var factory = new OnboardingEventFactory();
        var payload = factory.create(APP, SUBJECT, ACTIVATION, 2, 1, "FIRST_ACTIVATION");
        var writer = new JdbcOnboardingIntentWriter(runtime);

        assertThatThrownBy(() -> writer.append(new OnboardingIntentCommand("evt_712345678901234567", ACTIVATION,
                APP, SUBJECT, 2, 1, "FIRST_ACTIVATION", "development", "cor_0123456789012345",
                payload.json(), "b".repeat(64)))).isInstanceOf(OnboardingIntentException.class);
        assertThat(owner.queryForObject("select count(*) from outbox_event", Integer.class)).isZero();
    }

    @Test void intentFunctionIsRuntimeExecutableAndNotPublic() {
        assertThat(owner.queryForObject("select has_function_privilege('iam_runtime',?,'EXECUTE')", Boolean.class,
                "public.append_onboarding_intent(text,text,text,text,bigint,bigint,text,text,text,text,text)")).isTrue();
        assertThat(owner.queryForObject("select has_function_privilege('public',?,'EXECUTE')", Boolean.class,
                "public.append_onboarding_intent(text,text,text,text,bigint,bigint,text,text,text,text,text)")).isFalse();
    }

    private static AppActivation activation() {
        return new AppActivation(ACTIVATION, ActivationState.ACTIVE, 2, 1, "FIRST_ACTIVATION");
    }

    private static OnboardingIntentCommand command(String eventId, OnboardingPayload payload) {
        return new OnboardingIntentCommand(eventId, ACTIVATION, APP, SUBJECT, 2, 1, "FIRST_ACTIVATION",
                "development", "cor_0123456789012345", payload.json(), payload.fingerprint());
    }
}
