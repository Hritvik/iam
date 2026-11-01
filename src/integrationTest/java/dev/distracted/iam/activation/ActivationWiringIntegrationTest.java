package dev.distracted.iam.activation;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.bootstrap.IamApplication;
import dev.distracted.iam.messaging.OnboardingIntentWriter;
import java.sql.DriverManager;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

@SpringBootTest(classes = IamApplication.class, properties = {
        "iam.activation.enabled=true",
        "iam.app-subject.enabled=true",
        "iam.messaging.enabled=true",
        "iam.registration.dutch-development.enabled=true",
        "iam.environment=development",
        "iam.issuer=https://iam.distracted.invalid",
        "spring.flyway.enabled=false",
        "spring.profiles.active=test"
})
class ActivationWiringIntegrationTest {
    private static final String RUNTIME_PASSWORD = UUID.randomUUID().toString();
    private static final String RECONCILER_PASSWORD = UUID.randomUUID().toString();
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
            statement.execute("create role iam_runtime_login login password '" + RUNTIME_PASSWORD + "' in role iam_runtime");
            statement.execute("create role iam_reconciler_login login password '" + RECONCILER_PASSWORD
                    + "' in role iam_registration_reconciler");
            statement.execute("grant iam_migrator to " + POSTGRES.getUsername());
        } catch (Exception exception) {
            throw new ExceptionInInitializerError(exception);
        }
        Flyway.configure().dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load().migrate();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", () -> "iam_runtime_login");
        properties.add("spring.datasource.password", () -> RUNTIME_PASSWORD);
        properties.add("iam.registration.reconciler.jdbc-url", POSTGRES::getJdbcUrl);
        properties.add("iam.registration.reconciler.username", () -> "iam_reconciler_login");
        properties.add("iam.registration.reconciler.password", () -> RECONCILER_PASSWORD);
    }

    @Autowired FirstActivationTransaction firstActivationTransaction;
    @Autowired AppActivationService appActivationService;
    @Autowired OnboardingIntentWriter onboardingIntentWriter;

    @Test void theShippingActivationGraphIsWiredAndLoads() {
        assertThat(firstActivationTransaction).isNotNull();
        assertThat(appActivationService).isNotNull();
        assertThat(onboardingIntentWriter).isNotNull();
    }
}
