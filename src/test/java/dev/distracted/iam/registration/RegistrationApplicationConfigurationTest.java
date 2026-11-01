package dev.distracted.iam.registration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RegistrationApplicationConfigurationTest {
    private final RegistrationApplicationConfiguration configuration = new RegistrationApplicationConfiguration();
    private final PinnedRegistrationSource source = new ClasspathPinnedRegistrationSource();
    private final RegistrationManifestValidator validator = new StrictRegistrationManifestValidator();

    @Test
    void developmentAndTestProfilesReconcileButDriftFails() throws Exception {
        var development = new MockEnvironment().withProperty("spring.profiles.active", "development");
        development.setActiveProfiles("development");
        var created = registry(ReconciliationResult.CREATED);
        runner(development, "development", created).run(null);
        assertThat(created.findByAppId("dutch-development")).isPresent();

        var test = new MockEnvironment();
        test.setActiveProfiles("test");
        runner(test, "development", registry(ReconciliationResult.UNCHANGED)).run(null);
        assertThatThrownBy(() -> runner(test, "development", registry(ReconciliationResult.DRIFT)).run(null))
                .hasMessage("registration_drift");
    }

    @Test
    void forbiddenProfileAndEnvironmentMismatchFailClosed() {
        var empty = new MockEnvironment();
        assertThatThrownBy(() -> runner(empty, "development", registry(ReconciliationResult.CREATED)).run(null))
                .hasMessage("registration_profile_forbidden");
        var production = new MockEnvironment();
        production.setActiveProfiles("production");
        assertThatThrownBy(() -> runner(production, "development", registry(ReconciliationResult.CREATED)).run(null))
                .hasMessage("registration_profile_forbidden");
        var test = new MockEnvironment();
        test.setActiveProfiles("test");
        assertThatThrownBy(() -> runner(test, "test", registry(ReconciliationResult.CREATED)).run(null))
                .hasMessage("registration_environment_mismatch");
    }

    @Test
    void beanFactoriesUseTheStrictImplementations() {
        assertThat(configuration.pinnedRegistrationSource()).isInstanceOf(ClasspathPinnedRegistrationSource.class);
        assertThat(configuration.registrationManifestValidator()).isInstanceOf(StrictRegistrationManifestValidator.class);
        assertThat(configuration.registrationMetadata(registry(ReconciliationResult.CREATED),
                "https://iam.distracted.invalid")).isInstanceOf(RegistryRegistrationMetadata.class);
    }

    @Test
    void reconcilerConfigurationRejectsMissingOrSharedAuthority() {
        assertThatThrownBy(() -> new ReconcilerDataSourceProperties(null, "user", "value-placeholder"))
                .hasMessage("registration_reconciler_configuration_missing");
        var properties = new ReconcilerDataSourceProperties(
                "jdbc:postgresql://db/iam", "reconciler", "reconciler-placeholder");
        assertThatThrownBy(() -> properties.verifyDistinct("reconciler", "runtime-placeholder"))
                .hasMessage("registration_reconciler_authority_shared");
        assertThatThrownBy(() -> properties.verifyDistinct("runtime", "reconciler-placeholder"))
                .hasMessage("registration_reconciler_authority_shared");
    }

    @Test
    void authorityChecksFailClosedForMiswiredConnections() {
        var jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(anyString(), eq(Boolean.class))).thenReturn(false);
        assertThatThrownBy(() -> new RegistrationReconcilerConnection(jdbc).verifyAuthority())
                .hasMessage("registration_reconciler_authority_invalid");
    }

    private RegistrationRegistry registry(ReconciliationResult result) {
        return new RegistrationRegistry() {
            private RegistrationManifest stored;
            public ReconciliationResult reconcile(ValidatedRegistration value) {
                stored = value.manifest();
                return result;
            }
            public Optional<RegistrationManifest> findByAppId(String id) { return Optional.ofNullable(stored); }
            public Optional<RegistrationManifest> findByClientId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByResourceId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByAudience(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findSoleRegistration() { return Optional.ofNullable(stored); }
        };
    }

    private ApplicationRunner runner(MockEnvironment environment, String configuredEnvironment,
                                     RegistrationRegistry registry) {
        var jdbc = mock(JdbcTemplate.class);
        when(jdbc.queryForObject(anyString(), eq(Boolean.class))).thenReturn(true);
        return configuration.pinnedRegistrationReconciler(environment, configuredEnvironment, jdbc,
                new RegistrationReconcilerConnection(jdbc), source, validator, registry);
    }
}
