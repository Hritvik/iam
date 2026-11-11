package dev.distracted.iam.registration;

import dev.distracted.iam.registration.adapter.jdbc.JdbcRegistrationRegistry;
import java.util.Arrays;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.registration.dutch-development.enabled", havingValue = "true")
@EnableConfigurationProperties(ReconcilerDataSourceProperties.class)
public class RegistrationApplicationConfiguration {
    private static final Logger LOGGER = LoggerFactory.getLogger(RegistrationApplicationConfiguration.class);

    @Bean PinnedRegistrationSource pinnedRegistrationSource() { return new ClasspathPinnedRegistrationSource(); }
    @Bean RegistrationManifestValidator registrationManifestValidator() { return new StrictRegistrationManifestValidator(); }
    @Bean RegistrationRegistry registrationRegistry(@Qualifier("jdbcTemplate") JdbcTemplate jdbc) {
        return new JdbcRegistrationRegistry(jdbc);
    }
    @Bean RegistrationReconcilerConnection registrationReconcilerConnection(
            ReconcilerDataSourceProperties properties,
            @Value("${spring.datasource.username:}") String runtimeUsername,
            @Value("${spring.datasource.password:}") String runtimePassword) {
        properties.verifyDistinct(runtimeUsername, runtimePassword);
        return new RegistrationReconcilerConnection(new JdbcTemplate(new DriverManagerDataSource(
                properties.jdbcUrl(), properties.username(), properties.password())));
    }

    @Bean @Qualifier("registrationReconciliationRegistry")
    RegistrationRegistry registrationReconciliationRegistry(RegistrationReconcilerConnection connection) {
        return new JdbcRegistrationRegistry(connection.jdbc());
    }

    @Bean RegistrationMetadata registrationMetadata(@Qualifier("registrationRegistry") RegistrationRegistry registry,
                                                     @Value("${iam.issuer}") String issuer,
                                                     @Value("${iam.refresh.enabled:false}") boolean refreshEnabled) {
        return new RegistryRegistrationMetadata(registry, issuer, refreshEnabled);
    }

    @Bean ApplicationRunner pinnedRegistrationReconciler(
            Environment environment,
            @Value("${iam.environment:}") String configuredEnvironment,
            @Qualifier("jdbcTemplate") JdbcTemplate runtimeJdbc,
            RegistrationReconcilerConnection reconcilerConnection,
            PinnedRegistrationSource source,
            RegistrationManifestValidator validator,
            @Qualifier("registrationReconciliationRegistry") RegistrationRegistry registry) {
        return arguments -> {
            var profiles = Set.copyOf(Arrays.asList(environment.getActiveProfiles()));
            if (profiles.isEmpty() || !Set.of("development", "test").containsAll(profiles)) {
                throw new RegistrationException("registration_profile_forbidden");
            }
            var validated = validator.validate(source.load());
            reconcilerConnection.verifyAuthority();
            var runtimeAuthority = runtimeJdbc.queryForObject(
                    "select pg_has_role(current_user,'iam_runtime','member') "
                            + "and not pg_has_role(current_user,'iam_registration_reconciler','member')", Boolean.class);
            if (!Boolean.TRUE.equals(runtimeAuthority)) {
                throw new RegistrationException("registration_runtime_authority_invalid");
            }
            if (!validated.manifest().environment().equals(configuredEnvironment)) {
                throw new RegistrationException("registration_environment_mismatch");
            }
            var result = registry.reconcile(validated);
            if (result == ReconciliationResult.DRIFT) throw new RegistrationException("registration_drift");
            LOGGER.info("Pinned registration {}; appRegistrationId={}; manifestVersion={}; fingerprint={}",
                    result.name().toLowerCase(), validated.manifest().appRegistrationId(),
                    validated.manifest().manifestVersion(), validated.fingerprint().substring(0, 12));
        };
    }
}
