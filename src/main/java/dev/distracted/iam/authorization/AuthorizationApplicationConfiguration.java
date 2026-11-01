package dev.distracted.iam.authorization;

import dev.distracted.iam.authorization.adapter.jdbc.JdbcAuthorizationCodeConsumptionRepository;
import dev.distracted.iam.authorization.adapter.jdbc.JdbcAuthorizationCodeRepository;
import dev.distracted.iam.registration.RegistrationRegistry;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.authorization.enabled", havingValue = "true")
@org.springframework.boot.context.properties.EnableConfigurationProperties(AuthorizationEndpointLimitsProperties.class)
public class AuthorizationApplicationConfiguration {
    @Bean AuthorizationRequestValidator authorizationRequestValidator(@Value("${iam.issuer}") String issuer) {
        return new AuthorizationRequestValidator(issuer);
    }
    @Bean AuthorizationCodeRepository authorizationCodeRepository(JdbcTemplate jdbc) {
        return new JdbcAuthorizationCodeRepository(jdbc);
    }
    @Bean AuthorizationCodeConsumptionRepository authorizationCodeConsumptionRepository(JdbcTemplate jdbc) {
        return new JdbcAuthorizationCodeConsumptionRepository(jdbc);
    }
    @Bean RegisteredClientRepository registeredClientRepository(
            @Qualifier("registrationRegistry") RegistrationRegistry registry) {
        return new SasRegisteredClientRepository(registry);
    }
    @Bean AuthorizationRequestService authorizationRequestService(
            @Qualifier("registrationRegistry") RegistrationRegistry registry,
            AuthorizationRequestValidator validator, AuthorizationCodeRepository repository,
            AuthorizationCodeDigestCapability digestCapability,
            @Value("${iam.authorization.code-lifetime:120s}") Duration lifetime) {
        return new AuthorizationRequestService(registry, validator, repository, digestCapability,
                new SecureAuthorizationCodeMaterialGenerator(), lifetime);
    }
    @Bean AuthorizationCodeRedemption authorizationCodeRedemption(AuthorizationCodeConsumptionRepository repository,
            AuthorizationCodeDigestCapability digestCapability, @Value("${iam.issuer}") String issuer) {
        return new AuthorizationCodeRedemption(repository, digestCapability, issuer);
    }
}
