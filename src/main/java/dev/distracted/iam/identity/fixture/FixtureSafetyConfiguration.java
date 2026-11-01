package dev.distracted.iam.identity.fixture;

import java.util.Set;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration(proxyBeanMethods = false)
public class FixtureSafetyConfiguration {
    @Bean
    static BeanFactoryPostProcessor deterministicIdentityFixtureSafetyGuard(Environment environment) {
        return factory -> {
            if (!environment.getProperty("iam.fixtures.deterministic-identity.enabled", Boolean.class, false)) return;
            var profiles = Set.of(environment.getActiveProfiles());
            var allowed = Set.of("development", "test");
            if (profiles.isEmpty() || !allowed.containsAll(profiles)) {
                throw new FixtureException("fixture_profile_forbidden");
            }
        };
    }
}
