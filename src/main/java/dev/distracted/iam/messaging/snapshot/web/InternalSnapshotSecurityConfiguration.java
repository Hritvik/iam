package dev.distracted.iam.messaging.snapshot.web;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * The internal snapshot surface authenticates inside the controller through the workload binding;
 * without a resolver it fails closed with 404. This chain only avoids the foundation deny-all.
 */
@Configuration(proxyBeanMethods = false)
public class InternalSnapshotSecurityConfiguration {
    @Bean @Order(Ordered.HIGHEST_PRECEDENCE + 30)
    SecurityFilterChain internalOnboardingSnapshotFilterChain(HttpSecurity http) throws Exception {
        return http.securityMatcher("/internal/v1/apps/*/onboarding")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .requestCache(cache -> cache.disable())
                .build();
    }
}
