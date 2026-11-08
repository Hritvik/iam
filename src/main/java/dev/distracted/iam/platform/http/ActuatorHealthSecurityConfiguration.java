package dev.distracted.iam.platform.http;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

/**
 * Opens only the actuator health surface. Every other actuator endpoint stays behind the
 * foundation deny-all chain.
 */
@Configuration(proxyBeanMethods = false)
public class ActuatorHealthSecurityConfiguration {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 50)
    SecurityFilterChain actuatorHealthSecurityFilterChain(HttpSecurity http) throws Exception {
        var paths = new OrRequestMatcher(
                PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/actuator/health"),
                PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/actuator/health/**"));
        return http.securityMatcher(paths)
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .build();
    }
}
