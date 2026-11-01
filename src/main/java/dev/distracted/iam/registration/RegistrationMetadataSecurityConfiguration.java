package dev.distracted.iam.registration;

import org.springframework.context.annotation.Bean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.registration.dutch-development.enabled", havingValue = "true")
public class RegistrationMetadataSecurityConfiguration {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 100)
    SecurityFilterChain registrationMetadataSecurityFilterChain(HttpSecurity http) throws Exception {
        var paths = new OrRequestMatcher(
                PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/.well-known/oauth-authorization-server"),
                PathPatternRequestMatcher.pathPattern(HttpMethod.HEAD, "/.well-known/oauth-authorization-server"),
                PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/.well-known/oauth-protected-resource"),
                PathPatternRequestMatcher.pathPattern(HttpMethod.HEAD, "/.well-known/oauth-protected-resource"));
        return http.securityMatcher(paths).authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll()).build();
    }
}
