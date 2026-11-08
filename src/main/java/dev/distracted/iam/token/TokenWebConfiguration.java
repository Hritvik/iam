package dev.distracted.iam.token;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

@Configuration(proxyBeanMethods = false)
@ConditionalOnExpression("${iam.token.enabled:false} or ${iam.workload.enabled:false}")
public class TokenWebConfiguration {
    @Bean @Order(Ordered.HIGHEST_PRECEDENCE + 90)
    SecurityFilterChain jwksSecurityFilterChain(HttpSecurity http) throws Exception {
        var paths = new OrRequestMatcher(
                PathPatternRequestMatcher.pathPattern(HttpMethod.GET, "/oauth2/jwks"),
                PathPatternRequestMatcher.pathPattern(HttpMethod.HEAD, "/oauth2/jwks"));
        return http.securityMatcher(paths).authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();
    }
}
