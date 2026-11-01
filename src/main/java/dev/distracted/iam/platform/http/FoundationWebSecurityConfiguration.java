package dev.distracted.iam.platform.http;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.slf4j.MDC;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.ObjectMapper;

@Configuration(proxyBeanMethods = false)
public class FoundationWebSecurityConfiguration {
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    SecurityFilterChain foundationSecurityFilterChain(HttpSecurity http, ObjectMapper objectMapper)
            throws Exception {
        return http.securityMatcher("/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().denyAll())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, exception) -> writeError(
                                response,
                                objectMapper,
                                HttpServletResponse.SC_UNAUTHORIZED,
                                "authentication_required",
                                "Authentication is required"))
                        .accessDeniedHandler((request, response, exception) -> writeError(
                                response,
                                objectMapper,
                                HttpServletResponse.SC_FORBIDDEN,
                                "access_denied",
                                "Access is denied")))
                .build();
    }

    private static void writeError(
            HttpServletResponse response,
            ObjectMapper objectMapper,
            int status,
            String code,
            String message) throws IOException {
        var correlationId = CorrelationIdFilter.acceptedOrGenerated(
                MDC.get(CorrelationIdFilter.MDC_KEY));
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(
                response.getOutputStream(),
                ErrorEnvelope.of(code, message, correlationId));
    }
}

