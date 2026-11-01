package dev.distracted.iam.authorization.web;

import dev.distracted.iam.authorization.AuthorizationRequestService;
import dev.distracted.iam.authorization.AuthorizationEndpointLimitsProperties;
import dev.distracted.iam.platform.http.CorrelationIdFilter;
import dev.distracted.iam.platform.http.ErrorEnvelope;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.ObjectMapper;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.authorization.enabled", havingValue = "true")
public class AuthorizationEndpointSecurityConfiguration {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityFilterChain authorizationEndpointSecurityFilterChain(HttpSecurity http, ObjectMapper objectMapper,
            AuthorizationRequestService service, AuthorizationEndpointLimitsProperties limits)
            throws Exception {
        var endpoint = new OAuth2AuthorizationEndpointFilter(
                new ProviderManager(new AuthorizationRequestAuthenticationProvider(service)), "/oauth2/authorize");
        endpoint.setAuthenticationConverter(new AuthorizationRequestAuthenticationConverter(limits.maxRequestCharacters()));
        endpoint.setAuthenticationSuccessHandler((request, response, authentication) -> {
            var result = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
            var location = result.getRedirectUri() + "?code=" + encode(result.getAuthorizationCode().getTokenValue())
                    + "&state=" + encode(result.getState());
            response.setStatus(HttpServletResponse.SC_FOUND);
            response.setHeader("Location", location);
            response.setHeader("Cache-Control", "no-store");
        });
        endpoint.setAuthenticationFailureHandler((request, response, exception) -> writeError(response, objectMapper,
                HttpServletResponse.SC_BAD_REQUEST, "invalid_request", "Authorization request is invalid"));
        return http.securityMatcher("/oauth2/authorize")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .requestCache(cache -> cache.disable())
                .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint((request, response, exception) ->
                        writeError(response, objectMapper, HttpServletResponse.SC_UNAUTHORIZED,
                                "authentication_required", "Authentication is required")))
                .addFilterBefore(new AuthorizationRateLimitFilter(limits, objectMapper), AuthorizationFilter.class)
                .addFilterAfter(endpoint, AuthorizationFilter.class).build();
    }

    private static void writeError(HttpServletResponse response, ObjectMapper objectMapper, int status,
            String code, String message) throws java.io.IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(), ErrorEnvelope.of(
                code, message, MDC.get(CorrelationIdFilter.MDC_KEY)));
    }
    private static String encode(String value) {
        return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
    }
}
