package dev.distracted.iam.dpop.web;

import dev.distracted.iam.dpop.TokenEndpointOrchestrator;
import jakarta.servlet.http.HttpServletResponse;
import java.util.LinkedHashMap;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.ObjectMapper;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.dpop.enabled", havingValue = "true")
public class DpopTokenEndpointSecurityConfiguration {
    @Bean @Order(Ordered.HIGHEST_PRECEDENCE + 20)
    SecurityFilterChain dpopTokenEndpointSecurityFilterChain(HttpSecurity http, ObjectMapper mapper,
            TokenEndpointOrchestrator orchestrator) throws Exception {
        var filter = new OAuth2TokenEndpointFilter(
                new ProviderManager(new DpopTokenRequestAuthenticationProvider(orchestrator)), "/oauth2/token");
        filter.setAuthenticationConverter(new DpopTokenRequestAuthenticationConverter(8192, 4096));
        filter.setAuthenticationSuccessHandler((request, response, authentication) -> {
            var result = (org.springframework.security.oauth2.server.authorization.authentication
                    .OAuth2AccessTokenAuthenticationToken) authentication;
            var correlation = (String) result.getAdditionalParameters().get("correlation_id");
            common(response, correlation);
            response.setStatus(HttpServletResponse.SC_OK);
            var body = new LinkedHashMap<String, Object>();
            body.put("access_token", result.getAccessToken().getTokenValue());
            body.put("token_type", "DPoP");
            body.put("expires_in", java.time.Duration.between(result.getAccessToken().getIssuedAt(),
                    result.getAccessToken().getExpiresAt()).toSeconds());
            body.put("scope", String.join(" ", result.getAccessToken().getScopes().stream().sorted().toList()));
            var rotated = (String) result.getAdditionalParameters().get("refresh_token");
            if (rotated != null) {
                body.put("refresh_token", rotated);
            }
            mapper.writeValue(response.getOutputStream(), body);
        });
        filter.setAuthenticationFailureHandler((request, response, exception) -> {
            var code = exception instanceof org.springframework.security.oauth2.core.OAuth2AuthenticationException oauth
                    ? oauth.getError().getErrorCode() : "invalid_request";
            if (!DESCRIPTIONS.containsKey(code)) code = "invalid_request";
            if (exception instanceof DpopNonceRequiredException challenge) {
                response.setHeader("DPoP-Nonce", challenge.nonce());
            }
            var correlation = correlationId();
            common(response, correlation);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            var body = new LinkedHashMap<String, Object>();
            body.put("error", code);
            body.put("error_description", DESCRIPTIONS.get(code));
            body.put("correlation_id", correlation);
            mapper.writeValue(response.getOutputStream(), body);
        });
        return http.securityMatcher("/oauth2/token")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
                .requestCache(cache -> cache.disable())
                .addFilterAfter(filter, AuthorizationFilter.class).build();
    }

    private static final java.util.Map<String, String> DESCRIPTIONS = java.util.Map.of(
            "invalid_request", "Request is invalid",
            "invalid_client", "Client presentation is invalid",
            "invalid_grant", "Authorization grant is invalid",
            "invalid_dpop_proof", "DPoP proof is invalid",
            "use_dpop_nonce", "A fresh DPoP nonce is required",
            "temporarily_unavailable", "Service is temporarily unavailable");

    private static void common(HttpServletResponse response, String correlation) {
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        response.setHeader("X-Content-Type-Options", "nosniff");
        if (correlation != null) response.setHeader("X-Correlation-ID", correlation);
    }

    private static final java.util.regex.Pattern CORRELATION =
            java.util.regex.Pattern.compile("^cor_[A-Za-z0-9_-]{16,128}$");

    private static String correlationId() {
        var value = org.slf4j.MDC.get(dev.distracted.iam.platform.http.CorrelationIdFilter.MDC_KEY);
        var candidate = value == null || value.isBlank() ? "cor_" + java.util.UUID.randomUUID().toString().replace("-", "")
                : value.startsWith("cor_") ? value : "cor_" + value;
        return CORRELATION.matcher(candidate).matches() ? candidate
                : "cor_" + java.util.UUID.randomUUID().toString().replace("-", "");
    }
}
