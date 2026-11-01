package dev.distracted.iam.authorization.web;

import dev.distracted.iam.authorization.AuthenticatedIdentity;
import dev.distracted.iam.authorization.AuthorizationRequestCommand;
import dev.distracted.iam.authorization.AuthorizationRequestRejectedException;
import dev.distracted.iam.authorization.AuthorizationRequestService;
import dev.distracted.iam.authorization.IamIdentityPrincipal;
import dev.distracted.iam.platform.http.CorrelationIdFilter;
import java.util.Map;
import org.slf4j.MDC;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

final class AuthorizationRequestAuthenticationProvider implements AuthenticationProvider {
    private final AuthorizationRequestService service;

    AuthorizationRequestAuthenticationProvider(AuthorizationRequestService service) { this.service = service; }

    @Override public Authentication authenticate(Authentication authentication) {
        var request = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        if (!(request.getPrincipal() instanceof Authentication principal)
                || !(principal.getPrincipal() instanceof IamIdentityPrincipal identity)) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request"));
        }
        var additional = request.getAdditionalParameters();
        dev.distracted.iam.authorization.AuthorizationRedirectResult result;
        try {
            result = service.authorize(new AuthenticatedIdentity(identity.identity()), new AuthorizationRequestCommand(
                    request.getClientId(), text(additional, "response_type"), request.getRedirectUri(),
                    String.join(" ", request.getScopes()), text(additional, "resource"), request.getState(),
                    text(additional, "nonce"), text(additional, "code_challenge"),
                    text(additional, "code_challenge_method")), correlationId());
        } catch (AuthorizationRequestRejectedException exception) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request"));
        } catch (IllegalStateException exception) {
            throw new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable"));
        }
        var code = new OAuth2AuthorizationCode(result.code(), result.issuedAt(), result.expiresAt());
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getAuthorizationUri(),
                request.getClientId(), principal, code, result.redirectUri(), result.state(), request.getScopes());
    }

    @Override public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }
    private static String text(Map<String, Object> values, String key) { return (String) values.get(key); }
    private static String correlationId() {
        var value = MDC.get(CorrelationIdFilter.MDC_KEY);
        if (value == null) throw new IllegalStateException("correlation_id_unavailable");
        return value.startsWith("cor_") ? value : "cor_" + value;
    }
}
