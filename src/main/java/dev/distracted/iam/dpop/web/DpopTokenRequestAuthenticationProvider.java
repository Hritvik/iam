package dev.distracted.iam.dpop.web;

import dev.distracted.iam.dpop.TokenEndpointOrchestrator;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import java.util.LinkedHashMap;

final class DpopTokenRequestAuthenticationProvider implements AuthenticationProvider {
    private final TokenEndpointOrchestrator orchestrator;
    DpopTokenRequestAuthenticationProvider(TokenEndpointOrchestrator orchestrator) { this.orchestrator = orchestrator; }

    @Override public Authentication authenticate(Authentication authentication) {
        var request = (DpopTokenRequestAuthenticationToken) authentication;
        try {
            var outcome = orchestrator.exchange(request.command());
            if (outcome instanceof dev.distracted.iam.dpop.TokenEndpointOutcome.Challenge challenge) {
                throw new DpopNonceRequiredException(challenge.nonce());
            }
            var success = (dev.distracted.iam.dpop.TokenEndpointOutcome.Success) outcome;
            var now = java.time.Instant.now();
            var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.DPOP, success.accessToken(), now,
                    now.plusSeconds(success.expiresIn()), java.util.Set.copyOf(java.util.List.of(success.scope().split(" "))));
            var clientBuilder = RegisteredClient.withId(request.command().clientId())
                    .clientId(request.command().clientId())
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
            if (request.command().redirectUri() != null) {
                clientBuilder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri(request.command().redirectUri());
            }
            if (request.command().refreshToken() != null) {
                clientBuilder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
            }
            var parameters = new LinkedHashMap<String, Object>();
            parameters.put("correlation_id", request.command().correlationId());
            if (success.refreshToken() != null) {
                parameters.put("refresh_token", success.refreshToken());
            }
            return new OAuth2AccessTokenAuthenticationToken(clientBuilder.build(), request, token, null, parameters);
        } catch (DpopNonceRequiredException exception) {
            throw exception;
        } catch (dev.distracted.iam.dpop.DpopProofRejectedException exception) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_dpop_proof"));
        } catch (IllegalArgumentException exception) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_grant"));
        } catch (IllegalStateException exception) {
            throw new OAuth2AuthenticationException(new OAuth2Error("temporarily_unavailable"));
        }
    }
    @Override public boolean supports(Class<?> authentication) {
        return DpopTokenRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
