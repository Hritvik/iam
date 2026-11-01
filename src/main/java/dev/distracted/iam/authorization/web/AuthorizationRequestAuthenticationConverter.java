package dev.distracted.iam.authorization.web;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;

final class AuthorizationRequestAuthenticationConverter implements AuthenticationConverter {
    private static final Set<String> PARAMETERS = Set.of("client_id", "response_type", "redirect_uri", "scope",
            "resource", "state", "nonce", "code_challenge", "code_challenge_method");

    private final int maxRequestCharacters;

    AuthorizationRequestAuthenticationConverter(int maxRequestCharacters) {
        this.maxRequestCharacters = maxRequestCharacters;
    }

    @Override public Authentication convert(HttpServletRequest request) {
        if (!"GET".equals(request.getMethod()) || requestCharacters(request) > maxRequestCharacters || !closed(request)) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request"));
        }
        var additional = new HashMap<String, Object>();
        for (var name : Set.of("resource", "nonce", "code_challenge", "code_challenge_method", "response_type")) {
            additional.put(name, request.getParameter(name));
        }
        var scopeTokens = request.getParameter("scope").split(" ", -1);
        var scopes = new java.util.HashSet<>(java.util.Arrays.asList(scopeTokens));
        if (scopes.size() != scopeTokens.length) {
            throw new OAuth2AuthenticationException(new OAuth2Error("invalid_request"));
        }
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(request.getRequestURL().toString(),
                request.getParameter("client_id"), SecurityContextHolder.getContext().getAuthentication(),
                request.getParameter("redirect_uri"), request.getParameter("state"),
                Set.copyOf(scopes), Map.copyOf(additional));
    }

    private static boolean closed(HttpServletRequest request) {
        if (!request.getParameterMap().keySet().equals(PARAMETERS)) return false;
        return request.getParameterMap().values().stream().allMatch(values -> values.length == 1 && !values[0].isBlank());
    }

    private static long requestCharacters(HttpServletRequest request) {
        return request.getParameterMap().entrySet().stream().mapToLong(entry -> entry.getKey().length()
                + java.util.Arrays.stream(entry.getValue()).mapToInt(String::length).sum()).sum();
    }
}
