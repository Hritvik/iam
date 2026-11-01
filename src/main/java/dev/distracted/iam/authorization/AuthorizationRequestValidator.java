package dev.distracted.iam.authorization;

import dev.distracted.iam.registration.RegistrationManifest;
import java.util.Base64;
import java.util.Arrays;
import java.util.HashSet;

public final class AuthorizationRequestValidator {
    private final String issuer;

    public AuthorizationRequestValidator(String issuer) {
        if (!validIssuer(issuer)) throw new IllegalArgumentException("issuer_required");
        this.issuer = issuer;
    }

    public ValidatedAuthorizationRequest validate(
            AuthorizationRequestCommand request, RegistrationManifest registration) {
        if (request == null || registration == null
                || !registration.client().clientId().equals(request.clientId())
                || !"code".equals(request.responseType())
                || !registration.client().redirectUris().contains(request.redirectUri())
                || !registration.resource().audience().equals(request.resource())
                || !validScope(request.scope(), registration)
                || !validOpaque(request.state())
                || !validOpaque(request.nonce()) || request.codeChallenge() == null
                || !"S256".equals(request.codeChallengeMethod())) {
            throw new AuthorizationRequestRejectedException();
        }
        byte[] challenge;
        try {
            challenge = Base64.getUrlDecoder().decode(request.codeChallenge());
        } catch (IllegalArgumentException exception) {
            throw new AuthorizationRequestRejectedException();
        }
        if (request.codeChallenge().length() != 43 || !request.codeChallenge().matches("[A-Za-z0-9_-]{43}")
                || challenge.length != 32
                || !Base64.getUrlEncoder().withoutPadding().encodeToString(challenge).equals(request.codeChallenge())) {
            throw new AuthorizationRequestRejectedException();
        }
        return new ValidatedAuthorizationRequest(
                issuer, registration, request.redirectUri(), canonicalScope(request.scope()),
                request.state(), request.nonce(), challenge);
    }

    private static boolean validScope(String scope, RegistrationManifest registration) {
        if (scope == null || scope.isBlank()) return false;
        var values = scope.split(" ", -1);
        var distinct = new HashSet<>(Arrays.asList(values));
        return distinct.size() == values.length
                && distinct.stream().allMatch(value -> value.matches("[a-z][a-z0-9:_-]{0,63}"))
                && registration.resource().allowedScopes().containsAll(distinct);
    }

    private static String canonicalScope(String scope) {
        return Arrays.stream(scope.split(" ")).sorted().collect(java.util.stream.Collectors.joining(" "));
    }

    private static boolean validOpaque(String value) {
        return value != null && value.length() >= 16 && value.length() <= 256
                && value.matches("[A-Za-z0-9._~-]+");
    }

    private static boolean validIssuer(String value) {
        try {
            var uri = java.net.URI.create(value);
            return "https".equals(uri.getScheme()) && uri.getHost() != null && uri.getUserInfo() == null
                    && uri.getQuery() == null && uri.getFragment() == null && !value.endsWith("/");
        } catch (RuntimeException exception) {
            return false;
        }
    }
}
