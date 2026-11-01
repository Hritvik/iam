package dev.distracted.iam.dpop.web;

import dev.distracted.iam.dpop.TokenEndpointCommand;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationConverter;

final class DpopTokenRequestAuthenticationConverter implements AuthenticationConverter {
    private static final Set<String> PARAMETERS = Set.of("grant_type", "code", "redirect_uri", "client_id", "code_verifier");
    private final int maximumRawCharacters;
    private final int maximumDecodedCharacters;

    DpopTokenRequestAuthenticationConverter(int maximumRawCharacters, int maximumDecodedCharacters) {
        if (maximumRawCharacters < 1024 || maximumRawCharacters > 16384 || maximumDecodedCharacters < 512
                || maximumDecodedCharacters > maximumRawCharacters) throw new IllegalArgumentException("token limits invalid");
        this.maximumRawCharacters = maximumRawCharacters;
        this.maximumDecodedCharacters = maximumDecodedCharacters;
    }

    @Override public DpopTokenRequestAuthenticationToken convert(HttpServletRequest request) {
        if (!"POST".equals(request.getMethod()) || request.getQueryString() != null
                || request.getContentType() == null
                || !request.getContentType().startsWith("application/x-www-form-urlencoded")
                || request.getContentLengthLong() > maximumRawCharacters
                || request.getHeader("Authorization") != null
                || !PARAMETERS.equals(request.getParameterMap().keySet())) throw invalid("invalid_request");
        var decoded = request.getParameterMap().entrySet().stream()
                .mapToInt(entry -> entry.getKey().length() + java.util.Arrays.stream(entry.getValue())
                        .mapToInt(String::length).sum()).sum();
        if (decoded > maximumDecodedCharacters) throw invalid("invalid_request");
        var proofs = java.util.Collections.list(request.getHeaders("DPoP"));
        if (proofs.size() != 1 || proofs.getFirst().isBlank() || proofs.getFirst().length() > 16384) {
            throw invalid("invalid_dpop_proof");
        }
        var grant = one(request, "grant_type");
        if (!"authorization_code".equals(grant)) throw invalid("invalid_request");
        var correlation = correlationId();
        return new DpopTokenRequestAuthenticationToken(new TokenEndpointCommand(grant, one(request, "code"),
                one(request, "redirect_uri"), one(request, "client_id"), one(request, "code_verifier"),
                proofs.getFirst(), correlation, trustedNetworkContext(request)));
    }

    private static String one(HttpServletRequest request, String name) {
        var values = request.getParameterValues(name);
        if (values == null || values.length != 1 || values[0] == null || values[0].isBlank()) throw invalid("invalid_request");
        return values[0];
    }

    private static OAuth2AuthenticationException invalid(String code) {
        return new OAuth2AuthenticationException(new OAuth2Error(code));
    }

    private static String trustedNetworkContext(HttpServletRequest request) {
        var value = request.getRemoteAddr();
        if (value == null || value.isBlank() || value.length() > 64
                || !value.matches("^[0-9A-Fa-f:.]{2,64}$")) return "unknown-network";
        return value.toLowerCase(java.util.Locale.ROOT);
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
