package dev.distracted.iam.workload;

import dev.distracted.iam.messaging.snapshot.web.WorkloadAuthenticator;
import dev.distracted.iam.messaging.snapshot.web.WorkloadPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.Optional;

/**
 * Authenticates the internal snapshot surface with the published workload access token profile.
 *
 * <p>Any malformed, expired, wrong-audience, wrong-scope, foreign-app or unregistered-workload token
 * yields an empty principal so the resource answers its non-enumerating 404.
 */
public final class JwtWorkloadAuthenticator implements WorkloadAuthenticator {
    private static final String REQUIRED_AUDIENCE = "https://iam.distracted.invalid/internal/onboarding";
    private static final String REQUIRED_SCOPE = "iam:onboarding:read";

    private final WorkloadAccessTokenVerifier verifier;

    public JwtWorkloadAuthenticator(WorkloadAccessTokenVerifier verifier) {
        this.verifier = verifier;
    }

    @Override
    public Optional<WorkloadPrincipal> authenticate(Object request) {
        if (!(request instanceof HttpServletRequest http)) {
            return Optional.empty();
        }
        var values = Collections.list(http.getHeaders("Authorization"));
        if (values.size() != 1) {
            return Optional.empty();
        }
        var header = values.getFirst();
        if (header == null || !header.startsWith("Bearer ")) {
            return Optional.empty();
        }
        var token = header.substring("Bearer ".length());
        if (token.isBlank() || token.indexOf(' ') >= 0) {
            return Optional.empty();
        }
        try {
            return Optional.of(verifier.verify(token, REQUIRED_AUDIENCE, REQUIRED_SCOPE));
        } catch (RuntimeException exception) {
            return Optional.empty();
        }
    }
}
