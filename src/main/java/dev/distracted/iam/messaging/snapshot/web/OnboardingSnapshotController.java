package dev.distracted.iam.messaging.snapshot.web;

import dev.distracted.iam.messaging.snapshot.OnboardingSnapshotQuery;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@RestController
@RequestMapping("/internal/v1/apps")
@dev.distracted.iam.platform.http.PlatformEndpoint
@org.springframework.boot.autoconfigure.condition.ConditionalOnProperty(
        name = "iam.messaging.enabled", havingValue = "true")
public class OnboardingSnapshotController {
    static final String REQUIRED_SCOPE = "iam:onboarding:read";
    static final String REQUIRED_AUDIENCE = "https://iam.distracted.invalid/internal/onboarding";
    private static final java.util.regex.Pattern CORRELATION =
            java.util.regex.Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$");
    private final OnboardingSnapshotQuery query;
    private final WorkloadAuthenticator authenticator;

    public OnboardingSnapshotController(OnboardingSnapshotQuery query, WorkloadAuthenticator authenticator) {
        this.query = java.util.Objects.requireNonNull(query);
        this.authenticator = authenticator;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public OnboardingSnapshotController(OnboardingSnapshotQuery query,
            org.springframework.beans.factory.ObjectProvider<WorkloadAuthenticator> authenticator) {
        this(query, authenticator.getIfAvailable());
    }

    @GetMapping("/{appRegistrationId}/onboarding")
    public ResponseEntity<?> get(@PathVariable String appRegistrationId,
                                 @RequestParam(required = false) String cursor,
                                 @RequestParam(required = false) String limit,
                                 @RequestHeader(value = "X-Correlation-ID", required = false) String correlationId,
                                 HttpServletRequest request) {
        correlationId = validCorrelation(correlationId);
        var principal = authenticator == null ? Optional.<WorkloadPrincipal>empty() : authenticator.authenticate(request);
        if (principal.isEmpty() || !authorized(principal.get(), appRegistrationId)) {
            return notFound(correlationId);
        }
        final int pageSize;
        if (limit == null || limit.isBlank()) {
            pageSize = 100;
        } else {
            try {
                pageSize = Integer.parseInt(limit);
            } catch (NumberFormatException exception) {
                return error(400, "invalid_request", "Request is invalid", correlationId);
            }
            if (pageSize < 1 || pageSize > 200) {
                return error(400, "invalid_request", "Request is invalid", correlationId);
            }
        }
        try {
            var page = query.page(appRegistrationId, cursor, pageSize);
            return ResponseEntity.ok().header("X-Correlation-ID", correlationId)
                    .header(org.springframework.http.HttpHeaders.CACHE_CONTROL, "no-store")
                    .header(org.springframework.http.HttpHeaders.PRAGMA, "no-cache")
                    .body(Map.of("data", page));
        } catch (IllegalArgumentException exception) {
            return error(400, "invalid_request", "Request is invalid", correlationId);
        } catch (RuntimeException exception) {
            return error(500, "internal_error", "Request could not be completed", correlationId);
        }
    }

    private static boolean authorized(WorkloadPrincipal principal, String appRegistrationId) {
        return appRegistrationId != null && appRegistrationId.equals(principal.appRegistrationId())
                && principal.scopes().contains(REQUIRED_SCOPE)
                && REQUIRED_AUDIENCE.equals(principal.audience());
    }

    private static String validCorrelation(String correlationId) {
        return correlationId != null && CORRELATION.matcher(correlationId).matches() ? correlationId
                : "cor_" + java.util.UUID.randomUUID().toString().replace("-", "");
    }

    private static ResponseEntity<?> notFound(String correlationId) {
        return error(404, "not_found", "Resource was not found", correlationId);
    }

    private static ResponseEntity<?> error(int status, String code, String message, String correlationId) {
        return ResponseEntity.status(status).header("X-Correlation-ID", correlationId)
                .header(org.springframework.http.HttpHeaders.CACHE_CONTROL, "no-store")
                .header(org.springframework.http.HttpHeaders.PRAGMA, "no-cache").body(Map.of("error",
                Map.of("code", code, "message", message, "correlationId", correlationId, "details",
                        java.util.List.of())));
    }
}
