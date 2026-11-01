package dev.distracted.iam.authorization.web;

import dev.distracted.iam.authorization.AuthorizationEndpointLimitsProperties;
import dev.distracted.iam.platform.http.CorrelationIdFilter;
import dev.distracted.iam.platform.http.ErrorEnvelope;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

final class AuthorizationRateLimitFilter extends OncePerRequestFilter {
    private static final int MAX_KEYS = 10_000;
    private final AuthorizationEndpointLimitsProperties limits;
    private final ObjectMapper objectMapper;
    private final Clock clock;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    AuthorizationRateLimitFilter(AuthorizationEndpointLimitsProperties limits, ObjectMapper objectMapper) {
        this(limits, objectMapper, Clock.systemUTC());
    }

    AuthorizationRateLimitFilter(AuthorizationEndpointLimitsProperties limits, ObjectMapper objectMapper, Clock clock) {
        this.limits = java.util.Objects.requireNonNull(limits);
        this.objectMapper = java.util.Objects.requireNonNull(objectMapper);
        this.clock = java.util.Objects.requireNonNull(clock);
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        var now = clock.instant();
        discardExpired(now);
        var key = request.getRemoteAddr() + "\u0000" + request.getParameter("client_id");
        if (windows.size() >= MAX_KEYS && !windows.containsKey(key)) {
            reject(response);
            return;
        }
        var updated = windows.compute(key, (ignored, existing) -> next(existing, now));
        if (updated.count() > limits.requestsPerWindow()) {
            reject(response);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private Window next(Window existing, Instant now) {
        if (existing == null || !now.isBefore(existing.startedAt().plus(limits.window()))) {
            return new Window(now, 1);
        }
        return new Window(existing.startedAt(), existing.count() + 1);
    }

    private void discardExpired(Instant now) {
        if (windows.size() < MAX_KEYS) return;
        windows.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().startedAt().plus(limits.window())));
    }

    private void reject(HttpServletResponse response) throws IOException {
        var correlation = MDC.get(CorrelationIdFilter.MDC_KEY);
        if (correlation == null) correlation = java.util.UUID.randomUUID().toString().replace("-", "");
        response.setStatus(429);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Retry-After", Long.toString(Math.max(1, limits.window().toSeconds())));
        objectMapper.writeValue(response.getOutputStream(), ErrorEnvelope.of(
                "rate_limit_exceeded", "Too many authorization requests", correlation));
    }

    private record Window(Instant startedAt, int count) { }
}
