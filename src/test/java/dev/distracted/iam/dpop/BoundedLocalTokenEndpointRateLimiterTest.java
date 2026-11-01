package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import org.junit.jupiter.api.Test;

class BoundedLocalTokenEndpointRateLimiterTest {
    @Test void boundsRequestsKeysAndWindowsWithoutStoringRequestArtifacts() {
        var clock = new MutableClock();
        var limiter = new BoundedLocalTokenEndpointRateLimiter(clock, 2, 1, 3);

        assertThat(limiter.allow(request("client-a", "network-a", TokenRateLimitCategory.CHALLENGE))).isTrue();
        assertThat(limiter.allow(request("client-a", "network-a", TokenRateLimitCategory.CHALLENGE))).isTrue();
        assertThat(limiter.allow(request("client-a", "network-a", TokenRateLimitCategory.CHALLENGE))).isFalse();
        assertThat(limiter.allow(request("client-a", "network-a", TokenRateLimitCategory.RETRY))).isTrue();
        assertThat(limiter.allow(request("client-a", "network-a", TokenRateLimitCategory.RETRY))).isFalse();
        assertThat(limiter.allow(request("client-b", "network-b", TokenRateLimitCategory.CHALLENGE))).isTrue();
        assertThat(limiter.allow(request("client-c", "network-c", TokenRateLimitCategory.CHALLENGE))).isTrue();
        assertThat(limiter.allow(request("client-a", "network-a", TokenRateLimitCategory.CHALLENGE))).isTrue();
        assertThat(limiter.allow(null)).isFalse();
        clock.instant = clock.instant.plusSeconds(60);
        assertThat(limiter.allow(request("client-a", "network-a", TokenRateLimitCategory.RETRY))).isTrue();
    }

    @Test void rejectsUnsafeConfigurationBounds() {
        assertThatThrownBy(() -> new BoundedLocalTokenEndpointRateLimiter(Clock.systemUTC(), 0, 1, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BoundedLocalTokenEndpointRateLimiter(Clock.systemUTC(), 1001, 1, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BoundedLocalTokenEndpointRateLimiter(Clock.systemUTC(), 1, 0, 1))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BoundedLocalTokenEndpointRateLimiter(Clock.systemUTC(), 1, 1, 0))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BoundedLocalTokenEndpointRateLimiter(Clock.systemUTC(), 1, 1, 100_001))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static TokenRateLimitRequest request(String client, String network, TokenRateLimitCategory category) {
        return new TokenRateLimitRequest(client, network, category);
    }

    private static final class MutableClock extends Clock {
        private Instant instant = Instant.parse("2026-10-26T00:00:00Z");
        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return instant; }
    }
}
