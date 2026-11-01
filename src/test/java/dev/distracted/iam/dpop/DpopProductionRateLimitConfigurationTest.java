package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.util.List;
import org.junit.jupiter.api.Test;

class DpopProductionRateLimitConfigurationTest {
    @Test void productionRequiresExactlyOneExternalLimiterAndNeverAcceptsTheLocalAdapter() {
        ExternalTokenEndpointRateLimiter external = request -> true;
        assertThatCode(() -> new DpopProductionRateLimitConfiguration(List.of(external), List.of()))
                .doesNotThrowAnyException();
        assertThatThrownBy(() -> new DpopProductionRateLimitConfiguration(List.of(), List.of()))
                .isInstanceOf(IllegalStateException.class).hasMessage("external_token_rate_limiter_required");
        assertThatThrownBy(() -> new DpopProductionRateLimitConfiguration(List.of(external, external), List.of()))
                .isInstanceOf(IllegalStateException.class);
        var local = new BoundedLocalTokenEndpointRateLimiter(Clock.systemUTC(), 1, 1, 1);
        assertThatThrownBy(() -> new DpopProductionRateLimitConfiguration(List.of(external), List.of(local)))
                .isInstanceOf(IllegalStateException.class);
    }
}
