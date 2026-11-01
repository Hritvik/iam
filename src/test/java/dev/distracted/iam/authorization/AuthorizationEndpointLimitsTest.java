package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import org.junit.jupiter.api.Test;

class AuthorizationEndpointLimitsTest {
    @Test
    void rejectsUnsafeAuthorizationEndpointLimitConfiguration() {
        assertThatThrownBy(() -> new AuthorizationEndpointLimitsProperties(0, 60, Duration.ofMinutes(1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuthorizationEndpointLimitsProperties(4096, 0, Duration.ofMinutes(1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuthorizationEndpointLimitsProperties(4096, 60, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
