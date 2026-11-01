package dev.distracted.iam.authorization;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.authorization.limits")
public record AuthorizationEndpointLimitsProperties(
        @DefaultValue("4096") int maxRequestCharacters,
        @DefaultValue("60") int requestsPerWindow,
        @DefaultValue("1m") Duration window) {
    public AuthorizationEndpointLimitsProperties {
        if (maxRequestCharacters < 512 || maxRequestCharacters > 16384
                || requestsPerWindow < 1 || requestsPerWindow > 1000
                || window == null || window.compareTo(Duration.ofSeconds(1)) < 0
                || window.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalArgumentException("authorization_endpoint_limits_invalid");
        }
    }
}
