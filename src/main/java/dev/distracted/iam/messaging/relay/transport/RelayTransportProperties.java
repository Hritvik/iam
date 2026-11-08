package dev.distracted.iam.messaging.relay.transport;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("iam.messaging.relay.transport")
public record RelayTransportProperties(
        String mode,
        String endpoint,
        String workloadId,
        String audience,
        String scope,
        Integer connectTimeoutMs,
        Integer requestTimeoutMs) {
}
