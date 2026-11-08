package dev.distracted.iam.messaging.relay.transport;

import dev.distracted.iam.messaging.relay.OnboardingRelay;
import dev.distracted.iam.messaging.relay.OutboxTransport;
import dev.distracted.iam.workload.WorkloadAccessTokenIssuer;
import io.micrometer.core.instrument.MeterRegistry;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Wires the production relay transport and its scheduler. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.messaging.relay.enabled", havingValue = "true")
@EnableConfigurationProperties(RelayTransportProperties.class)
public class RelayRuntimeConfiguration {
    @Bean
    @ConditionalOnProperty(name = "iam.messaging.relay.transport.mode", havingValue = "http")
    OutboxTransport httpOutboxTransport(
            RelayTransportProperties properties,
            ObjectProvider<WorkloadAccessTokenIssuer> issuers) {
        var issuer = issuers.getIfAvailable();
        if (issuer == null) {
            throw new IllegalStateException("relay_workload_signing_unavailable");
        }
        if (properties.endpoint() == null || properties.workloadId() == null
                || properties.audience() == null || properties.scope() == null) {
            throw new IllegalStateException("relay_transport_configuration_missing");
        }
        var connectTimeout = timeout(properties.connectTimeoutMs(), 2000, "connect");
        var requestTimeout = timeout(properties.requestTimeoutMs(), 5000, "request");
        var client = HttpClient.newBuilder().connectTimeout(connectTimeout).build();
        var supplier = new SelfIssuedWorkloadTokenSupplier(
                issuer, properties.workloadId(), properties.audience(), properties.scope());
        return new HttpOutboxTransport(URI.create(properties.endpoint()), client, supplier, requestTimeout);
    }

    private static Duration timeout(Integer value, int fallbackMillis, String name) {
        var millis = value == null ? fallbackMillis : value;
        if (millis < 100 || millis > 60000) {
            throw new IllegalStateException("relay_transport_" + name + "_timeout_invalid");
        }
        return Duration.ofMillis(millis);
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(name = "iam.messaging.relay.schedule.enabled", havingValue = "true")
    @EnableScheduling
    static class SchedulingConfiguration {
        @Bean
        RelayScheduler relayScheduler(OnboardingRelay relay, MeterRegistry registry) {
            return new RelayScheduler(relay, registry);
        }
    }
}
