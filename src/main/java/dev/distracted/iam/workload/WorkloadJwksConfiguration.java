package dev.distracted.iam.workload;

import dev.distracted.iam.token.JwksPublisher;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Publishes the workload signing key at the platform JWKS.
 *
 * <p>When the human token surface is on, {@code TokenCapabilityConfiguration} publishes the primary
 * JWKS with both the access-token keys and this workload key; this workload-only publisher remains
 * as a non-primary fallback so a context with both surfaces still resolves one publisher.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.workload.enabled", havingValue = "true")
public class WorkloadJwksConfiguration {
    @Bean
    JwksPublisher workloadJwksPublisher(WorkloadPublicKey workloadPublicKey) {
        return JwksPublisher.fromPublicKeys(List.of(workloadPublicKey.key()));
    }
}
