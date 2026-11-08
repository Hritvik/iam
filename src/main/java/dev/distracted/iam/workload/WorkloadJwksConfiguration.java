package dev.distracted.iam.workload;

import dev.distracted.iam.token.JwksPublisher;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Publishes the workload signing key at the platform JWKS when the human token surface is off.
 *
 * <p>When the human token surface is on, {@code TokenCapabilityConfiguration} publishes the same
 * JWKS with both the access-token keys and this workload key.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnExpression("${iam.workload.enabled:false} and !${iam.token.enabled:false}")
public class WorkloadJwksConfiguration {
    @Bean
    JwksPublisher workloadJwksPublisher(WorkloadPublicKey workloadPublicKey) {
        return JwksPublisher.fromPublicKeys(List.of(workloadPublicKey.key()));
    }
}
