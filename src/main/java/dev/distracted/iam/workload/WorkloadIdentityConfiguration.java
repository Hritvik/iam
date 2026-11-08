package dev.distracted.iam.workload;

import dev.distracted.iam.messaging.snapshot.web.WorkloadAuthenticator;
import dev.distracted.iam.token.SecureAccessTokenMaterialGenerator;
import java.security.SecureRandom;
import java.time.Clock;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the workload access token profile: issuance for registered workloads and verification for
 * resources this service owns.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.workload.enabled", havingValue = "true")
@EnableConfigurationProperties(WorkloadIdentityProperties.class)
public class WorkloadIdentityConfiguration {
    @Bean
    WorkloadAccessTokenIssuer workloadAccessTokenIssuer(WorkloadIdentityProperties properties) {
        return new WorkloadAccessTokenIssuer(
                properties,
                new SecureAccessTokenMaterialGenerator(new SecureRandom()),
                Clock.systemUTC());
    }

    @Bean
    WorkloadPublicKey workloadPublicKey(WorkloadIdentityProperties properties) {
        var signing = properties.signing();
        return new WorkloadPublicKey(WorkloadKeys.publicKey(signing.keyId(), signing.publicKey()));
    }

    @Bean
    WorkloadAccessTokenVerifier workloadAccessTokenVerifier(WorkloadIdentityProperties properties) {
        return new WorkloadAccessTokenVerifier(properties, Clock.systemUTC());
    }

    @Bean
    WorkloadAuthenticator workloadAuthenticator(WorkloadAccessTokenVerifier verifier) {
        return new JwtWorkloadAuthenticator(verifier);
    }
}
