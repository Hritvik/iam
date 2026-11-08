package dev.distracted.iam.token;

import dev.distracted.iam.workload.WorkloadPublicKey;
import java.util.List;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.token.enabled", havingValue = "true")
public class TokenCapabilityConfiguration {
    @Bean JwksPublisher jwksPublisher(
            AccessTokenSigningCapability capability,
            ObjectProvider<WorkloadPublicKey> workloadPublicKey) {
        var workload = workloadPublicKey.getIfAvailable();
        return new JwksPublisher(capability, workload == null ? List.of() : List.of(workload.key()));
    }
}
