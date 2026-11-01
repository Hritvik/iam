package dev.distracted.iam.token;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "iam.token.enabled", havingValue = "true")
public class TokenCapabilityConfiguration {
    @Bean JwksPublisher jwksPublisher(AccessTokenSigningCapability capability) {
        return new JwksPublisher(capability);
    }
}
