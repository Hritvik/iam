package dev.distracted.iam.dpop;

import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration(proxyBeanMethods = false)
@Profile("production | staging | production-like")
@ConditionalOnProperty(name = "iam.dpop.enabled", havingValue = "true")
public class DpopProductionRateLimitConfiguration {
    public DpopProductionRateLimitConfiguration(List<ExternalTokenEndpointRateLimiter> external,
            List<BoundedLocalTokenEndpointRateLimiter> local) {
        if (external.size() != 1 || !local.isEmpty()) {
            throw new IllegalStateException("external_token_rate_limiter_required");
        }
    }
}
