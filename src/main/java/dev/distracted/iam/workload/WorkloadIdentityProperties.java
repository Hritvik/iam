package dev.distracted.iam.workload;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Runtime bindings for the workload access token profile.
 *
 * <p>Production registrations arrive through the reviewed manifest path. These properties hold the
 * runtime trust bundle and the bindings a resource enforces; private material is injected from
 * secret storage and is never committed.
 */
@ConfigurationProperties("iam.workload")
public record WorkloadIdentityProperties(
        Boolean enabled,
        String issuer,
        Integer lifetimeSeconds,
        Integer skewSeconds,
        Signing signing,
        List<TrustedKey> trustedKeys,
        List<Binding> bindings) {
    public record Signing(String keyId, String privateKey, String publicKey) {
    }

    public record TrustedKey(String keyId, String publicKey) {
    }

    public record Binding(
            String workloadId,
            String appRegistrationId,
            String clientId,
            List<String> audiences,
            List<String> scopes) {
    }
}
