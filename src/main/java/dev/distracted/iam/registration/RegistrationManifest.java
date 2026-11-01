package dev.distracted.iam.registration;

import java.util.List;

public record RegistrationManifest(
        int manifestVersion,
        String appRegistrationId,
        String displayName,
        String environment,
        Client client,
        Resource resource,
        SecurityPolicy securityPolicy) {
    public RegistrationManifest {
        client = client == null ? null : client.immutableCopy();
        resource = resource == null ? null : resource.immutableCopy();
        securityPolicy = securityPolicy == null ? null : securityPolicy.immutableCopy();
    }

    public record Client(String clientId, String clientType, List<String> redirectUris,
                         List<String> grantTypes, List<String> pkceMethods, String browserMode) {
        Client immutableCopy() {
            return new Client(clientId, clientType, copy(redirectUris), copy(grantTypes), copy(pkceMethods), browserMode);
        }
    }

    public record Resource(String resourceId, String audience, List<String> allowedScopes) {
        Resource immutableCopy() { return new Resource(resourceId, audience, copy(allowedScopes)); }
    }

    public record SecurityPolicy(int policyVersion, boolean requireDpop, String requiredPkceMethod,
                                 List<String> allowedGrantTypes, List<String> requiredActivationEvidence) {
        SecurityPolicy immutableCopy() {
            return new SecurityPolicy(policyVersion, requireDpop, requiredPkceMethod,
                    copy(allowedGrantTypes), copy(requiredActivationEvidence));
        }
    }

    private static <T> List<T> copy(List<T> values) { return values == null ? null : List.copyOf(values); }
}
