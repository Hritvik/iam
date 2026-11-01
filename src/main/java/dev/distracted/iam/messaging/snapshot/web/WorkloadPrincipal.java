package dev.distracted.iam.messaging.snapshot.web;

public record WorkloadPrincipal(String appRegistrationId, java.util.Set<String> scopes, String audience) {
    public WorkloadPrincipal {
        scopes = scopes == null ? java.util.Set.of() : java.util.Set.copyOf(scopes);
    }
}
