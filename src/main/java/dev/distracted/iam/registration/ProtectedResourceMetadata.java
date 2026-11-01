package dev.distracted.iam.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record ProtectedResourceMetadata(
        String resource,
        @JsonProperty("authorization_servers") List<String> authorizationServers,
        @JsonProperty("scopes_supported") List<String> scopesSupported,
        @JsonProperty("bearer_methods_supported") List<String> bearerMethodsSupported,
        @JsonProperty("resource_signing_alg_values_supported") List<String> resourceSigningAlgValuesSupported) {
    public ProtectedResourceMetadata {
        authorizationServers = List.copyOf(authorizationServers);
        scopesSupported = List.copyOf(scopesSupported);
        bearerMethodsSupported = List.copyOf(bearerMethodsSupported);
        resourceSigningAlgValuesSupported = List.copyOf(resourceSigningAlgValuesSupported);
    }
}
