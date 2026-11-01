package dev.distracted.iam.authorization;

import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.registration.RegistrationRegistry;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

public final class SasRegisteredClientRepository implements RegisteredClientRepository {
    private final RegistrationRegistry registry;

    public SasRegisteredClientRepository(RegistrationRegistry registry) {
        this.registry = java.util.Objects.requireNonNull(registry);
    }

    @Override public void save(RegisteredClient registeredClient) {
        throw new UnsupportedOperationException("registered_client_registry_is_immutable");
    }

    @Override public RegisteredClient findById(String id) {
        return registry.findByAppId(id).map(this::adapt).orElse(null);
    }

    @Override public RegisteredClient findByClientId(String clientId) {
        return registry.findByClientId(clientId).map(this::adapt).orElse(null);
    }

    private RegisteredClient adapt(RegistrationManifest registration) {
        if (!"NATIVE_PUBLIC".equals(registration.client().clientType())
                || !registration.client().grantTypes().equals(java.util.List.of("authorization_code"))
                || !registration.client().pkceMethods().equals(java.util.List.of("S256"))) {
            throw new IllegalStateException("registered_client_not_supported");
        }
        var builder = RegisteredClient.withId(registration.appRegistrationId())
                .clientId(registration.client().clientId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientSettings(ClientSettings.builder().requireProofKey(true)
                        .requireAuthorizationConsent(false).build());
        registration.client().redirectUris().forEach(builder::redirectUri);
        registration.resource().allowedScopes().forEach(builder::scope);
        return builder.build();
    }
}
