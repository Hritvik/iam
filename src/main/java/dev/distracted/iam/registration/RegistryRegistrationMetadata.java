package dev.distracted.iam.registration;

import java.net.URI;
import java.util.List;

public final class RegistryRegistrationMetadata implements RegistrationMetadata {
    private final RegistrationRegistry registry;
    private final String issuer;
    private final boolean refreshEnabled;

    public RegistryRegistrationMetadata(RegistrationRegistry registry, String issuer) {
        this(registry, issuer, false);
    }

    public RegistryRegistrationMetadata(RegistrationRegistry registry, String issuer, boolean refreshEnabled) {
        this.registry = registry;
        this.issuer = validateIssuer(issuer);
        this.refreshEnabled = refreshEnabled;
    }

    @Override public AuthorizationServerMetadata authorizationServer() {
        requireDutchRegistration();
        return AuthorizationServerMetadata.of(issuer, refreshEnabled);
    }

    @Override public ProtectedResourceMetadata protectedResource() {
        var manifest = requireDutchRegistration();
        return new ProtectedResourceMetadata(manifest.resource().audience(), List.of(issuer),
                manifest.resource().allowedScopes().stream().sorted().toList(), List.of("header"), List.of("ES256"));
    }

    private RegistrationManifest requireDutchRegistration() {
        try {
            return registry.findSoleRegistration().orElseThrow(MetadataUnavailableException::new);
        } catch (MetadataUnavailableException exception) {
            throw exception;
        } catch (RuntimeException exception) {
            throw new MetadataUnavailableException();
        }
    }

    static String validateIssuer(String value) {
        try {
            var uri = URI.create(value);
            if (!"https".equals(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null
                    || uri.getQuery() != null || uri.getFragment() != null || uri.getPath().endsWith("/")
                    || !uri.getPath().isEmpty()) throw new IllegalArgumentException();
            return value;
        } catch (RuntimeException exception) {
            throw new RegistrationException("issuer_invalid");
        }
    }
}
