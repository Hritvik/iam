package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.registration.RegistrationRegistry;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

class SasRegisteredClientRepositoryTest {
    @Test
    void exposesOnlyThePinnedPublicAuthorizationCodeClient() {
        var repository = new SasRegisteredClientRepository(registry());

        var client = repository.findByClientId("dutch-mobile");

        assertThat(client.getClientAuthenticationMethods()).containsExactly(ClientAuthenticationMethod.NONE);
        assertThat(client.getAuthorizationGrantTypes()).containsExactly(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(client.getRedirectUris()).containsExactly("dutch://oauth/callback");
        assertThat(client.getClientSettings().isRequireProofKey()).isTrue();
        assertThat(client.getClientSecret()).isNull();
    }

    private static RegistrationRegistry registry() {
        var registration = new RegistrationManifest(1, "dutch-development", "Dutch Development", "development",
                new RegistrationManifest.Client("dutch-mobile", "NATIVE_PUBLIC", List.of("dutch://oauth/callback"),
                        List.of("authorization_code"), List.of("S256"), "EXTERNAL"),
                new RegistrationManifest.Resource("dutch-api", "https://api.dutch.invalid", List.of("member:read")),
                new RegistrationManifest.SecurityPolicy(1, true, "S256", List.of("authorization_code"),
                        List.of("verified_identifier", "usable_factor", "recovery_path")));
        return new RegistrationRegistry() {
            public Optional<RegistrationManifest> findByClientId(String id) {
                return "dutch-mobile".equals(id) ? Optional.of(registration) : Optional.empty();
            }
            public Optional<RegistrationManifest> findByAppId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByResourceId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByAudience(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findSoleRegistration() { return Optional.of(registration); }
            public dev.distracted.iam.registration.ReconciliationResult reconcile(
                    dev.distracted.iam.registration.ValidatedRegistration value) { throw new UnsupportedOperationException(); }
        };
    }
}
