package dev.distracted.iam.registration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RegistrationMetadataTest {
    @Test
    void buildsClosedMetadataFromRegistryAndStrictIssuer() {
        var manifest = new StrictRegistrationManifestValidator()
                .validate(new ClasspathPinnedRegistrationSource().load()).manifest();
        RegistrationRegistry registry = registry(manifest);
        var metadata = new RegistryRegistrationMetadata(registry, "https://iam.distracted.invalid");

        assertThat(metadata.authorizationServer().issuer()).isEqualTo("https://iam.distracted.invalid");
        assertThat(metadata.authorizationServer().grantTypesSupported()).containsExactly("authorization_code");
        assertThat(metadata.authorizationServer().codeChallengeMethodsSupported()).containsExactly("S256");
        assertThat(metadata.protectedResource().resource()).isEqualTo("https://api.dutch.invalid");
        assertThat(metadata.protectedResource().scopesSupported()).containsExactly("member:read");
    }

    @Test
    void rejectsMissingRegistrationAndUnsafeIssuer() {
        assertThatThrownBy(() -> new RegistryRegistrationMetadata(registry(null), "http://iam.invalid"))
                .isInstanceOf(RegistrationException.class).hasMessage("issuer_invalid");
        var metadata = new RegistryRegistrationMetadata(registry(null), "https://iam.distracted.invalid");
        assertThatThrownBy(metadata::protectedResource)
                .isInstanceOf(MetadataUnavailableException.class).hasMessage("metadata_unavailable");
    }

    @Test
    void convertsRegistryFailureIntoUnavailableWithoutLeakingIt() {
        RegistrationRegistry failing = new RegistrationRegistry() {
            public ReconciliationResult reconcile(ValidatedRegistration value) { throw new UnsupportedOperationException(); }
            public Optional<RegistrationManifest> findByAppId(String id) { throw new IllegalStateException("database-canary"); }
            public Optional<RegistrationManifest> findByClientId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByResourceId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByAudience(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findSoleRegistration() { throw new IllegalStateException("database-canary"); }
        };
        var metadata = new RegistryRegistrationMetadata(failing, "https://iam.distracted.invalid");
        assertThatThrownBy(metadata::authorizationServer).isInstanceOf(MetadataUnavailableException.class)
                .hasMessageNotContaining("canary");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "http://iam.invalid", "https://user@iam.invalid", "https://iam.invalid/path",
            "https://iam.invalid?query=x", "https://iam.invalid#fragment", "https://iam.invalid/"})
    void rejectsEachUnsafeIssuerShape(String issuer) {
        assertThatThrownBy(() -> new RegistryRegistrationMetadata(registry(null), issuer))
                .isInstanceOf(RegistrationException.class).hasMessage("issuer_invalid");
    }

    private static RegistrationRegistry registry(RegistrationManifest manifest) {
        return new RegistrationRegistry() {
            public ReconciliationResult reconcile(ValidatedRegistration value) { throw new UnsupportedOperationException(); }
            public Optional<RegistrationManifest> findByAppId(String id) { return Optional.ofNullable(manifest); }
            public Optional<RegistrationManifest> findByClientId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByResourceId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByAudience(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findSoleRegistration() { return Optional.ofNullable(manifest); }
        };
    }
}
