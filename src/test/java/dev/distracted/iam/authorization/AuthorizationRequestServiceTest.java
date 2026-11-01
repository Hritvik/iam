package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.identity.IdentityReference;
import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.registration.RegistrationRegistry;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AuthorizationRequestServiceTest {
    @Test
    void issuesAnOpaqueCodeWithoutPersistingItsSecret() {
        var persisted = new AtomicReference<AuthorizationCodeIssue>();
        AuthorizationCodeRepository repository = issue -> {
            persisted.set(issue);
            return new AuthorizationIssueReceipt(java.time.Instant.parse("2026-01-01T00:00:00Z"),
                    java.time.Instant.parse("2026-01-01T00:02:00Z"), 1L);
        };
        var digest = new HmacAuthorizationCodeDigestCapability("development", (short) 1,
                Map.of((short) 1, "authorization-code-test-key-00001".getBytes(StandardCharsets.US_ASCII)),
                Map.of((short) 1, "test://authorization-code/1"));
        var service = new AuthorizationRequestService(
                registry(), new AuthorizationRequestValidator("https://iam.distracted.invalid"), repository,
                digest, new SecureAuthorizationCodeMaterialGenerator(), Duration.ofSeconds(120));

        var result = service.authorize(new AuthenticatedIdentity(new IdentityReference(
                        "hid_0123456789012345678901")), command(), "cor_0123456789012345");

        assertThat(result.code()).matches("^acd_[A-Za-z0-9_-]{22,128}\\.[A-Za-z0-9_-]{43}$");
        assertThat(result.state()).isEqualTo("state_0123456789");
        assertThat(persisted.get().codeDigest()).hasSize(32);
        assertThat(persisted.get().toString()).doesNotContain(result.code());
    }

    private static AuthorizationRequestCommand command() {
        return new AuthorizationRequestCommand("dutch-mobile", "code", "dutch://oauth/callback", "member:read",
                "https://api.dutch.invalid", "state_0123456789", "nonce_0123456789",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256");
    }

    private static RegistrationRegistry registry() {
        var registration = new RegistrationManifest(1, "dutch-development", "Dutch Development", "development",
                new RegistrationManifest.Client("dutch-mobile", "NATIVE_PUBLIC", List.of("dutch://oauth/callback"),
                        List.of("authorization_code"), List.of("S256"), "EXTERNAL"),
                new RegistrationManifest.Resource("dutch-api", "https://api.dutch.invalid", List.of("member:read")),
                new RegistrationManifest.SecurityPolicy(1, true, "S256", List.of("authorization_code"),
                        List.of("verified_identifier", "usable_factor", "recovery_path")));
        return new RegistrationRegistry() {
            public Optional<RegistrationManifest> findByClientId(String id) { return Optional.of(registration); }
            public Optional<RegistrationManifest> findByAppId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByResourceId(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findByAudience(String id) { return Optional.empty(); }
            public Optional<RegistrationManifest> findSoleRegistration() { return Optional.of(registration); }
            public dev.distracted.iam.registration.ReconciliationResult reconcile(
                    dev.distracted.iam.registration.ValidatedRegistration value) { throw new UnsupportedOperationException(); }
        };
    }
}
