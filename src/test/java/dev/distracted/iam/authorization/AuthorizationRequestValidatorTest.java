package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.registration.RegistrationManifest;
import java.util.List;
import org.junit.jupiter.api.Test;

class AuthorizationRequestValidatorTest {
    @Test
    void acceptsTheExactRegisteredRedirectWithS256() {
        var validator = new AuthorizationRequestValidator("https://iam.distracted.invalid");
        var request = new AuthorizationRequestCommand(
                "dutch-mobile", "code", "dutch://oauth/callback", "member:read",
                "https://api.dutch.invalid", "state_0123456789", "nonce_0123456789",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256");

        var result = validator.validate(request, registration());

        assertThat(result.redirectUri()).isEqualTo("dutch://oauth/callback");
        assertThat(result.scope()).isEqualTo("member:read");
    }

    @Test
    void rejectsAnUnregisteredScope() {
        var validator = new AuthorizationRequestValidator("https://iam.distracted.invalid");
        var request = new AuthorizationRequestCommand(
                "dutch-mobile", "code", "dutch://oauth/callback", "admin:write",
                "https://api.dutch.invalid", "state_0123456789", "nonce_0123456789",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256");

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> validator.validate(request, registration()))
                .isInstanceOf(AuthorizationRequestRejectedException.class)
                .hasMessage("authorization_request_rejected");
    }

    @Test
    void rejectsShortStateWithoutReflectingIt() {
        var validator = new AuthorizationRequestValidator("https://iam.distracted.invalid");
        var request = new AuthorizationRequestCommand(
                "dutch-mobile", "code", "dutch://oauth/callback", "member:read",
                "https://api.dutch.invalid", "short", "nonce_0123456789",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256");

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> validator.validate(request, registration()))
                .isInstanceOf(AuthorizationRequestRejectedException.class)
                .hasMessage("authorization_request_rejected")
                .hasMessageNotContaining("short");
    }

    private static RegistrationManifest registration() {
        return new RegistrationManifest(1, "dutch-development", "Dutch Development", "development",
                new RegistrationManifest.Client("dutch-mobile", "NATIVE_PUBLIC",
                        List.of("dutch://oauth/callback"), List.of("authorization_code"),
                        List.of("S256"), "EXTERNAL"),
                new RegistrationManifest.Resource("dutch-api", "https://api.dutch.invalid",
                        List.of("member:read")),
                new RegistrationManifest.SecurityPolicy(1, true, "S256",
                        List.of("authorization_code"),
                        List.of("verified_identifier", "usable_factor", "recovery_path")));
    }
}
