package dev.distracted.iam.registration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class RegistrationManifestValidatorTest {
    private final RegistrationManifestValidator validator = new StrictRegistrationManifestValidator();

    @Test
    void immutableValueCopiesHandleAbsentOptionalConstructionInput() {
        var empty = new RegistrationManifest(1, "app", "App", "test", null, null, null);
        assertThat(empty.client()).isNull();
        var client = new RegistrationManifest.Client("client", "NATIVE_PUBLIC", null, null, null, "EXTERNAL");
        var resource = new RegistrationManifest.Resource("resource", "https://example.invalid", null);
        var policy = new RegistrationManifest.SecurityPolicy(1, true, "S256", null, null);
        var copied = new RegistrationManifest(1, "app", "App", "test", client, resource, policy);
        assertThat(copied.client().redirectUris()).isNull();
        assertThat(copied.resource().allowedScopes()).isNull();
        assertThat(copied.securityPolicy().requiredActivationEvidence()).isNull();
    }

    @Test
    void validatesTheExactImmutableDutchTuple() {
        var result = validator.validate(new ClasspathPinnedRegistrationSource().load());

        assertThat(result.manifest().appRegistrationId()).isEqualTo("dutch-development");
        assertThat(result.manifest().client().redirectUris()).containsExactly("dutch://oauth/callback");
        assertThat(result.manifest().client().grantTypes()).containsExactly("authorization_code");
        assertThat(result.manifest().client().pkceMethods()).containsExactly("S256");
        assertThat(result.manifest().resource().audience()).isEqualTo("https://api.dutch.invalid");
        assertThat(result.fingerprint()).matches("[0-9a-f]{64}");
        assertThatThrownBy(() -> result.manifest().client().redirectUris().add("x"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void rejectsDuplicateKeysWithoutEchoingInput() {
        assertSafeFailure("{\"manifestVersion\":1,\"manifestVersion\":1}", "registration_json_invalid");
    }

    @Test
    void rejectsNullAndOversizeSourcesAndCoversLoopbackSemanticBounds() {
        assertThatThrownBy(() -> validator.validate(null)).hasMessage("registration_source_oversize");
        assertThatThrownBy(() -> validator.validate(new PinnedRegistrationDocument("test", new byte[32_769])))
                .hasMessage("registration_source_oversize");
        StrictRegistrationManifestValidator.validateRedirect("other-app", "http://127.0.0.1:8080/callback");
        StrictRegistrationManifestValidator.validateRedirect("other-app", "http://[::1]:8080/callback");
        StrictRegistrationManifestValidator.validateRedirect("other-app", "https://login.example.test/callback",
                Map.of("other-app", Set.of("login.example.test")));
        assertThatThrownBy(() -> StrictRegistrationManifestValidator.validateRedirect("other-app",
                "https://evil.login.example.test/callback", Map.of("other-app", Set.of("login.example.test"))))
                .hasMessage("registration_redirect_invalid");
        assertThatThrownBy(() -> StrictRegistrationManifestValidator.validateRedirect("other-app",
                "https://login.example.test.evil/callback", Map.of("other-app", Set.of("login.example.test"))))
                .hasMessage("registration_redirect_invalid");
        assertThatThrownBy(() -> StrictRegistrationManifestValidator.validateRedirect(
                "other-app", "http://127.a.0.1:8080/callback")).hasMessage("registration_redirect_invalid");
        assertThatThrownBy(() -> StrictRegistrationManifestValidator.validateRedirect(
                "other-app", "not a uri")).hasMessage("registration_redirect_invalid");
    }

    @Test
    void rejectsUnknownFieldsAndUnsafeRedirects() {
        var canonical = new String(new ClasspathPinnedRegistrationSource().load().bytes(), StandardCharsets.UTF_8);
        assertSafeFailure(canonical.replace("\"manifestVersion\": 1,", "\"manifestVersion\": 1,\"unknown\":true,"),
                "registration_schema_invalid");
        assertSafeFailure(canonical.replace("dutch://oauth/callback", "dutch://oauth/*"),
                "registration_schema_invalid");
        assertSafeFailure(canonical.replace("dutch://oauth/callback", "http://localhost:8080/callback"),
                "registration_schema_invalid");
    }

    @ParameterizedTest
    @MethodSource("invalidMutations")
    void rejectsEveryInvalidRegistrationDimension(String from, String to) {
        var canonical = new String(new ClasspathPinnedRegistrationSource().load().bytes(), StandardCharsets.UTF_8);
        assertThatThrownBy(() -> validator.validate(new PinnedRegistrationDocument(
                "test", canonical.replace(from, to).getBytes(StandardCharsets.UTF_8))))
                .isInstanceOf(RegistrationException.class);
    }

    private static Stream<String[]> invalidMutations() {
        return Stream.of(
                mutation("\"manifestVersion\": 1", "\"manifestVersion\": 2"),
                mutation("\"appRegistrationId\": \"dutch-development\"", "\"appRegistrationId\": \"other-app\""),
                mutation("\"displayName\": \"Dutch Development\"", "\"displayName\": \"Wrong\""),
                mutation("\"environment\": \"development\"", "\"environment\": \"production\""),
                mutation("\"clientId\": \"dutch-mobile\"", "\"clientId\": \"wrong-mobile\""),
                mutation("\"clientType\": \"NATIVE_PUBLIC\"", "\"clientType\": \"CONFIDENTIAL\""),
                mutation("\"browserMode\": \"EXTERNAL\"", "\"browserMode\": \"EMBEDDED\""),
                mutation("\"grantTypes\": [\"authorization_code\"]", "\"grantTypes\": []"),
                mutation("\"grantTypes\": [\"authorization_code\"]", "\"grantTypes\": [\"refresh_token\"]"),
                mutation("\"pkceMethods\": [\"S256\"]", "\"pkceMethods\": []"),
                mutation("\"pkceMethods\": [\"S256\"]", "\"pkceMethods\": [\"plain\"]"),
                mutation("\"redirectUris\": [\"dutch://oauth/callback\"]", "\"redirectUris\": []"),
                mutation("\"resourceId\": \"dutch-api\"", "\"resourceId\": \"other-api\""),
                mutation("\"audience\": \"https://api.dutch.invalid\"", "\"audience\": \"http://api.dutch.invalid\""),
                mutation("\"allowedScopes\": [\"member:read\"]", "\"allowedScopes\": []"),
                mutation("\"allowedScopes\": [\"member:read\"]", "\"allowedScopes\": [\"member:write\"]"),
                mutation("\"policyVersion\": 1", "\"policyVersion\": 2"),
                mutation("\"requireDpop\": true", "\"requireDpop\": false"),
                mutation("\"requiredPkceMethod\": \"S256\"", "\"requiredPkceMethod\": \"plain\""),
                mutation("\"allowedGrantTypes\": [\"authorization_code\"]", "\"allowedGrantTypes\": []"),
                mutation("\"requiredActivationEvidence\": [\"verified_identifier\", \"usable_factor\", \"recovery_path\"]",
                        "\"requiredActivationEvidence\": [\"verified_identifier\"]"),
                mutation("dutch://oauth/callback", "javascript://oauth/callback"),
                mutation("dutch://oauth/callback", "dutch://user@oauth/callback"),
                mutation("dutch://oauth/callback", "dutch://oauth/callback#fragment"),
                mutation("dutch://oauth/callback", "dutch://oauth/other"),
                mutation("dutch://oauth/callback", "http://127.0.0.1/callback"),
                mutation("dutch://oauth/callback", "http://127.0.0.1:0/callback"),
                mutation("dutch://oauth/callback", "http://127.0.0.999:8080/callback"),
                mutation("dutch://oauth/callback", "http://128.0.0.1:8080/callback"));
    }

    private static String[] mutation(String from, String to) { return new String[]{from, to}; }

    private void assertSafeFailure(String value, String code) {
        var document = new PinnedRegistrationDocument("test", value.getBytes(StandardCharsets.UTF_8));
        assertThatThrownBy(() -> validator.validate(document))
                .isInstanceOf(RegistrationException.class)
                .hasMessage(code)
                .hasMessageNotContaining("dutch://");
    }
}
