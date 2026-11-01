package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.platform.crypto.CapabilityMetadata;
import dev.distracted.iam.platform.crypto.CapabilityPurpose;
import dev.distracted.iam.platform.crypto.CapabilitySelfCheck;
import dev.distracted.iam.platform.crypto.ChallengeDigestCapability;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class AuthorizationNegativeMatrixTest {
    @Test
    void productionAuthorizationCapabilityIsRequiredAndHealthy() {
        var properties = new AuthorizationCodeCapabilityProperties("test://key/1");
        assertThatThrownBy(() -> new AuthorizationProductionCapabilityConfiguration(
                properties, List.of(), List.of(), List.of(), List.of()))
                .hasMessage("authorization_code_digest_capability_required");
        org.assertj.core.api.Assertions.assertThatCode(() -> new AuthorizationProductionCapabilityConfiguration(
                properties, List.of(digest()), List.of(), List.of(), List.of())).doesNotThrowAnyException();
        assertThatThrownBy(() -> new AuthorizationProductionCapabilityConfiguration(
                new AuthorizationCodeCapabilityProperties("test://other"), List.of(digest()),
                List.of(), List.of(), List.of())).hasMessage("authorization_code_digest_capability_invalid");
    }

    @Test
    void productionAuthorizationCapabilityRejectsEachFailClosedShape() {
        var properties = new AuthorizationCodeCapabilityProperties("test://key/1");
        for (var capability : List.of(
                capability(new CapabilityMetadata(CapabilityPurpose.IDENTIFIER_BLIND_INDEX,
                        "external", "test://key/1", "HMAC-SHA-256"), CapabilitySelfCheck.ready(), Set.of((short) 1)),
                capability(new CapabilityMetadata(CapabilityPurpose.AUTHORIZATION_CODE_DIGEST,
                        "external", "test://key/1", "HMAC-SHA-512"), CapabilitySelfCheck.ready(), Set.of((short) 1)),
                capability(new CapabilityMetadata(CapabilityPurpose.AUTHORIZATION_CODE_DIGEST,
                        "external", "test://key/1", "HMAC-SHA-256"), CapabilitySelfCheck.unhealthy("kms_down"), Set.of((short) 1)),
                capability(new CapabilityMetadata(CapabilityPurpose.AUTHORIZATION_CODE_DIGEST,
                        "external", "test://key/1", "HMAC-SHA-256"), CapabilitySelfCheck.ready(), Set.of()))) {
            assertThatThrownBy(() -> new AuthorizationProductionCapabilityConfiguration(
                    properties, List.of(capability), List.of(), List.of(), List.of()))
                    .hasMessage("authorization_code_digest_capability_invalid");
        }
        var challenge = org.mockito.Mockito.mock(ChallengeDigestCapability.class);
        org.mockito.Mockito.when(challenge.keyReferences()).thenReturn(Map.of((short) 9, "test://key/1"));
        assertThatThrownBy(() -> new AuthorizationProductionCapabilityConfiguration(
                properties, List.of(digest()), List.of(), List.of(), List.of(challenge)))
                .hasMessage("authorization_code_digest_capability_invalid");
    }

    @ParameterizedTest
    @MethodSource("invalidRequests")
    void rejectsEveryClosedRequestBoundary(UnaryOperator<AuthorizationRequestCommand> mutation) {
        var validator = new AuthorizationRequestValidator("https://iam.distracted.invalid");
        assertThatThrownBy(() -> validator.validate(mutation.apply(validRequest()), registration()))
                .isInstanceOf(AuthorizationRequestRejectedException.class)
                .hasMessage("authorization_request_rejected");
    }

    static Stream<UnaryOperator<AuthorizationRequestCommand>> invalidRequests() {
        return Stream.of(
                request -> copy(request, "other", request.responseType(), request.redirectUri(), request.scope(),
                        request.resource(), request.state(), request.nonce(), request.codeChallenge(), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), "token", request.redirectUri(), request.scope(),
                        request.resource(), request.state(), request.nonce(), request.codeChallenge(), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), request.responseType(), "dutch://oauth/callback/", request.scope(),
                        request.resource(), request.state(), request.nonce(), request.codeChallenge(), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), request.responseType(), request.redirectUri(), request.scope(),
                        "https://other.invalid", request.state(), request.nonce(), request.codeChallenge(), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), request.responseType(), request.redirectUri(), "member:read member:read",
                        request.resource(), request.state(), request.nonce(), request.codeChallenge(), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), request.responseType(), request.redirectUri(), "BAD",
                        request.resource(), request.state(), request.nonce(), request.codeChallenge(), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), request.responseType(), request.redirectUri(), request.scope(),
                        request.resource(), request.state(), "short", request.codeChallenge(), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), request.responseType(), request.redirectUri(), request.scope(),
                        request.resource(), "x".repeat(257), request.nonce(), request.codeChallenge(), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), request.responseType(), request.redirectUri(), request.scope(),
                        request.resource(), "invalid value 123", request.nonce(), request.codeChallenge(), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), request.responseType(), request.redirectUri(), request.scope(),
                        request.resource(), request.state(), request.nonce(), request.codeChallenge(), "plain"),
                request -> copy(request, request.clientId(), request.responseType(), request.redirectUri(), request.scope(),
                        request.resource(), request.state(), request.nonce(), "x".repeat(42), request.codeChallengeMethod()),
                request -> copy(request, request.clientId(), request.responseType(), request.redirectUri(), request.scope(),
                        request.resource(), request.state(), request.nonce(), ".".repeat(43), request.codeChallengeMethod()));
    }

    @Test
    void redemptionRejectsMalformedUnknownAndMismatchedCodesWithoutConsuming() {
        var digest = digest();
        var repository = new AuthorizationCodeConsumptionRepository() {
            public Optional<AuthorizationCodeProtection> findProtection(String codeId) { return Optional.empty(); }
            public Optional<ConsumedAuthorization> consume(AuthorizationCodeConsumption command) {
                throw new AssertionError("consume must not be called");
            }
        };
        var service = new AuthorizationCodeRedemption(repository, digest, "https://iam.distracted.invalid");
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assertThat(service.redeem(new AuthorizationCodeRedemptionCommand(
                "refresh_token", "bad", "dutch-mobile", "dutch://oauth/callback", verifier,
                "cor_0123456789012345"))).isEmpty();
        assertThat(service.redeem(new AuthorizationCodeRedemptionCommand(
                "authorization_code", "bad", "dutch-mobile", "dutch://oauth/callback", verifier,
                "cor_0123456789012345"))).isEmpty();
        assertThat(service.redeem(new AuthorizationCodeRedemptionCommand(
                "authorization_code", "acd_0123456789012345678901." + "A".repeat(43), "dutch-mobile",
                "dutch://oauth/callback", "short", "cor_0123456789012345"))).isEmpty();
        assertThat(service.redeem(new AuthorizationCodeRedemptionCommand(
                "authorization_code", "acd_0123456789012345678901." + "A".repeat(43), "dutch-mobile",
                "dutch://oauth/callback", verifier, "cor_0123456789012345"))).isEmpty();
        assertThat(service.redeem(null)).isEmpty();
        for (var invalid : List.of("", "no-separator", "acd_0123456789012345678901.a.b",
                "bad_0123456789012345678901." + "A".repeat(43),
                "acd_0123456789012345678901." + "A".repeat(42))) {
            assertThat(service.redeem(new AuthorizationCodeRedemptionCommand(
                    "authorization_code", invalid, "dutch-mobile", "dutch://oauth/callback", verifier,
                    "cor_0123456789012345"))).isEmpty();
        }
    }

    @Test
    void digestCapabilityFailsClosedOnInvalidConfigurationAndUnknownVersions() {
        assertThatThrownBy(() -> new HmacAuthorizationCodeDigestCapability(null, (short) 1,
                Map.of((short) 1, key()), Map.of((short) 1, "test://key/1"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacAuthorizationCodeDigestCapability("test", (short) 1,
                null, Map.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacAuthorizationCodeDigestCapability("test", (short) 1,
                Map.of(), Map.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacAuthorizationCodeDigestCapability("", (short) 1,
                Map.of((short) 1, key()), Map.of((short) 1, "test://key/1"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacAuthorizationCodeDigestCapability("test", (short) 2,
                Map.of((short) 1, key()), Map.of((short) 1, "test://key/1"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacAuthorizationCodeDigestCapability("test", (short) 1,
                Map.of((short) 1, new byte[2]), Map.of((short) 1, "test://key/1"))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HmacAuthorizationCodeDigestCapability("test", (short) 1,
                Map.of((short) 1, key()), Map.of((short) 2, "test://key/2"))).isInstanceOf(IllegalArgumentException.class);
        assertThat(digest().matches("acd_0123456789012345678901", new byte[32], (short) 9, new byte[32])).isFalse();
        assertThat(digest().matches("acd_0123456789012345678901", new byte[32], (short) 1, null)).isFalse();
        assertThatThrownBy(() -> digest().protect("acd_0123456789012345678901", new byte[2]))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> digest().protect(null, new byte[32])).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> digest().protect("acd_0123456789012345678901", null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(digest().selfCheck().healthy()).isTrue();
    }

    @Test
    void validatorsAndRedemptionConstructorsRejectMissingAuthority() {
        assertThatThrownBy(() -> new AuthorizationRequestValidator(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuthorizationRequestValidator(" ")).isInstanceOf(IllegalArgumentException.class);
        for (var unsafeIssuer : List.of("http://iam.distracted.invalid", "https://user@iam.distracted.invalid",
                "https://iam.distracted.invalid?query=x", "https://iam.distracted.invalid#fragment",
                "https://iam.distracted.invalid/")) {
            assertThatThrownBy(() -> new AuthorizationRequestValidator(unsafeIssuer))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        var validator = new AuthorizationRequestValidator("https://iam.distracted.invalid");
        assertThatThrownBy(() -> validator.validate(null, registration()))
                .isInstanceOf(AuthorizationRequestRejectedException.class);
        assertThatThrownBy(() -> validator.validate(validRequest(), null))
                .isInstanceOf(AuthorizationRequestRejectedException.class);
        assertThatThrownBy(() -> new AuthorizationCodeRedemption(null, digest(), "issuer"))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AuthorizationCodeRedemption(new EmptyConsumptionRepository(), digest(), ""))
                .isInstanceOf(IllegalArgumentException.class);
        var redemption = new AuthorizationCodeRedemption(new EmptyConsumptionRepository(), digest(), "issuer");
        var verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assertThat(redemption.redeem(new AuthorizationCodeRedemptionCommand(
                "authorization_code", null, "client", "redirect", verifier, "cor_0123456789012345"))).isEmpty();
        assertThat(redemption.redeem(new AuthorizationCodeRedemptionCommand(
                "authorization_code", "code", "client", "redirect", "x".repeat(129),
                "cor_0123456789012345"))).isEmpty();
        assertThat(redemption.redeem(new AuthorizationCodeRedemptionCommand(
                "authorization_code", "code", "client", "redirect", "!".repeat(43),
                "cor_0123456789012345"))).isEmpty();
    }

    private static AuthorizationRequestCommand validRequest() {
        return new AuthorizationRequestCommand("dutch-mobile", "code", "dutch://oauth/callback", "member:read",
                "https://api.dutch.invalid", "state_0123456789", "nonce_0123456789",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "S256");
    }
    private static AuthorizationRequestCommand copy(AuthorizationRequestCommand ignored, String client, String response,
            String redirect, String scope, String resource, String state, String nonce, String challenge, String method) {
        return new AuthorizationRequestCommand(client, response, redirect, scope, resource, state, nonce, challenge, method);
    }
    private static RegistrationManifest registration() {
        return new RegistrationManifest(1, "dutch-development", "Dutch", "development",
                new RegistrationManifest.Client("dutch-mobile", "NATIVE_PUBLIC", List.of("dutch://oauth/callback"),
                        List.of("authorization_code"), List.of("S256"), "EXTERNAL"),
                new RegistrationManifest.Resource("dutch-api", "https://api.dutch.invalid", List.of("member:read")),
                new RegistrationManifest.SecurityPolicy(1, true, "S256", List.of("authorization_code"), List.of()));
    }
    private static HmacAuthorizationCodeDigestCapability digest() {
        return new HmacAuthorizationCodeDigestCapability("test", (short) 1,
                Map.of((short) 1, key()), Map.of((short) 1, "test://key/1"));
    }
    private static byte[] key() { return "authorization-code-test-key-00001".getBytes(StandardCharsets.US_ASCII); }

    private static final class EmptyConsumptionRepository implements AuthorizationCodeConsumptionRepository {
        public Optional<AuthorizationCodeProtection> findProtection(String codeId) { return Optional.empty(); }
        public Optional<ConsumedAuthorization> consume(AuthorizationCodeConsumption command) { return Optional.empty(); }
    }

    private static AuthorizationCodeDigestCapability capability(CapabilityMetadata metadata,
            CapabilitySelfCheck selfCheck, Set<Short> readable) {
        return new AuthorizationCodeDigestCapability() {
            public ProtectedAuthorizationCode protect(String id, byte[] secret) { throw new UnsupportedOperationException(); }
            public boolean matches(String id, byte[] secret, short version, byte[] expected) { return false; }
            public short keyVersion() { return 1; }
            public Set<Short> readableKeyVersions() { return readable; }
            public Map<Short, String> keyReferences() { return Map.of((short) 1, "test://key/1"); }
            public CapabilityMetadata metadata() { return metadata; }
            public CapabilitySelfCheck selfCheck() { return selfCheck; }
        };
    }
}
