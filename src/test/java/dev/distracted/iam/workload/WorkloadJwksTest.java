package dev.distracted.iam.workload;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import dev.distracted.iam.token.JwksPublisher;
import dev.distracted.iam.token.SecureAccessTokenMaterialGenerator;
import dev.distracted.iam.token.web.JwksController;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class WorkloadJwksTest {
    private static final String AUDIENCE = "https://iam.distracted.invalid/internal/onboarding";
    private static final String WORKLOAD_ID = "wl_0123456789abcdefghijklmnop";
    private static final Instant NOW = Instant.parse("2026-11-08T00:00:00Z");

    @Test
    void publishesTheWorkloadKeyAtThePlatformJwksAndVerifiesIssuedTokens() throws Exception {
        var pair = pair();
        var properties = properties(pair, "workload-key-1");
        var publicKey = WorkloadKeys.publicKey("workload-key-1",
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        var publisher = JwksPublisher.fromPublicKeys(List.of(publicKey));

        assertThat(publisher.document().keys()).extracting(value -> value.get("kid"))
                .containsExactly("workload-key-1");

        var mvc = MockMvcBuilders.standaloneSetup(new JwksController(publisher)).build();
        mvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value("workload-key-1"))
                .andExpect(jsonPath("$.keys[0].alg").value("ES256"))
                .andExpect(jsonPath("$.keys[0].kty").value("EC"));

        var issuer = new WorkloadAccessTokenIssuer(
                properties, new SecureAccessTokenMaterialGenerator(new SecureRandom()),
                Clock.fixed(NOW, ZoneOffset.UTC));
        var verifier = new WorkloadAccessTokenVerifier(properties, Clock.fixed(NOW, ZoneOffset.UTC));
        var token = issuer.issue(WORKLOAD_ID, AUDIENCE, "iam:onboarding:read");
        assertThat(verifier.verify(token, AUDIENCE, "iam:onboarding:read").appRegistrationId())
                .isEqualTo("dutch-development");

        var stale = new WorkloadAccessTokenVerifier(
                properties(pair(), "stale-key-1"), Clock.fixed(NOW, ZoneOffset.UTC));
        assertThatThrownBy(() -> stale.verify(token, AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
    }

    @Test
    void refusesUnusablePublishedKeys() throws Exception {
        var pair = pair();
        assertThatThrownBy(() -> JwksPublisher.fromPublicKeys(List.of()))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> JwksPublisher.fromPublicKeys(List.of(
                publicKey(pair, "workload-key-1", JWSAlgorithm.ES256, KeyUse.SIGNATURE, true))))
                .as("private keys are never published")
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> JwksPublisher.fromPublicKeys(List.of(
                publicKey(pair, "workload-key-1", JWSAlgorithm.RS256, KeyUse.SIGNATURE, false))))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> JwksPublisher.fromPublicKeys(List.of(
                publicKey(pair, "workload-key-1", JWSAlgorithm.ES256, KeyUse.ENCRYPTION, false))))
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> JwksPublisher.fromPublicKeys(List.of(
                publicKey(pair, "workload-key-1", JWSAlgorithm.ES256, KeyUse.SIGNATURE, false),
                publicKey(pair, "workload-key-1", JWSAlgorithm.ES256, KeyUse.SIGNATURE, false))))
                .as("duplicate key ids are rejected")
                .isInstanceOf(RuntimeException.class);
        assertThatThrownBy(() -> new WorkloadPublicKey(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new WorkloadPublicKey(
                publicKey(pair, "workload-key-1", JWSAlgorithm.ES256, KeyUse.SIGNATURE, true)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static WorkloadIdentityProperties properties(KeyPair pair, String keyId) {
        var publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        return new WorkloadIdentityProperties(
                true,
                "https://iam.distracted.invalid",
                300,
                30,
                new WorkloadIdentityProperties.Signing(
                        keyId, Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()), publicKey),
                List.of(new WorkloadIdentityProperties.TrustedKey(keyId, publicKey)),
                List.of(new WorkloadIdentityProperties.Binding(
                        WORKLOAD_ID, "dutch-development", "ums-ingestion",
                        List.of(AUDIENCE), List.of("iam:onboarding:read"))));
    }

    private static ECKey publicKey(KeyPair pair, String keyId, JWSAlgorithm algorithm, KeyUse use, boolean privateKey) {
        var builder = new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) pair.getPublic())
                .keyID(keyId)
                .keyUse(use)
                .algorithm(algorithm);
        if (privateKey) {
            builder.privateKey((java.security.interfaces.ECPrivateKey) pair.getPrivate());
        }
        return builder.build();
    }

    private static KeyPair pair() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

}
