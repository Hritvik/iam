package dev.distracted.iam.messaging.relay.transport;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.token.SecureAccessTokenMaterialGenerator;
import dev.distracted.iam.workload.WorkloadAccessTokenIssuer;
import dev.distracted.iam.workload.WorkloadIdentityProperties;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class SelfIssuedWorkloadTokenSupplierTest {
    private static final String AUDIENCE = "https://ums.localhost/internal/v1/iam/events";
    private static final String WORKLOAD_ID = "wl_0123456789abcdefghijklmnop";

    @Test
    void mintsADistinctTokenForEveryDeliveryAttempt() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        var properties = new WorkloadIdentityProperties(
                true,
                "https://iam.distracted.invalid",
                300,
                30,
                new WorkloadIdentityProperties.Signing(
                        "workload-key-1",
                        Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                        Base64.getEncoder().encodeToString(pair.getPublic().getEncoded())),
                List.of(new WorkloadIdentityProperties.TrustedKey(
                        "workload-key-1", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()))),
                List.of(new WorkloadIdentityProperties.Binding(
                        WORKLOAD_ID, "dutch-development", "iam-relay",
                        List.of(AUDIENCE), List.of("ums:onboarding:write"))));
        var issuer = new WorkloadAccessTokenIssuer(
                properties, new SecureAccessTokenMaterialGenerator(new SecureRandom()),
                Clock.fixed(Instant.parse("2026-11-08T00:00:00Z"), ZoneOffset.UTC));
        var supplier = new SelfIssuedWorkloadTokenSupplier(
                issuer, WORKLOAD_ID, AUDIENCE, "ums:onboarding:write");

        var first = supplier.token();
        var second = supplier.token();

        assertThat(second).isNotEqualTo(first);
        assertThat(jti(first)).isNotEqualTo(jti(second));
    }

    private static String jti(String compact) throws Exception {
        var payload = compact.split("\\.")[1];
        var json = new ObjectMapper().readTree(new String(Base64.getUrlDecoder().decode(payload),
                StandardCharsets.UTF_8));
        return json.required("jti").textValue();
    }
}
