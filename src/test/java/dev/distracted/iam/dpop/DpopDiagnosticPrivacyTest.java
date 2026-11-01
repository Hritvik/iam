package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;

import dev.distracted.iam.token.DpopKeyThumbprint;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class DpopDiagnosticPrivacyTest {
    @Test void renderingsAndJacksonDiagnosticsExcludeAllCredentialAndReplayCanaries() throws Exception {
        var values = java.util.List.of("code-canary-value", "verifier-canary-value", "proof-canary-value",
                "nonce_canary_abcdefghijklmnopqrstuvwxyzAB", "jti-canary-value-1234567890",
                java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[32]),
                "trusted-network-canary");
        var command = new TokenEndpointCommand("authorization_code", values.get(0), "dutch://oauth/callback",
                "dutch-mobile", values.get(1), values.get(2), "cor_abcdefghijklmnop", values.get(6));
        var proof = new VerifiedDpopProof("POST", "https://iam.example/oauth2/token", Instant.EPOCH,
                values.get(4), values.get(3), values.get(5));
        var nonce = new DpopNonceMaterial("dpn_abcdefghijklmnopqrstuv", "a".repeat(43));
        var outcome = new TokenEndpointOutcome.Challenge(values.get(3));
        var thumbprint = new DpopKeyThumbprint(values.get(5));
        var mapper = new ObjectMapper();

        var diagnostics = command + "\n" + proof + "\n" + nonce + "\n" + outcome + "\n" + thumbprint
                + "\n" + mapper.writeValueAsString(command) + "\n" + mapper.writeValueAsString(proof)
                + "\n" + mapper.writeValueAsString(nonce) + "\n" + mapper.writeValueAsString(outcome)
                + "\n" + mapper.writeValueAsString(thumbprint);

        assertThat(diagnostics).doesNotContain(values.toArray(String[]::new));
    }
}
