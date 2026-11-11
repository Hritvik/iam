package dev.distracted.iam.dpop.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.distracted.iam.bootstrap.IamApplication;
import dev.distracted.iam.dpop.TokenEndpointOrchestrator;
import dev.distracted.iam.dpop.TokenEndpointOutcome;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(classes = {IamApplication.class, DpopTokenEndpointHttpTest.Support.class}, properties = {
        "iam.dpop.enabled=true",
        "iam.dpop.persistence.enabled=false",
        "spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
                + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"
})
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class DpopTokenEndpointHttpTest {
    @Autowired MockMvc mvc;
    @Autowired io.micrometer.core.instrument.MeterRegistry meterRegistry;

    @Test void returnsAStandardNonceChallengeWithoutOpeningOtherMethods() throws Exception {
        mvc.perform(valid("challenge.proof.compact"))
                .andExpect(status().isBadRequest())
                .andExpect(header().string("DPoP-Nonce", "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH"))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("Pragma", "no-cache"))
                .andExpect(header().string("X-Correlation-ID", "cor_abcdefghijklmnop"))
                .andExpect(header().doesNotExist("Set-Cookie"))
                .andExpect(jsonPath("$.error").value("use_dpop_nonce"));
        mvc.perform(get("/oauth2/token")).andExpect(status().isNotFound());
    }

    @Test void returnsOnlyTheClosedDpopTokenResponse() throws Exception {
        mvc.perform(valid("valid.proof.compact"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(header().string("X-Correlation-ID", "cor_abcdefghijklmnop"))
                .andExpect(jsonPath("$.access_token").value("compact.access.token"))
                .andExpect(jsonPath("$.token_type").value("DPoP"))
                .andExpect(jsonPath("$.expires_in").value(300))
                .andExpect(jsonPath("$.scope").value("member:read"))
                .andExpect(jsonPath("$.refresh_token").doesNotExist())
                .andExpect(jsonPath("$.id_token").doesNotExist());
    }

    @Test void returnsTheRotatedRefreshTokenForTheRefreshGrant() throws Exception {
        mvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", "a".repeat(43))
                        .param("client_id", "dutch-mobile")
                        .header("DPoP", "refresh.proof.compact")
                        .header("X-Correlation-ID", "cor_abcdefghijklmnop"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").value("compact.access.token"))
                .andExpect(jsonPath("$.refresh_token").value("refresh_" + "a".repeat(43)))
                .andExpect(jsonPath("$.id_token").doesNotExist());
    }

    @Test void mapsInvalidProofsToTheClosedDpopErrorWithoutInternalDetails() throws Exception {
        mvc.perform(valid("invalid.proof.compact"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_dpop_proof"))
                .andExpect(jsonPath("$.error_description").value("DPoP proof is invalid"))
                .andExpect(jsonPath("$.correlation_id").value("cor_abcdefghijklmnop"))
                .andExpect(header().string("X-Correlation-ID", "cor_abcdefghijklmnop"))
                .andExpect(header().doesNotExist("DPoP-Nonce"));
    }

    @Test void requestCredentialsNeverEnterConfiguredLogsMetricsOrErrorResponses(CapturedOutput output)
            throws Exception {
        var canaries = java.util.List.of("authorization-code-canary", "verifier-canary-value-abcdefghijklmnop",
                "challenge.proof-canary.compact", "network-canary", "thumbprint-canary", "jti-canary");
        var result = mvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code").param("code", canaries.get(0))
                        .param("redirect_uri", "dutch://oauth/callback").param("client_id", "dutch-mobile")
                        .param("code_verifier", canaries.get(1)).header("DPoP", canaries.get(2))
                        .header("X-Correlation-ID", "cor_abcdefghijklmnop"))
                .andExpect(status().isBadRequest()).andReturn();
        var diagnostics = result.getResponse().getContentAsString() + result.getResponse().getHeaderNames()
                + output.getAll() + meterRegistry.getMeters().stream().map(value -> value.getId().toString()).toList();
        assertThat(diagnostics).doesNotContain(canaries.toArray(String[]::new));
    }

    @Test void generatesAndEchoesOneCorrelationIdWhenTheCallerOmitsIt() throws Exception {
        var result = mvc.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code").param("code", "code-placeholder")
                        .param("redirect_uri", "dutch://oauth/callback").param("client_id", "dutch-mobile")
                        .param("code_verifier", "verifier-placeholder-value-abcdefghijklmnop")
                        .header("DPoP", "invalid.proof.compact"))
                .andExpect(status().isBadRequest()).andReturn();
        assertThat(result.getResponse().getHeader("X-Correlation-ID"))
                .matches("^cor_[A-Za-z0-9_-]{16,128}$");
    }

    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder valid(String proof) {
        return post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", "acd_abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO12")
                .param("redirect_uri", "dutch://oauth/callback").param("client_id", "dutch-mobile")
                .param("code_verifier", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ")
                .header("DPoP", proof).header("X-Correlation-ID", "cor_abcdefghijklmnop");
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Support {
        @Bean TokenEndpointOrchestrator testTokenEndpointOrchestrator() {
            return command -> {
                if (command.dpopProof().startsWith("invalid")) {
                    throw new dev.distracted.iam.dpop.DpopProofRejectedException();
                }
                if (command.dpopProof().startsWith("challenge")) {
                    return new TokenEndpointOutcome.Challenge("nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH");
                }
                return command.dpopProof().startsWith("refresh")
                        ? new TokenEndpointOutcome.Success("compact.access.token", 300, "member:read",
                                "refresh_" + "a".repeat(43))
                        : new TokenEndpointOutcome.Success("compact.access.token", 300, "member:read");
            };
        }
    }
}
