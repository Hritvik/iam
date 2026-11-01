package dev.distracted.iam.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import dev.distracted.iam.bootstrap.IamApplication;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest(classes = {IamApplication.class, TokenEndpointHttpTest.Support.class}, properties = {
    "iam.token.enabled=true", "iam.token.issuer-authority.enabled=false",
    "spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
            + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"
})
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class TokenEndpointHttpTest {
    @Autowired MockMvc mvc;
    @Autowired JwksPublisher publisher;
    @Autowired io.micrometer.core.instrument.MeterRegistry meterRegistry;

    @Test void getAndHeadHaveParityAndConditionalGetIsBodyless() throws Exception {
        var getResult = mvc.perform(get("/oauth2/jwks")).andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "public, max-age=300, must-revalidate"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE)).andReturn();
        mvc.perform(head("/oauth2/jwks")).andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, getResult.getResponse().getContentType()))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL,
                        getResult.getResponse().getHeader(HttpHeaders.CACHE_CONTROL)))
                .andExpect(header().string(HttpHeaders.ETAG, getResult.getResponse().getHeader(HttpHeaders.ETAG)))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE)).andExpect(content().string(""));
        mvc.perform(get("/oauth2/jwks").header(HttpHeaders.IF_NONE_MATCH, publisher.etag()))
                .andExpect(status().isNotModified()).andExpect(content().string(""));
    }

    @ParameterizedTest
    @MethodSource("closedEndpoints")
    void everyExcludedProtocolEndpointRemainsDenied(MockHttpServletRequestBuilder request) throws Exception {
        mvc.perform(request.with(user("authenticated-but-not-authorized")))
                .andExpect(status().isForbidden())
                .andExpect(header().doesNotExist("Location"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE));
    }

    @Test void configuredHttpLogsMetricsHeadersAndBodyDoNotReflectSensitiveCanaries(CapturedOutput output)
            throws Exception {
        var canaries = List.of("raw-email-canary@example.test", "+15550001111", "hid_global_canary",
                "credential-canary", "authorization-code-canary", "refresh-token-canary",
                "session-token-canary", "private-key-canary", "provider-reference-canary", "aps_cross_app_canary");
        var result = mvc.perform(get("/oauth2/jwks").queryParam("ignored", String.join("-", canaries)))
                .andExpect(status().isOk()).andReturn();
        var diagnostics = result.getResponse().getContentAsString() + "\n"
                + result.getResponse().getHeaderNames() + "\n"
                + result.getResponse().getHeaderValues(HttpHeaders.ETAG) + "\n"
                + output.getAll() + "\n"
                + meterRegistry.getMeters().stream().map(meter -> meter.getId().toString()).toList();
        assertThat(diagnostics).doesNotContain(canaries.toArray(String[]::new));
    }

    static List<MockHttpServletRequestBuilder> closedEndpoints() {
        return List.of(post("/oauth2/token"), get("/.well-known/openid-configuration"), get("/userinfo"),
                post("/oauth2/introspect"), post("/oauth2/revoke"), post("/oauth2/device_authorization"),
                post("/connect/register"));
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Support {
        @Bean AccessTokenSigningCapability testAccessTokenSigningCapability() throws Exception {
            var key = new ECKeyGenerator(Curve.P_256).keyID("httpkey01")
                    .keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
            return new TestSigner(key);
        }
    }

    private record TestSigner(ECKey key) implements AccessTokenSigningCapability {
        @Override public AccessTokenSigningSnapshot snapshot() {
            return new AccessTokenSigningSnapshot("ACCESS_TOKEN_SIGNING", "ES256", key.getKeyID(),
                    List.of(key.toPublicJWK()), true, this::sign);
        }
        private byte[] sign(byte[] input) {
            try { return new ECDSASigner(key).sign(new JWSHeader(JWSAlgorithm.ES256), input).decode(); }
            catch (Exception exception) { throw new IllegalStateException(exception); }
        }
    }
}
