package dev.distracted.iam.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.authentication;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.distracted.iam.bootstrap.IamApplication;
import dev.distracted.iam.identity.IdentityReference;
import dev.distracted.iam.registration.RegistrationManifest;
import dev.distracted.iam.registration.RegistrationRegistry;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(classes = {IamApplication.class, AuthorizationEndpointHttpTest.Support.class}, properties = {
    "iam.authorization.enabled=true", "iam.issuer=https://iam.distracted.invalid",
    "spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
            + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"
})
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class AuthorizationEndpointHttpTest {
    @Autowired MockMvc mvc;
    @Autowired io.micrometer.core.instrument.MeterRegistry meterRegistry;

    @Test
    void authenticatedExactRequestRedirectsOnlyWithCodeAndOriginalState() throws Exception {
        mvc.perform(request("dutch://oauth/callback").with(authentication(identity())))
                .andExpect(status().isFound())
                .andExpect(header().string("Cache-Control", org.hamcrest.Matchers.containsString("no-store")))
                .andExpect(header().string("Location", org.hamcrest.Matchers.matchesPattern(
                        "^dutch://oauth/callback\\?code=acd_[A-Za-z0-9_-]{22,128}\\.[A-Za-z0-9_-]{43}&state=state_0123456789$")));
    }

    @Test
    void unauthenticatedRequestIsCorrelatedAndCreatesNoRedirect() throws Exception {
        mvc.perform(request("dutch://oauth/callback").header("X-Correlation-Id", "request-correlation"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().doesNotExist("Location"))
                .andExpect(header().string("X-Correlation-Id", "request-correlation"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "DUTCH://oauth/callback", "dutch://oauth/callback/", "dutch://oauth/callback?next=x",
        "dutch://oauth/callback#fragment", "dutch://user@oauth/callback", "dutch://oauth/callbac",
        "dutch://oauth/callback.evil", "midas://oauth/callback", "https://oauth/callback",
        "%64utch://oauth/callback", "dutch%253A%252F%252Foauth%252Fcallback"
    })
    void redirectNearMissNeverReceivesACode(String redirect) throws Exception {
        mvc.perform(request(redirect).with(authentication(identity())))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("Location"));
    }

    @Test
    void servletFormDecodingAcceptsExactlyOnceEncodedRedirectFromRawQuery() throws Exception {
        mvc.perform(rawAuthorizationRequest("dutch://oauth/callback")
                        .with(authentication(identity())))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", org.hamcrest.Matchers.startsWith(
                        "dutch://oauth/callback?code=")));
    }

    @Test
    void servletFormDecodingRejectsDoubleEncodedRedirectFromRawQuery() throws Exception {
        mvc.perform(rawAuthorizationRequest("dutch%3A%2F%2Foauth%2Fcallback")
                        .with(authentication(identity())))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("Location"));
    }

    @Test
    void duplicateUnknownParametersAndWrongPrincipalFailClosed() throws Exception {
        mvc.perform(request("dutch://oauth/callback").param("state", "second-state-value").with(authentication(identity())))
                .andExpect(status().isBadRequest()).andExpect(header().doesNotExist("Location"));
        mvc.perform(request("dutch://oauth/callback").param("unknown", "value").with(authentication(identity())))
                .andExpect(status().isBadRequest()).andExpect(header().doesNotExist("Location"));
        mvc.perform(request("dutch://oauth/callback").with(user("not-an-iam-principal")))
                .andExpect(status().isBadRequest()).andExpect(header().doesNotExist("Location"));
    }

    @Test
    void duplicateScopeTokenFailsBeforeSetConversion() throws Exception {
        mvc.perform(requestWithScope("member:read member:read")
                        .with(authentication(identity())))
                .andExpect(status().isBadRequest())
                .andExpect(header().doesNotExist("Location"));
    }

    @Test
    void tokenAndUnsafeAuthorizationMethodsRemainClosed() throws Exception {
        mvc.perform(post("/oauth2/authorize").with(authentication(identity())))
                .andExpect(status().isForbidden()).andExpect(header().doesNotExist("Location"));
        mvc.perform(post("/oauth2/token").with(authentication(identity())))
                .andExpect(status().isForbidden()).andExpect(header().doesNotExist("Location"));
        mvc.perform(get("/oauth2/jwks").with(authentication(identity())))
                .andExpect(status().isForbidden()).andExpect(header().doesNotExist("Location"));
        mvc.perform(get("/oauth2/%61uthorize").with(authentication(identity())))
                .andExpect(status().is4xxClientError()).andExpect(header().doesNotExist("Location"));
    }

    @Test
    void protectedAuthorizationValuesNeverEnterLogsOrMetricIdentifiers(CapturedOutput output) throws Exception {
        var result = mvc.perform(request("dutch://oauth/callback").with(authentication(identity())))
                .andExpect(status().isFound()).andReturn();
        var location = result.getResponse().getHeader("Location");
        var rawCode = location.substring(location.indexOf("code=") + 5, location.indexOf("&state="));
        var metrics = meterRegistry.getMeters().stream().map(meter -> meter.getId().toString())
                .collect(java.util.stream.Collectors.joining("\n"));

        assertThat(output.getAll()).doesNotContain(rawCode, "state_0123456789", "nonce_0123456789",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "hid_0123456789012345678901");
        assertThat(metrics).doesNotContain(rawCode, "state_0123456789", "nonce_0123456789",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "hid_0123456789012345678901");
    }

    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request(String redirect) {
        return get("/oauth2/authorize").param("client_id", "dutch-mobile").param("response_type", "code")
                .param("redirect_uri", redirect).param("scope", "member:read")
                .param("resource", "https://api.dutch.invalid").param("state", "state_0123456789")
                .param("nonce", "nonce_0123456789")
                .param("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .param("code_challenge_method", "S256");
    }
    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder rawAuthorizationRequest(
            String redirect) {
        return get("/oauth2/authorize?client_id=dutch-mobile&response_type=code&redirect_uri={redirect}"
                + "&scope={scope}&resource={resource}"
                + "&state=state_0123456789&nonce=nonce_0123456789"
                + "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
                redirect, "member:read", "https://api.dutch.invalid");
    }
    private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder requestWithScope(String scope) {
        return get("/oauth2/authorize").param("client_id", "dutch-mobile").param("response_type", "code")
                .param("redirect_uri", "dutch://oauth/callback").param("scope", scope)
                .param("resource", "https://api.dutch.invalid").param("state", "state_0123456789")
                .param("nonce", "nonce_0123456789")
                .param("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .param("code_challenge_method", "S256");
    }
    private static UsernamePasswordAuthenticationToken identity() {
        return UsernamePasswordAuthenticationToken.authenticated(
                new IamIdentityPrincipal(new IdentityReference("hid_0123456789012345678901")), null, List.of());
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class Support {
        @Bean JdbcTemplate jdbcTemplate() {
            return org.mockito.Mockito.mock(JdbcTemplate.class);
        }
        @Bean @org.springframework.context.annotation.Primary AuthorizationCodeRepository testAuthorizationCodeRepository() {
            return issue -> new AuthorizationIssueReceipt(
                    java.time.Instant.EPOCH, java.time.Instant.EPOCH.plusSeconds(120), 1);
        }
        @Bean AuthorizationCodeDigestCapability authorizationCodeDigestCapability() {
            return new HmacAuthorizationCodeDigestCapability("development", (short) 1,
                    Map.of((short) 1, "authorization-code-test-key-00001".getBytes(StandardCharsets.US_ASCII)),
                    Map.of((short) 1, "test://authorization-code/1"));
        }
        @Bean RegistrationRegistry registrationRegistry() {
            var registration = new RegistrationManifest(1, "dutch-development", "Dutch Development", "development",
                    new RegistrationManifest.Client("dutch-mobile", "NATIVE_PUBLIC", List.of("dutch://oauth/callback"),
                            List.of("authorization_code"), List.of("S256"), "EXTERNAL"),
                    new RegistrationManifest.Resource("dutch-api", "https://api.dutch.invalid", List.of("member:read")),
                    new RegistrationManifest.SecurityPolicy(1, true, "S256", List.of("authorization_code"),
                            List.of("verified_identifier", "usable_factor", "recovery_path")));
            return new RegistrationRegistry() {
                public Optional<RegistrationManifest> findByClientId(String id) { return Optional.of(registration); }
                public Optional<RegistrationManifest> findByAppId(String id) { return Optional.of(registration); }
                public Optional<RegistrationManifest> findByResourceId(String id) { return Optional.of(registration); }
                public Optional<RegistrationManifest> findByAudience(String id) { return Optional.of(registration); }
                public Optional<RegistrationManifest> findSoleRegistration() { return Optional.of(registration); }
                public dev.distracted.iam.registration.ReconciliationResult reconcile(
                        dev.distracted.iam.registration.ValidatedRegistration value) { throw new UnsupportedOperationException(); }
            };
        }
    }
}
