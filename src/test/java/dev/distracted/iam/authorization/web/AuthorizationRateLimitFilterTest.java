package dev.distracted.iam.authorization.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.distracted.iam.authorization.AuthorizationEndpointLimitsProperties;
import java.time.Duration;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

class AuthorizationRateLimitFilterTest {
    @Test
    void rejectsRequestsBeyondTheConfiguredClientAndAddressWindow() throws Exception {
        var filter = new AuthorizationRateLimitFilter(
                new AuthorizationEndpointLimitsProperties(4096, 2, Duration.ofMinutes(1)), new JsonMapper());

        assertThat(invoke(filter).getStatus()).isEqualTo(200);
        assertThat(invoke(filter).getStatus()).isEqualTo(200);
        var rejected = invoke(filter);
        assertThat(rejected.getStatus()).isEqualTo(429);
        assertThat(rejected.getContentAsString()).contains("rate_limit_exceeded").doesNotContain("dutch-mobile");
    }

    @Test
    void converterRejectsAnOversizedOtherwiseClosedRequest() {
        var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.addParameter("client_id", "dutch-mobile");
        request.addParameter("response_type", "code");
        request.addParameter("redirect_uri", "dutch://oauth/callback");
        request.addParameter("scope", "member:read");
        request.addParameter("resource", "https://" + "x".repeat(5000));
        request.addParameter("state", "state_0123456789");
        request.addParameter("nonce", "nonce_0123456789");
        request.addParameter("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        request.addParameter("code_challenge_method", "S256");

        assertThatThrownBy(() -> new AuthorizationRequestAuthenticationConverter(4096).convert(request))
                .isInstanceOf(org.springframework.security.oauth2.core.OAuth2AuthenticationException.class);
    }

    @Test
    void expiredWindowAllowsTheClientAgain() throws Exception {
        var clock = new MutableClock();
        var filter = new AuthorizationRateLimitFilter(
                new AuthorizationEndpointLimitsProperties(4096, 1, Duration.ofSeconds(1)), new JsonMapper(), clock);
        assertThat(invoke(filter).getStatus()).isEqualTo(200);
        assertThat(invoke(filter).getStatus()).isEqualTo(429);
        clock.now = clock.now.plusSeconds(1);
        assertThat(invoke(filter).getStatus()).isEqualTo(200);
    }

    @Test
    void limiterCapsAttackerControlledKeyCardinality() throws Exception {
        var filter = new AuthorizationRateLimitFilter(
                new AuthorizationEndpointLimitsProperties(4096, 1, Duration.ofMinutes(15)), new JsonMapper());
        for (int index = 0; index < 10_000; index++) {
            assertThat(invoke(filter, "192.0.2." + index).getStatus()).isEqualTo(200);
        }
        assertThat(invoke(filter, "198.51.100.1").getStatus()).isEqualTo(429);
    }

    private static MockHttpServletResponse invoke(AuthorizationRateLimitFilter filter) throws Exception {
        return invoke(filter, "192.0.2.1");
    }

    private static MockHttpServletResponse invoke(AuthorizationRateLimitFilter filter, String address) throws Exception {
        var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setRemoteAddr(address);
        request.addParameter("client_id", "dutch-mobile");
        var response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain());
        return response;
    }

    private static final class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");
        @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
