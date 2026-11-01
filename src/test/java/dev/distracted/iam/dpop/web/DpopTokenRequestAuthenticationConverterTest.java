package dev.distracted.iam.dpop.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

class DpopTokenRequestAuthenticationConverterTest {
    @Test void convertsOnlyTheClosedAuthorizationCodeFormAndSingleProofHeader() {
        var request = validRequest();
        var authentication = (DpopTokenRequestAuthenticationToken)
                new DpopTokenRequestAuthenticationConverter(8192, 4096).convert(request);

        assertThat(authentication.command().grantType()).isEqualTo("authorization_code");
        assertThat(authentication.command().clientId()).isEqualTo("dutch-mobile");
        assertThat(authentication.command().dpopProof()).isEqualTo("proof.compact.value");
        assertThat(authentication.command().trustedNetworkContext()).isEqualTo("127.0.0.1");
    }

    @Test void rejectsQueryUnknownDuplicateSecretAuthorizationAndMissingProofInputs() {
        var converter = new DpopTokenRequestAuthenticationConverter(8192, 4096);
        var query = validRequest();
        query.setQueryString("code=confused");
        var unknown = validRequest();
        unknown.addParameter("extra", "x");
        var duplicate = validRequest();
        duplicate.addParameter("code", "second");
        var clientCredentialRequest = validRequest();
        clientCredentialRequest.addParameter("client_" + "secret", "forbidden");
        var basic = validRequest();
        basic.addHeader("Authorization", "Basic redacted");
        var missingProof = validRequest();
        missingProof.removeHeader("DPoP");

        for (var request : java.util.List.of(query, unknown, duplicate, clientCredentialRequest, basic, missingProof)) {
            assertThatThrownBy(() -> converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class);
        }
    }

    @Test void rejectsMethodMediaSizeProofAndGrantBoundaryViolations() {
        var converter = new DpopTokenRequestAuthenticationConverter(8192, 4096);
        var get = validRequest();
        get.setMethod("GET");
        var noMedia = validRequest();
        noMedia.setContentType(null);
        var wrongMedia = validRequest();
        wrongMedia.setContentType("application/json");
        var oversizedRaw = validRequest();
        oversizedRaw.setContent(new byte[8193]);
        var oversizedDecoded = validRequest();
        oversizedDecoded.setParameter("code", "x".repeat(4096));
        var duplicateProof = validRequest();
        duplicateProof.addHeader("DPoP", "second.proof.value");
        var blankProof = validRequest();
        blankProof.removeHeader("DPoP");
        blankProof.addHeader("DPoP", " ");
        var unsupported = validRequest();
        unsupported.setParameter("grant_type", "refresh_token");
        for (var request : java.util.List.of(get, noMedia, wrongMedia, oversizedRaw, oversizedDecoded,
                duplicateProof, blankProof, unsupported)) {
            assertThatThrownBy(() -> converter.convert(request)).isInstanceOf(OAuth2AuthenticationException.class);
        }
        assertThatThrownBy(() -> new DpopTokenRequestAuthenticationConverter(1023, 512))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopTokenRequestAuthenticationConverter(16385, 512))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopTokenRequestAuthenticationConverter(8192, 511))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopTokenRequestAuthenticationConverter(8192, 8193))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test void usesOnlyTheContainerTrustedRemoteAddressAndIgnoresForwardedSpoofing() {
        var request = validRequest();
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("X-Forwarded-For", "198.51.100.99");
        var authentication = (DpopTokenRequestAuthenticationToken)
                new DpopTokenRequestAuthenticationConverter(8192, 4096).convert(request);
        assertThat(authentication.command().trustedNetworkContext()).isEqualTo("203.0.113.10");
        assertThat(authentication.command().toString()).doesNotContain("203.0.113.10", "198.51.100.99");
    }

    private static MockHttpServletRequest validRequest() {
        var request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.setContentType("application/x-www-form-urlencoded");
        request.addParameter("grant_type", "authorization_code");
        request.addParameter("code", "acd_abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO12");
        request.addParameter("redirect_uri", "dutch://oauth/callback");
        request.addParameter("client_id", "dutch-mobile");
        request.addParameter("code_verifier", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ");
        request.addHeader("DPoP", "proof.compact.value");
        request.addHeader("X-Correlation-ID", "cor_abcdefghijklmnop");
        return request;
    }
}
