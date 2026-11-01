package dev.distracted.iam.token.web;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import dev.distracted.iam.token.AccessTokenSigningCapability;
import dev.distracted.iam.token.JwksPublisher;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class JwksControllerTest {
    @Test void getHeadAndConditionalRequestHaveExactCacheAndBodyBehavior() throws Exception {
        var key = new ECKeyGenerator(Curve.P_256).keyID("signing01")
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
        var publisher = new JwksPublisher(new Signer(key));
        var mvc = MockMvcBuilders.standaloneSetup(new JwksController(publisher)).build();

        mvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk()).andExpect(content().contentType("application/json"))
                .andExpect(header().string(HttpHeaders.ETAG, publisher.etag()))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "public, max-age=300, must-revalidate"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().doesNotExist(HttpHeaders.SET_COOKIE))
                .andExpect(content().bytes(publisher.json()));
        mvc.perform(head("/oauth2/jwks")).andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.ETAG, publisher.etag())).andExpect(content().string(""));
        mvc.perform(get("/oauth2/jwks").header(HttpHeaders.IF_NONE_MATCH, publisher.etag()))
                .andExpect(status().isNotModified()).andExpect(content().string(""));
    }

    private record Signer(ECKey key) implements AccessTokenSigningCapability {
        @Override public dev.distracted.iam.token.AccessTokenSigningSnapshot snapshot() {
            return new dev.distracted.iam.token.AccessTokenSigningSnapshot(
                    "ACCESS_TOKEN_SIGNING", "ES256", key.getKeyID(), List.of(key.toPublicJWK()), true, this::sign);
        }
        private byte[] sign(byte[] input) {
            try { return new ECDSASigner(key).sign(new JWSHeader(JWSAlgorithm.ES256), input).decode(); }
            catch (Exception exception) { throw new IllegalStateException(exception); }
        }
    }
}
