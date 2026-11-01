package dev.distracted.iam.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import dev.distracted.iam.registration.RegistrationManifest;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

class HumanAccessTokenVerifierTest {
    private static final Instant NOW = Instant.parse("2026-10-25T00:00:00Z");
    private ECKey key;
    private HumanAccessTokenVerifier verifier;

    @BeforeEach void setUp() throws Exception {
        key = new ECKeyGenerator(Curve.P_256).keyID("signing01")
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
        verifier = new HumanAccessTokenVerifier(List.of(key.toPublicJWK()), Clock.fixed(NOW, ZoneOffset.UTC),
                "https://iam.distracted.dev", Duration.ofSeconds(30));
    }

    @Test void verifiesExactClaimsAndRejectsUnknownClaim() throws Exception {
        var claims = claims();
        var verified = verifier.verify(sign(claims, Map.of("typ", "at+jwt", "alg", "ES256", "kid", "signing01")),
                registration(), 4);
        assertThat(verified.subject().value()).isEqualTo("aps_AAAAAAAAAAAAAAAAAAAAAAAA");
        assertThat(verified.toString()).doesNotContain(verified.subject().value());

        claims.put("email", "pii-canary@example.test");
        assertThatThrownBy(() -> verifier.verify(sign(claims,
                Map.of("typ", "at+jwt", "alg", "ES256", "kid", "signing01")), registration(), 4))
                .isInstanceOf(HumanAccessTokenIssueException.class)
                .hasMessage("access token could not be issued");
    }

    @Test void rejectsWrongTypeAudienceSecurityVersionExpiryAndTampering() throws Exception {
        var cases = List.of(
                changed("iss", "https://wrong.example"),
                changed("app_id", "other-app"),
                changed("client_id", "other-client"),
                changed("aud", "https://wrong.example"),
                changed("token_profile", "other"),
                changed("token_version", 2),
                changed("token_version", 1.5),
                changed("token_version", new java.math.BigInteger("2147483648")),
                changed("security_version", new java.math.BigInteger("-2147483649")),
                changed("subject_kind", "identity"),
                changed("security_version", 5),
                changed("sub", "hid_global"),
                changed("scope", "member:write"),
                changed("scope", "member:read member:read"),
                changed("scope", "Member:read"),
                changed("jti", "short"),
                changed("iat", (double) NOW.getEpochSecond()),
                changed("exp", (double) NOW.plusSeconds(300).getEpochSecond()),
                changed("iat", new java.math.BigInteger("9223372036854775808")),
                changed("exp", new java.math.BigInteger("-9223372036854775809")),
                changed("iat", NOW.plusSeconds(31).getEpochSecond()),
                changed("exp", NOW.plusSeconds(30).getEpochSecond()),
                changed("exp", NOW.plusSeconds(901).getEpochSecond()),
                changed("cnf", Map.of()),
                changed("cnf", "not-an-object"),
                changed("cnf", Map.of("jkt", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "extra", "x")),
                changed("cnf", Map.of("jkt", "short")),
                changed("exp", NOW.minusSeconds(31).getEpochSecond()));
        for (var claims : cases) {
            assertThatThrownBy(() -> verifier.verify(sign(claims,
                    Map.of("typ", "at+jwt", "alg", "ES256", "kid", "signing01")), registration(), 4))
                    .isInstanceOf(HumanAccessTokenIssueException.class);
        }
        assertThatThrownBy(() -> verifier.verify(sign(claims(),
                Map.of("typ", "JWT", "alg", "ES256", "kid", "signing01")), registration(), 4))
                .isInstanceOf(HumanAccessTokenIssueException.class);
        assertThatThrownBy(() -> verifier.verify(sign(claims(),
                Map.of("typ", "at+jwt", "alg", "ES256", "kid", "signing01", "jwk", "forbidden")),
                registration(), 4)).isInstanceOf(HumanAccessTokenIssueException.class);
        assertThatThrownBy(() -> verifier.verify(sign(claims(),
                Map.of("typ", "at+jwt", "alg", "HS256", "kid", "signing01")), registration(), 4))
                .isInstanceOf(HumanAccessTokenIssueException.class);
        assertThatThrownBy(() -> verifier.verify(sign(claims(),
                Map.of("typ", "at+jwt", "alg", "ES256", "kid", "unknown01")), registration(), 4))
                .isInstanceOf(HumanAccessTokenIssueException.class);
        assertThatThrownBy(() -> verifier.verify(null, registration(), 4))
                .isInstanceOf(HumanAccessTokenIssueException.class);
        assertThatThrownBy(() -> verifier.verify("broken", registration(), 4))
                .isInstanceOf(HumanAccessTokenIssueException.class);
        var valid = sign(claims(), Map.of("typ", "at+jwt", "alg", "ES256", "kid", "signing01"));
        var tampered = valid.substring(0, valid.length() - 2) + "AA";
        assertThatThrownBy(() -> verifier.verify(tampered, registration(), 4))
                .isInstanceOf(HumanAccessTokenIssueException.class);
    }

    @Test void rejectsInvalidVerifierConfigurationAndNonDpopRegistration() throws Exception {
        assertThatThrownBy(() -> new HumanAccessTokenVerifier(null, Clock.systemUTC(),
                "https://iam.distracted.dev", Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenVerifier(List.of(), Clock.systemUTC(),
                "https://iam.distracted.dev", Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenVerifier(List.of(key.toPublicJWK(), key.toPublicJWK()),
                Clock.systemUTC(), "https://iam.distracted.dev", Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenVerifier(List.of(key.toPublicJWK()), Clock.systemUTC(),
                "https://iam.distracted.dev", Duration.ofSeconds(61))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenVerifier(List.of(key.toPublicJWK()), Clock.systemUTC(),
                "https://iam.distracted.dev", Duration.ofSeconds(-1))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenVerifier(List.of(key.toPublicJWK()), Clock.systemUTC(),
                "https://iam.distracted.dev", Duration.ofNanos(1))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenVerifier(List.of(key), Clock.systemUTC(),
                "https://iam.distracted.dev", Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
        var wrongUse = new ECKeyGenerator(Curve.P_256).keyID("wronguse01")
                .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION).algorithm(JWSAlgorithm.ES256)
                .generate().toPublicJWK();
        var wrongAlgorithm = new ECKeyGenerator(Curve.P_256).keyID("wrongalg01")
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256)
                .generate().toPublicJWK();
        assertThatThrownBy(() -> new HumanAccessTokenVerifier(List.of(wrongUse), Clock.systemUTC(),
                "https://iam.distracted.dev", Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new HumanAccessTokenVerifier(List.of(wrongAlgorithm), Clock.systemUTC(),
                "https://iam.distracted.dev", Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
        var source = registration();
        var bearerRegistration = new RegistrationManifest(source.manifestVersion(), source.appRegistrationId(),
                source.displayName(), source.environment(), source.client(), source.resource(),
                new RegistrationManifest.SecurityPolicy(1, false, "S256", List.of("authorization_code"), List.of()));
        assertThatThrownBy(() -> verifier.verify(sign(claims(),
                Map.of("typ", "at+jwt", "alg", "ES256", "kid", "signing01")), bearerRegistration, 4))
                .isInstanceOf(HumanAccessTokenIssueException.class);
    }

    private Map<String, Object> changed(String keyName, Object value) {
        var result = claims();
        result.put(keyName, value);
        return result;
    }

    private Map<String, Object> claims() {
        var result = new LinkedHashMap<String, Object>();
        result.put("iss", "https://iam.distracted.dev");
        result.put("sub", "aps_AAAAAAAAAAAAAAAAAAAAAAAA");
        result.put("aud", "https://api.dutch.example");
        result.put("iat", NOW.getEpochSecond());
        result.put("exp", NOW.plusSeconds(300).getEpochSecond());
        result.put("jti", "BBBBBBBBBBBBBBBBBBBBBB");
        result.put("client_id", "dutch-mobile");
        result.put("token_profile", "human_access");
        result.put("token_version", 1);
        result.put("subject_kind", "app_subject");
        result.put("scope", "member:read");
        result.put("app_id", "dutch-development");
        result.put("security_version", 4);
        result.put("cnf", Map.of("jkt", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
        return result;
    }

    private String sign(Map<String, Object> claims, Map<String, Object> header) throws Exception {
        var mapper = new ObjectMapper();
        var encodedHeader = Base64URL.encode(mapper.writeValueAsBytes(header));
        var encodedClaims = Base64URL.encode(mapper.writeValueAsBytes(claims));
        var input = (encodedHeader + "." + encodedClaims).getBytes(StandardCharsets.US_ASCII);
        var signature = new ECDSASigner(key).sign(new JWSHeader(JWSAlgorithm.ES256), input);
        return encodedHeader + "." + encodedClaims + "." + signature;
    }

    private static RegistrationManifest registration() {
        return new RegistrationManifest(1, "dutch-development", "Dutch", "development",
                new RegistrationManifest.Client("dutch-mobile", "public_native", List.of("dutch://oauth/callback"),
                        List.of("authorization_code"), List.of("S256"), "external"),
                new RegistrationManifest.Resource("dutch-api", "https://api.dutch.example", List.of("member:read")),
                new RegistrationManifest.SecurityPolicy(1, true, "S256", List.of("authorization_code"), List.of()));
    }
}
