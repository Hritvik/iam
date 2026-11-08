package dev.distracted.iam.workload;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class WorkloadAccessTokenTest {
    private static final String ISSUER = "https://iam.distracted.invalid";
    private static final String AUDIENCE = "https://iam.distracted.invalid/internal/onboarding";
    private static final String WORKLOAD_ID = "wl_0123456789abcdefghijklmnop";
    private static final String APP_ID = "dutch-development";
    private static final String CLIENT_ID = "ums-ingestion";
    private static final Instant NOW = Instant.parse("2026-11-08T00:00:00Z");

    private ECKey signingJwk;
    private WorkloadIdentityProperties properties;
    private dev.distracted.iam.token.SecureAccessTokenMaterialGenerator material;

    @BeforeEach
    void setUp() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        signingJwk = jwk(pair);
        material = new dev.distracted.iam.token.SecureAccessTokenMaterialGenerator(new SecureRandom());
        properties = properties(pair, List.of(
                new WorkloadIdentityProperties.Binding(WORKLOAD_ID, APP_ID, CLIENT_ID,
                        List.of(AUDIENCE), List.of("iam:onboarding:read", "ums:onboarding:write"))));
    }

    @Test
    void issuesAndVerifiesOneBoundWorkloadToken() {
        var issuer = issuer(Clock.fixed(NOW, ZoneOffset.UTC));
        var verifier = verifier(Clock.fixed(NOW.plusSeconds(30), ZoneOffset.UTC));

        var token = issuer.issue(WORKLOAD_ID, AUDIENCE, "iam:onboarding:read");

        var principal = verifier.verify(token, AUDIENCE, "iam:onboarding:read");
        assertThat(principal.appRegistrationId()).isEqualTo(APP_ID);
        assertThat(principal.audience()).isEqualTo(AUDIENCE);
        assertThat(principal.scopes()).containsExactly("iam:onboarding:read");
    }

    @Test
    void rejectsWrongAudienceScopeAndForeignAppBinding() {
        var issuer = issuer(Clock.fixed(NOW, ZoneOffset.UTC));
        var verifier = verifier(Clock.fixed(NOW, ZoneOffset.UTC));
        var token = issuer.issue(WORKLOAD_ID, AUDIENCE, "iam:onboarding:read");

        assertThatThrownBy(() -> verifier.verify(token, "https://other.invalid/internal", "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> verifier.verify(token, AUDIENCE, "ums:onboarding:write"))
                .isInstanceOf(WorkloadAccessTokenException.class);

        var foreign = properties(pairFrom(signingJwk), List.of(
                new WorkloadIdentityProperties.Binding(WORKLOAD_ID, "other-app", CLIENT_ID,
                        List.of(AUDIENCE), List.of("iam:onboarding:read"))));
        var foreignVerifier = new WorkloadAccessTokenVerifier(foreign, Clock.fixed(NOW, ZoneOffset.UTC));
        assertThatThrownBy(() -> foreignVerifier.verify(token, AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
    }

    @Test
    void rejectsExpiredAndTamperedTokens() {
        var issuer = issuer(Clock.fixed(NOW, ZoneOffset.UTC));
        var token = issuer.issue(WORKLOAD_ID, AUDIENCE, "iam:onboarding:read");
        var later = new WorkloadAccessTokenVerifier(properties, Clock.fixed(NOW.plusSeconds(331), ZoneOffset.UTC));
        assertThatThrownBy(() -> later.verify(token, AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);

        var verifier = verifier(Clock.fixed(NOW, ZoneOffset.UTC));
        var tampered = token.substring(0, token.length() - 2) + "AA";
        assertThatThrownBy(() -> verifier.verify(tampered, AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
    }

    @Test
    void rejectsWrongIssuerAndHumanProfileClaims() throws Exception {
        var verifier = verifier(Clock.fixed(NOW, ZoneOffset.UTC));
        var wrongIssuer = properties(pairFrom(signingJwk), List.of(
                new WorkloadIdentityProperties.Binding(WORKLOAD_ID, APP_ID, CLIENT_ID,
                        List.of(AUDIENCE), List.of("iam:onboarding:read"))));
        wrongIssuer = new WorkloadIdentityProperties(true, "https://other.invalid", 300, 30,
                wrongIssuer.signing(), wrongIssuer.trustedKeys(), wrongIssuer.bindings());
        var otherVerifier = new WorkloadAccessTokenVerifier(wrongIssuer, Clock.fixed(NOW, ZoneOffset.UTC));
        var token = issuer(Clock.fixed(NOW, ZoneOffset.UTC)).issue(WORKLOAD_ID, AUDIENCE, "iam:onboarding:read");
        assertThatThrownBy(() -> otherVerifier.verify(token, AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);

        var human = signed(signingJwk, humanClaims());
        assertThatThrownBy(() -> verifier.verify(human, AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
    }

    @Test
    void authenticatorMapsOnlyAValidBearerHeader() {
        var issuer = issuer(Clock.fixed(NOW, ZoneOffset.UTC));
        var authenticator = new JwtWorkloadAuthenticator(verifier(Clock.fixed(NOW, ZoneOffset.UTC)));

        assertThat(authenticator.authenticate(new Object())).isEmpty();
        assertThat(authenticator.authenticate(new MockHttpServletRequest())).isEmpty();
        assertThat(authenticator.authenticate(request(null))).isEmpty();
        assertThat(authenticator.authenticate(request("Basic abc"))).isEmpty();
        assertThat(authenticator.authenticate(request("Bearer "))).isEmpty();
        var principal = authenticator.authenticate(
                request("Bearer " + issuer.issue(WORKLOAD_ID, AUDIENCE, "iam:onboarding:read")));
        assertThat(principal).isPresent();
        assertThat(principal.orElseThrow().appRegistrationId()).isEqualTo(APP_ID);
    }

    @Test
    void issuerRejectsUnregisteredAudienceAndScope() {
        var issuer = issuer(Clock.fixed(NOW, ZoneOffset.UTC));
        assertThatThrownBy(() -> issuer.issue("wl_unknown0123456789abcdefghij", AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer.issue(WORKLOAD_ID, "https://other.invalid", "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer.issue(WORKLOAD_ID, AUDIENCE, "iam:onboarding:write"))
                .isInstanceOf(WorkloadAccessTokenException.class);
    }

    private WorkloadAccessTokenIssuer issuer(Clock clock) {
        return new WorkloadAccessTokenIssuer(properties, material, clock);
    }

    private WorkloadAccessTokenVerifier verifier(Clock clock) {
        return new WorkloadAccessTokenVerifier(properties, clock);
    }

    private static MockHttpServletRequest request(String authorization) {
        var request = new MockHttpServletRequest();
        if (authorization != null) request.addHeader("Authorization", authorization);
        return request;
    }

    private static WorkloadIdentityProperties properties(
            KeyPair pair, List<WorkloadIdentityProperties.Binding> bindings) {
        var signing = new WorkloadIdentityProperties.Signing(
                "workload-key-1",
                Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()),
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        return new WorkloadIdentityProperties(true, ISSUER, 300, 30, signing,
                List.of(new WorkloadIdentityProperties.TrustedKey(
                        "workload-key-1", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()))),
                bindings);
    }

    private static ECKey jwk(KeyPair pair) {
        return new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) pair.getPublic())
                .privateKey((java.security.interfaces.ECPrivateKey) pair.getPrivate())
                .keyID("workload-key-1")
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .build();
    }

    private static KeyPair pairFrom(ECKey jwk) {
        try {
            return new KeyPair(jwk.toECPublicKey(), jwk.toECPrivateKey());
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static String signed(ECKey key, LinkedHashMap<String, Object> claims) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("at+jwt"))
                .keyID(key.getKeyID())
                .build();
        var object = new JWSObject(header, new Payload(claims));
        object.sign(new ECDSASigner(key));
        return object.serialize();
    }

    private static LinkedHashMap<String, Object> humanClaims() {
        var claims = new LinkedHashMap<String, Object>();
        claims.put("iss", ISSUER);
        claims.put("sub", WORKLOAD_ID);
        claims.put("aud", AUDIENCE);
        claims.put("iat", NOW.getEpochSecond());
        claims.put("exp", NOW.getEpochSecond() + 300);
        claims.put("jti", "0123456789abcdefghijklmnop");
        claims.put("client_id", CLIENT_ID);
        claims.put("token_profile", "human_access");
        claims.put("token_version", 1);
        claims.put("subject_kind", "workload");
        claims.put("scope", "iam:onboarding:read");
        claims.put("app_id", APP_ID);
        claims.put("security_version", 1);
        return claims;
    }
}
