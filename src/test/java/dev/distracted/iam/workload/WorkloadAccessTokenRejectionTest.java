package dev.distracted.iam.workload;

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
import dev.distracted.iam.token.SecureAccessTokenMaterialGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class WorkloadAccessTokenRejectionTest {
    private static final String ISSUER = "https://iam.distracted.invalid";
    private static final String AUDIENCE = "https://iam.distracted.invalid/internal/onboarding";
    private static final String WORKLOAD_ID = "wl_0123456789abcdefghijklmnop";
    private static final String APP_ID = "dutch-development";
    private static final String CLIENT_ID = "ums-ingestion";
    private static final String KEY_ID = "workload-key-1";
    private static final Instant NOW = Instant.parse("2026-11-08T00:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private KeyPair pair;
    private ECKey jwk;
    private WorkloadIdentityProperties properties;
    private WorkloadAccessTokenVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        pair = generator.generateKeyPair();
        jwk = jwk(pair, KEY_ID);
        properties = properties(pair, ISSUER, List.of(binding(APP_ID, "iam:onboarding:read")));
        verifier = new WorkloadAccessTokenVerifier(properties, CLOCK);
    }

    @Test
    void rejectsEveryClaimSetAndValueMutation() throws Exception {
        var mutations = new ArrayList<Consumer<Map<String, Object>>>();
        mutations.add(claims -> claims.remove("iss"));
        mutations.add(claims -> claims.put("cnf", Map.of("jkt", "ignored")));
        mutations.add(claims -> claims.put("token_profile", "human_access"));
        mutations.add(claims -> claims.put("token_version", 2));
        mutations.add(claims -> claims.put("subject_kind", "app_subject"));
        mutations.add(claims -> claims.put("sub", "wl_short"));
        mutations.add(claims -> claims.put("app_id", "Bad App"));
        mutations.add(claims -> claims.put("client_id", "Bad Client"));
        mutations.add(claims -> claims.put("app_id", "other-app"));
        mutations.add(claims -> claims.put("aud", "https://other.invalid/internal"));
        mutations.add(claims -> claims.put("scope", "iam:onboarding:read ums:onboarding:write"));
        mutations.add(claims -> claims.put("scope", "iam:onboarding:read iam:onboarding:read"));
        mutations.add(claims -> claims.put("scope", "ums:onboarding:write"));
        mutations.add(claims -> claims.put("security_version", 0));
        mutations.add(claims -> claims.put("jti", "short"));
        mutations.add(claims -> claims.put("iat", NOW.getEpochSecond() + 120));
        mutations.add(claims -> claims.put("exp", NOW.getEpochSecond() + 1000));
        mutations.add(claims -> claims.put("exp", NOW.getEpochSecond() - 60));
        for (var mutation : mutations) {
            var claims = validClaims();
            mutation.accept(claims);
            assertThatThrownBy(() -> verifier.verify(signed(claims, "at+jwt", KEY_ID), AUDIENCE, "iam:onboarding:read"))
                    .as("mutation must be rejected")
                    .isInstanceOf(WorkloadAccessTokenException.class);
        }
    }

    @Test
    void rejectsHeaderAndEncodingMutations() throws Exception {
        assertThatThrownBy(() -> verifier.verify(signed(validClaims(), "JWT", KEY_ID), AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> verifier.verify(signed(validClaims(), "at+jwt", "unknown-key"), AUDIENCE,
                "iam:onboarding:read")).isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> verifier.verify("not.a.jwt", AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> verifier.verify("a.b", AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> verifier.verify(null, AUDIENCE, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> verifier.verify(signed(validClaims(), "at+jwt", KEY_ID), null, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
    }

    @Test
    void issuerRejectsInvalidLifetimeBindingsAndRequests() throws Exception {
        assertThatThrownBy(() -> issuer(properties(ISSUER, 59, List.of(binding(APP_ID, "iam:onboarding:read")))))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer(properties(ISSUER, 901, List.of(binding(APP_ID, "iam:onboarding:read")))))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer(properties(ISSUER, 300, List.of())))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer(properties("http://iam.invalid", 300,
                List.of(binding(APP_ID, "iam:onboarding:read")))))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer(properties(ISSUER, 300, List.of(
                new WorkloadIdentityProperties.Binding("bad", APP_ID, CLIENT_ID,
                        List.of(AUDIENCE), List.of("iam:onboarding:read"))))))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer(properties(ISSUER, 300,
                List.of(binding("Bad App", "iam:onboarding:read")))))
                .isInstanceOf(WorkloadAccessTokenException.class);

        var issuer = issuer(properties);
        assertThatThrownBy(() -> issuer.issue(WORKLOAD_ID, null, "iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer.issue(WORKLOAD_ID, AUDIENCE, "iam:onboarding:read iam:onboarding:read"))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer.issue(WORKLOAD_ID, AUDIENCE, " " + "a".repeat(70)))
                .isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> issuer.issue(WORKLOAD_ID, AUDIENCE, tooManyScopes()))
                .isInstanceOf(WorkloadAccessTokenException.class);
    }

    @Test
    void rejectsInvalidKeyMaterialAndBindings() throws Exception {
        var badKey = new WorkloadIdentityProperties(true, ISSUER, 300, 30,
                new WorkloadIdentityProperties.Signing("workload-key-1", "not-base64!", "not-base64!"),
                List.of(new WorkloadIdentityProperties.TrustedKey("workload-key-1", "not-base64!")),
                List.of(binding(APP_ID, "iam:onboarding:read")));
        assertThatThrownBy(() -> issuer(badKey)).isInstanceOf(WorkloadAccessTokenException.class);
        assertThatThrownBy(() -> new WorkloadAccessTokenVerifier(badKey, CLOCK))
                .isInstanceOf(WorkloadAccessTokenException.class);

        var badKeyId = new WorkloadIdentityProperties(true, ISSUER, 300, 30,
                new WorkloadIdentityProperties.Signing("bad", encode(pair.getPrivate().getEncoded()),
                        encode(pair.getPublic().getEncoded())),
                List.of(new WorkloadIdentityProperties.TrustedKey("workload-key-1", encode(pair.getPublic().getEncoded()))),
                List.of(binding(APP_ID, "iam:onboarding:read")));
        assertThatThrownBy(() -> issuer(badKeyId)).isInstanceOf(WorkloadAccessTokenException.class);

        var noTrustKeys = new WorkloadIdentityProperties(true, ISSUER, 300, 30,
                properties.signing(), List.of(), properties.bindings());
        assertThatThrownBy(() -> new WorkloadAccessTokenVerifier(noTrustKeys, CLOCK))
                .isInstanceOf(WorkloadAccessTokenException.class);

        var noBindings = new WorkloadIdentityProperties(true, ISSUER, 300, 30,
                properties.signing(), properties.trustedKeys(), null);
        assertThatThrownBy(() -> new WorkloadAccessTokenVerifier(noBindings, CLOCK))
                .isInstanceOf(WorkloadAccessTokenException.class);

        var badSkew = new WorkloadIdentityProperties(true, ISSUER, 300, 61,
                properties.signing(), properties.trustedKeys(), properties.bindings());
        assertThatThrownBy(() -> new WorkloadAccessTokenVerifier(badSkew, CLOCK))
                .isInstanceOf(WorkloadAccessTokenException.class);
    }

    @Test
    void rejectsMalformedIssuerFormsAndBindingShapes() {
        for (var issuer : new String[] {
                null, " ", "http://iam.invalid", "https://iam.invalid/path",
                "https://user@iam.invalid", "https://iam.invalid?x=1", "https://iam.invalid#fragment"}) {
            assertThatThrownBy(() -> issuer(properties(issuer, 300,
                    List.of(binding(APP_ID, "iam:onboarding:read")))))
                    .as("issuer must be rejected: %s", issuer)
                    .isInstanceOf(WorkloadAccessTokenException.class);
        }
        new WorkloadAccessTokenIssuer(
                new WorkloadIdentityProperties(true, ISSUER, null, 30, properties.signing(),
                        properties.trustedKeys(), List.of(binding(APP_ID, "iam:onboarding:read"))),
                new SecureAccessTokenMaterialGenerator(new SecureRandom()), CLOCK);
        var noAudience = new WorkloadIdentityProperties.Binding(
                WORKLOAD_ID, APP_ID, CLIENT_ID, null, List.of("iam:onboarding:read"));
        assertThatThrownBy(() -> issuer(properties(ISSUER, 300, List.of(noAudience))))
                .isInstanceOf(WorkloadAccessTokenException.class);
        var noScope = new WorkloadIdentityProperties.Binding(
                WORKLOAD_ID, APP_ID, CLIENT_ID, List.of(AUDIENCE), List.of());
        assertThatThrownBy(() -> issuer(properties(ISSUER, 300, List.of(noScope))))
                .isInstanceOf(WorkloadAccessTokenException.class);
        var noWorkload = new WorkloadIdentityProperties.Binding(
                null, APP_ID, CLIENT_ID, List.of(AUDIENCE), List.of("iam:onboarding:read"));
        assertThatThrownBy(() -> issuer(properties(ISSUER, 300, List.of(noWorkload))))
                .isInstanceOf(WorkloadAccessTokenException.class);
        var noClient = new WorkloadIdentityProperties.Binding(
                WORKLOAD_ID, APP_ID, null, List.of(AUDIENCE), List.of("iam:onboarding:read"));
        assertThatThrownBy(() -> issuer(properties(ISSUER, 300, List.of(noClient))))
                .isInstanceOf(WorkloadAccessTokenException.class);
    }

    private WorkloadAccessTokenIssuer issuer(WorkloadIdentityProperties configured) {
        return new WorkloadAccessTokenIssuer(configured,
                new SecureAccessTokenMaterialGenerator(new SecureRandom()), CLOCK);
    }

    private WorkloadIdentityProperties properties(WorkloadIdentityProperties.Binding... bindings) {
        return properties(ISSUER, 300, List.of(bindings));
    }

    private WorkloadIdentityProperties properties(
            String issuer, int lifetime, List<WorkloadIdentityProperties.Binding> bindings) {
        return new WorkloadIdentityProperties(true, issuer, lifetime, 30, properties.signing(),
                properties.trustedKeys(), bindings);
    }

    private LinkedHashMap<String, Object> validClaims() {
        var claims = new LinkedHashMap<String, Object>();
        claims.put("iss", ISSUER);
        claims.put("sub", WORKLOAD_ID);
        claims.put("aud", AUDIENCE);
        claims.put("iat", NOW.getEpochSecond());
        claims.put("exp", NOW.getEpochSecond() + 300);
        claims.put("jti", "0123456789abcdefghijklmnop");
        claims.put("client_id", CLIENT_ID);
        claims.put("token_profile", "workload_access");
        claims.put("token_version", 1);
        claims.put("subject_kind", "workload");
        claims.put("scope", "iam:onboarding:read");
        claims.put("app_id", APP_ID);
        claims.put("security_version", 1);
        return claims;
    }

    private String signed(Map<String, Object> claims, String type, String keyId) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(type))
                .keyID(keyId)
                .build();
        var object = new JWSObject(header, new Payload(claims));
        object.sign(new ECDSASigner(jwk));
        return object.serialize();
    }

    private static WorkloadIdentityProperties.Binding binding(String appId, String scope) {
        return new WorkloadIdentityProperties.Binding(WORKLOAD_ID, appId, CLIENT_ID,
                List.of(AUDIENCE), List.of(scope));
    }

    private static String tooManyScopes() {
        var scopes = new ArrayList<String>();
        for (var index = 0; index < 33; index++) {
            scopes.add("scope:" + index);
        }
        return String.join(" ", scopes);
    }

    private static WorkloadIdentityProperties properties(
            KeyPair pair, String issuer, List<WorkloadIdentityProperties.Binding> bindings) {
        return new WorkloadIdentityProperties(true, issuer, 300, 30,
                new WorkloadIdentityProperties.Signing(
                        KEY_ID, encode(pair.getPrivate().getEncoded()), encode(pair.getPublic().getEncoded())),
                List.of(new WorkloadIdentityProperties.TrustedKey(KEY_ID, encode(pair.getPublic().getEncoded()))),
                bindings);
    }

    private static ECKey jwk(KeyPair pair, String keyId) {
        return new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) pair.getPublic())
                .privateKey((java.security.interfaces.ECPrivateKey) pair.getPrivate())
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .build();
    }

    private static String encode(byte[] material) {
        return Base64.getEncoder().encodeToString(material);
    }
}
