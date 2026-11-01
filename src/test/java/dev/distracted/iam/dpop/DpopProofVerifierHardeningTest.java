package dev.distracted.iam.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import org.junit.jupiter.api.Test;

/** Branch-hardening tests for the closed DPoP proof profile (W07-I). */
class DpopProofVerifierHardeningTest {
    private static final String TARGET = "https://iam.example/oauth2/token";
    private static final Instant NOW = Instant.parse("2026-10-26T00:00:00Z");
    private static final String NONCE = "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH";

    @Test void rejectsInvalidIssuerAuthorities() {
        for (var issuer : java.util.List.of("http://iam.example", "https://user@iam.example",
                "https://iam.example?x=1", "https://iam.example#f", "https://IAM.example",
                "https://iam.example:443", "https://iam.example/oauth2")) {
            assertThatThrownBy(() -> new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 60, 4096, () -> issuer))
                    .as(issuer).isInstanceOf(IllegalArgumentException.class);
        }
        assertThat(new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 60, 4096,
                () -> "https://iam.example/")).isNotNull();
    }

    @Test void rejectsPercentEncodedUnreservedCharactersAndLowercaseHex() throws Exception {
        var key = generate();
        for (var encoded : java.util.List.of("%61", "%41", "%30", "%2D", "%2E", "%5F", "%7E", "%6a", "%2f")) {
            var htu = "https://iam.example/oauth2/token" + encoded;
            var proof = sign(key, claims(htu, NOW));
            assertThatThrownBy(() -> verifier().verifyTokenProof(proof, "POST", TARGET, NONCE))
                    .as(encoded).isInstanceOf(DpopProofRejectedException.class);
        }
    }

    @Test void rejectsResourceProofsWithoutTokenOrBinding() {
        var verifier = verifier();
        assertThatThrownBy(() -> verifier.verifyResourceProof("a.b.c", "GET", TARGET, NONCE, null, "thumb"))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyResourceProof("a.b.c", "GET", TARGET, NONCE, " ", "thumb"))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyResourceChallengeProof("a.b.c", "GET", TARGET, "token", null))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyResourceChallengeProof("a.b.c", "GET", TARGET, null, "thumb"))
                .isInstanceOf(DpopProofRejectedException.class);
    }

    @Test void rejectsNonIntegralAndOversizedTimes() throws Exception {
        var key = generate();
        for (var issueTime : java.util.List.of(new Date(Long.MAX_VALUE), new Date(0L))) {
            var proof = sign(key, claims(TARGET, Instant.ofEpochMilli(issueTime.getTime())));
            assertThatThrownBy(() -> verifier().verifyTokenProof(proof, "POST", TARGET, NONCE))
                    .isInstanceOf(DpopProofRejectedException.class);
        }
        var decimal = sign(key, new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", TARGET)
                .claim("iat", 1.5).jwtID("proof_jti_abcdefghijklmnop").claim("nonce", NONCE).build());
        assertThatThrownBy(() -> verifier().verifyTokenProof(decimal, "POST", TARGET, NONCE))
                .isInstanceOf(DpopProofRejectedException.class);
        var text = sign(key, new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", TARGET)
                .claim("iat", "not-a-number").jwtID("proof_jti_abcdefghijklmnop").claim("nonce", NONCE).build());
        assertThatThrownBy(() -> verifier().verifyTokenProof(text, "POST", TARGET, NONCE))
                .isInstanceOf(DpopProofRejectedException.class);
    }

    @Test void rejectsStructuralNonceAndTimeVariants() throws Exception {
        var verifier = verifier();
        assertThatThrownBy(() -> verifier.verifyPresentedTokenProof(null, "POST", TARGET))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyPresentedTokenProof("x".repeat(4097), "POST", TARGET))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyResourceProof("a.b.c", "GET", TARGET, NONCE, "token", ""))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyResourceChallengeProof("a.b.c", "GET", TARGET, " ", "thumb"))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof("a.b", "POST", TARGET, NONCE))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof("a..c", "POST", TARGET, NONCE))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof("a.b.c!", "POST", TARGET, NONCE))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThat(new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 60, 4096,
                () -> "https://iam.example:444")).isNotNull();

        var key = generate();
        for (var htu : java.util.List.of("/oauth2/token", "https://iam.example/oauth2/token?x",
                "https://iam.example/oauth2/token#f", "https://iam.example/oauth2//token")) {
            var proof = sign(key, claims(htu, NOW));
            assertThatThrownBy(() -> verifier.verifyTokenProof(proof, "POST", TARGET, NONCE))
                    .as(htu).isInstanceOf(DpopProofRejectedException.class);
        }
        var big = sign(key, new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", TARGET)
                .claim("iat", new java.math.BigInteger("100000000000000000000"))
                .jwtID("proof_jti_abcdefghijklmnop").claim("nonce", NONCE).build());
        assertThatThrownBy(() -> verifier.verifyTokenProof(big, "POST", TARGET, NONCE))
                .isInstanceOf(DpopProofRejectedException.class);
        var longTime = sign(key, new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", TARGET)
                .claim("iat", 4_000_000_000L).jwtID("proof_jti_abcdefghijklmnop").claim("nonce", NONCE).build());
        assertThatThrownBy(() -> verifier.verifyTokenProof(longTime, "POST", TARGET, NONCE))
                .isInstanceOf(DpopProofRejectedException.class);
        var zeroS = sign(key, claims(TARGET, NOW)).split("\\.");
        var zeroBytes = java.util.Base64.getUrlDecoder().decode(zeroS[2]);
        java.util.Arrays.fill(zeroBytes, 32, 64, (byte) 0);
        zeroS[2] = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(zeroBytes);
        assertThatThrownBy(() -> verifier.verifyTokenProof(String.join(".", zeroS), "POST", TARGET, NONCE))
                .isInstanceOf(DpopProofRejectedException.class);
        var shortSignature = sign(key, claims(TARGET, NOW)).split("\\.");
        shortSignature[2] = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(new byte[63]);
        assertThatThrownBy(() -> verifier.verifyTokenProof(String.join(".", shortSignature), "POST", TARGET, NONCE))
                .isInstanceOf(DpopProofRejectedException.class);
    }

    private static DpopProofVerifier verifier() {
        return new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 60, 4096, () -> "https://iam.example");
    }

    private static JWTClaimsSet claims(String htu, Instant issuedAt) {
        return new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", htu)
                .issueTime(Date.from(issuedAt)).jwtID("proof_jti_abcdefghijklmnop").claim("nonce", NONCE).build();
    }

    private static String sign(ECKey key, JWTClaimsSet claims) throws Exception {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt"))
                .jwk(key.toPublicJWK()).build(), claims);
        jwt.sign(new ECDSASigner(key));
        return withLowS(jwt.serialize());
    }

    private static String withLowS(String compact) {
        var parts = compact.split("\\.");
        var signature = java.util.Base64.getUrlDecoder().decode(parts[2]);
        var order = new java.math.BigInteger(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        var s = new java.math.BigInteger(1, java.util.Arrays.copyOfRange(signature, 32, 64));
        if (s.compareTo(order.shiftRight(1)) > 0) {
            var source = order.subtract(s).toByteArray();
            var encoded = new byte[32];
            System.arraycopy(source, Math.max(0, source.length - 32), encoded,
                    Math.max(0, 32 - source.length), Math.min(32, source.length));
            System.arraycopy(encoded, 0, signature, 32, 32);
            parts[2] = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        }
        return String.join(".", parts);
    }

    private static ECKey generate() throws Exception {
        var generator = java.security.KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        var pair = generator.generateKeyPair();
        return new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) pair.getPublic())
                .privateKey((java.security.interfaces.ECPrivateKey) pair.getPrivate()).build();
    }
}
