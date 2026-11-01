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

class DpopProofVerifierTest {
    private static final Instant NOW = Instant.parse("2026-10-26T00:00:00Z");
    private static final String TARGET = "https://iam.example/oauth2/token";

    @Test
    void verifiesAClosedEs256TokenProofAndDerivesTheRfc7638Thumbprint() throws Exception {
        var key = new ECKeyGenerator().generate();
        var proof = proof(key, "proof_jti_abcdefghijklmnop", "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH");

        var verified = authoritativeVerifier()
                .verifyTokenProof(proof, "POST", TARGET, "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH");

        assertThat(verified.method()).isEqualTo("POST");
        assertThat(verified.target()).isEqualTo(TARGET);
        assertThat(verified.jti()).isEqualTo("proof_jti_abcdefghijklmnop");
        assertThat(verified.keyThumbprint()).hasSize(43);
    }

    @Test
    void rejectsAProofThatContainsAthAtTheTokenEndpoint() throws Exception {
        var key = new ECKeyGenerator().generate();
        var claims = baseClaims("proof_jti_abcdefghijklmnop", "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH")
                .claim("ath", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").build();
        var proof = sign(key, claims);

        assertThatThrownBy(() -> authoritativeVerifier()
                .verifyTokenProof(proof, "POST", TARGET, "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH"))
                .isInstanceOf(DpopProofRejectedException.class)
                .hasMessage("invalid_dpop_proof");
    }

    @Test
    void verifiesAResourceProofAgainstTheAccessTokenHash() throws Exception {
        var key = new ECKeyGenerator().generate();
        var compactCredential = "signed.access.token";
        var ath = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                java.security.MessageDigest.getInstance("SHA-256")
                        .digest(compactCredential.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        var claims = baseClaims("proof_jti_abcdefghijklmnop", "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH")
                .claim("ath", ath).build();

        var verified = authoritativeVerifier()
                .verifyResourceProof(sign(key, claims), "POST", TARGET,
                        "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH", compactCredential, key.computeThumbprint().toString());

        assertThat(verified.keyThumbprint()).isEqualTo(key.computeThumbprint().toString());
    }

    @Test
    void rejectsMalformedMismatchedExpiredAndOversizedProofs() throws Exception {
        var verifier = authoritativeVerifier();
        var key = new ECKeyGenerator().generate();
        var nonce = "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH";
        var valid = proof(key, "proof_jti_abcdefghijklmnop", nonce);
        var wrongMethod = sign(key, baseClaims("proof_jti_abcdefghijklmnop", nonce)
                .claim("htm", "GET").build());
        var wrongTarget = sign(key, new JWTClaimsSet.Builder().claim("htm", "POST")
                .claim("htu", "https://iam.example/other").issueTime(Date.from(NOW))
                .jwtID("proof_jti_abcdefghijklmnop").claim("nonce", nonce).build());
        var expired = sign(key, new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", TARGET)
                .issueTime(Date.from(NOW.minusSeconds(61))).jwtID("proof_jti_abcdefghijklmnop")
                .claim("nonce", nonce).build());

        assertThatThrownBy(() -> verifier.verifyTokenProof(null, "POST", TARGET, nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof("x".repeat(4097), "POST", TARGET, nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof("bad", "POST", TARGET, nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(valid, "post", TARGET, nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(wrongMethod, "POST", TARGET, nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(wrongTarget, "POST", TARGET, nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(expired, "POST", TARGET, nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 9, 4096,
                () -> "https://iam.example"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsWrongResourceTokenHashAndThumbprint() throws Exception {
        var key = new ECKeyGenerator().generate();
        var nonce = "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH";
        var compactCredential = "signed.access.token";
        var ath = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                java.security.MessageDigest.getInstance("SHA-256")
                        .digest(compactCredential.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        var proof = sign(key, baseClaims("proof_jti_abcdefghijklmnop", nonce).claim("ath", ath).build());
        var verifier = authoritativeVerifier();

        assertThatThrownBy(() -> verifier.verifyResourceProof(proof, "POST", TARGET, nonce,
                "other.access.token", key.computeThumbprint().toString())).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyResourceProof(proof, "POST", TARGET, nonce,
                compactCredential, "a".repeat(43))).isInstanceOf(DpopProofRejectedException.class);
    }

    @Test
    void rejectsInvalidBoundsTargetsNonceJtiAndFutureTime() throws Exception {
        var key = new ECKeyGenerator().generate();
        var nonce = "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH";
        var verifier = authoritativeVerifier();
        var valid = proof(key, "proof_jti_abcdefghijklmnop", nonce);
        var badJti = proof(key, "short", nonce);
        var future = sign(key, new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", TARGET)
                .issueTime(Date.from(NOW.plusSeconds(6))).jwtID("proof_jti_abcdefghijklmnop")
                .claim("nonce", nonce).build());

        assertThatThrownBy(() -> new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 121, 4096,
                () -> "https://iam.example")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 60, 511,
                () -> "https://iam.example")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 60, 31, 4096,
                () -> "https://iam.example")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 60, 16385,
                () -> "https://iam.example")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(valid, "POST", "http://iam.example/oauth2/token", nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(valid, "POST", TARGET + "?x=1", nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(valid, "POST", TARGET + "#x", nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(valid, "POST", "https://user@iam.example/oauth2/token", nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(valid, "POST", TARGET, "short")).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(badJti, "POST", TARGET, nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(future, "POST", TARGET, nonce)).isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyResourceProof(valid, "POST", TARGET, nonce, null, "a".repeat(43))).isInstanceOf(DpopProofRejectedException.class);
    }

    @Test
    void verifiesAnInitialNonceChallengeProofWithoutReadingAnAuthorizationCode() throws Exception {
        var key = new ECKeyGenerator().generate();
        var claims = new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", TARGET)
                .issueTime(Date.from(NOW)).jwtID("proof_jti_initial_abcdef").build();

        var verified = authoritativeVerifier()
                .verifyNonceChallengeProof(sign(key, claims), "POST", TARGET);

        assertThat(verified.nonce()).isNull();
        assertThat(verified.keyThumbprint()).isEqualTo(key.computeThumbprint().toString());
    }

    @Test
    void verifiesTheSignedPresentedNonceBeforePersistenceLookup() throws Exception {
        var key = new ECKeyGenerator().generate();
        var nonce = "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH";

        var verified = authoritativeVerifier()
                .verifyPresentedTokenProof(proof(key, "proof_jti_abcdefghijklmnop", nonce), "POST", TARGET);

        assertThat(verified.nonce()).isEqualTo(nonce);
    }

    @Test
    void rejectsShortJtiPaddedSegmentsAndHighSSignatures() throws Exception {
        var key = new ECKeyGenerator().generate();
        var nonce = "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH";
        var verifier = authoritativeVerifier();
        var shortJti = proof(key, "j".repeat(21), nonce);
        var valid = proof(key, "j".repeat(22), nonce);
        var segments = valid.split("\\.");
        var padded = segments[0] + "=." + segments[1] + "." + segments[2];

        assertThatThrownBy(() -> verifier.verifyTokenProof(shortJti, "POST", TARGET, nonce))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(padded, "POST", TARGET, nonce))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> verifier.verifyTokenProof(withHighS(valid), "POST", TARGET, nonce))
                .isInstanceOf(DpopProofRejectedException.class);
    }

    @Test
    void tokenProofTargetComesOnlyFromTheTrustedIssuerAuthority() throws Exception {
        var key = new ECKeyGenerator().generate();
        var nonce = "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH";
        var valid = proof(key, "j".repeat(22), nonce);
        var verifier = authoritativeVerifier();

        assertThat(verifier.verifyTokenProof(valid, "POST", TARGET, nonce).target()).isEqualTo(TARGET);
        assertThatThrownBy(() -> verifier.verifyTokenProof(valid, "POST", "https://evil.example/oauth2/token", nonce))
                .isInstanceOf(DpopProofRejectedException.class);
        assertThatThrownBy(() -> new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 60, 4096,
                () -> "https://iam.example/other"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsNonCanonicalRfc3986Targets() throws Exception {
        var key = new ECKeyGenerator().generate();
        var nonce = "nonce_abcdefghijklmnopqrstuvwxyzABCDEFGH";
        var verifier = authoritativeVerifier();
        for (var target : java.util.List.of("https://iam.example:443/oauth2/token",
                "https://iam.example/oauth2/./token", "https://iam.example/oauth2/%74oken",
                "https://iam.example/oauth2/%2574oken", "https://IAM.example/oauth2/token")) {
            var claims = new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", target)
                    .issueTime(Date.from(NOW)).jwtID("j".repeat(22)).claim("nonce", nonce).build();
            var proof = sign(key, claims);
            assertThatThrownBy(() -> verifier.verifyTokenProof(proof, "POST", TARGET, nonce))
                    .as(target).isInstanceOf(DpopProofRejectedException.class);
        }
    }

    private static DpopProofVerifier authoritativeVerifier() {
        return new DpopProofVerifier(Clock.fixed(NOW, ZoneOffset.UTC), 60, 4096,
                () -> "https://iam.example");
    }

    private static String withHighS(String compact) {
        var parts = compact.split("\\.");
        var signature = java.util.Base64.getUrlDecoder().decode(parts[2]);
        var order = new java.math.BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        var s = new java.math.BigInteger(1, java.util.Arrays.copyOfRange(signature, 32, 64));
        var high = s.compareTo(order.shiftRight(1)) > 0 ? s : order.subtract(s);
        var encoded = unsigned32(high);
        System.arraycopy(encoded, 0, signature, 32, 32);
        parts[2] = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        return String.join(".", parts);
    }

    private static String withLowS(String compact) {
        var parts = compact.split("\\.");
        var signature = java.util.Base64.getUrlDecoder().decode(parts[2]);
        var order = new java.math.BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
        var s = new java.math.BigInteger(1, java.util.Arrays.copyOfRange(signature, 32, 64));
        if (s.compareTo(order.shiftRight(1)) > 0) {
            var encoded = unsigned32(order.subtract(s));
            System.arraycopy(encoded, 0, signature, 32, 32);
            parts[2] = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        }
        return String.join(".", parts);
    }

    private static byte[] unsigned32(java.math.BigInteger value) {
        var source = value.toByteArray();
        var result = new byte[32];
        System.arraycopy(source, Math.max(0, source.length - 32), result, Math.max(0, 32 - source.length),
                Math.min(32, source.length));
        return result;
    }

    private static String proof(ECKey key, String jti, String nonce) throws Exception {
        return sign(key, baseClaims(jti, nonce).build());
    }

    private static JWTClaimsSet.Builder baseClaims(String jti, String nonce) {
        return new JWTClaimsSet.Builder().claim("htm", "POST").claim("htu", TARGET)
                .issueTime(Date.from(NOW)).jwtID(jti).claim("nonce", nonce);
    }

    private static String sign(ECKey key, JWTClaimsSet claims) throws Exception {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType("dpop+jwt"))
                .jwk(key.toPublicJWK()).build(), claims);
        jwt.sign(new ECDSASigner(key));
        return withLowS(jwt.serialize());
    }

    private static final class ECKeyGenerator {
        ECKey generate() throws Exception {
            var generator = java.security.KeyPairGenerator.getInstance("EC");
            generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            var pair = generator.generateKeyPair();
            return new ECKey.Builder(Curve.P_256, (java.security.interfaces.ECPublicKey) pair.getPublic())
                    .privateKey((java.security.interfaces.ECPrivateKey) pair.getPrivate()).build();
        }
    }
}
