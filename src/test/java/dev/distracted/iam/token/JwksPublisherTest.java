package dev.distracted.iam.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

@ExtendWith(OutputCaptureExtension.class)
class JwksPublisherTest {
    @Test void publishesSortedPublicAllowlistWithStableStrongEtag() throws Exception {
        var active = key("signing02");
        var old = key("signing01").toPublicJWK();
        var publisher = new JwksPublisher(new Signer(active, List.of(active.toPublicJWK(), old), true));

        assertThat(publisher.document().keys()).extracting(key -> key.get("kid"))
                .containsExactly("signing01", "signing02");
        assertThat(publisher.document().keys()).allSatisfy(key -> {
            assertThat(key).containsOnlyKeys("kty", "use", "alg", "kid", "crv", "x", "y");
            assertThat(key).doesNotContainKeys("d", "provider", "keyReference");
        });
        assertThat(publisher.etag()).matches("\"[a-f0-9]{64}\"");
        assertThat(new String(publisher.json())).doesNotContain("\"d\"");
    }

    @Test void containsExternalCapabilityDetailsAndDoesNotLogThem(CapturedOutput output) {
        for (var stage : ThrowAt.values()) {
            assertThatThrownBy(() -> new JwksPublisher(new ThrowingCapability(stage)))
                    .isInstanceOf(HumanAccessTokenIssueException.class)
                    .hasMessage("access token could not be issued")
                    .hasMessageNotContaining("provider-secret-canary");
        }
        assertThat(output.getAll()).doesNotContain("provider-secret-canary");
    }

    @Test void capturesExactlyOneImmutableProviderSnapshotAndRejectsKidSignerMismatch() throws Exception {
        var first = key("signing01");
        var second = key("signing02");
        var reads = new java.util.concurrent.atomic.AtomicInteger();
        AccessTokenSigningCapability changing = () -> {
            if (reads.incrementAndGet() == 1) {
                return new AccessTokenSigningSnapshot("ACCESS_TOKEN_SIGNING", "ES256", first.getKeyID(),
                        List.of(first.toPublicJWK()), true, input -> sign(first, input));
            }
            return new AccessTokenSigningSnapshot("ACCESS_TOKEN_SIGNING", "ES256", second.getKeyID(),
                    List.of(second), true, input -> sign(second, input));
        };
        var publisher = new JwksPublisher(changing);
        assertThat(reads).hasValue(1);
        assertThat(publisher.document().keys()).extracting(value -> value.get("kid")).containsExactly("signing01");

        var mismatch = new AccessTokenSigningSnapshot("ACCESS_TOKEN_SIGNING", "ES256", first.getKeyID(),
                List.of(first.toPublicJWK()), true, input -> sign(second, input));
        assertThatThrownBy(() -> new JwksPublisher(mismatch))
                .isInstanceOf(HumanAccessTokenIssueException.class)
                .hasMessage("access token could not be issued");
    }

    private static byte[] sign(ECKey key, byte[] input) {
        try { return new ECDSASigner(key).sign(new JWSHeader(JWSAlgorithm.ES256), input).decode(); }
        catch (Exception exception) { throw new IllegalStateException(exception); }
    }

    @Test void rejectsPrivateDuplicateMissingActiveAndUnhealthyMaterial() throws Exception {
        var key = key("signing01");
        var cases = List.<AccessTokenSigningCapability>of(
                new Signer(key, List.of(key), true),
                new Signer(key, List.of(key.toPublicJWK(), key.toPublicJWK()), true),
                new Signer(key, List.of(key("signing02").toPublicJWK()), true),
                new Signer(key, List.of(key.toPublicJWK()), false),
                new Signer(key, List.of(), true),
                new Signer(key, List.of(key.toPublicJWK()), true, "OTHER", "ES256", "signing01", true),
                new Signer(key, List.of(key.toPublicJWK()), true,
                        "ACCESS_TOKEN_SIGNING", "RS256", "signing01", true),
                new Signer(key, List.of(key.toPublicJWK()), true,
                        "ACCESS_TOKEN_SIGNING", "ES256", "bad", true),
                new Signer(key, List.of(key.toPublicJWK()), true,
                        "ACCESS_TOKEN_SIGNING", "ES256", "signing01", false),
                new Signer(key, List.of(new ECKeyGenerator(Curve.P_256).keyID("wronguse01")
                        .keyUse(com.nimbusds.jose.jwk.KeyUse.ENCRYPTION)
                        .algorithm(JWSAlgorithm.ES256).generate().toPublicJWK()), true,
                        "ACCESS_TOKEN_SIGNING", "ES256", "wronguse01", true),
                new Signer(key, List.of(new ECKeyGenerator(Curve.P_256).keyID("wrongalg01")
                        .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                        .algorithm(JWSAlgorithm.RS256).generate().toPublicJWK()), true,
                        "ACCESS_TOKEN_SIGNING", "ES256", "wrongalg01", true));
        for (var candidate : cases) {
            assertThatThrownBy(() -> new JwksPublisher(candidate))
                    .isInstanceOf(HumanAccessTokenIssueException.class)
                    .hasMessage("access token could not be issued");
        }
    }

    private static ECKey key(String keyId) throws Exception {
        return new ECKeyGenerator(Curve.P_256).keyID(keyId)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
    }

    private record Signer(ECKey active, List<ECKey> publicKeys, boolean healthy,
                          String purpose, String algorithm, String activeId, boolean validSignature)
            implements AccessTokenSigningCapability {
        private Signer(ECKey active, List<ECKey> publicKeys, boolean healthy) {
            this(active, publicKeys, healthy, "ACCESS_TOKEN_SIGNING", "ES256", active.getKeyID(), true);
        }
        @Override public AccessTokenSigningSnapshot snapshot() {
            return new AccessTokenSigningSnapshot(purpose, algorithm, activeId, publicKeys, healthy, this::sign);
        }
        private byte[] sign(byte[] input) {
            if (!validSignature) return new byte[64];
            try { return new ECDSASigner(active).sign(new JWSHeader(JWSAlgorithm.ES256), input).decode(); }
            catch (Exception exception) { throw new IllegalStateException(exception); }
        }
    }

    private enum ThrowAt { SNAPSHOT, SIGN }

    private static final class ThrowingCapability implements AccessTokenSigningCapability {
        private final ThrowAt stage;
        private final ECKey key;

        private ThrowingCapability(ThrowAt stage) {
            this.stage = stage;
            try { this.key = key("signing01"); }
            catch (Exception exception) { throw new IllegalStateException(exception); }
        }

        @Override public AccessTokenSigningSnapshot snapshot() {
            fail(ThrowAt.SNAPSHOT);
            return new AccessTokenSigningSnapshot("ACCESS_TOKEN_SIGNING", "ES256", key.getKeyID(),
                    List.of(key.toPublicJWK()), true, this::sign);
        }
        private byte[] sign(byte[] input) {
            fail(ThrowAt.SIGN);
            try { return new ECDSASigner(key).sign(new JWSHeader(JWSAlgorithm.ES256), input).decode(); }
            catch (Exception exception) { throw new IllegalStateException(exception); }
        }
        private void fail(ThrowAt point) {
            if (stage == point) throw new IllegalStateException("provider-secret-canary");
        }
    }
}
