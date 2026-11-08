package dev.distracted.iam.platform.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import org.junit.jupiter.api.Test;

class JcaEs256TokenSignerCapabilityTest {
    private static final String PROVIDER = "local-jca";
    private static final String KEY_REFERENCE = "local-signing-v1";

    @Test
    void signsVerifiableEs256Signatures() throws Exception {
        var pair = keyPair();
        var signer = new JcaEs256TokenSignerCapability(PROVIDER, KEY_REFERENCE, "ES256", pair.getPrivate().getEncoded());
        var input = "human-access-token-signing-input".getBytes(StandardCharsets.UTF_8);

        var signed = signer.sign(input);

        assertThat(signed).hasSize(64);
        var verifier = Signature.getInstance("SHA256withECDSAinP1363Format");
        verifier.initVerify(pair.getPublic());
        verifier.update(input);
        assertThat(verifier.verify(signed)).isTrue();
        assertThat(signer.metadata().purpose()).isEqualTo(CapabilityPurpose.ACCESS_TOKEN_SIGNING);
        assertThat(signer.metadata().provider()).isEqualTo(PROVIDER);
        assertThat(signer.metadata().keyReference()).isEqualTo(KEY_REFERENCE);
        assertThat(signer.metadata().algorithm()).isEqualTo("ES256");
        assertThat(signer.selfCheck()).isEqualTo(CapabilitySelfCheck.ready());
    }

    @Test
    void rejectsNonEs256Algorithm() throws Exception {
        var pair = keyPair();
        assertThatThrownBy(() -> new JcaEs256TokenSignerCapability(
                PROVIDER, KEY_REFERENCE, "RS256", pair.getPrivate().getEncoded()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("signer_algorithm_invalid");
    }

    @Test
    void rejectsMaterialThatIsNotAnEcPrivateKey() {
        assertThatThrownBy(() -> new JcaEs256TokenSignerCapability(
                PROVIDER, KEY_REFERENCE, "ES256", new byte[] {1, 2, 3}))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("signer_key_invalid");
    }

    @Test
    void rejectsSecp256k1DespiteIts256BitOrder() throws Exception {
        var parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256k1"));
        var key = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(
                BigInteger.ONE, parameters.getParameterSpec(ECParameterSpec.class)));

        assertThatThrownBy(() -> new JcaEs256TokenSignerCapability(
                PROVIDER, KEY_REFERENCE, "ES256", key.getEncoded()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("signer_key_not_p256");
    }

    @Test
    void rejectsMissingKeyMaterial() {
        assertThatThrownBy(() -> new JcaEs256TokenSignerCapability(PROVIDER, KEY_REFERENCE, "ES256", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("signer_key_missing");
        assertThatThrownBy(() -> new JcaEs256TokenSignerCapability(PROVIDER, KEY_REFERENCE, "ES256", new byte[0]))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("signer_key_missing");
    }

    private static KeyPair keyPair() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
}
